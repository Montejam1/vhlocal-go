"""Scan execution as a library call.

`run.py` is now a thin CLI over this. The server drives the same function, so
there is exactly one implementation of the phase pipeline — a CLI scan and a
web-submitted scan are the same code path.

Two additions over the original CLI loop:

* **Structured events.** `on_event` receives dicts describing phase and agent
  boundaries. A logging handler also forwards the agent's own log lines, so the
  UI gets a live tool-by-tool feed without threading callbacks through
  `agent.py`.
* **Cooperative cancellation.** `should_cancel` is polled between turns inside
  the agent loop, so a cancelled scan stops within one model turn rather than
  running to completion.
"""

import datetime as _dt
import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .agent import run_agent
from .client import (
    DEFAULT_MODEL,
    DEFAULT_NUM_CTX,
    OllamaError,
    Usage,
    make_client,
)
from .phases import (
    CLASS_GROUPS,
    COMBINED_GROUP,
    PHASES,
    PHASES_BY_KEY,
    Partition,
    augment_partitions_for_coverage,
    build_system,
    build_task,
    load_preamble,
    resolve_partitions,
)
from .handoff import HANDOFF_FILE, write_handoff
from .tools import Sandbox

log = logging.getLogger(__name__)

EventFn = Callable[[Dict[str, Any]], None]
CancelFn = Callable[[], bool]


class ScanError(RuntimeError):
    """Configuration or preflight failure — the scan never started."""


def model_tag(model: str) -> str:
    """gpt-oss:120b -> gptoss120b, mirroring upstream results-dir naming."""
    return re.sub(r"[^a-z0-9]", "", model.lower()) or "model"


# Reports live outside the scanned repository by default. Writing them into the
# target was the upstream behaviour, but it pollutes the working tree with
# runnable exploit PoCs for that very service — one careless `git add` away from
# being committed and pushed. A central directory also makes the history of all
# scans browsable in one place.
DEFAULT_REPORTS_DIR = Path.home() / "vulnhunter-reports"


@dataclass
class ScanSpec:
    repo: Path
    skill_dir: Path
    out: Optional[Path] = None
    reports_dir: Optional[Path] = None
    model: str = DEFAULT_MODEL
    host: str = "http://localhost:11434"
    num_ctx: int = DEFAULT_NUM_CTX
    temperature: Optional[float] = None
    phases: str = "all"
    max_partitions: int = 8
    verify_model: Optional[str] = None
    verify_host: Optional[str] = None
    # Per-role model routing. Each phase runs on the "hunt" model (model/backend/
    # host above) unless its role has an explicit override here. Roles: recon
    # (phase 1), hunt (phase 2 + default), verify (phase 2b), reproduce (phases
    # 3/3d-model/4). An override falls back to the hunt backend/host when only its
    # model is set. See _role_client_config / _make_phase_clients.
    verify_backend: Optional[str] = None
    recon_model: Optional[str] = None
    recon_backend: Optional[str] = None
    recon_host: Optional[str] = None
    reproduce_model: Optional[str] = None
    reproduce_backend: Optional[str] = None
    reproduce_host: Optional[str] = None
    resume: bool = False
    # Harness-enforced coverage: append deterministic partitions for any
    # enumerated route the model's partition plan omits, so Phase 2 traces the
    # whole attack surface. On by default.
    enforce_coverage: bool = True
    # Seed Phase 1 recon with the full enumerated route list (opt-in).
    seed_routes: bool = False
    # Mode B (opt-in, off by default): seed Phase 1 with the prior report's
    # findings as hot spots to independently re-verify. Correlates this run with
    # the prior one — good for production tracking, unsuitable for union-recall
    # benchmarking, so it is recorded in scan_meta when used. See lifecycle.py.
    seed_prior: bool = False
    # Phase-2 fan-out: "split" = one agent per (partition x class), thorough but
    # 3x the agents; "combined" = one agent per partition covering all classes.
    phase2_mode: str = "split"
    # Quality-uncertain lever, off by default: reasoning-effort level for
    # gpt-oss-family models ("low"/"medium"/"high"; None = model default).
    reasoning_effort: Optional[str] = None
    # Quality-NEUTRAL speed lever: how many Phase-2 agents to dispatch at once.
    # 1 = serial (current). >1 needs OLLAMA_NUM_PARALLEL set on the server to
    # actually overlap; otherwise requests just queue harmlessly.
    concurrency: int = 1
    # Inference backend: "ollama" (native /api/chat, default) or "openai" (any
    # OpenAI-compatible server — mlx_lm.server on Apple Silicon, vLLM, LM Studio).
    backend: str = "ollama"
    # Max completion tokens per call (OpenAI/OpenRouter backends only; Ollama caps
    # via context). Bounds per-call cost and, critically for paid gateways, the
    # up-front credit reservation — without it OpenRouter pre-authorizes the full
    # model output (~65k) on every request. 0 = uncapped.
    max_output_tokens: int = 32768
    # Phase 3d root-cause sweep: "deterministic" (harness greps each confirmed
    # sink pattern directly — fast, complete, default) or "model" (the old
    # model-driven iterative grep).
    sweep_mode: str = "deterministic"

    def to_dict(self) -> Dict[str, Any]:
        d = {}
        for k, v in self.__dict__.items():
            d[k] = str(v) if isinstance(v, Path) else v
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ScanSpec":
        kwargs: Dict[str, Any] = {}
        for f in ("repo", "skill_dir", "out", "reports_dir"):
            if d.get(f):
                kwargs[f] = Path(d[f]).expanduser()
        for f in (
            "model", "host", "phases", "verify_model", "verify_host",
            "phase2_mode", "reasoning_effort", "backend", "sweep_mode",
            "verify_backend", "recon_model", "recon_backend", "recon_host",
            "reproduce_model", "reproduce_backend", "reproduce_host",
        ):
            if d.get(f) not in (None, ""):
                kwargs[f] = d[f]
        for f in ("num_ctx", "max_partitions", "concurrency", "max_output_tokens"):
            if d.get(f) not in (None, ""):
                kwargs[f] = int(d[f])
        if d.get("temperature") not in (None, ""):
            kwargs["temperature"] = float(d["temperature"])
        if d.get("resume") is not None:
            kwargs["resume"] = bool(d["resume"])
        if d.get("enforce_coverage") is not None:
            kwargs["enforce_coverage"] = bool(d["enforce_coverage"])
        if d.get("seed_routes") is not None:
            kwargs["seed_routes"] = bool(d["seed_routes"])
        if d.get("seed_prior") is not None:
            kwargs["seed_prior"] = bool(d["seed_prior"])
        return cls(**kwargs)


SCAN_META_FILE = "scan_meta.json"


@dataclass
class RunRecord:
    """What the engine actually did — the factual basis for the consolidated
    report. Every field here is observed by the engine, never model-authored,
    which is why the report renders from this rather than from prose the model
    wrote about its own run."""

    started_at: float = 0.0
    finished_at: float = 0.0
    repo: str = ""
    results_dir: str = ""
    model: str = ""
    verify_model: Optional[str] = None
    host: str = ""
    num_ctx: int = 0
    max_partitions: int = 0
    phases_requested: List[str] = field(default_factory=list)
    phases_completed: List[str] = field(default_factory=list)
    phases_skipped: List[str] = field(default_factory=list)
    phase_timings: Dict[str, float] = field(default_factory=dict)
    partitions: List[str] = field(default_factory=list)
    # How Phase-2 partitions were obtained (see phases.resolve_partitions).
    # partition_fallback True => the model's own table was unusable; collapsed
    # True => it degenerated to one whole-repo pass (coverage degraded).
    partition_source: str = ""
    partition_fallback: bool = False
    partition_parse_error: str = ""
    partition_collapsed: bool = False
    # Harness-enforced coverage: deterministic partitions appended for routes the
    # model's plan omitted, plus any files still uncovered at the cap.
    coverage_partitions_added: List[str] = field(default_factory=list)
    coverage_files_added: List[str] = field(default_factory=list)
    coverage_uncovered_remaining: List[str] = field(default_factory=list)
    vuln_classes: List[str] = field(default_factory=list)
    agents: List[Dict[str, Any]] = field(default_factory=list)
    usage: Dict[str, Any] = field(default_factory=dict)
    cancelled: bool = False
    engine_version: str = ""
    tool_envelope: List[str] = field(default_factory=list)
    bash_enabled: bool = False
    # Git provenance of the scanned tree (best-effort; empty when not a git repo).
    # Recorded so cross-run reconciliation (lifecycle Mode A) can say which commit
    # a finding first appeared in / was fixed at.
    git_commit: str = ""
    git_branch: str = ""
    git_dirty: bool = False
    # Mode B: the prior report id this run's Phase 1 was seeded from, or "" when
    # unseeded. A non-empty value marks the run as NOT independent (it was
    # correlated with a prior scan), which matters for union-recall benchmarking.
    seeded_from_prior: str = ""
    # Set when a systemic failure (endpoint unreachable) ended the run early.
    aborted: str = ""
    # The tag this run's lines carry in the central log (for `vhlocal logs`).
    scan_tag: str = ""
    # Per-role model provenance (empty when the role used the hunt model).
    recon_model: str = ""
    reproduce_model: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


def _handoff_confirmed_count(handoff_path) -> Optional[int]:
    """Confirmed-finding count from the Phase-2b handoff, for the live dashboard.
    Best-effort — returns None if it can't be read."""
    try:
        text = Path(handoff_path).read_text(encoding="utf-8")
    except (OSError, TypeError):
        return None
    import re as _re
    m = _re.search(r"Total confirmed findings:\s*(\d+)", text)
    if m:
        return int(m.group(1))
    return len(_re.findall(r"^\|\s*VULN-\d+\s*\|", text, _re.MULTILINE)) or None


def _findings_json_count(results_dir) -> Optional[int]:
    """Unique (non-duplicate) finding count from findings.json, or None."""
    try:
        data = json.loads((Path(results_dir) / "findings.json").read_text("utf-8"))
    except (OSError, ValueError):
        return None
    fs = data.get("findings") or []
    return sum(1 for f in fs if not f.get("duplicate_of"))


# Which model role runs each phase. Unlisted keys fall back to the hunt model.
_PHASE_ROLE = {"1": "recon", "2": "hunt", "2b": "verify",
               "3": "reproduce", "3d": "reproduce", "4": "reproduce"}


def _role_client_config(spec: "ScanSpec", role: str) -> Tuple[str, str, str]:
    """Resolve (backend, model, host) for a role. An override supplies its own
    model and may pin its own backend/host; anything it leaves blank falls back
    to the hunt model's backend/host. No override → the hunt model itself."""
    if role == "recon" and spec.recon_model:
        return (spec.recon_backend or spec.backend, spec.recon_model,
                spec.recon_host or spec.host)
    if role == "verify" and spec.verify_model:
        return (spec.verify_backend or spec.backend, spec.verify_model,
                spec.verify_host or spec.host)
    if role == "reproduce" and spec.reproduce_model:
        return (spec.reproduce_backend or spec.backend, spec.reproduce_model,
                spec.reproduce_host or spec.host)
    return (spec.backend, spec.model, spec.host)


def _make_phase_clients(spec: "ScanSpec", selected) -> Tuple[Dict[str, Any], list]:
    """One client per distinct (backend, model, host) used by the selected
    phases. Returns (client_by_phase_key, distinct_clients_to_preflight). A model
    shared across phases is built once. Phase 3d in deterministic sweep mode uses
    no model, so it is not assigned a client."""
    cache: Dict[Tuple[str, str, str], Any] = {}
    by_phase: Dict[str, Any] = {}
    for ph in selected:
        if ph.key == "3d" and spec.sweep_mode == "deterministic":
            continue
        cfg = _role_client_config(spec, _PHASE_ROLE.get(ph.key, "hunt"))
        if cfg not in cache:
            backend, model, host = cfg
            cache[cfg] = make_client(
                backend, model=model, host=host,
                num_ctx=spec.num_ctx, temperature=spec.temperature,
                reasoning_effort=spec.reasoning_effort,
                max_tokens=spec.max_output_tokens,
            )
        by_phase[ph.key] = cache[cfg]
    return by_phase, list(cache.values())


@dataclass
class ScanResult:
    results_dir: Path
    usage: Usage
    seconds: float
    completed_phases: List[str] = field(default_factory=list)
    cancelled: bool = False
    record: Optional[RunRecord] = None


class _EventLogHandler(logging.Handler):
    """Forward vhlocal log records to the event stream as `log` events."""

    def __init__(self, on_event: EventFn):
        super().__init__(level=logging.INFO)
        self._on_event = on_event

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._on_event({
                "type": "log",
                "level": record.levelname,
                "message": record.getMessage(),
            })
        except Exception:
            pass  # never let telemetry kill a scan


def _state_path(results_dir: Path) -> Path:
    return results_dir / ".vhlocal_state.json"


def load_state(results_dir: Path) -> dict:
    p = _state_path(results_dir)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"completed": []}


def save_state(results_dir: Path, state: dict) -> None:
    _state_path(results_dir).write_text(json.dumps(state, indent=2), encoding="utf-8")


def resolve_results_dir(spec: ScanSpec) -> Path:
    """Where this scan writes.

    Precedence: explicit ``out`` > ``reports_dir`` > DEFAULT_REPORTS_DIR.
    The directory name keeps upstream's shape so existing tooling that globs
    for ``*_VULNHUNT_RESULTS_*`` still matches.
    """
    if spec.out:
        return Path(spec.out).expanduser().resolve()
    stamp = _dt.datetime.now().strftime("%Y-%m-%d-%H%M%S")
    name = "{0}_VULNHUNT_RESULTS_{1}_{2}".format(
        spec.repo.name, model_tag(spec.model), stamp
    )
    base = Path(spec.reports_dir).expanduser() if spec.reports_dir else DEFAULT_REPORTS_DIR
    return (base / name).resolve()


def select_phases(phases: str) -> List[Any]:
    if phases.strip().lower() == "all":
        return list(PHASES)
    keys = [k.strip() for k in phases.split(",") if k.strip()]
    unknown = [k for k in keys if k not in PHASES_BY_KEY]
    if unknown:
        raise ScanError(
            "unknown phase(s) {0}. Valid: {1}".format(
                ", ".join(unknown), ", ".join(p.key for p in PHASES)
            )
        )
    return [PHASES_BY_KEY[k] for k in keys]


def _noop(_ev: Dict[str, Any]) -> None:
    pass


def _never() -> bool:
    return False


def execute_scan(
    spec: ScanSpec,
    on_event: Optional[EventFn] = None,
    should_cancel: Optional[CancelFn] = None,
    attach_log_handler: bool = True,
) -> ScanResult:
    """Run the phase pipeline. Raises ScanError on configuration problems."""
    emit = on_event or _noop
    cancelled = should_cancel or _never

    repo = Path(spec.repo).expanduser().resolve()
    if not repo.is_dir():
        raise ScanError("repo {0} is not a directory".format(repo))

    skill_dir = Path(spec.skill_dir).expanduser().resolve()
    phases_dir = skill_dir / "phases"
    if not phases_dir.is_dir():
        raise ScanError(
            "phases directory not found at {0}. Point skill_dir at the "
            "vulnhunt/ directory.".format(phases_dir)
        )

    results_dir = resolve_results_dir(spec)
    results_dir.mkdir(parents=True, exist_ok=True)

    selected = select_phases(spec.phases)

    # Per-role model routing: each phase gets a client for its role's model,
    # sharing one client across phases on the same (backend, model, host).
    phase_clients, distinct_clients = _make_phase_clients(spec, selected)

    def client_for(phase_key):
        return phase_clients.get(phase_key) or phase_clients.get("2") \
            or next(iter(phase_clients.values()), None)

    for c in distinct_clients:
        try:
            c.preflight()
        except OllamaError as exc:
            raise ScanError("model {0}: {1}".format(getattr(c, "model", "?"), exc))

    # The hunt client is the pipeline's default (Phase 2 and any single-agent
    # phase without a role override).
    client = client_for("2")

    sandbox = Sandbox(read_roots=[repo, skill_dir, results_dir], write_root=results_dir)
    system = build_system(load_preamble(skill_dir))

    handler = None
    if attach_log_handler:
        handler = _EventLogHandler(emit)
        logging.getLogger("vhlocal").addHandler(handler)

    # Tag every log line from this run with a scan id so the central log stays
    # greppable per-scan. The server sets this to the job id before calling us
    # (jobs.py); a direct CLI run has none, so derive one from the results dir.
    from .logsetup import current_scan, set_scan
    own_scan_tag = None
    if current_scan() is None:
        own_scan_tag = _derive_scan_tag(results_dir)
        set_scan(own_scan_tag)

    state = load_state(results_dir)
    total = Usage()
    started = time.time()

    from . import __version__ as _ver
    from .lifecycle import git_provenance
    prov = git_provenance(repo)
    record = RunRecord(
        started_at=started, repo=str(repo), results_dir=str(results_dir),
        model=spec.model, verify_model=spec.verify_model, host=spec.host,
        num_ctx=spec.num_ctx, max_partitions=spec.max_partitions,
        phases_requested=[p.key for p in selected],
        vuln_classes=[c[0] for c in CLASS_GROUPS],
        engine_version=_ver,
        # The harness has no Bash tool at all: exploit tests are written but
        # never executed, and the target's dependencies are never installed.
        tool_envelope=["Read", "Grep", "Glob", "Write"],
        bash_enabled=False,
        git_commit=prov["git_commit"], git_branch=prov["git_branch"],
        git_dirty=prov["git_dirty"],
        recon_model=(spec.recon_model or ""),
        reproduce_model=(spec.reproduce_model or ""),
    )

    emit({
        "type": "scan_start",
        "repo": str(repo),
        "results_dir": str(results_dir),
        "model": spec.model,
        "verify_model": spec.verify_model,
        "phases": [p.key for p in selected],
        "num_ctx": spec.num_ctx,
    })

    was_cancelled = False
    aborted = None  # set to an OllamaError message when a systemic failure ends the run
    try:
        for spec_phase in selected:
            if cancelled():
                was_cancelled = True
                break

            if spec.resume and spec_phase.key in state.get("completed", []):
                record.phases_skipped.append(spec_phase.key)
                emit({"type": "phase_skip", "key": spec_phase.key, "reason": "resume"})
                continue

            prompt_path = phases_dir / spec_phase.prompt_file
            if not prompt_path.exists():
                emit({
                    "type": "error",
                    "message": "phase file missing: {0}".format(prompt_path),
                })
                continue

            emit({
                "type": "phase_start",
                "key": spec_phase.key,
                "title": spec_phase.title,
            })
            t0 = time.time()

            # Phase 3d (root-cause instance sweep) is mechanical: find every other
            # location matching each confirmed finding's sink pattern. The model
            # did this by grepping iteratively (redundantly, sometimes giving up);
            # the harness does it directly, completely, in a fraction of a second.
            if spec_phase.key == "3d" and spec.sweep_mode == "deterministic":
                from .sweep import run_phase3d_sweep
                emit({"type": "agent_start", "label": "p3d",
                      "model": "deterministic", "index": 1, "total": 1})
                run_phase3d_sweep(results_dir, repo)
                record.agents.append({
                    "label": "p3d", "phase": "3d", "model": "deterministic",
                    "turns": 0, "stopped_reason": "complete"})
                emit({"type": "agent_done", "label": "p3d", "turns": 0,
                      "stopped_reason": "complete", "index": 1, "total": 1})
            elif spec_phase.fan_out:
                fan_err = _run_fan_out(
                    client_for(spec_phase.key), sandbox, system, spec_phase, phases_dir, repo,
                    results_dir, spec.max_partitions, total, emit, cancelled,
                    record, enforce_coverage=spec.enforce_coverage,
                    phase2_mode=spec.phase2_mode, concurrency=spec.concurrency,
                )
                if fan_err:
                    aborted = fan_err
            else:
                prompt_text = prompt_path.read_text(encoding="utf-8")
                out_path = results_dir / spec_phase.output_file
                extra = ""
                if spec_phase.reads:
                    reads = _resolve_reads(spec_phase.reads, results_dir)
                    inputs = "\n".join(
                        "  - {0}".format(results_dir / r) for r in reads
                    )
                    extra = (
                        "## Inputs produced by earlier phases\n\n"
                        "Read these before you begin:\n{0}\n".format(inputs)
                    )
                # Opt-in: hand Phase 1 the deterministic route list so its input
                # inventory starts from the complete attack surface rather than
                # whatever it discovers on its own.
                if spec.seed_routes and spec_phase.key == "1":
                    from .inventory import route_inventory_markdown
                    seed = route_inventory_markdown(repo)
                    if seed:
                        extra = (extra + "\n\n" + seed) if extra else seed
                # Mode B (opt-in): hand Phase 1 the prior report's findings as
                # hot spots to independently re-verify. Recorded so the run is
                # never mistaken for an independent sample.
                if spec.seed_prior and spec_phase.key == "1":
                    from .lifecycle import prior_hotspots_markdown
                    seed, prior_name = prior_hotspots_markdown(
                        results_dir, str(repo), started,
                        reports_dir=results_dir.parent)
                    if seed:
                        extra = (extra + "\n\n" + seed) if extra else seed
                        record.seeded_from_prior = prior_name
                        log.info("Mode B: seeded Phase 1 from prior report %s",
                                 prior_name)
                task = build_task(spec_phase, prompt_text, repo, results_dir, extra=extra)
                active = client_for(spec_phase.key)
                emit({
                    "type": "agent_start",
                    "label": "p{0}".format(spec_phase.key),
                    "model": active.model,
                    "index": 1, "total": 1,
                })
                res = run_agent(
                    active, sandbox, system, task,
                    max_turns=spec_phase.max_turns,
                    expect_files=[out_path],
                    label="p{0}".format(spec_phase.key),
                    should_cancel=cancelled,
                )
                total.merge(res.usage)
                record.agents.append({
                    "label": "p{0}".format(spec_phase.key),
                    "phase": spec_phase.key, "model": active.model,
                    "turns": res.turns, "stopped_reason": res.stopped_reason,
                })
                emit({
                    "type": "agent_done",
                    "label": "p{0}".format(spec_phase.key),
                    "turns": res.turns,
                    "stopped_reason": res.stopped_reason,
                    "prompt_tokens": total.prompt_tokens,
                    "completion_tokens": total.completion_tokens,
                })
                if res.systemic:
                    aborted = res.error

            if spec_phase.fan_out:
                produced = any((results_dir / "results").glob("*.md"))
            else:
                produced = (results_dir / spec_phase.output_file).exists()

            state.setdefault("completed", [])
            if produced and spec_phase.key not in state["completed"]:
                state["completed"].append(spec_phase.key)
            save_state(results_dir, state)

            record.phase_timings[spec_phase.key] = time.time() - t0
            if produced and spec_phase.key not in record.phases_completed:
                record.phases_completed.append(spec_phase.key)

            # Distil 2b's verdict table into a compact handoff so Phase 3 starts
            # from ~1-2KB instead of the whole transcript.
            if spec_phase.key == "2b" and produced:
                try:
                    hp = write_handoff(results_dir)
                    emit({"type": "handoff",
                          "written": bool(hp),
                          "file": str(hp) if hp else None})
                    # Surface the confirmed-finding count for the live dashboard.
                    n = _handoff_confirmed_count(hp)
                    if n is not None:
                        emit({"type": "findings", "count": n, "stage": "confirmed"})
                except Exception as exc:  # never let this stop the pipeline
                    log.warning("handoff generation failed: %s", exc)

            emit({
                "type": "phase_done",
                "key": spec_phase.key,
                "seconds": time.time() - t0,
                "produced": produced,
            })

            if aborted:
                emit({"type": "error", "message":
                      "aborting scan — inference endpoint unreachable: " + aborted})
                break

            if cancelled():
                was_cancelled = True
                break
    finally:
        if own_scan_tag is not None:
            set_scan(None)
        if handler is not None:
            logging.getLogger("vhlocal").removeHandler(handler)

    elapsed = time.time() - started
    record.finished_at = time.time()
    record.cancelled = was_cancelled
    record.usage = {
        "calls": total.calls,
        "prompt_tokens": total.prompt_tokens,
        "completion_tokens": total.completion_tokens,
        "seconds": total.seconds,
        "peak_prompt_tokens": total.peak_prompt_tokens,
        "summary": total.summary(),
    }
    record.scan_tag = current_scan() or own_scan_tag or ""
    if aborted:
        record.aborted = aborted
    try:
        (results_dir / SCAN_META_FILE).write_text(
            json.dumps(record.to_dict(), indent=2), encoding="utf-8")
    except OSError as exc:
        log.warning("could not write %s: %s", SCAN_META_FILE, exc)

    # Consolidated report is rendered from the record + parsed artifacts, never
    # by the model. Failure here must not fail the scan — the raw artifacts are
    # already on disk and remain the source of truth.
    try:
        from .consolidate import write_consolidated
        write_consolidated(results_dir)
        # Final unique-finding count for the dashboard (supersedes the confirmed
        # count emitted after 2b).
        n = _findings_json_count(results_dir)
        if n is not None:
            emit({"type": "findings", "count": n, "stage": "final"})
    except Exception as exc:
        log.warning("consolidated report generation failed: %s", exc)

    emit({
        "type": "scan_done",
        "seconds": elapsed,
        "usage": total.summary(),
        "cancelled": was_cancelled,
        "aborted": aborted,
        "results_dir": str(results_dir),
        "report": str(results_dir / "README.md")
        if (results_dir / "README.md").exists() else None,
    })

    return ScanResult(
        results_dir=results_dir,
        usage=total,
        seconds=elapsed,
        completed_phases=list(state.get("completed", [])),
        cancelled=was_cancelled,
        record=record,
    )


def _derive_scan_tag(results_dir: Path) -> str:
    """Short, unique-per-run tag from a results dir name.

    Prefers the trailing ``YYYY-MM-DD-HHMMSS`` stamp (unique to the second);
    falls back to the full basename.
    """
    name = Path(results_dir).name
    m = re.search(r"(\d{4}-\d{2}-\d{2}-\d{6})$", name)
    return m.group(1) if m else name


def _resolve_reads(reads, results_dir):
    """Map declared read files to what actually exists.

    Phase 3 declares the compact handoff; if it wasn't produced (2b failed or
    was unparseable), fall back to the raw 2b output so Phase 3 still has input.
    """
    out = []
    for r in reads:
        if r == HANDOFF_FILE and not (Path(results_dir) / HANDOFF_FILE).exists():
            out.append("phase2b_output.md")
        else:
            out.append(r)
    return out


def _run_fan_out(
    client, sandbox, system, spec_phase, phases_dir, repo, results_dir,
    max_partitions, total, emit, cancelled, record=None, enforce_coverage=True,
    phase2_mode="split", concurrency=1,
):
    """Phase 2: (classes x partitions) + 1 sink-driven.

    Agents are independent (own message history, each writes its own file), so
    with ``concurrency`` > 1 they dispatch through a thread pool. The single GPU
    still serialises unless the Ollama server has OLLAMA_NUM_PARALLEL set, in
    which case they overlap — either way the results are identical.

    Returns a message string if a systemic failure (endpoint unreachable) ended
    the fan-out early, else None. A per-response failure on one unit does not
    stop the others — only a systemic one does.
    """
    # One corrective retry in a fresh, minimal context: if the model's Phase-1
    # partition table can't be parsed, ask it once more for a strict JSON
    # contract before falling back to deterministic route enumeration.
    def _repartition(recon_text: str, schema_hint: str) -> str:
        recon = recon_text[-8000:]  # the partition section lives near the end
        msg = [
            {"role": "system", "content":
             "You convert a security recon report into a partition plan. "
             + schema_hint},
            {"role": "user", "content":
             "Recon report:\n\n" + recon + "\n\n" + schema_hint},
        ]
        return client.chat(msg).content

    resolution = resolve_partitions(
        results_dir / "phase1_output.md", repo=repo,
        max_partitions=max_partitions, repartition_fn=_repartition,
    )
    partitions: List[Partition] = resolution.partitions
    partition_source = resolution.source

    # Harness-enforced coverage: ensure every enumerated route lands in some
    # partition. How depends on how we got the partitions:
    #   * model_table  — descriptions carry file paths, so reconcile and APPEND
    #                    coverage partitions only for the files the model omitted.
    #   * model_retry  — the retry JSON has vague, path-free descriptions that
    #                    cannot be reconciled; augmenting on top re-covers files
    #                    already partitioned (the "12 partitions / 6h" bug). Use
    #                    the complete deterministic subsystem plan instead.
    #   * deterministic / single_fallback — already complete (or the only option);
    #                    no augmentation needed.
    aug = None
    if enforce_coverage and resolution.source in ("model_table", "model_retry"):
        base = partitions if resolution.source == "model_table" else []
        aug = augment_partitions_for_coverage(base, repo, max_partitions)
        if aug.added:
            partitions = aug.partitions
            if resolution.source == "model_retry":
                partition_source = "deterministic_coverage"
                log.info("model partition plan unusable (retry); using %d "
                         "deterministic subsystem partitions for complete, "
                         "non-overlapping coverage", len(partitions))
            else:
                log.info("harness-enforced coverage: added %d partition(s) for "
                         "%d route file(s) the model omitted (%s)",
                         len(aug.added), len(aug.added_files), ", ".join(aug.added))
        if aug.uncovered_remaining:
            log.warning("coverage cap reached; %d file(s) still unpartitioned: %s",
                        len(aug.uncovered_remaining),
                        ", ".join(aug.uncovered_remaining))

    shared = (phases_dir / "phase2_shared.md").read_text(encoding="utf-8")
    results_sub = results_dir / "results"
    results_sub.mkdir(parents=True, exist_ok=True)

    # One agent per (partition x class) in split mode; one agent per partition
    # covering all classes in combined mode (~3x fewer sequential agents).
    groups = [COMBINED_GROUP] if phase2_mode == "combined" else CLASS_GROUPS
    units = [
        (p, code, cf, blurb)
        for p in partitions
        for code, cf, blurb in groups
    ]
    grand_total = len(units) + 1
    if record is not None:
        record.partitions = [p.ident for p in partitions]
        record.partition_source = partition_source
        record.partition_fallback = resolution.fallback
        record.partition_parse_error = resolution.parse_error
        record.partition_collapsed = resolution.collapsed
        if aug is not None:
            record.coverage_partitions_added = aug.added
            record.coverage_files_added = aug.added_files
            record.coverage_uncovered_remaining = aug.uncovered_remaining
    if resolution.fallback:
        log.warning("phase 2 partitioning used a fallback (%s): %s",
                    resolution.source, resolution.parse_error)
    emit({
        "type": "fanout_plan",
        "partitions": [p.ident for p in partitions],
        "agents": grand_total,
        "partition_source": resolution.source,
        "partition_fallback": resolution.fallback,
        "coverage_partitions_added": aug.added if aug else [],
    })

    # Guards the only shared state a concurrent agent touches: the merged usage
    # accumulator, the agent roster, and event emission. run_agent itself (the
    # expensive part) runs OUTSIDE the lock so agents actually overlap.
    lock = threading.Lock()

    def _run_unit(idx, unit):
        part, code, class_file, blurb = unit
        if cancelled():
            return None
        out_path = results_sub / "{0}_{1}.md".format(part.slug, code.lower())
        label = "p2:{0}:{1}".format(part.slug, code.lower())
        if out_path.exists() and out_path.stat().st_size > 0:
            with lock:
                emit({"type": "agent_skip", "label": label,
                      "index": idx, "total": grand_total})
            return None

        # class_file is a single reference (split mode) or a list of all class
        # references (combined mode) concatenated for one agent.
        if isinstance(class_file, (list, tuple)):
            class_text = "\n\n---\n\n".join(
                (phases_dir / cf).read_text(encoding="utf-8") for cf in class_file)
            scope = (
                "Investigate inputs belonging to this partition across ALL "
                "vulnerability classes below — injection, access control, and "
                "logic & crypto. Be as thorough on each class as a dedicated "
                "pass would be; do not stop at the first class."
            )
        else:
            class_text = (phases_dir / class_file).read_text(encoding="utf-8")
            scope = (
                "Investigate ONLY inputs belonging to this partition, and ONLY "
                "this vulnerability class."
            )
        extra = (
            "## Your assigned scope\n\n"
            "**Partition:** {ident} - {desc}\n"
            "**Vulnerability class:** {code} - {blurb}\n\n"
            "Read {p1} first for the input inventory and this partition's entry "
            "points. {scope} Write your findings to:\n  {out}\n"
        ).format(
            ident=part.ident, desc=part.description, code=code, blurb=blurb,
            p1=results_dir / "phase1_output.md", out=out_path, scope=scope,
        )
        prompt_text = (
            shared + "\n\n---\n\n# Vulnerability class reference: " + code
            + "\n\n" + class_text
        )
        task = build_task(spec_phase, prompt_text, repo, results_dir, extra=extra)

        with lock:
            emit({
                "type": "agent_start", "label": label, "model": client.model,
                "index": idx, "total": grand_total,
                "partition": part.ident, "vuln_class": code,
            })
        res = run_agent(
            client, sandbox, system, task,
            max_turns=spec_phase.max_turns, expect_files=[out_path],
            label=label, should_cancel=cancelled,
        )
        if not out_path.exists() and res.stopped_reason != "cancelled":
            out_path.write_text(
                "# {0} / {1}\n\nAgent produced no output ({2}).\n".format(
                    part.ident, code, res.stopped_reason),
                encoding="utf-8")
        with lock:
            total.merge(res.usage)
            if record is not None:
                record.agents.append({
                    "label": label, "phase": "2", "model": client.model,
                    "turns": res.turns, "stopped_reason": res.stopped_reason,
                    "partition": part.ident, "vuln_class": code,
                })
            emit({
                "type": "agent_done", "label": label, "turns": res.turns,
                "stopped_reason": res.stopped_reason,
                "index": idx, "total": grand_total,
                "prompt_tokens": total.prompt_tokens,
                "completion_tokens": total.completion_tokens,
            })
        return res.error if res.systemic else None

    if concurrency and concurrency > 1:
        # Agents are independent; overlap them. A systemic failure on one means
        # the endpoint is down, so the others will fail fast too — collect the
        # first error and report it once all in-flight units settle.
        systemic = None
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = [ex.submit(_run_unit, i, u)
                       for i, u in enumerate(units, start=1)]
            for fut in as_completed(futures):
                err = fut.result()
                if err and systemic is None:
                    systemic = err
        if systemic:
            return systemic
    else:
        for idx, unit in enumerate(units, start=1):
            if cancelled():
                return None
            err = _run_unit(idx, unit)
            if err:
                return err

    if cancelled():
        return None

    sink_out = results_sub / "sink_driven.md"
    if sink_out.exists() and sink_out.stat().st_size > 0:
        return None
    extra = (
        "## Your assigned scope\n\n"
        "**Sink-driven audit.** Unlike the partition agents, you start at the "
        "sinks. Read the sink inventory in {p1}, then for each dangerous sink "
        "work BACKWARD to determine whether any attacker-controlled input "
        "reaches it. Report only sinks with a complete path from an "
        "attacker-controlled source.\n\nWrite your findings to:\n  {out}\n"
    ).format(p1=results_dir / "phase1_output.md", out=sink_out)
    task = build_task(spec_phase, shared, repo, results_dir, extra=extra)
    emit({
        "type": "agent_start", "label": "p2:sink", "model": client.model,
        "index": grand_total, "total": grand_total,
    })
    res = run_agent(
        client, sandbox, system, task,
        max_turns=spec_phase.max_turns, expect_files=[sink_out],
        label="p2:sink", should_cancel=cancelled,
    )
    total.merge(res.usage)
    if not sink_out.exists() and res.stopped_reason != "cancelled":
        sink_out.write_text("# Sink-driven audit\n\nNo output produced.\n", encoding="utf-8")
    if res.systemic:
        return res.error
    if record is not None:
        record.agents.append({
            "label": "p2:sink", "phase": "2", "model": client.model,
            "turns": res.turns, "stopped_reason": res.stopped_reason,
            "vuln_class": "SINK",
        })
    emit({
        "type": "agent_done", "label": "p2:sink", "turns": res.turns,
        "stopped_reason": res.stopped_reason,
        "index": grand_total, "total": grand_total,
        "prompt_tokens": total.prompt_tokens,
        "completion_tokens": total.completion_tokens,
    })
    return None
