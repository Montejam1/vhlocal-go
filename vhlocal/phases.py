"""Phase definitions — the sequential replacement for Claude Code's dispatch.

VulnHunter's phase prompts were already written as independent, file-mediated
units ("read X, write output to Y, return <=20 words"). That makes them a
direct fit for a sequential runner; we're reusing them verbatim rather than
rewriting the methodology.

Two details are easy to get wrong and both are handled here:

* **The shared preamble.** Every phase prompt opens with "The orchestrator's
  Operating Principles and Investigation Discipline are in effect throughout
  this phase." Those live in SKILL.md, not in the phase files. We extract them
  at runtime so a phase agent inherits the scope exclusions (skip tests,
  vendor, generated code) and the tracing discipline. Without this the agent
  happily reports findings in node_modules.

* **Phase 2 fan-out.** Phase 1 emits a partition table; Phase 2 runs three
  vulnerability-class agents per partition plus one sink-driven agent. We parse
  the table and run them sequentially, each in its own context.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

PREAMBLE_START = "## Operating Principles"
PREAMBLE_END = "## Workflow"


def default_skill_dir() -> Path:
    """Locate the vulnhunt skill (SKILL.md + phases/).

    Prefers the copy bundled in this repo (``skill/``), so a fresh clone runs
    with no setup on any OS. Falls back to a skill installed under
    ``~/.claude/skills/vulnhunt`` for the Claude-Code layout.
    """
    bundled = Path(__file__).resolve().parent.parent / "skill"
    if (bundled / "phases").is_dir():
        return bundled
    return Path.home() / ".claude" / "skills" / "vulnhunt"

BASE_SYSTEM = """You are VulnHunter, an expert security auditor analysing a codebase.

You work by calling tools. Grep and Read are your primary instruments: grep to
locate code, read to understand it, then grep again to follow the data. Never
answer from assumption — every claim you make must be backed by a file:line you
actually read.

Rules that override any instinct to be brief:
- Do NOT summarise your findings in chat. Your deliverable is the output file.
  Call the Write tool with the exact path you were given.
- Trace to a conclusion. If data passes through six functions across four
  files, follow all six. Stopping early produces a wrong answer, not a short one.
- If a tool returns an ERROR, read the message, correct the call, and continue.
- Cite file:line for every finding. A finding without a citation is invalid.
"""


@dataclass
class PhaseSpec:
    key: str
    title: str
    prompt_file: str
    output_file: str
    max_turns: int = 60
    # Files from earlier phases this phase must read first.
    reads: List[str] = field(default_factory=list)
    # Phase 2 is the only fan-out phase.
    fan_out: bool = False


PHASES: List[PhaseSpec] = [
    PhaseSpec(
        key="1",
        title="Recon — attack surface mapping",
        prompt_file="phase1_recon.md",
        output_file="phase1_output.md",
        max_turns=90,
    ),
    PhaseSpec(
        key="2",
        title="Hunt — forward tracing",
        prompt_file="phase2_hunt.md",
        output_file="results/",
        max_turns=80,
        reads=["phase1_output.md"],
        fan_out=True,
    ),
    PhaseSpec(
        key="2b",
        title="Verify — adversarial falsification",
        prompt_file="phase2b_verify.md",
        output_file="phase2b_output.md",
        max_turns=70,
        reads=["results/"],
    ),
    PhaseSpec(
        key="3",
        title="Reproduce, test, fix",
        prompt_file="phase3_reproduce_test.md",
        output_file="phase3_output.md",
        max_turns=80,
        # Compact structured handoff, not the full 2b transcript — Phase 3 is
        # where the model degraded on inflated context. write_handoff() falls
        # back to phase2b_output.md if the handoff can't be built.
        reads=["phase2b_handoff.md"],
    ),
    PhaseSpec(
        key="3d",
        title="Sweep — root-cause instances",
        prompt_file="phase3d_sweep.md",
        output_file="phase3d_output.md",
        max_turns=60,
        reads=["phase3_output.md"],
    ),
    PhaseSpec(
        key="4",
        title="Report",
        prompt_file="phase4_report.md",
        output_file="README.md",
        max_turns=50,
        reads=["phase1_output.md", "phase2b_output.md", "phase3_output.md", "phase3d_output.md"],
    ),
]

PHASES_BY_KEY: Dict[str, PhaseSpec] = {p.key: p for p in PHASES}

# Phase 2 vulnerability classes. Mirrors phase2_hunt.md's class-group dispatch.
# In "split" mode each is a separate agent per partition (thorough, 3x agents);
# in "combined" mode one agent per partition covers all three (~3x faster).
CLASS_GROUPS = [
    ("INJ", "phase2_class_inj.md", "injection (SQLi, command, path traversal, SSRF, XSS, XXE, SSTI, upload)"),
    ("NAV", "phase2_class_nav.md", "navigation & access control (authz bypass, IDOR, redirects, deserialization)"),
    ("LOG", "phase2_class_log.md", "logic & crypto (weak crypto, race conditions, business-logic flaws)"),
]

# One combined unit per partition. class_file is the list of all class references,
# concatenated at dispatch time so a single agent traces every class.
COMBINED_GROUP = (
    "ALL",
    [cf for _code, cf, _blurb in CLASS_GROUPS],
    "all vulnerability classes: injection, access control, and logic & crypto",
)


def load_preamble(skill_dir: Path) -> str:
    """Extract Operating Principles + Investigation Discipline from SKILL.md.

    Extracted rather than duplicated so edits to SKILL.md take effect without
    touching this file.
    """
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        raise FileNotFoundError(
            "SKILL.md not found at {0}. Point --skill-dir at the vulnhunt "
            "skill directory.".format(skill_md)
        )
    text = skill_md.read_text(encoding="utf-8")
    start = text.find(PREAMBLE_START)
    end = text.find(PREAMBLE_END, start + 1)
    if start == -1:
        log.warning("could not locate %r in SKILL.md; preamble omitted", PREAMBLE_START)
        return ""
    if end == -1:
        end = len(text)
    return text[start:end].strip()


def build_system(preamble: str) -> str:
    if not preamble:
        return BASE_SYSTEM
    return BASE_SYSTEM + "\n\n---\n\n" + preamble


def build_task(
    spec: PhaseSpec,
    prompt_text: str,
    repo: Path,
    results_dir: Path,
    extra: str = "",
) -> str:
    """Wrap a phase prompt with its concrete paths and output contract."""
    out_desc = (
        "the directory {0}".format(results_dir / spec.output_file)
        if spec.output_file.endswith("/")
        else "the file {0}".format(results_dir / spec.output_file)
    )
    header = (
        "# Assignment: Phase {key} — {title}\n\n"
        "**Target repository (read-only):** {repo}\n"
        "**Results directory (your only writable location):** {out}\n"
        "**Your deliverable:** {deliver}\n\n"
        "Follow the phase instructions below exactly. When you have finished the "
        "analysis, call the Write tool to save your output. Do not print the "
        "report in chat — write it to the file.\n"
    ).format(
        key=spec.key,
        title=spec.title,
        repo=repo,
        out=results_dir,
        deliver=out_desc,
    )
    body = "\n---\n\n# Phase instructions\n\n" + prompt_text
    return header + (("\n" + extra + "\n") if extra else "") + body


# --------------------------------------------------------------------------
# Phase 1 partition-table parsing (drives Phase 2 fan-out)
# --------------------------------------------------------------------------

_PARTITION_HEADING = re.compile(r"^#{1,6}\s*.*Subgraph Partitions", re.IGNORECASE | re.MULTILINE)
# Tolerate any dash (or none) between "SG" and the number — see normalize_text.
_SG_ID = re.compile(r"\bSG\s*[-_.]?\s*(\d+)", re.IGNORECASE)

# gpt-oss emits typographic punctuation in prose and, critically, inside table
# cells: "SG‑1" uses U+2011 NON-BREAKING HYPHEN, not ASCII '-'. Left unhandled,
# the partition regex misses every row, the parser silently falls back to a
# single whole-repo partition, and Phase 2 drops from (3 x partitions) + 1
# agents to 3 — a large, invisible loss of coverage. Normalize before parsing.
_PUNCT_MAP = {
    0x2010: "-", 0x2011: "-", 0x2012: "-", 0x2013: "-", 0x2014: "-",
    0x2015: "-", 0x2212: "-",              # hyphens, dashes, minus
    0x00A0: " ", 0x2007: " ", 0x2009: " ", 0x202F: " ",  # non-breaking spaces
    0x2018: "'", 0x2019: "'", 0x201C: '"', 0x201D: '"',  # smart quotes
}


def normalize_text(text: str) -> str:
    """Fold typographic punctuation to ASCII so regexes match model output."""
    return text.translate(_PUNCT_MAP)


@dataclass
class Partition:
    ident: str
    description: str

    @property
    def slug(self) -> str:
        return self.ident.lower().replace(" ", "-")


def _parse_partition_table_text(text: str, max_partitions: int = 8) -> List[Partition]:
    """Core Subgraph-Partitions table parse. Returns [] when nothing parses.

    Deliberately tolerant of the malformed markdown a local model produces:
    find the section, take table rows, pull an SG-N id from each. Unlike the
    public helpers it never invents a fallback — the caller decides what an
    empty result means.
    """
    text = normalize_text(text)
    m = _PARTITION_HEADING.search(text)
    section = text[m.end():] if m else text

    partitions: List[Partition] = []
    seen = set()
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            if partitions and not line:
                continue
            if partitions and not line.startswith("|"):
                break  # table ended
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells or all(set(c) <= set("-: ") for c in cells):
            continue
        idm = _SG_ID.search(cells[0])
        if not idm:
            continue
        ident = "SG-{0}".format(idm.group(1))
        if ident in seen:
            continue
        seen.add(ident)
        desc = " | ".join(c for c in cells[1:4] if c)
        partitions.append(Partition(ident, desc or "(no description)"))

    if len(partitions) > max_partitions:
        log.warning(
            "phase 1 emitted %d partitions; capping at %d to bound runtime "
            "(raise with --max-partitions)",
            len(partitions), max_partitions,
        )
        partitions = partitions[:max_partitions]
    return partitions


def parse_partitions(phase1_output: Path, max_partitions: int = 8) -> List[Partition]:
    """Backward-compatible partition parse with a single-partition fallback.

    Kept for callers that only need the list. New orchestration uses
    :func:`resolve_partitions`, which distinguishes a clean parse from a
    fallback and can synthesise subsystem partitions instead of collapsing to
    one whole-repo pass.
    """
    if not phase1_output.exists():
        log.warning("phase1 output missing; falling back to a single partition")
        return [Partition("SG-1", "entire repository")]
    parts = _parse_partition_table_text(
        phase1_output.read_text(encoding="utf-8", errors="replace"), max_partitions)
    if not parts:
        log.warning(
            "could not parse a partition table from %s — falling back to one "
            "whole-repo partition.", phase1_output.name)
        return [Partition("SG-1", "entire repository")]
    return parts


# ---------------------------------------------------------------------------
# Structured contract + resolution (P1-E)
# ---------------------------------------------------------------------------

# The corrective-retry contract: the model is asked to emit ONLY this, so it is
# cheap to validate and cheap to fall back from.
PARTITION_JSON_SCHEMA_HINT = (
    'Output ONLY a JSON array, no prose. Each element: '
    '{"id": "SG-N", "description": "<subsystem or entry points>"}. '
    'Group entry points that share application code into the same partition; '
    'aim for one partition per security-relevant subsystem (auth, authorization, '
    'file/upload/webhook, config/secrets, operations/admin, core).'
)


def parse_partition_json(text: str, max_partitions: int = 8) -> List[Partition]:
    """Parse the structured partition contract (a JSON array).

    Tolerates the array being wrapped in prose or a ```json fence — we extract
    the first bracketed array and validate its shape. Returns [] on any failure
    so the caller can fall through to the deterministic partitioner.
    """
    if not text:
        return []
    m = re.search(r"\[.*\]", text, re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    out: List[Partition] = []
    seen = set()
    for i, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            continue
        ident = str(item.get("id") or item.get("ident") or "").strip()
        idm = _SG_ID.search(ident) if ident else None
        ident = "SG-{0}".format(idm.group(1)) if idm else "SG-{0}".format(i)
        if ident in seen:
            continue
        seen.add(ident)
        desc = str(item.get("description") or item.get("desc") or "").strip()
        out.append(Partition(ident, desc or "(no description)"))
    return out[:max_partitions]


@dataclass
class PartitionResolution:
    """How the partitions for a run were obtained — recorded in scan metadata so
    a degraded run cannot masquerade as a thorough one."""
    partitions: List[Partition]
    source: str          # model_table | model_retry | deterministic | single_fallback
    fallback: bool       # True when the model's own partition table was unusable
    parse_error: str     # why the table failed (empty when it parsed)
    collapsed: bool      # True when it degenerated to one whole-repo partition


def resolve_partitions(
    phase1_output: Path,
    repo: Optional[Path] = None,
    max_partitions: int = 8,
    repartition_fn=None,
) -> PartitionResolution:
    """Resolve Phase-2 partitions: model table → one corrective retry → fallback.

    1. Parse the Subgraph-Partitions table the model wrote (the normal path).
    2. If that yields nothing and ``repartition_fn`` is available, ask the model
       once more for a strict JSON contract in a fresh, minimal context.
    3. If still nothing, synthesise subsystem partitions deterministically from
       the repo's routes (never a silent single-blob collapse when the repo has
       structure).

    Every non-table outcome is flagged (``fallback``) and, when it degenerates
    to a single whole-repo partition, ``collapsed`` — both surface in the report
    so coverage is marked degraded rather than silently narrowed.
    """
    text = ""
    if phase1_output.exists():
        text = phase1_output.read_text(encoding="utf-8", errors="replace")

    parts = _parse_partition_table_text(text, max_partitions)
    if parts:
        return PartitionResolution(parts, "model_table", False, "", False)

    parse_error = ("phase1 output missing" if not text
                   else "no parseable Subgraph Partitions table")

    if repartition_fn is not None and text:
        try:
            retry_text = repartition_fn(text, PARTITION_JSON_SCHEMA_HINT)
        except Exception as exc:  # never let the retry crash the scan
            log.warning("partition corrective-retry failed: %s", exc)
            retry_text = ""
        retry_parts = parse_partition_json(retry_text or "", max_partitions)
        if len(retry_parts) > 1:
            log.warning("partition table unparsed; recovered %d partitions via "
                        "corrective retry", len(retry_parts))
            return PartitionResolution(retry_parts, "model_retry", True,
                                       parse_error, False)

    # Deterministic fallback — synthesise from enumerated routes.
    det_parts: List[Partition] = []
    if repo is not None:
        from .inventory import deterministic_partitions, collapsed_to_whole_repo
        det = deterministic_partitions(repo, max_partitions)
        det_parts = [Partition(d.ident, d.description) for d in det]
        collapsed = collapsed_to_whole_repo(det)
    else:
        collapsed = True

    if not det_parts:
        det_parts = [Partition("SG-1", "entire repository")]
        collapsed = True

    if collapsed:
        log.warning("could not partition %s and no route structure found — one "
                    "whole-repo partition (coverage degraded)", phase1_output.name)
        source = "single_fallback"
    else:
        log.warning("partition table unparsed; using %d deterministic subsystem "
                    "partitions from route enumeration", len(det_parts))
        source = "deterministic"
    return PartitionResolution(det_parts, source, True, parse_error, collapsed)


@dataclass
class CoverageAugmentation:
    """Result of forcing every enumerated route into some partition."""
    partitions: List[Partition]   # model partitions + appended coverage ones
    added: List[str]              # idents of the coverage partitions added
    added_files: List[str]        # source files those partitions bring in
    uncovered_remaining: List[str]  # files still uncovered (hit the cap)


def _max_sg_number(partitions: List[Partition]) -> int:
    n = 0
    for p in partitions:
        m = _SG_ID.search(p.ident)
        if m:
            n = max(n, int(m.group(1)))
    return n


def augment_partitions_for_coverage(
    model_partitions: List[Partition],
    repo: Path,
    max_partitions: int = 8,
) -> CoverageAugmentation:
    """Guarantee every enumerated source file is covered by some partition.

    The model's partition plan typically covers only the files it happened to
    notice during recon. Enumerated routes in files the plan never mentions would
    otherwise never be traced — the exact "36 of 100 entry points not reviewed"
    gap. For each subsystem whose files are absent from the model's partition
    descriptions, append a deterministic **coverage partition** that names the
    concrete routes (method / path / file:line) so a Phase-2 agent can trace them
    without relying on the recon inventory.

    Coverage partitions are additive. ``max_partitions`` bounds the model's own
    partitions; coverage may push the total up to one extra partition per
    security subsystem (at most ~7), which is the "Phase 2 may roughly double"
    cost the harness-enforced mode accepts. Anything beyond that hard ceiling is
    reported in ``uncovered_remaining`` rather than silently dropped.
    """
    from .inventory import (
        enumerate_entry_points, _SUBSYSTEMS, _DEFAULT_SUBSYSTEM,
        _SUBSYSTEM_TITLES,
    )
    eps = enumerate_entry_points(repo)
    if not eps:
        return CoverageAugmentation(list(model_partitions), [], [], [])

    blob = " ".join(p.description for p in model_partitions).lower()

    def is_covered(f: str) -> bool:
        return f.lower() in blob or Path(f).name.lower() in blob

    uncovered = [e for e in eps if not is_covered(e.file)]
    if not uncovered:
        return CoverageAugmentation(list(model_partitions), [], [], [])

    groups: Dict[str, list] = {}
    for e in uncovered:
        groups.setdefault(e.subsystem, []).append(e)

    order = [n for n, _t in _SUBSYSTEMS] + [_DEFAULT_SUBSYSTEM]
    ordered = sorted(groups, key=lambda s: (order.index(s) if s in order else 99, s))

    # Hard ceiling: model partitions plus at most one coverage partition per
    # subsystem. Subsystems are a small fixed set, so this cannot explode.
    ceiling = max_partitions + len(order)

    parts = list(model_partitions)
    added: List[str] = []
    added_files: List[str] = []
    uncovered_remaining: List[str] = []
    idx = _max_sg_number(parts)

    for sub in ordered:
        members = groups[sub]
        files = sorted({m.file for m in members})
        if len(parts) >= ceiling:
            uncovered_remaining.extend(files)
            continue
        idx += 1
        routes = "; ".join(
            "{0} {1} ({2}:{3})".format(m.method, m.path, m.file, m.line)
            for m in members[:15])
        if len(members) > 15:
            routes += "; …+{0} more".format(len(members) - 15)
        desc = (
            "[HARNESS-ENFORCED COVERAGE] {0} — files absent from the model's "
            "partition plan; trace every route below. Files: {1}. Routes: {2}"
        ).format(_SUBSYSTEM_TITLES.get(sub, sub), ", ".join(files), routes)
        parts.append(Partition("SG-{0}".format(idx), desc))
        added.append("SG-{0}".format(idx))
        added_files.extend(files)

    return CoverageAugmentation(parts, added, added_files, uncovered_remaining)
