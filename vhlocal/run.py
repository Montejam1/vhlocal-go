"""CLI orchestrator — sequential replacement for Claude Code's phase dispatch.

Usage:
    python3 -m vhlocal.run --repo /path/to/target
    python3 -m vhlocal.run --repo /path/to/target --phases 1
    python3 -m vhlocal.run --repo /path/to/target --resume
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from .client import DEFAULT_HOST, DEFAULT_MODEL, DEFAULT_NUM_CTX
from .engine import (
    DEFAULT_REPORTS_DIR,
    ScanError,
    ScanSpec,
    _derive_scan_tag,
    execute_scan,
    resolve_results_dir,
)
from .logsetup import configure_logging, scan_context
from .phases import default_skill_dir

log = logging.getLogger("vhlocal")

DEFAULT_SKILL_DIR = default_skill_dir()




def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="vhlocal",
        description="Run VulnHunter's phase methodology against a local Ollama model.",
    )
    ap.add_argument("--repo", required=True, help="Target repository to scan")
    ap.add_argument(
        "--backend", choices=["ollama", "openai"], default="ollama",
        help="Inference backend. 'ollama' (default): native /api/chat. 'openai': "
             "any OpenAI-compatible server — mlx_lm.server on Apple Silicon, "
             "vLLM, LM Studio. With 'openai', pass the base URL via --host "
             "(e.g. http://localhost:8080).",
    )
    ap.add_argument("--out", help="Exact results directory (overrides --reports-dir)")
    ap.add_argument("--reports-dir", default=str(DEFAULT_REPORTS_DIR),
                    help="Where reports are written (default: ~/vulnhunter-reports). "
                         "Reports are kept OUT of the scanned repo by design.")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--host", default=DEFAULT_HOST,
                    help="Ollama endpoint (default: $VHLOCAL_OLLAMA_HOST or localhost)")
    ap.add_argument("--num-ctx", type=int, default=DEFAULT_NUM_CTX)
    ap.add_argument("--temperature", type=float, default=None)
    ap.add_argument(
        "--skill-dir",
        default=str(DEFAULT_SKILL_DIR),
        help="vulnhunt skill directory (needs SKILL.md + phases/)",
    )
    ap.add_argument(
        "--phases",
        default="all",
        help="Comma-separated phase keys to run: 1,2,2b,3,3d,4 (default: all)",
    )
    ap.add_argument("--max-partitions", type=int, default=8)
    ap.add_argument(
        "--verify-model",
        default=None,
        help=(
            "Model for Phase 2b (falsification) only. Phase 2b reads the "
            "accumulated candidate files rather than the codebase, so it is a "
            "small share of total tokens but carries the entire precision "
            "load. Pointing it at a stronger model is the cheapest way to "
            "suppress false positives. Use with --verify-host to reach a "
            "different endpoint."
        ),
    )
    ap.add_argument(
        "--verify-host",
        default=None,
        help="Ollama host for --verify-model (default: same as --host)",
    )
    ap.add_argument("--resume", action="store_true", help="Skip phases already completed")
    ap.add_argument(
        "--no-enforce-coverage", dest="enforce_coverage", action="store_false",
        help="Disable harness-enforced coverage. By default, Phase 2 appends "
             "deterministic partitions for any enumerated route the model's plan "
             "omits, so the whole attack surface is traced (may add agents).",
    )
    ap.set_defaults(enforce_coverage=True)
    ap.add_argument(
        "--seed-routes", action="store_true",
        help="Seed Phase 1 recon with the full enumerated route list so its "
             "input inventory starts from the complete attack surface.",
    )
    ap.add_argument(
        "--phase2-mode", choices=["split", "combined"], default="split",
        help="Phase 2 fan-out. 'split' (default): one agent per partition per "
             "vulnerability class (thorough, ~3x agents). 'combined': one agent "
             "per partition covering all classes (~3x faster, less depth).",
    )
    ap.add_argument(
        "--concurrency", type=int, default=1,
        help="Dispatch this many Phase-2 agents at once (default 1 = serial). "
             "Quality-neutral — same findings, just overlapped. Needs "
             "OLLAMA_NUM_PARALLEL>=N on the server to actually speed up.",
    )
    ap.add_argument(
        "--reasoning-effort", choices=["low", "medium", "high"], default=None,
        help="gpt-oss reasoning level. Default (unset) = the model's own "
             "behaviour. Lower = fewer reasoning tokens (faster) but a quality "
             "risk — opt-in.",
    )
    ap.add_argument("--log-file", default=None,
                    help="Central log path (default: $VHLOCAL_LOG_FILE or "
                         "~/.vhlocal/vhlocal.log). Shared across all runs.")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args(argv)

    # If the user picked the openai backend but left --host at the Ollama
    # default, point at the usual OpenAI-compatible port instead of :11434.
    if args.backend == "openai" and args.host == DEFAULT_HOST:
        from .openai_client import DEFAULT_OPENAI_HOST
        args.host = DEFAULT_OPENAI_HOST

    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        print("error: --repo {0} is not a directory".format(repo), file=sys.stderr)
        return 2

    skill_dir = Path(args.skill_dir).expanduser().resolve()
    phases_dir = skill_dir / "phases"
    if not phases_dir.is_dir():
        print(
            "error: phases directory not found at {0}\n"
            "Run ./install.sh from the VulnHunter repo, or pass --skill-dir "
            "pointing at the repo's vulnhunt/ directory.".format(phases_dir),
            file=sys.stderr,
        )
        return 2

    spec = ScanSpec(
        repo=repo,
        skill_dir=skill_dir,
        out=Path(args.out).expanduser() if args.out else None,
        reports_dir=Path(args.reports_dir).expanduser(),
        model=args.model,
        host=args.host,
        num_ctx=args.num_ctx,
        temperature=args.temperature,
        phases=args.phases,
        max_partitions=args.max_partitions,
        verify_model=args.verify_model,
        verify_host=args.verify_host,
        resume=args.resume,
        enforce_coverage=args.enforce_coverage,
        seed_routes=args.seed_routes,
        phase2_mode=args.phase2_mode,
        concurrency=args.concurrency,
        reasoning_effort=args.reasoning_effort,
        backend=args.backend,
    )

    results_dir = resolve_results_dir(spec)
    results_dir.mkdir(parents=True, exist_ok=True)
    spec.out = results_dir
    log_path = configure_logging(args.verbose,
                                 log_file=getattr(args, "log_file", None))

    # Tag the CLI banner with the same scan id the engine will use, so a scan's
    # slice of the central log includes its own header. execute_scan sees the
    # context already set and reuses it rather than deriving a second tag.
    with scan_context(_derive_scan_tag(results_dir)):
        log.info("=" * 72)
        log.info("VulnHunter (local) - %s @ %s", args.model, args.host)
        log.info("target   : %s", repo)
        log.info("results  : %s", results_dir)
        log.info("phases   : %s", args.phases)
        log.info("context  : %d tokens", args.num_ctx)
        log.info("log      : %s", log_path)
        log.info("=" * 72)

        try:
            # The CLI already logs via configure_logging; attaching the engine's
            # event->log bridge too would double every line.
            result = execute_scan(spec, attach_log_handler=False)
        except ScanError as exc:
            print("error: {0}".format(exc), file=sys.stderr)
            return 2

        log.info("")
        log.info("=" * 72)
        log.info("DONE in %.1f min", result.seconds / 60)
        log.info("usage: %s", result.usage.summary())
        log.info("results: %s", result.results_dir)
        # Point at the deterministic consolidated report, not the model-authored
        # README (which Phase 4 sometimes leaves as a stub). Prefer the HTML
        # (designed, filterable) then the markdown.
        for name in ("SCAN_REPORT.html", "SCAN_REPORT.md", "README.md"):
            report = result.results_dir / name
            if report.exists():
                log.info("report : %s", report)
                break
        log.info("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
