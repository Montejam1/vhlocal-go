"""CLI orchestrator — sequential replacement for Claude Code's phase dispatch.

Feature-complete with the web UI: model routing per phase, multi-sample hunt
voting, the IaC lens, redaction, remediation DTOs, the vulnerability ledger, a
budget cap, and config profiles.

Usage:
    python3 -m vhlocal.run --repo /path/to/target
    python3 -m vhlocal.run --repo /path/to/target --profile thorough
    python3 -m vhlocal.run --repo /path/to/target --backend openrouter \
        --model z-ai/glm-5.3 --hunt-samples 3 --max-budget-usd 5 --redact
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

# Fields a --profile can preset. Each also uses argparse.SUPPRESS as its default,
# so `vars(args)` contains the key ONLY when the user passed it explicitly — that
# is how an explicit flag overrides the profile, which overrides the hardcoded
# default below.
_PROFILE_DEFAULTS = {
    "num_ctx": DEFAULT_NUM_CTX, "max_partitions": 8, "phase2_mode": "split",
    "phases": "all", "concurrency": 1, "reasoning_effort": None,
    "max_output_tokens": 32768, "max_budget_usd": 0.0,
    "enforce_coverage": True, "seed_routes": False, "seed_prior": False,
    "hunt_samples": 1, "iac_lens": True, "remediate": False, "redact": False,
    "ledger": False,
}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="vhlocal",
        description="Run VulnHunter's phase methodology against a local or paid model.",
    )
    ap.add_argument("--repo", required=True, help="Target repository to scan")
    ap.add_argument(
        "--backend", choices=["ollama", "openai", "openrouter"], default="ollama",
        help="Inference backend. 'ollama' (default): native /api/chat. 'openai': "
             "any OpenAI-compatible server (mlx_lm.server, vLLM, LM Studio) — pass "
             "its base URL via --host. 'openrouter': the paid cloud gateway — set "
             "the key via $VHLOCAL_OPENROUTER_API_KEY.",
    )
    ap.add_argument("--out", help="Exact results directory (overrides --reports-dir)")
    ap.add_argument("--reports-dir", default=str(DEFAULT_REPORTS_DIR),
                    help="Where reports are written (default: ~/vulnhunter-reports).")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="Hunt / default model.")
    ap.add_argument("--host", default=DEFAULT_HOST,
                    help="Endpoint for the hunt model (Ollama/OpenAI base URL). "
                         "OpenRouter uses its fixed host automatically.")
    ap.add_argument(
        "--skill-dir", default=str(DEFAULT_SKILL_DIR),
        help="vulnhunt skill directory (needs SKILL.md + phases/).",
    )
    ap.add_argument("--temperature", type=float, default=None)
    ap.add_argument("--profile", default=None,
                    help="Apply a config profile's structural presets "
                         "(quick/thorough/share/benchmark, or a user profile). "
                         "Explicit flags override the profile.")

    # --- per-role model routing (each falls back to the hunt model) ---
    role = ap.add_argument_group("per-phase model routing")
    role.add_argument("--verify-model", default=None,
                      help="Model for Phase 2b falsification only — the cheapest "
                           "place to raise precision. Pair with --verify-host / "
                           "--verify-backend to reach a different endpoint.")
    role.add_argument("--verify-host", default=None)
    role.add_argument("--verify-backend", default=None,
                      choices=["ollama", "openai", "openrouter"])
    role.add_argument("--recon-model", default=None, help="Model for Phase 1 recon.")
    role.add_argument("--recon-host", default=None)
    role.add_argument("--recon-backend", default=None,
                      choices=["ollama", "openai", "openrouter"])
    role.add_argument("--reproduce-model", default=None,
                      help="Model for Phases 3/3d/4 (reproduce, sweep, report).")
    role.add_argument("--reproduce-host", default=None)
    role.add_argument("--reproduce-backend", default=None,
                      choices=["ollama", "openai", "openrouter"])

    # --- profile-overridable knobs (default = SUPPRESS so explicit wins) ---
    S = argparse.SUPPRESS
    ap.add_argument("--phases", default=S,
                    help="Comma-separated phase keys: 1,2,2b,3,3d,4 (default: all).")
    ap.add_argument("--num-ctx", dest="num_ctx", type=int, default=S)
    ap.add_argument("--max-partitions", dest="max_partitions", type=int, default=S)
    ap.add_argument("--phase2-mode", dest="phase2_mode",
                    choices=["split", "combined"], default=S,
                    help="Phase 2 fan-out: 'split' (per class, thorough) or "
                         "'combined' (one agent per partition, ~3x faster).")
    ap.add_argument("--concurrency", type=int, default=S,
                    help="Phase-2 agents to run at once (needs OLLAMA_NUM_PARALLEL).")
    ap.add_argument("--reasoning-effort", dest="reasoning_effort",
                    choices=["low", "medium", "high"], default=S,
                    help="Reasoning level for models that support it (lower=faster).")
    ap.add_argument("--max-output-tokens", dest="max_output_tokens", type=int, default=S,
                    help="Cap completion length per call; on paid gateways also caps "
                         "the up-front credit reservation. 0 = uncapped.")
    ap.add_argument("--max-budget-usd", dest="max_budget_usd", type=float, default=S,
                    help="Hard USD ceiling for paid backends; the run halts before "
                         "exceeding it. 0 (default) = no cap. Inert for local models.")
    ap.add_argument("--hunt-samples", dest="hunt_samples", type=int, default=S,
                    help="Run each hunt agent N times (1-5) and UNION the findings — "
                         "raises recall on the volatile access-control class. "
                         "Multiplies hunt cost ~N×; pair with a budget cap.")
    ap.add_argument("--sweep-mode", choices=["deterministic", "model"],
                    default="deterministic",
                    help="Phase 3d sweep: 'deterministic' (grep, default) or 'model'.")

    # profile-overridable booleans
    ap.add_argument("--seed-routes", dest="seed_routes", action="store_true", default=S,
                    help="Seed Phase 1 with the enumerated route list.")
    ap.add_argument("--seed-prior", dest="seed_prior", action="store_true", default=S,
                    help="Mode B: seed Phase 1 with the prior report's findings.")
    ap.add_argument("--no-enforce-coverage", dest="enforce_coverage",
                    action="store_false", default=S,
                    help="Disable harness-enforced route coverage.")
    ap.add_argument("--iac-lens", dest="iac_lens", action="store_true", default=S,
                    help="Force the IaC/CI-CD lens on (on by default; auto-skips "
                         "when the repo has no infrastructure).")
    ap.add_argument("--no-iac-lens", dest="iac_lens", action="store_false", default=S,
                    help="Disable the IaC/CI-CD lens.")
    ap.add_argument("--remediate", action="store_true", default=S,
                    help="Write per-finding remediation DTOs (report-only).")
    ap.add_argument("--redact", action="store_true", default=S,
                    help="Mask cards/SSNs/credentials in the written artifacts.")
    ap.add_argument("--ledger", action="store_true", default=S,
                    help="Merge this run's confirmed findings into the per-target "
                         "vulnerability ledger and score its recall.")
    ap.add_argument("--threat-model", dest="threat_model", action="store_true",
                    help="Run Phase 1t: a post-recon PASTA threat model + data-flow "
                         "diagram whose hunt targets ADD partitions for surfaces "
                         "recon's entry-point enumeration missed. Also builds the SBOM.")

    # --- run mode (not profile-overridable) ---
    ap.add_argument("--resume", action="store_true", help="Skip completed phases.")
    ap.add_argument("--log-file", default=None,
                    help="Central log path (default: ~/.vhlocal/vhlocal.log).")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args(argv)

    # Resolve the profile-overridable knobs: hardcoded default < profile < explicit.
    resolved = dict(_PROFILE_DEFAULTS)
    if args.profile:
        from .profiles import load_profile
        ov = load_profile(args.profile)
        if not ov and args.profile:
            print("warning: unknown profile '{0}' — using defaults".format(args.profile),
                  file=sys.stderr)
        resolved.update(ov)
    for k in _PROFILE_DEFAULTS:
        if hasattr(args, k):                      # present only if explicitly passed
            resolved[k] = getattr(args, k)
    resolved["hunt_samples"] = max(1, min(5, int(resolved["hunt_samples"])))
    resolved["max_budget_usd"] = max(0.0, float(resolved["max_budget_usd"]))

    # Backend-specific host defaults + credential checks.
    if args.backend == "openai" and args.host == DEFAULT_HOST:
        from .openai_client import DEFAULT_OPENAI_HOST
        args.host = DEFAULT_OPENAI_HOST
    if args.backend == "openrouter":
        from .openai_client import DEFAULT_OPENROUTER_HOST, get_openrouter_key
        if args.host == DEFAULT_HOST:
            args.host = DEFAULT_OPENROUTER_HOST
        if not get_openrouter_key():
            print("error: OpenRouter needs an API key — set "
                  "$VHLOCAL_OPENROUTER_API_KEY.", file=sys.stderr)
            return 2

    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        print("error: --repo {0} is not a directory".format(repo), file=sys.stderr)
        return 2

    skill_dir = Path(args.skill_dir).expanduser().resolve()
    phases_dir = skill_dir / "phases"
    if not phases_dir.is_dir():
        print(
            "error: phases directory not found at {0}\n"
            "Pass --skill-dir pointing at a directory with SKILL.md + phases/ "
            "(e.g. vulnhunt-local/skill).".format(phases_dir),
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
        backend=args.backend,
        temperature=args.temperature,
        verify_model=args.verify_model,
        verify_host=args.verify_host,
        verify_backend=args.verify_backend,
        recon_model=args.recon_model,
        recon_host=args.recon_host,
        recon_backend=args.recon_backend,
        reproduce_model=args.reproduce_model,
        reproduce_host=args.reproduce_host,
        reproduce_backend=args.reproduce_backend,
        resume=args.resume,
        sweep_mode=args.sweep_mode,
        num_ctx=resolved["num_ctx"],
        max_partitions=resolved["max_partitions"],
        phase2_mode=resolved["phase2_mode"],
        phases=resolved["phases"],
        concurrency=resolved["concurrency"],
        reasoning_effort=resolved["reasoning_effort"],
        max_output_tokens=resolved["max_output_tokens"],
        max_budget_usd=resolved["max_budget_usd"],
        enforce_coverage=resolved["enforce_coverage"],
        seed_routes=resolved["seed_routes"],
        seed_prior=resolved["seed_prior"],
        hunt_samples=resolved["hunt_samples"],
        iac_lens=resolved["iac_lens"],
        remediate=resolved["remediate"],
        redact=resolved["redact"],
        ledger=resolved["ledger"],
        threat_model=args.threat_model,
    )

    results_dir = resolve_results_dir(spec)
    results_dir.mkdir(parents=True, exist_ok=True)
    spec.out = results_dir
    log_path = configure_logging(args.verbose,
                                 log_file=getattr(args, "log_file", None))

    with scan_context(_derive_scan_tag(results_dir)):
        log.info("=" * 72)
        log.info("VulnHunter (local) - %s @ %s [%s]", args.model, args.host, args.backend)
        log.info("target   : %s", repo)
        log.info("results  : %s", results_dir)
        log.info("phases   : %s | mode: %s | partitions: %d | samples: %d",
                 spec.phases, spec.phase2_mode, spec.max_partitions, spec.hunt_samples)
        opts = [n for n, on in (("iac", spec.iac_lens), ("remediate", spec.remediate),
                                ("redact", spec.redact), ("ledger", spec.ledger)) if on]
        if args.profile:
            opts.insert(0, "profile=" + args.profile)
        if spec.max_budget_usd:
            opts.append("budget=$%.2f" % spec.max_budget_usd)
        log.info("options  : %s", ", ".join(opts) or "(defaults)")
        log.info("log      : %s", log_path)
        log.info("=" * 72)

        try:
            result = execute_scan(spec, attach_log_handler=False)
        except ScanError as exc:
            print("error: {0}".format(exc), file=sys.stderr)
            return 2

        log.info("")
        log.info("=" * 72)
        log.info("DONE in %.1f min", result.seconds / 60)
        log.info("usage: %s", result.usage.summary())
        log.info("results: %s", result.results_dir)
        for name in ("SCAN_REPORT.html", "SCAN_REPORT.md", "README.md"):
            report = result.results_dir / name
            if report.exists():
                log.info("report : %s", report)
                break
        log.info("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
