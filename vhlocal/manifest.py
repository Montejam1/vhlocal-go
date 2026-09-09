"""run_manifest.json — a compact, auditable record of one scan.

scan_meta.json is the engine's full internal record; this is the operator-facing
audit view: what tool/version ran, on which commit, with which model roles and
config, how long it took, and how it ended. Deterministic, stdlib only.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

MANIFEST_FILE = "run_manifest.json"

# The subset of config that defines the run's identity — a change here means a
# different scan. Hashed so two runs are comparable at a glance.
_CONFIG_KEYS = ("model", "verify_model", "recon_model", "reproduce_model",
                "backend", "num_ctx", "max_partitions", "phase2_mode",
                "phases_requested", "seed_prior", "ledger", "redact",
                "reasoning_effort", "max_output_tokens", "hunt_samples",
                "max_budget_usd", "quality_strictness")


def _config_hash(meta: Dict[str, Any]) -> str:
    sub = {k: meta.get(k) for k in _CONFIG_KEYS if meta.get(k) is not None}
    blob = json.dumps(sub, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def build_manifest(meta: Dict[str, Any], run_status: Optional[Dict[str, Any]] = None,
                   counts: Optional[Dict[str, int]] = None,
                   redaction: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    run_status = run_status or {}
    started = meta.get("started_at")
    finished = meta.get("finished_at")
    duration = None
    if isinstance(started, (int, float)) and isinstance(finished, (int, float)):
        duration = round(finished - started, 1)

    agents = meta.get("agents") or []
    incomplete = [a for a in agents
                  if a.get("stopped_reason") not in ("complete", None, "")]

    man: Dict[str, Any] = {
        "tool": {"name": "vhlocal", "version": meta.get("engine_version") or ""},
        "run_id": meta.get("results_dir", "").rstrip("/").split("/")[-1]
        or meta.get("run_id", ""),
        "target": {
            "repo": meta.get("repo") or "",
            "git_commit": meta.get("git_commit") or meta.get("commit") or "",
            "git_branch": meta.get("git_branch") or meta.get("branch") or "",
        },
        "models": {
            "hunt": meta.get("model") or "",
            "verify": meta.get("verify_model") or meta.get("model") or "",
            "recon": meta.get("recon_model") or meta.get("model") or "",
            "reproduce": meta.get("reproduce_model") or meta.get("model") or "",
        },
        "transport": {"backend": meta.get("backend") or "", "host": meta.get("host") or ""},
        "config": {
            "hash": _config_hash(meta),
            "num_ctx": meta.get("num_ctx"),
            "max_partitions": meta.get("max_partitions"),
            "phase2_mode": meta.get("phase2_mode"),
            "quality_strictness": meta.get("quality_strictness") or "balanced",
            "phases_requested": meta.get("phases_requested") or [],
            "seed_prior": bool(meta.get("seed_prior")),
            "ledger": bool(meta.get("ledger")),
            "redact": bool(meta.get("redact")),
            "hunt_samples": meta.get("hunt_samples") or 1,
        },
        "cost": {
            "spent_usd": meta.get("budget_spent_usd") or 0.0,
            "cap_usd": meta.get("max_budget_usd") or 0.0,
            "halted_on_budget": bool(meta.get("budget_halted_reason")),
        },
        "timing": {
            "started_at": started,
            "finished_at": finished,
            "duration_seconds": duration,
            "phase_timings": meta.get("phase_timings") or {},
        },
        "outcome": {
            "execution_status": run_status.get("execution_status") or "",
            "coverage_status": run_status.get("coverage_status") or "",
            "coverage_degraded_reasons": run_status.get("coverage_degraded_reasons") or [],
            "hunt_halted": bool(meta.get("hunt_halted_reason")),
            "agents_total": len(agents),
            "agents_incomplete": len(incomplete),
        },
        "findings": {"counts": counts or {},
                     "total": sum((counts or {}).values())},
    }
    if redaction is not None:
        man["redaction"] = redaction
    return man


def write_manifest(results_dir, meta: Dict[str, Any],
                   run_status: Optional[Dict[str, Any]] = None,
                   counts: Optional[Dict[str, int]] = None,
                   redaction: Optional[Dict[str, Any]] = None) -> Path:
    man = build_manifest(meta, run_status, counts, redaction)
    out = Path(results_dir) / MANIFEST_FILE
    out.write_text(json.dumps(man, indent=2), encoding="utf-8")
    return out
