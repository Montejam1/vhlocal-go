"""Scan config profiles — named presets of ScanSpec knobs.

The Visa harness ships YAML profiles (default/sdk/full/taint). vhlocal is
stdlib-only, so profiles here are JSON: a handful of built-in, connection-agnostic
presets (structural knobs only — never a hardcoded model/host, since those come
from the user's configured connections), plus any user JSON files under
``$VHLOCAL_PROFILES_DIR`` (default ``~/.vhlocal/profiles``). The UI applies a
profile by filling the New-Scan form, so the operator still sees and can tweak
every value before launching.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List

# Only structural, connection-independent fields. A profile never sets model/host/
# backend — those are chosen from configured connections at launch.
_ALLOWED = {
    "num_ctx", "max_partitions", "phase2_mode", "phases", "concurrency",
    "reasoning_effort", "max_output_tokens", "sweep_mode", "quality_strictness",
    "enforce_coverage", "seed_routes", "seed_prior",
    "hunt_samples", "iac_lens", "remediate", "redact", "ledger",
    "max_budget_usd",
}

_BUILTIN: List[Dict[str, Any]] = [
    {"name": "quick",
     "description": "Fast single pass — combined classes, fewer partitions. A "
                    "first look; lowest cost/time.",
     "overrides": {"hunt_samples": 1, "phase2_mode": "combined",
                   "max_partitions": 4, "iac_lens": True}},
    {"name": "thorough",
     "description": "Best recall — 3× multi-sample voting, split classes, full "
                    "partitions, IaC + remediation. The variance-beating default.",
     "overrides": {"hunt_samples": 3, "phase2_mode": "split",
                   "max_partitions": 8, "iac_lens": True, "remediate": True}},
    {"name": "share",
     "description": "Thorough, plus redaction + remediation DTOs + ledger — for a "
                    "report you'll archive or hand off.",
     "overrides": {"hunt_samples": 3, "phase2_mode": "split", "max_partitions": 8,
                   "iac_lens": True, "remediate": True, "redact": True,
                   "ledger": True}},
    {"name": "benchmark",
     "description": "Single independent pass into the ledger — no seeding, split "
                    "classes — for honest cross-run recall measurement.",
     "overrides": {"hunt_samples": 1, "phase2_mode": "split", "max_partitions": 8,
                   "seed_prior": False, "seed_routes": False, "ledger": True}},
]


def profiles_dir() -> Path:
    base = os.environ.get("VHLOCAL_PROFILES_DIR")
    return Path(base).expanduser() if base else (Path.home() / ".vhlocal" / "profiles")


def _sanitize(overrides: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only allowed structural keys (a profile must never pin a model)."""
    return {k: v for k, v in (overrides or {}).items() if k in _ALLOWED}


def list_profiles() -> List[Dict[str, Any]]:
    """Built-in presets first, then user JSON profiles (a user file with a built-in
    name overrides it). Each: {name, description, overrides}."""
    out: Dict[str, Dict[str, Any]] = {}
    for p in _BUILTIN:
        out[p["name"]] = {"name": p["name"], "description": p["description"],
                          "overrides": _sanitize(p["overrides"]), "builtin": True}
    d = profiles_dir()
    if d.is_dir():
        for f in sorted(d.glob("*.json")):
            try:
                data = json.loads(f.read_text("utf-8"))
            except (OSError, ValueError):
                continue
            name = data.get("name") or f.stem
            out[name] = {"name": name,
                         "description": data.get("description") or "(user profile)",
                         "overrides": _sanitize(data.get("overrides") or {}),
                         "builtin": False}
    return list(out.values())


def load_profile(name: str) -> Dict[str, Any]:
    """The sanitized override dict for a profile name, or {} if unknown."""
    for p in list_profiles():
        if p["name"] == name:
            return dict(p["overrides"])
    return {}


def apply_profile(spec_dict: Dict[str, Any], name: str) -> Dict[str, Any]:
    """Return spec_dict with a profile's overrides applied (explicit values in
    spec_dict win — a profile is a starting point, not an override of user input)."""
    ov = load_profile(name)
    merged = dict(ov)
    merged.update({k: v for k, v in (spec_dict or {}).items() if v is not None})
    return merged
