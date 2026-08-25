"""Per-target vulnerability ledger — a persistent "memory bank" of findings.

Accumulates the UNION of confirmed findings across every opted-in run of a
target, deduped by a stable fingerprint. Run-to-run detection is variance-prone
(the same target yields wildly different counts across models/runs), so the
honest coverage of a codebase is the growing ledger, not any single run. Each run
that opts in (the "Include in Vulnerability Ledger" option) merges its findings
and is scored for recall against what the ledger already knows.

Design points:

* **Stable key.** The cross-run identity is ``family : file : sink-function`` —
  the volatile flow-signature that made Mode A's lifecycle key noisy is dropped,
  but the sink function is kept so two distinct bugs in one file (e.g. eval vs
  SSTI, both CWE-94 in the same module) stay separate.
* **Idempotent.** Keyed by the results-dir name, so re-rendering a report never
  double-counts a run.
* **Confidence tiers** guard against a lenient verify polluting the bank:
  provisional (seen once) → confirmed (>=2 runs, or once cross-family) →
  reliable (>=3 runs, or >=2 cross-family).
* **Persisted** as one JSON per target under ``$VHLOCAL_LEDGER_DIR`` (default
  ``~/.vhlocal/ledger``). Written only when a run opts in.
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .knowledge import normalized_cwe as _normalized_cwe
from .lifecycle import _fval, _loc_file

_FILE = re.compile(r"([\w./+\-]+\.[A-Za-z0-9]{1,6})")


def ledger_dir() -> Path:
    base = os.environ.get("VHLOCAL_LEDGER_DIR")
    return Path(base).expanduser() if base else (Path.home() / ".vhlocal" / "ledger")


def _slug(target: str) -> str:
    """Readable + collision-free filename for a target path."""
    try:
        p = str(Path(target).expanduser().resolve())
    except (OSError, RuntimeError):
        p = str(target or "unknown")
    h = hashlib.sha1(p.encode("utf-8")).hexdigest()[:8]
    name = Path(p).name or "target"
    return "{0}-{1}".format(name, h)


def ledger_path(target: str) -> Path:
    return ledger_dir() / (_slug(target) + ".json")


def _loc_line(text: str) -> int:
    m = re.search(r"\.\w{1,6}[:\s]+(\d+)", text or "")
    return int(m.group(1)) if m else 0


def ledger_key(f: Any) -> str:
    """Stable cross-run identity.

    * **Sink findings** (a sink function is known): ``family : file : func`` —
      the func (``eval``/``loads``/``render``/``find_one``) is the stable, unique
      identity, so line drift doesn't split them and two distinct sinks in one
      file stay separate. Family is normalized so a sibling-CWE relabel still
      matches.
    * **Logic/authz/info findings** (no sink function): ``raw-cwe : file : line
      bucket`` — normalizing the family here would collapse distinct co-located
      findings (a CWE-285 ledger bug and a CWE-639 IDOR both roll up to CWE-284),
      so the raw CWE plus a coarse line bucket keeps them apart. Merging two real
      findings (losing coverage) is worse than occasionally splitting one."""
    rck = _fval(f, "root_cause_key")
    fam = fil = func = ""
    if rck:
        parts = rck.split(":")
        head = parts[0] if parts else ""
        fam = _normalized_cwe(head) if head.upper().startswith("CWE-") else head
        fil = parts[1] if len(parts) > 1 else ""
        func = parts[2] if len(parts) > 2 else ""
    if not fil:
        fil = _loc_file(_fval(f, "location")) or _loc_file(_fval(f, "data_flow"))
    if func:
        return "{0}:{1}:{2}".format(fam or "?", fil, func)
    raw = _fval(f, "cwe") or _fval(f, "normalized_cwe") or "?"
    line = _loc_line(_fval(f, "location"))
    return "{0}:{1}:@{2}".format(raw, fil, (line // 20) if line else "")


def _provider(model: str) -> str:
    """Coarse model-family/provider, for cross-family confidence."""
    m = (model or "").lower()
    if "/" in m:
        return m.split("/")[0]
    for token, fam in (("gpt-oss", "openai"), ("qwen", "qwen"), ("glm", "zhipu"),
                       ("kimi", "moonshot"), ("gemma", "google"), ("gemini", "google"),
                       ("llama", "meta"), ("mistral", "mistral"), ("codestral", "mistral"),
                       ("claude", "anthropic"), ("fable", "anthropic")):
        if token in m:
            return fam
    return m.split(":")[0]


def _confidence(entry: Dict[str, Any]) -> str:
    n = int(entry.get("confirmed_count") or 0)
    cf = bool(entry.get("cross_family"))
    if n >= 3 or (n >= 2 and cf):
        return "reliable"
    if n >= 2 or cf:
        return "confirmed"
    return "provisional"


def _load(target: str) -> Dict[str, Any]:
    p = ledger_path(target)
    try:
        data = json.loads(p.read_text("utf-8"))
        data.setdefault("findings", [])
        data.setdefault("runs_recorded", [])
        return data
    except (OSError, ValueError):
        return {"target": target, "updated": 0, "runs_recorded": [], "findings": []}


def _save(target: str, data: Dict[str, Any]) -> None:
    d = ledger_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / (_slug(target) + ".json")).write_text(
        json.dumps(data, indent=2), encoding="utf-8")


def update_ledger(results_dir, findings: List[Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    """Merge this run's findings into the target's ledger (idempotent by run id)
    and return a coverage summary. Only the *unique* (non-duplicate) findings
    participate. Safe to call on report re-render — a run already recorded is not
    merged again, but the current coverage summary is still returned."""
    target = meta.get("repo") or ""
    run_id = Path(results_dir).name
    model = meta.get("model") or ""
    verify = meta.get("verify_model") or ""
    cross_family = bool(verify) and _provider(verify) != _provider(model)
    when = float(meta.get("finished_at") or meta.get("started_at") or 0)

    led = _load(target)
    by_key = {e["key"]: e for e in led["findings"]}
    unique = [f for f in findings if not _fval(f, "duplicate_of")]
    cur = {}
    for f in unique:
        cur[ledger_key(f)] = f

    already = run_id in led["runs_recorded"]
    if not already:
        for k, f in cur.items():
            stamp = {"run": run_id, "model": model, "date": when}
            e = by_key.get(k)
            if e:
                if run_id not in e["confirmed_in"]:
                    e["confirmed_in"].append(run_id)
                e["confirmed_count"] = len(e["confirmed_in"])
                e["last_seen"] = stamp
                e["cross_family"] = bool(e.get("cross_family")) or cross_family
                if e.get("status") == "fixed":
                    e["status"] = "regressed"
            else:
                e = {
                    "key": k,
                    "canonical_cwe": _fval(f, "normalized_cwe") or _fval(f, "cwe"),
                    "family": _fval(f, "cwe_family"),
                    "title": _fval(f, "title"),
                    "location": _fval(f, "location"),
                    "severity": _fval(f, "severity"),
                    "first_seen": stamp,
                    "last_seen": stamp,
                    "confirmed_in": [run_id],
                    "confirmed_count": 1,
                    "cross_family": cross_family,
                    "status": "open",
                }
                led["findings"].append(e)
                by_key[k] = e
        led["runs_recorded"].append(run_id)
        led["updated"] = when
        for e in led["findings"]:
            e["confidence"] = _confidence(e)
        _save(target, led)

    return _coverage(led, cur, run_id)


def _coverage(led: Dict[str, Any], cur: Dict[str, Any], run_id: str) -> Dict[str, Any]:
    found_keys = set(cur.keys())
    known = led["findings"]
    open_known = [e for e in known if e.get("status") != "fixed"]
    found = [e for e in open_known if e["key"] in found_keys]
    missed = [e for e in open_known if e["key"] not in found_keys]
    new = [e for e in known
           if e["key"] in found_keys and (e.get("first_seen") or {}).get("run") == run_id]
    reliable = [e for e in known if e.get("confidence") == "reliable"]
    denom = len(open_known) or 1
    return {
        "ledger_file": str(ledger_path(led.get("target") or "")),
        "runs_recorded": len(led["runs_recorded"]),
        "total_known": len(known),
        "open_known": len(open_known),
        "reliable": len(reliable),
        "found": len(found),
        "new": len(new),
        "missed_count": len(missed),
        "recall_pct": round(100.0 * len(found) / denom),
        "missed": [{"title": e.get("title"), "cwe": e.get("canonical_cwe"),
                    "location": e.get("location"), "confidence": e.get("confidence"),
                    "confirmed_count": e.get("confirmed_count")}
                   for e in sorted(missed, key=lambda x: -(x.get("confirmed_count") or 0))],
    }


def rebuild_from_reports(reports_dir, extra_dirs: Optional[List[Path]] = None) -> Dict[str, int]:
    """Bootstrap ledgers from every report already on disk. Idempotent — re-runs
    don't double-count. Returns a per-target run tally."""
    from .reports import list_reports
    tally: Dict[str, int] = {}
    for rep in list_reports(Path(reports_dir), extra_dirs):
        root = Path(rep.path)
        try:
            fj = json.loads((root / "findings.json").read_text("utf-8"))
            meta = json.loads((root / "scan_meta.json").read_text("utf-8"))
        except (OSError, ValueError):
            continue
        findings = fj.get("findings") or []
        if not meta.get("repo"):
            meta["repo"] = getattr(rep, "repo", "") or root.name
        update_ledger(root, findings, meta)
        tally[meta["repo"]] = tally.get(meta["repo"], 0) + 1
    return tally


if __name__ == "__main__":   # `python -m vhlocal.membank rebuild [reports_dir]`
    import sys
    from .engine import DEFAULT_REPORTS_DIR
    if len(sys.argv) >= 2 and sys.argv[1] == "rebuild":
        rd = sys.argv[2] if len(sys.argv) > 2 else str(DEFAULT_REPORTS_DIR)
        t = rebuild_from_reports(rd)
        print("Rebuilt ledgers from reports under", rd)
        for target, n in t.items():
            print("  {0}: {1} runs".format(target, n))
    else:
        print("usage: python -m vhlocal.membank rebuild [reports_dir]")
