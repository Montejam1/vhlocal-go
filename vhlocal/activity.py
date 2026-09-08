"""Centralized activity log — a structured, append-only audit trail of notable
actions across the whole engine, distinct from the raw debug log
(``vhlocal.log``). Where the text log answers *why / details*, this answers
*what happened, when*: scans started/finished, applications named/forgotten,
reports deleted, threat models built.

One JSONL file (``~/.vhlocal/activity.jsonl``, beside the log + job state). Each
line is one event: ``{ts, type, message, ...fields}`` where ``type`` is a
namespaced verb (``scan.started``, ``app.forgotten``, …). Appends are best-effort
and never raise — activity logging must never break a scan or an API call.
Stdlib only.
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Keep the tail bounded so a long-lived engine's activity file can't grow without
# limit. Trimming is lazy — only when the file crosses the size threshold.
MAX_EVENTS = 5000
_TRIM_BYTES = 2_000_000


def activity_file() -> Path:
    env = os.environ.get("VHLOCAL_ACTIVITY_FILE")
    if env:
        return Path(env).expanduser()
    from .logsetup import default_log_file
    return default_log_file().parent / "activity.jsonl"


def record(kind: str, message: str = "", **fields: Any) -> None:
    """Append one activity event. ``kind`` is the namespaced type. Extra keyword
    fields (repo, app, model, scan, findings, level, …) are stored as-is; None
    values are dropped. Never raises."""
    ev: Dict[str, Any] = {
        "ts": fields.pop("ts", None) or time.time(),
        "type": kind,
        "message": message or "",
    }
    for k, v in fields.items():
        if v is not None:
            ev[k] = v
    try:
        p = activity_file()
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev) + "\n")
        _maybe_trim(p)
    except OSError:
        pass


def _maybe_trim(p: Path) -> None:
    try:
        if p.stat().st_size < _TRIM_BYTES:
            return
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) > MAX_EVENTS:
            p.write_text("\n".join(lines[-MAX_EVENTS:]) + "\n", encoding="utf-8")
    except OSError:
        pass


def recent(limit: int = 200, type_prefix: str = "", since: float = 0.0,
           scan: str = "") -> List[Dict[str, Any]]:
    """The most recent events, newest first. ``type_prefix`` filters by type
    (e.g. ``"scan"`` or ``"scan.completed"``); ``since`` is a unix-time floor;
    ``scan`` filters to one scan tag/id."""
    try:
        lines = activity_file().read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out: List[Dict[str, Any]] = []
    for ln in reversed(lines):
        ln = ln.strip()
        if not ln:
            continue
        try:
            ev = json.loads(ln)
        except ValueError:
            continue
        if type_prefix and not str(ev.get("type", "")).startswith(type_prefix):
            continue
        if since and float(ev.get("ts") or 0) < since:
            continue
        if scan and str(ev.get("scan") or "") != scan:
            continue
        out.append(ev)
        if len(out) >= max(1, limit):
            break
    return out


# --- convenience emitters (keep call sites terse + consistent) --------------

def scan_started(job_id: str, repo: str, model: str, threat_model: bool = False) -> None:
    name = Path(str(repo or "")).name or repo
    record("scan.started", "{0} · {1}".format(name, model),
           scan=job_id, repo=str(repo or ""), model=model,
           threat_model=bool(threat_model) or None, level="info")


def scan_finished(job_id: str, status: str, repo: str, model: str,
                  findings: Optional[int] = None, seconds: Optional[float] = None,
                  degraded: Optional[bool] = None) -> None:
    kind = {"done": "scan.completed", "cancelled": "scan.cancelled",
            "failed": "scan.failed", "interrupted": "scan.interrupted"}.get(
        status, "scan.ended")
    name = Path(str(repo or "")).name or repo
    bits = [name]
    if findings is not None and status == "done":
        bits.append("{0} finding{1}".format(findings, "" if findings == 1 else "s"))
    if degraded:
        bits.append("degraded")
    record(kind, " · ".join(bits), scan=job_id, repo=str(repo or ""), model=model,
           findings=findings, seconds=round(seconds, 1) if seconds else None,
           level="warn" if status in ("failed", "interrupted") else "info")


def app_event(kind: str, slug: str, name: str = "", repo: str = "") -> None:
    record(kind, name or slug, app=slug, repo=str(repo or "") or None, level="info")


def report_deleted(report_id: str, repo: str = "") -> None:
    record("report.deleted", report_id, report=report_id,
           repo=str(repo or "") or None, level="info")


def threat_model_built(job_id: str, repo: str, targets: Optional[int] = None) -> None:
    name = Path(str(repo or "")).name or repo
    msg = name + (" · {0} hunt targets".format(targets) if targets else "")
    record("threat_model.built", msg, scan=job_id, repo=str(repo or ""),
           targets=targets, level="info")
