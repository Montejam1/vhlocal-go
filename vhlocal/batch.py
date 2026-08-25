"""Multi-repo batch scanning — scan many repositories from a CSV, grouped by
application, into one ``batch_summary.md``.

vhlocal scans one repo per run (a single GPU serialises anyway). This drives a
list of repos through the engine sequentially and rolls the per-repo results up
by AppId, mirroring the Visa harness's batch mode. Deterministic parts (CSV
parsing, the roll-up summary) are pure; the scan itself is injected as ``runner``
so it can be stubbed in tests. Stdlib only.
"""

import csv
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

BATCH_SUMMARY_FILE = "batch_summary.md"


def parse_repos_csv(path) -> List[Dict[str, str]]:
    """Rows of {repo, app_id} from a CSV. Accepts a header row (any of
    repo/path/repository and app/app_id/application, case-insensitive) or a plain
    ``repo[,app_id]`` layout. Blank lines and ``#`` comments are skipped."""
    rows: List[Dict[str, str]] = []
    text = Path(path).read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines()
             if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        return rows
    reader = list(csv.reader(lines))
    header = [c.strip().lower() for c in reader[0]]
    repo_hdr = {"repo", "path", "repository"}
    app_hdr = {"app", "app_id", "appid", "application"}
    has_header = any(c in repo_hdr for c in header)
    ri, ai = 0, 1
    start = 0
    if has_header:
        ri = next((i for i, c in enumerate(header) if c in repo_hdr), 0)
        ai = next((i for i, c in enumerate(header) if c in app_hdr), None)
        start = 1
    for cols in reader[start:]:
        if not cols or not cols[ri].strip():
            continue
        repo = cols[ri].strip()
        app = (cols[ai].strip() if (ai is not None and ai < len(cols) and cols[ai].strip())
               else Path(repo).name)
        rows.append({"repo": repo, "app_id": app})
    return rows


def _counts_for(results_dir) -> Dict[str, Any]:
    """(counts, total, status) read from a completed run's findings.json."""
    try:
        d = json.loads((Path(results_dir) / "findings.json").read_text("utf-8"))
    except (OSError, ValueError):
        return {"counts": {}, "total": 0, "coverage": ""}
    counts = d.get("counts") or {}
    rs = d.get("run_status") or {}
    return {"counts": counts, "total": sum(counts.values()),
            "coverage": rs.get("coverage_status") or ""}


def build_batch_summary(results: List[Dict[str, Any]]) -> str:
    """Markdown roll-up grouped by AppId. results: [{repo, app_id, results_dir,
    status, counts, total, coverage, error}]."""
    L: List[str] = ["# Batch scan summary", ""]
    L.append("{0} repositor{1} across {2} application{3}.".format(
        len(results), "y" if len(results) == 1 else "ies",
        len({r["app_id"] for r in results}),
        "" if len({r["app_id"] for r in results}) == 1 else "s"))
    L.append("")
    by_app: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        by_app.setdefault(r["app_id"], []).append(r)
    grand = 0
    for app in sorted(by_app):
        group = by_app[app]
        app_total = sum(r.get("total", 0) for r in group)
        grand += app_total
        L.append("## {0} — {1} finding(s)".format(app, app_total))
        L.append("")
        L.append("| Repo | Status | Findings | Coverage |")
        L.append("|---|---|---|---|")
        for r in group:
            name = Path(r["repo"]).name
            if r.get("error"):
                L.append("| {0} | ❌ {1} | — | — |".format(name, r["error"][:50]))
            else:
                L.append("| {0} | {1} | {2} | {3} |".format(
                    name, r.get("status", "done"), r.get("total", 0),
                    r.get("coverage", "")))
        L.append("")
    L.append("---")
    L.append("")
    L.append("**Total across batch: {0} finding(s).**".format(grand))
    return "\n".join(L) + "\n"


def run_batch(rows: List[Dict[str, str]], base_spec: Dict[str, Any],
              runner: Callable[[Dict[str, Any]], Any],
              workspace: Optional[Path] = None) -> Dict[str, Any]:
    """Scan each repo in ``rows`` via ``runner`` (given a per-repo spec dict) and
    write batch_summary.md. ``runner`` returns an object with ``.results_dir`` (and
    optionally ``.cancelled``); a raised exception is captured per-repo, never
    aborting the batch. Returns {results, summary_path}."""
    results: List[Dict[str, Any]] = []
    for row in rows:
        spec = dict(base_spec)
        spec["repo"] = row["repo"]
        rec: Dict[str, Any] = {"repo": row["repo"], "app_id": row["app_id"]}
        try:
            res = runner(spec)
            rdir = getattr(res, "results_dir", None) or (
                res.get("results_dir") if isinstance(res, dict) else None)
            rec["results_dir"] = str(rdir) if rdir else ""
            rec["status"] = "cancelled" if getattr(res, "cancelled", False) else "done"
            rec.update(_counts_for(rdir) if rdir else {"counts": {}, "total": 0})
        except Exception as exc:  # pragma: no cover - per-repo isolation
            rec["error"] = "{0}: {1}".format(type(exc).__name__, exc)
            rec["total"] = 0
        results.append(rec)

    summary = build_batch_summary(results)
    ws = Path(workspace) if workspace else Path.cwd()
    ws.mkdir(parents=True, exist_ok=True)
    summary_path = ws / BATCH_SUMMARY_FILE
    try:
        summary_path.write_text(summary, encoding="utf-8")
    except OSError:
        pass
    return {"results": results, "summary_path": str(summary_path)}


def main(argv=None):   # `python -m vhlocal.batch repos.csv --skill-dir ... --model ...`
    import argparse
    from .engine import execute_scan, ScanSpec
    ap = argparse.ArgumentParser(description="Scan many repos from a CSV.")
    ap.add_argument("csv", help="CSV of repo[,app_id] rows")
    ap.add_argument("--skill-dir", required=True)
    ap.add_argument("--model", default="gpt-oss:120b")
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--backend", default="ollama")
    ap.add_argument("--reports-dir", default=None)
    ap.add_argument("--profile", default=None, help="apply a config profile")
    ap.add_argument("--workspace", default=None, help="where batch_summary.md is written")
    args = ap.parse_args(argv)

    base = {"skill_dir": args.skill_dir, "model": args.model, "host": args.host,
            "backend": args.backend, "reports_dir": args.reports_dir}
    if args.profile:
        from .profiles import load_profile
        base.update(load_profile(args.profile))

    def runner(spec_dict):
        return execute_scan(ScanSpec.from_dict(spec_dict))

    rows = parse_repos_csv(args.csv)
    print("batch: {0} repo(s)".format(len(rows)))
    out = run_batch(rows, base, runner, workspace=args.workspace)
    print("summary:", out["summary_path"])
    return 0


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(main())
