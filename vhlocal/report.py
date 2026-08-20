"""Regenerate the consolidated report for an existing results directory.

    python3 -m vhlocal.report <results-dir> [...]
    python3 -m vhlocal.report --all            # every report in ~/vulnhunter-reports

Useful after editing the renderer, or for runs produced before consolidation
existed — those have no scan_meta.json, so the metadata sections degrade to
"unknown" while the findings sections still render.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from .consolidate import SCAN_META_FILE, write_consolidated
from .engine import DEFAULT_REPORTS_DIR
from .reports import list_reports


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="vhlocal.report",
        description="Generate SCAN_REPORT.md + findings.json for scan results.",
    )
    ap.add_argument("dirs", nargs="*", help="Results directories")
    ap.add_argument("--all", action="store_true",
                    help="Process every report under --reports-dir")
    ap.add_argument("--reports-dir", default=str(DEFAULT_REPORTS_DIR))
    args = ap.parse_args(argv)

    targets: List[Path] = [Path(d).expanduser() for d in args.dirs]
    if args.all:
        targets += [Path(r.path) for r in list_reports(Path(args.reports_dir).expanduser())]
    if not targets:
        ap.error("give at least one results directory, or --all")

    rc = 0
    for d in targets:
        if not d.is_dir():
            print("skip (not a directory): {0}".format(d), file=sys.stderr)
            rc = 1
            continue
        try:
            md, js = write_consolidated(d)
        except Exception as exc:
            print("failed {0}: {1}".format(d, exc), file=sys.stderr)
            rc = 1
            continue
        note = "" if (d / SCAN_META_FILE).exists() else "  (no scan_meta.json — metadata limited)"
        print("wrote {0}{1}".format(md, note))
    return rc


if __name__ == "__main__":
    sys.exit(main())
