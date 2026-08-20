"""Read the central vhlocal log, optionally sliced to one scan.

    python3 -m vhlocal.logs                 # whole central log path + tail
    python3 -m vhlocal.logs --tail 100      # last 100 lines
    python3 -m vhlocal.logs <scan-tag>      # only that scan's lines
    python3 -m vhlocal.logs --path          # print the log file path and exit

A scan tag is the trailing timestamp of a results dir (e.g. 2026-08-16-115632)
or, for a server-run scan, its job id. `scan_meta.json` records the tag as
`scan_tag`.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from .logsetup import default_log_file, scan_lines


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="vhlocal.logs",
        description="Read the central vhlocal log (optionally one scan's slice).")
    ap.add_argument("scan", nargs="?", help="Scan tag (results-dir stamp or job id)")
    ap.add_argument("--tail", type=int, default=0, help="Show only the last N lines")
    ap.add_argument("--path", action="store_true", help="Print the log path and exit")
    ap.add_argument("--log-file", default=None, help="Override the central log path")
    args = ap.parse_args(argv)

    path = Path(args.log_file).expanduser() if args.log_file else default_log_file()
    if args.path:
        print(path)
        return 0

    if args.scan:
        text = scan_lines(args.scan, log_file=path)
        if not text:
            print("no lines for scan {0!r} in {1}".format(args.scan, path),
                  file=sys.stderr)
            return 1
        lines = text.splitlines()
    else:
        if not path.exists():
            print("no central log yet at {0}".format(path), file=sys.stderr)
            return 1
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    if args.tail and args.tail > 0:
        lines = lines[-args.tail:]
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
