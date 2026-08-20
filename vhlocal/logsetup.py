"""Centralized logging for vhlocal.

Previously each entry point configured logging itself (the CLI, the server, and
the job worker each set up their own handlers) and every scan dropped a separate
``vhlocal.log`` into its results folder. This module replaces all of that with:

* **one** ``configure_logging()`` that every entry point calls, and
* **one** rotating central log file the whole application shares.

The central log stays greppable per-scan because each line is tagged with the
active scan via a thread-local set around a run (see ``scan_context``). Lines
emitted outside a scan (server startup, queue events) carry ``-``.

Default location is ``~/.vhlocal/vhlocal.log`` (beside the job-queue state),
overridable with ``VHLOCAL_LOG_FILE``, or ``VHLOCAL_LOG_DIR`` for just the
directory. Stdlib only.
"""

import logging
import os
import threading
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

LOGGER_NAME = "vhlocal"
_LOG_FORMAT = "%(asctime)s %(levelname)-7s [%(scan)s] %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"

# One rotating file, capped so a long-lived engine's central log can't grow
# without bound (5 MB x 5 = 25 MB ceiling).
_MAX_BYTES = 5 * 1024 * 1024
_BACKUPS = 5

_configured = False
_ctx = threading.local()


def default_log_file() -> Path:
    """Resolve the central log path from env, else ~/.vhlocal/vhlocal.log."""
    explicit = os.environ.get("VHLOCAL_LOG_FILE")
    if explicit:
        return Path(explicit).expanduser()
    base = os.environ.get("VHLOCAL_LOG_DIR")
    root = Path(base).expanduser() if base else Path.home() / ".vhlocal"
    return root / "vhlocal.log"


class _ScanFilter(logging.Filter):
    """Inject the active scan tag into every record as ``%(scan)s``."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.scan = getattr(_ctx, "scan", None) or "-"
        return True


def current_scan() -> Optional[str]:
    return getattr(_ctx, "scan", None)


def set_scan(tag: Optional[str]) -> None:
    _ctx.scan = tag


@contextmanager
def scan_context(tag: str):
    """Tag every log line emitted on this thread while the block runs."""
    prev = getattr(_ctx, "scan", None)
    _ctx.scan = tag
    try:
        yield
    finally:
        _ctx.scan = prev


def configure_logging(verbose: int = 0, log_file: Optional[Path] = None) -> Path:
    """Set up the shared console + rotating-file handlers. Idempotent.

    Safe to call more than once (the server calls it at startup, tests may call
    it repeatedly) — handlers are installed only on the first call, and the
    level is updated on later calls so a ``-v`` still takes effect.

    Returns the resolved central log-file path.
    """
    global _configured
    level = logging.DEBUG if verbose >= 2 else logging.INFO
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    # Don't propagate to root — root may have its own handlers (pytest, etc.)
    # that would double-print or bypass the scan filter.
    logger.propagate = False

    path = Path(log_file).expanduser() if log_file else default_log_file()

    if _configured:
        # Re-point the file handler only if the caller asked for a new path.
        for h in logger.handlers:
            if isinstance(h, RotatingFileHandler):
                h.setLevel(level)
            else:
                h.setLevel(level)
        return path

    fmt = logging.Formatter(_LOG_FORMAT, _DATEFMT)
    scan_filter = _ScanFilter()

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    console.addFilter(scan_filter)
    console.setLevel(level)
    logger.addHandler(console)

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fileh = RotatingFileHandler(
            str(path), maxBytes=_MAX_BYTES, backupCount=_BACKUPS, encoding="utf-8")
        fileh.setFormatter(fmt)
        fileh.addFilter(scan_filter)
        fileh.setLevel(logging.INFO)  # file always keeps INFO regardless of -v noise
        logger.addHandler(fileh)
    except OSError as exc:  # pragma: no cover - disk/permission issues
        logger.warning("could not open central log at %s: %s", path, exc)

    _configured = True
    return path


def scan_lines(tag: str, log_file: Optional[Path] = None) -> str:
    """Return the central log lines belonging to one scan tag.

    Reads the current log plus its rotated backups (oldest first) so a scan
    that straddled a rotation is still complete.
    """
    path = Path(log_file).expanduser() if log_file else default_log_file()
    needle = "[{0}]".format(tag)
    out = []
    # Rotated files are path.1 (newest backup) … path.N (oldest); read oldest→new.
    candidates = []
    for i in range(_BACKUPS, 0, -1):
        candidates.append(path.with_name(path.name + "." + str(i)))
    candidates.append(path)
    for f in candidates:
        if not f.exists():
            continue
        try:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                if needle in line:
                    out.append(line)
        except OSError:
            continue
    return "\n".join(out)
