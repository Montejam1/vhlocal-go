"""Sandboxed file tools exposed to the model.

Tool names deliberately match Claude Code's (`Read`, `Grep`, `Glob`, `Write`)
because VulnHunter's phase prompts refer to them by name throughout — e.g.
"Trace forward using Grep", "Use Glob to discover files". Renaming them would
mean rewriting 165KB of prompts.

Two sandboxes, enforced by resolved-path prefix checks:
  * read roots  — the target repo plus the phase-prompt directory
  * write root  — the results directory only

Every tool caps its own output. Context is the scarcest resource in this
design: one unbounded Grep over a monorepo can consume a 128k window in a
single turn and silently push the phase instructions out of scope.
"""

import fnmatch
import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# Output caps. Tuned for a 128k context: a single tool result should never
# be able to dominate the window.
MAX_READ_LINES = 1200
MAX_LINE_CHARS = 500
MAX_GREP_MATCHES = 150
MAX_GLOB_RESULTS = 400
MAX_RESULT_CHARS = 60_000

# Directories that are never worth spending context on. Mirrors the skill's
# Operating Principle #5 exclusions plus the usual noise.
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "third_party", "third-party",
    "external", "deps", "generated", "gen", "dist", "build", "target",
    "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
    ".idea", ".vscode", "site-packages",
}

_BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".jar", ".class", ".so", ".dylib", ".dll", ".exe", ".bin", ".woff",
    ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wasm", ".pyc",
}


class ToolError(Exception):
    """Recoverable tool failure — surfaced to the model, not fatal."""


def _truncate(text: str, limit: int = MAX_RESULT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [truncated: {0} more chars]".format(len(text) - limit)


class Sandbox:
    """Resolves and authorizes every path the model asks for."""

    def __init__(self, read_roots: List[Path], write_root: Path):
        self.read_roots = [p.resolve() for p in read_roots]
        self.write_root = write_root.resolve()

    def _resolve(self, raw: str, base: Optional[Path] = None) -> Path:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = (base or self.read_roots[0]) / p
        # resolve() collapses .. before the prefix check, so traversal via
        # "repo/../../etc/passwd" is caught rather than normalized away.
        return p.resolve()

    def read_path(self, raw: str) -> Path:
        p = self._resolve(raw)
        for root in self.read_roots:
            if p == root or str(p).startswith(str(root) + os.sep):
                return p
        raise ToolError(
            "path {0!r} is outside the allowed read roots ({1})".format(
                raw, ", ".join(str(r) for r in self.read_roots)
            )
        )

    def write_path(self, raw: str) -> Path:
        p = self._resolve(raw, base=self.write_root)
        owned = {"candidate_manifest.json", "verification_decisions.json",
                 "verification_reconciliation.json", "scan_meta.json", "findings.json",
                 "run_manifest.json", ".vhlocal_state.json", "phase2b_output.md",
                 "phase2b_handoff.md", "phase3_output.md"}
        if p.parent == self.write_root and (p.name in owned or p.name.startswith(".vhlocal-")):
            raise ToolError("This artifact is harness-owned and cannot be written by a model: " + p.name)
        if p == self.write_root or str(p).startswith(str(self.write_root) + os.sep):
            return p
        raise ToolError(
            "path {0!r} is outside the results directory ({1}). "
            "Write output only inside the results directory.".format(
                raw, self.write_root
            )
        )


def _should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def _is_binary(path: Path) -> bool:
    if path.suffix.lower() in _BINARY_EXT:
        return True
    try:
        with open(path, "rb") as fh:
            return b"\0" in fh.read(2048)
    except OSError:
        return True


# --------------------------------------------------------------------------
# Tool implementations
# --------------------------------------------------------------------------

def tool_read(sb: Sandbox, file_path: str, offset: int = 1, limit: int = MAX_READ_LINES) -> str:
    path = sb.read_path(file_path)
    if path.is_dir():
        raise ToolError("{0} is a directory. Use Glob to list its contents.".format(file_path))
    if not path.exists():
        raise ToolError("file not found: {0}".format(file_path))
    if _is_binary(path):
        raise ToolError("{0} appears to be binary; skipping.".format(file_path))

    try:
        offset = max(1, int(offset or 1))
    except (TypeError, ValueError):
        offset = 1
    try:
        limit = min(int(limit or MAX_READ_LINES), MAX_READ_LINES)
    except (TypeError, ValueError):
        limit = MAX_READ_LINES

    out: List[str] = []
    total = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for idx, line in enumerate(fh, start=1):
            total = idx
            if idx < offset:
                continue
            if len(out) >= limit:
                continue
            line = line.rstrip("\n")
            if len(line) > MAX_LINE_CHARS:
                line = line[:MAX_LINE_CHARS] + " …[line truncated]"
            # Line-numbered output: the phase prompts require file:line
            # citations in every finding, so numbers must be visible.
            out.append("{0:6d}\t{1}".format(idx, line))

    if not out:
        return "(file has {0} lines; offset {1} is past the end)".format(total, offset)

    body = "\n".join(out)
    shown_last = offset + len(out) - 1
    if shown_last < total:
        body += "\n... [{0} more lines; total {1}. Re-read with offset={2}]".format(
            total - shown_last, total, shown_last + 1
        )
    return _truncate(body)


def tool_glob(sb: Sandbox, pattern: str, path: Optional[str] = None) -> str:
    root = sb.read_path(path) if path else sb.read_roots[0]
    if not root.is_dir():
        raise ToolError("{0} is not a directory".format(root))

    matches: List[Tuple[float, Path]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        d = Path(dirpath)
        for name in filenames:
            fp = d / name
            rel = fp.relative_to(root)
            if fnmatch.fnmatch(str(rel), pattern) or fnmatch.fnmatch(name, pattern):
                try:
                    matches.append((fp.stat().st_mtime, fp))
                except OSError:
                    continue
        if len(matches) > MAX_GLOB_RESULTS * 4:
            break

    if not matches:
        return "No files matched {0!r} under {1}".format(pattern, root)

    matches.sort(key=lambda t: -t[0])
    lines = [str(p) for _, p in matches[:MAX_GLOB_RESULTS]]
    header = "{0} match(es)".format(len(matches))
    if len(matches) > MAX_GLOB_RESULTS:
        header += " (showing first {0}, newest first)".format(MAX_GLOB_RESULTS)
    return _truncate(header + ":\n" + "\n".join(lines))


def _grep_ripgrep(
    root: Path, pattern: str, glob: Optional[str], ignore_case: bool, files_only: bool
) -> Optional[str]:
    rg = shutil.which("rg")
    if not rg:
        return None
    cmd = [rg, "--no-heading", "--line-number", "--color", "never"]
    if ignore_case:
        cmd.append("-i")
    if files_only:
        cmd = [rg, "--files-with-matches", "--color", "never"]
        if ignore_case:
            cmd.append("-i")
    for d in SKIP_DIRS:
        cmd += ["--glob", "!{0}/".format(d)]
    if glob:
        cmd += ["--glob", glob]
    cmd += ["--max-count", "20", "-e", pattern, str(root)]

    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode not in (0, 1):
        err = proc.stderr.decode("utf-8", "replace")[:300]
        raise ToolError("grep failed: {0}".format(err))
    return proc.stdout.decode("utf-8", "replace")


def _grep_python(
    root: Path, pattern: str, glob: Optional[str], ignore_case: bool, files_only: bool
) -> str:
    flags = re.IGNORECASE if ignore_case else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as exc:
        raise ToolError("invalid regex {0!r}: {1}".format(pattern, exc))

    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        d = Path(dirpath)
        for name in filenames:
            fp = d / name
            if glob and not (fnmatch.fnmatch(name, glob) or fnmatch.fnmatch(str(fp), glob)):
                continue
            if _is_binary(fp):
                continue
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    hits = 0
                    for idx, line in enumerate(fh, start=1):
                        if rx.search(line):
                            if files_only:
                                out.append(str(fp))
                                break
                            out.append(
                                "{0}:{1}:{2}".format(fp, idx, line.rstrip()[:MAX_LINE_CHARS])
                            )
                            hits += 1
                            if hits >= 20:
                                break
            except OSError:
                continue
            if len(out) > MAX_GREP_MATCHES * 3:
                return "\n".join(out)
    return "\n".join(out)


def tool_grep(
    sb: Sandbox,
    pattern: str,
    path: Optional[str] = None,
    glob: Optional[str] = None,
    ignore_case: bool = False,
    files_with_matches: bool = False,
) -> str:
    root = sb.read_path(path) if path else sb.read_roots[0]
    raw = _grep_ripgrep(root, pattern, glob, ignore_case, files_with_matches)
    if raw is None:
        raw = _grep_python(root, pattern, glob, ignore_case, files_with_matches)

    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if not lines:
        return "No matches for {0!r}{1}".format(
            pattern, " (glob {0})".format(glob) if glob else ""
        )

    shown = lines[:MAX_GREP_MATCHES]
    header = "{0} match(es)".format(len(lines))
    if len(lines) > MAX_GREP_MATCHES:
        header += " (showing first {0} — narrow the pattern or pass glob= to see the rest)".format(
            MAX_GREP_MATCHES
        )
    return _truncate(header + ":\n" + "\n".join(shown))


def tool_write(sb: Sandbox, file_path: str, content: str) -> str:
    path = sb.write_path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = content if isinstance(content, str) else str(content)
    path.write_text(text, encoding="utf-8")
    return "Wrote {0} bytes to {1}".format(len(text.encode("utf-8")), path)


# --------------------------------------------------------------------------
# Schema + dispatch
# --------------------------------------------------------------------------

TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "Read",
            "description": (
                "Read a file from the target repository. Returns line-numbered "
                "content. Use offset/limit to page through large files."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path to the file"},
                    "offset": {"type": "integer", "description": "1-based first line to read"},
                    "limit": {"type": "integer", "description": "Max lines to return"},
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "Grep",
            "description": (
                "Search the repository with a regular expression. Returns "
                "file:line:content matches. This is your primary instrument for "
                "tracing data flow forward from an input to a sink."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regular expression"},
                    "path": {"type": "string", "description": "Directory to search (default: repo root)"},
                    "glob": {"type": "string", "description": "Filter filenames, e.g. '*.py'"},
                    "ignore_case": {"type": "boolean"},
                    "files_with_matches": {
                        "type": "boolean",
                        "description": "Return only filenames, not matching lines",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "Glob",
            "description": "Find files by name pattern, e.g. '**/*.go' or 'routes*.js'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "path": {"type": "string", "description": "Directory to search under"},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "Write",
            "description": (
                "Write your output file. Only paths inside the results directory "
                "are permitted. Use the exact filename your instructions specify."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["file_path", "content"],
            },
        },
    },
]

_DISPATCH = {
    "Read": tool_read,
    "Grep": tool_grep,
    "Glob": tool_glob,
    "Write": tool_write,
}

# Aliases the model reaches for when it doesn't echo the schema name exactly.
_DISPATCH_CI = {k.lower(): v for k, v in _DISPATCH.items()}
_DISPATCH_CI.update({
    "read_file": tool_read,
    "readfile": tool_read,
    "cat": tool_read,
    "search": tool_grep,
    "ripgrep": tool_grep,
    "rg": tool_grep,
    "find": tool_glob,
    "list_files": tool_glob,
    "write_file": tool_write,
    "writefile": tool_write,
})


def call_tool(sb: Sandbox, name: str, args: Dict[str, Any]) -> str:
    """Execute a tool call, returning a string result for the model.

    Errors are returned as text rather than raised: a malformed tool call
    should teach the model to correct itself on the next turn, not kill the
    phase.
    """
    # Case-insensitive lookup: local models routinely emit `glob` for `Glob`.
    # Rejecting those wastes a turn and teaches nothing useful.
    fn = _DISPATCH.get(name) or _DISPATCH_CI.get((name or "").strip().lower())
    if fn is None:
        return "ERROR: unknown tool {0!r}. Available: {1}".format(
            name, ", ".join(sorted(_DISPATCH))
        )
    if not isinstance(args, dict):
        try:
            args = json.loads(args)
        except Exception:
            return "ERROR: tool arguments must be a JSON object, got {0!r}".format(args)

    try:
        return fn(sb, **args)
    except ToolError as exc:
        return "ERROR: {0}".format(exc)
    except TypeError as exc:
        return "ERROR: bad arguments for {0}: {1}".format(name, exc)
    except Exception as exc:  # pragma: no cover - defensive
        log.exception("tool %s crashed", name)
        return "ERROR: {0} failed: {1}".format(name, exc)
