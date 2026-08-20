"""Deterministic entry-point inventory — the harness-owned coverage denominator.

The scan model decides *where to look*; it must not also decide *what counts as
the whole attack surface*. If recon silently omits a router, a run can look
complete while never having seen half the endpoints. So the harness enumerates
the entry points itself, deterministically, straight from the source — and the
model is asked to *disposition* that fixed inventory, not to reproduce it.

Two consumers:

* **Partitioning fallback (P1-E).** When the model's Phase-1 partition table
  cannot be parsed, we do not collapse to one whole-repo pass — we synthesise
  subsystem partitions from the enumerated routes so Phase 2 still fans out.
* **Coverage ledger (P1-F).** The enumerated routes are the denominator: every
  one ends the run in a disposition (reviewed / finding / excluded / not
  reviewed), and a run cannot be called complete while any is `not_reviewed`.

Enumeration is AST-based (stdlib `ast`, no dependencies) and covers the two
frameworks these scans target: FastAPI (`@app.get`, `APIRouter`, `include_router`
prefixes) and Flask (`@app.route`, blueprints). Non-Python entry points are out
of scope for v1 and are reported as a known limitation rather than silently
dropped.
"""

import ast
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .tools import SKIP_DIRS

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head", "trace"}
# Decorator attributes that register a route. `route`/`api_route` carry methods
# in a kwarg rather than the attribute name.
_ROUTE_ATTRS = HTTP_METHODS | {"route", "api_route", "websocket"}

# Security-relevant subsystems. Order matters: the first matching rule wins, so
# more specific subsystems (auth, authz) precede the catch-all. Each rule is a
# set of substrings tested against the route path + defining file path.
_SUBSYSTEMS = [
    ("auth", ("login", "logout", "register", "signup", "signin", "password",
              "reset", "token", "session", "oauth", "mfa", "otp", "verify-email",
              "credential", "/auth")),
    ("authz", ("permission", "role", "grant", "revoke", "tenant", "region",
               "scope", "acl", "authorize", "authz", "membership")),
    ("filedata", ("upload", "download", "export", "import", "csv", "webhook",
                  "attachment", "file", "document", "media", "backup", "vault")),
    ("config", ("config", "setting", "secret", "key", "env", "feature-flag",
                "admin/system")),
    ("ops", ("/ops", "internal", "worker", "dispatch", "/admin", "job", "task",
             "cron", "queue", "debug", "trace", "healthz", "metrics")),
    ("users", ("user", "profile", "account", "customer", "member", "directory")),
]
_DEFAULT_SUBSYSTEM = "core"

_SUBSYSTEM_TITLES = {
    "auth": "Authentication, sessions & password recovery",
    "authz": "Authorization & region/tenant boundaries",
    "filedata": "File handling, uploads, exports & webhooks",
    "config": "Configuration, keys & secret storage",
    "ops": "Operations, admin & background/dispatch routes",
    "users": "User & account endpoints",
    "core": "Core application endpoints",
}


@dataclass
class EntryPoint:
    method: str        # upper-case HTTP method, or "ROUTE"/"WS"
    path: str          # best-effort URL path, incl. router prefix when known
    file: str          # repo-relative source file
    line: int          # 1-indexed line of the handler
    function: str      # handler function name
    subsystem: str = ""

    @property
    def key(self) -> str:
        """Stable identity for ledger bookkeeping and dedup."""
        return "{0} {1} [{2}:{3}]".format(self.method, self.path, self.file, self.line)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def subsystem_for(path: str, file: str) -> str:
    hay = "{0} {1}".format(path or "", file or "").lower()
    for name, needles in _SUBSYSTEMS:
        if any(n in hay for n in needles):
            return name
    return _DEFAULT_SUBSYSTEM


def _iter_source_files(repo: Path):
    for p in sorted(repo.rglob("*.py")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        # Skip obvious test files — they are not the production attack surface.
        low = p.name.lower()
        if low.startswith("test_") or low.endswith("_test.py") or low == "conftest.py":
            continue
        if any(part in ("tests", "test") for part in p.parts):
            continue
        yield p


def _str_arg(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _router_prefixes(tree: ast.AST) -> Dict[str, str]:
    """Map local variable name -> URL prefix for APIRouter(prefix=...) / Blueprint.

    So `router = APIRouter(prefix="/ops")` followed by `@router.get("/x")` yields
    the real path `/ops/x`, not `/x`.
    """
    prefixes: Dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        callee = node.value.func
        name = getattr(callee, "id", None) or getattr(callee, "attr", None)
        if name not in ("APIRouter", "Blueprint", "Router"):
            continue
        prefix = ""
        for kw in node.value.keywords:
            if kw.arg in ("prefix", "url_prefix"):
                prefix = _str_arg(kw.value) or ""
        # Blueprint's URL prefix is often set at register time, not construction;
        # capture what we can and let path stay relative otherwise.
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                prefixes[tgt.id] = prefix
    return prefixes


def _methods_from_decorator(call: ast.Call, attr: str) -> List[str]:
    if attr in HTTP_METHODS:
        return [attr.upper()]
    if attr == "websocket":
        return ["WS"]
    # route()/api_route(): methods=[...] kwarg, else default GET (Flask) / ROUTE.
    for kw in call.keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
            out = [_str_arg(e) for e in kw.value.elts]
            out = [m.upper() for m in out if m]
            if out:
                return out
    return ["ROUTE"]


def enumerate_entry_points(repo: Path) -> List[EntryPoint]:
    """Every HTTP route/handler the harness can see, straight from the AST."""
    repo = Path(repo)
    found: List[EntryPoint] = []
    seen = set()
    for src in _iter_source_files(repo):
        try:
            tree = ast.parse(src.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError):
            continue
        prefixes = _router_prefixes(tree)
        rel = str(src.relative_to(repo))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                    continue
                attr = dec.func.attr.lower()
                if attr not in _ROUTE_ATTRS:
                    continue
                obj = getattr(dec.func.value, "id", "")
                path = ""
                if dec.args:
                    path = _str_arg(dec.args[0]) or ""
                path = (prefixes.get(obj, "") + path) or path or "/"
                for method in _methods_from_decorator(dec, attr):
                    ep = EntryPoint(
                        method=method, path=path, file=rel,
                        line=node.lineno, function=node.name,
                        subsystem=subsystem_for(path, rel),
                    )
                    if ep.key in seen:
                        continue
                    seen.add(ep.key)
                    found.append(ep)
    found.sort(key=lambda e: (e.file, e.line, e.method))
    return found


# ---------------------------------------------------------------------------
# Deterministic partitions (P1-E fallback)
# ---------------------------------------------------------------------------

@dataclass
class DetPartition:
    ident: str
    description: str
    subsystem: str
    files: List[str] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)


def deterministic_partitions(repo: Path, max_partitions: int = 8) -> List[DetPartition]:
    """Subsystem partitions synthesised from enumerated routes.

    Never returns a single whole-repo blob when the repo has discoverable
    structure — that silent collapse is exactly the coverage failure this
    replaces. If no routes are found at all, falls back to top-level package
    directories; only a genuinely structureless repo yields one partition.
    """
    repo = Path(repo)
    eps = enumerate_entry_points(repo)

    groups: Dict[str, List[EntryPoint]] = {}
    for ep in eps:
        groups.setdefault(ep.subsystem, []).append(ep)

    parts: List[DetPartition] = []
    if groups:
        # Stable, meaningful ordering: known subsystems in definition order,
        # then any others alphabetically.
        order = [n for n, _t in _SUBSYSTEMS] + [_DEFAULT_SUBSYSTEM]
        ordered = sorted(groups, key=lambda s: (order.index(s) if s in order else 99, s))
        for i, sub in enumerate(ordered, start=1):
            members = groups[sub]
            files = sorted({m.file for m in members})
            parts.append(DetPartition(
                ident="SG-{0}".format(i),
                description="{0} ({1} route{2}: {3})".format(
                    _SUBSYSTEM_TITLES.get(sub, sub), len(members),
                    "" if len(members) == 1 else "s",
                    ", ".join(files[:4]) + ("…" if len(files) > 4 else "")),
                subsystem=sub, files=files,
                entry_points=[m.key for m in members],
            ))
    else:
        # No routes discovered — partition by top-level source package so Phase 2
        # still fans out instead of drowning one agent in the whole tree.
        pkgs = _top_level_packages(repo)
        for i, pkg in enumerate(pkgs, start=1):
            parts.append(DetPartition(
                ident="SG-{0}".format(i),
                description="Source package: {0}".format(pkg),
                subsystem="core", files=[pkg], entry_points=[]))

    if not parts:
        parts = [DetPartition("SG-1", "entire repository (no structure found)",
                              "core", ["."], [])]

    if len(parts) > max_partitions:
        parts = parts[:max_partitions]
    return parts


def _top_level_packages(repo: Path) -> List[str]:
    pkgs = []
    for base in (repo, repo / "app", repo / "backend", repo / "src"):
        if not base.is_dir():
            continue
        for child in sorted(base.iterdir()):
            if child.is_dir() and child.name not in SKIP_DIRS \
                    and (child / "__init__.py").exists():
                pkgs.append(str(child.relative_to(repo)))
    return pkgs or [str(repo.name)]


def collapsed_to_whole_repo(parts: List["DetPartition"]) -> bool:
    """True when partitioning degenerated to a single undivided pass."""
    return len(parts) <= 1


def route_inventory_markdown(repo: Path) -> str:
    """A Markdown checklist of every enumerated route, for seeding Phase 1.

    Handed to recon so its input inventory starts from the complete, source-of-
    truth route list instead of whatever it happens to discover. Empty string
    when nothing is enumerable (non-Python stack) — recon then proceeds normally.
    """
    eps = enumerate_entry_points(repo)
    if not eps:
        return ""
    lines = [
        "# Enumerated HTTP entry points (authoritative — from source AST)",
        "",
        "The harness enumerated every route below directly from the code. Your "
        "input inventory MUST account for **every** one: enumerate its inputs, or "
        "record why it carries none. Do not treat this list as complete evidence "
        "of safety — it is the coverage denominator you are required to close.",
        "",
        "| Method | Path | File:line | Subsystem |",
        "|---|---|---|---|",
    ]
    for e in eps:
        lines.append("| {0} | {1} | {2}:{3} | {4} |".format(
            e.method, e.path, e.file, e.line, e.subsystem))
    lines.append("")
    lines.append("Total entry points: {0}".format(len(eps)))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Coverage ledger (P1-F)
# ---------------------------------------------------------------------------

# Every enumerated entry point ends the run in exactly one of these. The
# denominator (the entry list) is harness-owned, so recon cannot shrink it by
# forgetting a router — a forgotten route simply shows as `not_reviewed`.
DISP_FINDING = "finding_emitted"
DISP_REVIEWED = "reviewed_no_issue"
DISP_PARENT = "covered_by_parent_analysis"
DISP_EXCLUDED = "excluded_with_reason"
DISP_NOT_REVIEWED = "not_reviewed"

# Artifacts that constitute "the model looked here". results/ is the per-agent
# hunt output; the phase files are the downstream analysis.
_LEDGER_ARTIFACTS = ("phase2b_output.md", "phase3_output.md", "phase3d_output.md",
                     "README.md", "phase1_output.md")


@dataclass
class LedgerEntry:
    method: str
    path: str
    file: str
    line: int
    subsystem: str
    disposition: str
    evidence: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class CoverageLedger:
    entries: List[LedgerEntry]
    counts: Dict[str, int]
    total: int
    reviewed: int
    not_reviewed: int

    @property
    def complete(self) -> bool:
        """A run has full entry-point coverage only when nothing is unreviewed.

        An empty denominator (no routes enumerable — non-Python stack, or a
        library with no HTTP surface) is *unknown*, not complete: we cannot
        assert coverage over a surface we could not enumerate.
        """
        return self.total > 0 and self.not_reviewed == 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "total": self.total,
            "reviewed": self.reviewed,
            "not_reviewed": self.not_reviewed,
            "complete": self.complete,
            "counts": self.counts,
            "entries": [e.to_dict() for e in self.entries],
        }


def _read_artifact_corpus(results_dir: Path) -> str:
    parts = []
    results_sub = results_dir / "results"
    if results_sub.is_dir():
        for p in sorted(results_sub.glob("*.md")):
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
    for name in _LEDGER_ARTIFACTS:
        p = results_dir / name
        if p.exists():
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def build_coverage_ledger(
    results_dir: Path,
    repo: Path,
    finding_files=None,
) -> CoverageLedger:
    """Disposition every enumerated entry point against what the scan produced.

    Deterministic and evidence-based — no model claim is trusted:

    * ``finding_emitted`` — a finding points at this entry's file.
    * ``reviewed_no_issue`` — the file (or its route path) appears in the
      produced analysis, so an agent demonstrably looked at it.
    * ``not_reviewed`` — no artifact references it. This is the honest gap that
      stops a narrow run from claiming complete coverage.
    """
    repo = Path(repo)
    eps = enumerate_entry_points(repo)
    finding_files = {f for f in (finding_files or []) if f}
    corpus = _read_artifact_corpus(results_dir)

    entries: List[LedgerEntry] = []
    counts: Dict[str, int] = {}
    for ep in eps:
        if ep.file in finding_files:
            disp, ev = DISP_FINDING, "finding at " + ep.file
        elif ep.file in corpus or (len(ep.path) > 1 and ep.path in corpus):
            disp, ev = DISP_REVIEWED, "referenced in analysis"
        else:
            disp, ev = DISP_NOT_REVIEWED, ""
        counts[disp] = counts.get(disp, 0) + 1
        entries.append(LedgerEntry(
            method=ep.method, path=ep.path, file=ep.file, line=ep.line,
            subsystem=ep.subsystem, disposition=disp, evidence=ev))

    total = len(entries)
    not_reviewed = counts.get(DISP_NOT_REVIEWED, 0)
    return CoverageLedger(
        entries=entries, counts=counts, total=total,
        reviewed=total - not_reviewed, not_reviewed=not_reviewed)
