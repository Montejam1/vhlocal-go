"""Index and summarise scan reports on disk.

The reports directory is the source of truth, not the job store. A report
produced by the CLI, by an older server process, or by a job whose record was
pruned still shows up here — the UI's Reports tab lists what exists on disk.

Parsing is deliberately forgiving. `phase4_report.md` specifies a header shape,
but a local model's adherence varies run to run, so every field degrades to a
sensible fallback rather than dropping the report from the list.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .phases import normalize_text

# Directory name shape written by resolve_results_dir.
DIR_RE = re.compile(r"^(?P<repo>.+)_VULNHUNT_RESULTS_(?P<model>[^_]+)_(?P<stamp>[\d-]+)$")

_HDR = {
    "run_id": re.compile(r"\*\*Run ID\*\*\s*:?\s*(.+)"),
    "repository": re.compile(r"\*\*Repository\*\*\s*:?\s*(.+)"),
    "audit_date": re.compile(r"\*\*Audit Date\*\*\s*:?\s*(.+)"),
    "branch": re.compile(r"\*\*Branch\*\*\s*:?\s*(.+)"),
    "model": re.compile(r"\*\*Model\*\*\s*:?\s*(.+)"),
    "findings_summary": re.compile(r"\*\*Findings Summary\*\*\s*:?\s*(.+)"),
}

# A finding row in the summary table: | VULN-001 | Title | CWE-89 | High | ...
_FINDING_ROW = re.compile(r"^\|\s*(VULN-\d+)\s*\|", re.IGNORECASE | re.MULTILINE)
_SEVERITIES = ("high+", "critical", "high", "medium", "low", "informational")

# Phase deliverables, in pipeline order, used to show how far a scan got.
PHASE_FILES = [
    ("1", "phase1_output.md"),
    ("2", "results"),
    ("2b", "phase2b_output.md"),
    ("3", "phase3_output.md"),
    ("3d", "phase3d_output.md"),
    ("4", "README.md"),
]


@dataclass
class Report:
    id: str
    path: str
    name: str
    repo: str = ""
    model: str = ""
    # What the report *claims*, kept for display; may disagree with `model`.
    model_reported: str = ""
    created: float = 0.0
    stamp: str = ""
    findings: int = 0
    severities: Dict[str, int] = field(default_factory=dict)
    findings_summary: str = ""
    branch: str = ""
    audit_date: str = ""
    complete: bool = False
    phases_present: List[str] = field(default_factory=list)
    size: int = 0
    has_report: bool = False
    has_consolidated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


def _dir_size(root: Path) -> int:
    total = 0
    for f in root.rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
            except OSError:
                pass
    return total


def parse_report(root: Path) -> Report:
    """Build a Report summary for one results directory."""
    rep = Report(id=root.name, path=str(root), name=root.name)

    m = DIR_RE.match(root.name)
    if m:
        rep.repo = m.group("repo")
        rep.model = m.group("model")
        rep.stamp = m.group("stamp")

    try:
        rep.created = root.stat().st_mtime
    except OSError:
        pass

    for key, rel in PHASE_FILES:
        target = root / rel
        if target.is_dir():
            if any(target.glob("*.md")):
                rep.phases_present.append(key)
        elif target.exists():
            rep.phases_present.append(key)

    from .consolidate import SCAN_REPORT_FILE, FINDINGS_JSON_FILE
    rep.has_consolidated = (root / SCAN_REPORT_FILE).exists()

    readme = root / "README.md"
    rep.has_report = readme.exists()
    rep.complete = rep.has_report

    # The finding COUNT comes from findings.json — the deterministic, engine-built
    # machine record — never from scraping README. Phase 4 sometimes leaves README
    # a boilerplate stub even when the run confirmed findings, and scraping it then
    # reports 0 (the Reports-tab "0 findings" bug). findings.json is authoritative;
    # README scraping remains only as a fallback for old runs that predate it.
    if not _findings_from_json(root / FINDINGS_JSON_FILE, rep):
        _findings_from_readme(readme, rep)

    # Header metadata (repo/model/branch/date) still comes from README when present.
    if readme.exists():
        _header_from_readme(readme, rep)

    rep.size = _dir_size(root)
    return rep


def _findings_from_json(path: Path, rep: Report) -> bool:
    """Populate finding count + severities from findings.json. Returns True on success."""
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return False
    findings = data.get("findings")
    if not isinstance(findings, list):
        return False
    # Unique root causes only — clustered duplicates are excluded, matching the
    # headline count in the consolidated report.
    unique = [f for f in findings if isinstance(f, dict) and not f.get("duplicate_of")]
    rep.findings = len(unique)
    counts = data.get("counts")
    if isinstance(counts, dict):
        for label, n in counts.items():
            if isinstance(n, int) and n:
                rep.severities[str(label).lower()] = n
    return True


def _findings_from_readme(readme: Path, rep: Report) -> None:
    """Legacy fallback: scrape the finding count out of a Phase-4 README table."""
    if not readme.exists():
        return
    try:
        text = normalize_text(readme.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return
    ids = {i.upper() for i in _FINDING_ROW.findall(text)}
    rep.findings = len(ids)
    low = text.lower()
    for sev in _SEVERITIES:
        n = low.count("| " + sev + " ")
        if n:
            rep.severities[sev] = n


def _header_from_readme(readme: Path, rep: Report) -> None:
    try:
        text = normalize_text(readme.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return
    head = text[:4000]
    for key, rx in _HDR.items():
        mm = rx.search(head)
        if not mm:
            continue
        val = mm.group(1).strip().strip("`")
        if key == "repository":
            rep.repo = val or rep.repo
        elif key == "model":
            # The directory name is engine-generated and authoritative. The
            # README's Model field is written by the model itself and is
            # unreliable — observed copying "claude-opus-4-8" straight out of the
            # phase4 template example. Header only fills a gap.
            rep.model_reported = val
            if not rep.model:
                rep.model = val
        elif key == "branch":
            rep.branch = val
        elif key == "audit_date":
            rep.audit_date = val
        elif key == "findings_summary":
            rep.findings_summary = val


def is_report_dir(p: Path) -> bool:
    if not p.is_dir():
        return False
    if DIR_RE.match(p.name):
        return True
    # Tolerate custom --out names: anything holding a recognised deliverable.
    return any((p / rel).exists() for _k, rel in PHASE_FILES)


def list_reports(reports_dir: Path, extra_dirs: Optional[List[Path]] = None) -> List[Report]:
    """All reports under ``reports_dir``, newest first.

    ``extra_dirs`` lets the caller fold in results directories recorded by jobs
    that used an explicit ``out`` outside the reports tree, so the tab shows
    everything the engine has produced rather than only the default location.
    """
    seen = {}
    roots: List[Path] = []

    base = Path(reports_dir).expanduser()
    if base.is_dir():
        for child in base.iterdir():
            if is_report_dir(child):
                roots.append(child)

    for extra in extra_dirs or []:
        p = Path(extra).expanduser()
        if p.is_dir() and is_report_dir(p):
            roots.append(p)

    for root in roots:
        try:
            key = str(root.resolve())
        except OSError:
            continue
        if key in seen:
            continue
        try:
            seen[key] = parse_report(root)
        except OSError:
            continue

    return sorted(seen.values(), key=lambda r: -r.created)


def resolve_report(reports_dir: Path, report_id: str,
                   extra_dirs: Optional[List[Path]] = None) -> Optional[Path]:
    """Map a report id back to its directory, refusing anything outside scope.

    ``report_id`` comes from the browser, so it is never joined to a path
    directly — it is matched against the enumerated set instead. That makes
    path traversal structurally impossible here rather than filtered.
    """
    for rep in list_reports(reports_dir, extra_dirs):
        if rep.id == report_id:
            return Path(rep.path)
    return None
