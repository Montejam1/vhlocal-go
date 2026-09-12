"""Legacy table display parsing and the canonical Phase-2b handoff entry point.

Markdown never authorizes reproduction. New scans use verification.py's JSON
manifest and validated decisions; the legacy parser is retained for old reports.
"""

import re
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .phases import normalize_text

HANDOFF_FILE = "phase2b_handoff.md"

# Findings are labelled VULN-NNN, but some trace agents number theirs
# "Finding 1", "Finding 2" instead. Both are real confirmed findings; matching
# only VULN-NNN silently dropped the Finding-N ones from the handoff (and thus
# from Phase 3's worklist) — the SSRF and weak-PRNG findings vanished this way.
_VULN = re.compile(r"\b(?:VULN-\d+|Finding[\s\-]?\d+)\b", re.IGNORECASE)
_CWE = re.compile(r"\bCWE-\d+", re.IGNORECASE)
_SEV = re.compile(
    r"\b(critical|high\+|high|medium|moderate|low|informational|info)\b", re.IGNORECASE)
_MD_FILE = re.compile(r"\b[\w.\-]+\.md\b")
_SEV_LABEL = {"high+": "High+", "high": "High", "critical": "Critical",
              "medium": "Medium", "moderate": "Medium", "low": "Low",
              "informational": "Informational", "info": "Informational"}


@dataclass
class HandoffItem:
    vuln: str          # source-namespaced legacy display ID
    severity: str
    cwe: str
    entry: str         # endpoint / entry point
    source: str        # per-class result file holding the detail
    source_id: str     # the finding's id within that source file


def parse_confirmed(text: str) -> List[HandoffItem]:
    """Legacy display parser only. Explicit named verdict columns are required.

    This does not authorize reproduction: write_handoff uses the validated JSON
    contract. Unknown/pending verdicts and CONFIRMED in narrative cells never count.
    """
    from .consolidate import _iter_md_tables
    out = []
    seen = set()
    for headers, rows in _iter_md_tables(normalize_text(text)):
        names = [h.strip().strip("*").lower() for h in headers]
        def column(*aliases):
            return next((i for i, h in enumerate(names) if h in aliases), None)
        cols = [column("verdict", "decision"), column("finding id", "id", "finding"),
                column("source", "source file"), column("cwe"),
                column("entry point", "endpoint"), column("severity")]
        if any(c is None for c in cols):
            continue
        for row in rows:
            if len(row) != len(headers):
                continue
            verdict, fid, source, cwe, entry, severity = [row[i].strip().strip("*`") for i in cols]
            if verdict.upper() != "CONFIRMED" or not _VULN.fullmatch(fid):
                continue
            if not _MD_FILE.fullmatch(source) or not _CWE.fullmatch(cwe):
                continue
            if not re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /", entry):
                continue
            if severity.lower() not in _SEV_LABEL:
                continue
            key = (source, fid)
            if key in seen:
                continue
            seen.add(key)
            legacy_id = "LEGACY-" + hashlib.sha256((source + "\0" + fid).encode()).hexdigest()[:16]
            out.append(HandoffItem(legacy_id, _SEV_LABEL[severity.lower()], cwe, entry, source, fid))
    return out


def write_handoff(results_dir: Path) -> Optional[Path]:
    """Only canonical JSON decisions can create a reproduction handoff."""
    from . import verification
    results_dir = Path(results_dir)
    if (results_dir / verification.MANIFEST).exists():
        verification.render(results_dir)
    else:
        (results_dir / HANDOFF_FILE).write_text(
            "# Verified candidate handoff\n\nNo structured verification decisions available.\n"
            "Total confirmed findings: 0\n", encoding="utf-8")
    return results_dir / HANDOFF_FILE
