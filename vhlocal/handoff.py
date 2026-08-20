"""Compact structured handoff from Phase 2b to Phase 3.

Phase 3 (reproduce → test → fix) previously read the full ``phase2b_output.md``
falsification transcript into its context — a large prose verdict table. Deep
into a long session that inflated context is exactly what pushed the local model
past the point where it emits valid tool-call JSON, and Phase 3 is where the
crash surfaced.

This distills 2b's verdict table into a small, stable list: one row per
confirmed, non-duplicate finding, with a sequential global VULN-NNN, severity,
CWE, entry point, and a pointer to the per-class source file that holds the
detail. Phase 3 starts from ~1-2KB instead of the whole transcript, and pulls
only the specific source files it needs.

Deliberately a *separate* parser from ``consolidate.parse_findings``: that one
targets the well-formed Phase 4 README summary table and dedups by VULN id.
2b's raw verdict table varies run to run (this project has seen per-file ids
repeated across source files, slash-joined CWEs, and explicit
``(Duplicate of #N)`` rows), so the handoff parser is format-tolerant and does
its own duplicate handling.
"""

import re
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
_HTTP = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE)\b|/", re.IGNORECASE)
# Rows the verdict table marks as not-a-standalone-finding.
_DROP = re.compile(r"duplicate of|\brejected\b|\beliminated\b|\bnot exploitable\b|\bfalse positive\b",
                   re.IGNORECASE)
_SEV_LABEL = {"high+": "High+", "high": "High", "critical": "Critical",
              "medium": "Medium", "moderate": "Medium", "low": "Low",
              "informational": "Informational", "info": "Informational"}


@dataclass
class HandoffItem:
    vuln: str          # global sequential id, e.g. VULN-001
    severity: str
    cwe: str
    entry: str         # endpoint / entry point
    source: str        # per-class result file holding the detail
    source_id: str     # the finding's id within that source file


def _cells(line: str) -> List[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _is_divider(cells: List[str]) -> bool:
    return bool(cells) and all(set(c) <= set("-: ") for c in cells)


_VERDICT_WORD = re.compile(r"\bconfirmed\b", re.IGNORECASE)
_CANDIDATE_HDR = re.compile(r"candidate|manifest", re.IGNORECASE)
_CONFIRMED_HDR = re.compile(r"confirmed", re.IGNORECASE)


def _first_finding_table(text: str) -> List[str]:
    """Return the lines of the first markdown table that lists VULN ids.

    A table is a maximal run of consecutive ``|``-rows. The first such run that
    contains at least two distinct VULN ids is the confirmed-findings summary;
    later runs are per-finding detail we don't want to fan out from.
    """
    best: List[str] = []
    cur: List[str] = []
    for line in text.splitlines():
        if line.lstrip().startswith("|"):
            cur.append(line)
        else:
            if len(_VULN.findall(" ".join(cur))) >= 2:
                return cur
            cur = []
    if len(_VULN.findall(" ".join(cur))) >= 2:
        return cur
    return best


def _confirmed_finding_rows(text: str) -> List[str]:
    """Rows for findings 2b *positively confirmed* — never the candidate manifest.

    The prior heuristic took the first VULN-bearing table, but 2b now emits a
    **Candidate Manifest** (the pre-verification list) before its verdicts. Those
    rows carry no "eliminated" text, so they slipped through and the handoff
    listed findings 2b had actually rejected (a run confirming 2 produced a
    21-row handoff of mostly-eliminated candidates).

    Rule: when the transcript contains verdict language anywhere, include a row
    ONLY if it is positively confirmed — its own text says "confirmed", or it
    sits under a heading that says "Confirmed" (and not "Candidate"/"Manifest").
    Rows marked eliminated/false-positive/rejected are dropped. Only when the
    document has no verdict language at all do we fall back to the first-table
    heuristic (some 2b outputs are already a confirmed-only list).
    """
    heading = ""
    tables = []          # list of (heading_at_table_start, [rows])
    cur: List[str] = []
    cur_heading = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            heading = stripped
        if line.lstrip().startswith("|"):
            if not cur:
                cur_heading = heading
            cur.append(line)
        elif cur:
            tables.append((cur_heading, cur))
            cur = []
    if cur:
        tables.append((cur_heading, cur))

    fin_tables = [(h, t) for (h, t) in tables
                  if len(_VULN.findall(" ".join(t))) >= 2]

    # 1. A single table under a "Confirmed" heading is authoritative — use only
    #    it, so a following per-finding *detail* table is not re-counted.
    for h, rows in fin_tables:
        if _CONFIRMED_HDR.search(h) and not _CANDIDATE_HDR.search(h):
            return rows

    # 2. No confirmed-heading table (2b led with a Candidate Manifest): collect
    #    only rows whose own text says CONFIRMED, across the verdict tables.
    confirmed: List[str] = []
    saw_verdict = False
    for h, rows in fin_tables:
        for row in rows:
            if not _VULN.search(row):
                continue
            if _DROP.search(row):
                saw_verdict = True
                continue
            if _VERDICT_WORD.search(row):
                confirmed.append(row)
                saw_verdict = True
    if confirmed:
        return confirmed
    if saw_verdict:
        # Verdicts existed but nothing was positively confirmed → honest empty,
        # so write_handoff falls back to the raw 2b output for Phase 3.
        return []

    # 3. No verdict language anywhere — treat the first finding table as the
    #    confirmed list (the historical behaviour for confirmed-only transcripts).
    return _first_finding_table(text)


def parse_confirmed(text: str) -> List[HandoffItem]:
    """Pull confirmed, non-duplicate findings out of a 2b verdict table.

    Tolerant by design: it scans every markdown row that mentions a VULN id and
    plucks fields by shape (CWE token, severity token, endpoint-ish cell, *.md
    cell) rather than by fixed column position, because the table layout is not
    stable across runs.
    """
    text = normalize_text(text)
    # 2b output holds several tables (candidate manifest + verdicts + per-finding
    # detail). Take only the rows 2b positively CONFIRMED — never the manifest,
    # whose candidates may have been eliminated downstream.
    block = _confirmed_finding_rows(text)
    out: List[HandoffItem] = []
    seq = 0
    for line in block:
        cells = _cells(line)
        if _is_divider(cells) or len(cells) < 2:
            continue
        joined = " ".join(cells)
        vm = _VULN.search(joined)
        if not vm:
            continue
        # Header rows mention "Finding ID" etc. but carry no actual VULN-\d+.
        if _DROP.search(joined):
            continue
        # If the table carries an explicit verdict column, honour a negative one.
        low = joined.lower()
        if "confirmed" not in low and ("rejected" in low or "not confirmed" in low):
            continue

        cwem = _CWE.search(joined)
        sm = _SEV.search(joined)
        # Endpoint: the longest cell that looks like a route.
        ep = ""
        for c in cells:
            if _HTTP.search(c) and len(c) > len(ep) and not _MD_FILE.search(c):
                ep = c
        srcm = _MD_FILE.search(joined)

        seq += 1
        rank, label = (sm.group(1).lower() if sm else ""), ""
        label = _SEV_LABEL.get(rank, sm.group(1) if sm else "Unrated")
        out.append(HandoffItem(
            vuln="VULN-{0:03d}".format(seq),
            severity=label,
            cwe="CWE-" + cwem.group(0).split("-", 1)[1] if cwem else "",
            entry=ep or "(see source)",
            source=srcm.group(0) if srcm else "",
            source_id=vm.group(0).upper(),
        ))
    return out


def render_handoff(items: List[HandoffItem]) -> str:
    L = ["# Phase 2b → Phase 3 handoff (confirmed findings)",
         "",
         "This is the **authoritative list of confirmed findings** to reproduce, "
         "test, and fix. It is a compact distillation of the Phase 2b "
         "verification — do NOT re-read `phase2b_output.md`; everything you need "
         "is here or in the per-finding source file named below.",
         "",
         "Assign VULN-NNN in this exact order. For full detail on any finding "
         "(location, data flow, exploit reasoning), read only its **Source** "
         "file under `results/`.",
         "",
         "| VULN | Severity | CWE | Entry point | Source (results/…) |",
         "|---|---|---|---|---|"]
    for it in items:
        L.append("| {0} | {1} | {2} | {3} | {4} ({5}) |".format(
            it.vuln, it.severity, it.cwe or "—", it.entry,
            it.source or "?", it.source_id))
    L.append("")
    L.append("Total confirmed findings: {0}".format(len(items)))
    L.append("")
    return "\n".join(L)


def write_handoff(results_dir: Path) -> Optional[Path]:
    """Generate ``phase2b_handoff.md`` from ``phase2b_output.md``.

    Returns the path on success, None if 2b output is absent or unparseable —
    in which case the caller falls back to the raw 2b output so Phase 3 still
    has an input.
    """
    results_dir = Path(results_dir)
    src = results_dir / "phase2b_output.md"
    if not src.exists():
        return None
    try:
        items = parse_confirmed(src.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None
    if not items:
        return None
    out = results_dir / HANDOFF_FILE
    out.write_text(render_handoff(items), encoding="utf-8")
    return out
