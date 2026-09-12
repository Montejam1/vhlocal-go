"""Consolidated scan report — Qualys-style summary over a completed run.

Renders `SCAN_REPORT.md` (human) and `findings.json` (machine) from two sources:

* **`scan_meta.json`** — written by the engine. Timings, model, phases, agent
  roster, token usage, tool envelope. All observed fact.
* **The phase artifacts** — parsed for findings.

Nothing here asks a model anything. That is deliberate: run metadata is engine
truth, and the one time we trusted the model's own prose about its run it
reported `claude-opus-4-8` for a scan executed on gpt-oss:120b. Parsing is
forgiving about layout but never invents a field.

Findings are ranked by severity, then CWE, then id. Likely duplicates are
**flagged, not merged** — a real run produced two findings for the same path
traversal, and silently collapsing them would hide a genuine quality signal
about the scan.
"""

import datetime as _dt
import json
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .knowledge import apply_knowledge
from .lifecycle import reconcile as reconcile_lifecycle
from .phases import normalize_text

SCAN_REPORT_FILE = "SCAN_REPORT.md"
FINDINGS_JSON_FILE = "findings.json"
SCAN_META_FILE = "scan_meta.json"

# Ordered most severe first. `rank` drives sorting; `label` is canonical output.
SEVERITY_ORDER = [
    ("critical", "Critical"),
    ("high+", "High+"),
    ("high", "High"),
    ("medium", "Medium"),
    ("moderate", "Medium"),
    ("low", "Low"),
    ("informational", "Informational"),
    ("info", "Informational"),
]
_SEV_RANK = {k: i for i, (k, _v) in enumerate(SEVERITY_ORDER)}
_SEV_LABEL = dict(SEVERITY_ORDER)
UNKNOWN_RANK = len(SEVERITY_ORDER)

PHASE_TITLES = {
    "1": "Recon — attack surface mapping",
    "2": "Hunt — forward tracing",
    "2b": "Verify — adversarial falsification",
    "3": "Reproduce, test, fix",
    "3d": "Sweep — root-cause instances",
    "4": "Report",
}

CLASS_TITLES = {
    "INJ": "Injection (SQLi, command, path traversal, SSRF, XSS, XXE, SSTI, upload)",
    "NAV": "Navigation & access control (authz bypass, IDOR, redirects, deserialization)",
    "LOG": "Logic & crypto (weak crypto, race conditions, business-logic flaws)",
    "SINK": "Sink-driven backward audit",
}

_ROW = re.compile(r"^\|(?P<cells>.+)\|\s*$", re.MULTILINE)
_VULN_ID = re.compile(r"\b(VULN-\d+)\b", re.IGNORECASE)
_CWE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)
# NOTE: no trailing \b — it cannot match after the '+' in "High+", which
# silently downgraded High+ findings to High. A negative lookahead handles both.
_SEV_IN_TEXT = re.compile(
    r"\b(critical|high\+|high|medium|moderate|low|informational|info)(?![\w+])",
    re.IGNORECASE)
_DETAIL_HDR = re.compile(r"^#{2,4}\s*\[?(VULN-\d+)\]?\s*(?P<title>.*)$",
                         re.IGNORECASE | re.MULTILINE)
_FIELD = re.compile(r"^\|\s*\*\*(?P<k>[^*|]+)\*\*\s*\|\s*(?P<v>.*?)\s*\|\s*$", re.MULTILINE)


# Cells that are verdict/gate values, not titles. When a findings parser is
# pointed at a Phase-2b verdict table, these are what it would otherwise grab as
# the title (every finding came out "Yes").
_VERDICT_CELL = re.compile(
    r"^(yes|no|n/?a|confirmed|eliminated|false[ -]?positive|rejected|pass(ed)?|"
    r"fail(ed)?|\d+\s*(/|of)\s*\d+.*|—|-)$", re.IGNORECASE)


def _pick_title(cells: List[str]) -> str:
    """Choose the title cell from a findings-table row.

    Robust across the several table shapes we fall back through: the README
    summary (``ID | Title | CWE | Sev | …``), the Phase-3 assignment table
    (``ID | Phase 2b # | Title | Sev``), and stray verdict tables. Skips the id,
    CWE, severity, pure-numeric (the "Phase 2b #" column) and verdict/gate cells,
    then prefers the most title-like remaining cell."""
    cands = []
    for c in cells[1:]:
        cc = c.strip().strip("`*")
        if not cc or cc.isdigit():
            continue
        if _CWE.fullmatch(cc) or _SEV_IN_TEXT.fullmatch(cc) or _VERDICT_CELL.match(cc):
            continue
        cands.append(cc)
    if not cands:
        return ""
    worded = [c for c in cands if " " in c and any(ch.isalpha() for ch in c)]
    return max(worded or cands, key=len)


def _sev_key(raw: str) -> Tuple[int, str]:
    s = (raw or "").strip().lower()
    for key in sorted(_SEV_RANK, key=len, reverse=True):
        if key in s:
            return _SEV_RANK[key], _SEV_LABEL[key]
    return UNKNOWN_RANK, (raw.strip() or "Unrated")


# ---------------------------------------------------------------------------
# Validation vocabulary — harness-owned, never model-authored.
#
# The scan model writes "PASS" / "Confirmed" into its finding tables. With no
# shell tool the harness never executed a single exploit, so those strings are
# claims, not verdicts. We preserve the model's claim verbatim (as
# `reported_status`) but derive the *authoritative* state ourselves from a fact
# only the engine knows: whether code execution was enabled. See
# `apply_validation`.
# ---------------------------------------------------------------------------
TEST_NOT_RUN = "not_run"
TEST_PASSED = "passed"
TEST_FAILED = "failed"
VALIDATION_STATIC = "static_reasoning"
VALIDATION_DYNAMIC = "dynamic_execution"
STATE_STATIC_SUPPORTED = "statically_supported"
STATE_DYNAMIC_CONFIRMED = "dynamically_confirmed"
# A candidate the harness could NOT support on the evidence present — never
# silently promoted to a finding, never silently dropped. It stays accounted for
# so "candidates" and "supported findings" are distinct, and reported confidence
# never exceeds the evidence collected.
STATE_UNRESOLVED = "unresolved"
POC_AUTHORED = "authored"
POC_NONE = "none"

# Candidate assessment is distinct from the hunter's claim. Only an explicit
# review with matching source evidence can substantiate a vulnerability.
ASSESS_SUPPORTED = "supported"
ASSESS_UNRESOLVED = "unresolved"

# Publication tier (``classification``). Confidence never exceeds evidence, so a
# candidate is labelled by the strongest evidence it clears — not collapsed to a
# single "vulnerability yes/no":
#   hypothesis           — clears no evidence gate (no weakness class, a
#                          placeholder title, or a source location that does not
#                          resolve against the scanned tree). Not published as a
#                          finding; surfaced separately as worth investigating.
#   statically_supported — clears the harness's own static gate (weakness class +
#                          a concrete claim + a location that resolves). The
#                          scanner can honestly stand behind this from static
#                          facts, but no independent source-grounded review exists.
#   reviewed             — additionally backed by a source-grounded review record
#                          (see evidence.review_support): the highest tier.
# "Substantiated" = statically_supported OR reviewed = assessment == SUPPORTED.
CLASS_HYPOTHESIS = "hypothesis"
CLASS_STATICALLY_SUPPORTED = "statically_supported"
CLASS_REVIEWED = "reviewed"
SUBSTANTIATED_CLASSES = (CLASS_STATICALLY_SUPPORTED, CLASS_REVIEWED)


def _is_substantiated(classification: str) -> bool:
    """Whether a classification denotes a published finding (not a hypothesis)."""
    return classification in SUBSTANTIATED_CLASSES


def _assessment_label(classification: str) -> str:
    """Human-facing tier label for a candidate's classification."""
    return {
        CLASS_REVIEWED: "Reviewed vulnerability (source-grounded review on record)",
        CLASS_STATICALLY_SUPPORTED: "Statically-supported finding (harness static gate; no review on record)",
        CLASS_HYPOTHESIS: "Hypothesis — further investigation required",
    }.get(classification, "Hypothesis — further investigation required")


_QUALITY_SYMBOL = {"pass": "✓", "fail": "✗", "na": "—"}


def _format_quality_checks(checks: List[Dict[str, str]]) -> str:
    """One-line ``✓ name / ✗ name / — name`` summary of the quality battery."""
    return " · ".join("{0} {1}".format(_QUALITY_SYMBOL.get(c.get("status", ""), "?"),
                                       c.get("name", "")) for c in checks)


@dataclass
class Finding:
    id: str
    title: str = ""
    severity: str = "Unrated"
    severity_rank: int = UNKNOWN_RANK
    cwe: str = ""
    location: str = ""
    entry_point: str = ""
    data_flow: str = ""
    status: str = ""          # raw model claim, verbatim (e.g. "Confirmed")
    poc: str = ""
    exploit_test: str = ""    # raw model claim, verbatim (e.g. "PASS")
    fix: str = ""
    source: str = ""
    source_id: str = ""
    verification_status: str = ""
    verification_reason: str = ""
    verification_record: Dict[str, Any] = field(default_factory=dict)
    stable_identity: str = ""
    duplicate_of: Optional[str] = None
    # Canonical-root-cause clustering. `root_cause_key` is a stable fingerprint;
    # `cluster_id` is the canonical (kept) finding all members map to.
    root_cause_key: str = ""
    cluster_id: str = ""
    # Harness-derived validation state (set by apply_validation). Kept distinct
    # from the model's `status`/`exploit_test` claims above.
    poc_status: str = ""
    test_status: str = ""
    validation_method: str = ""
    finding_state: str = ""
    # Publication assessment, separate from runtime reproduction status.
    assessment: str = ""
    classification: str = "hypothesis"
    candidate_key: str = ""
    hypothesis_reason: str = ""
    assessment_reason: str = ""
    # Deterministic CWE knowledge (set by knowledge.apply_knowledge). `cve` is
    # deliberately "N/A" for first-party code findings — see knowledge.py.
    description: str = ""
    exploitability: str = ""
    reference: str = ""
    cve: str = ""
    # Standardized labels: canonical family + deterministic severity. The
    # model's reported cwe/severity above are preserved; these are the stable,
    # cross-run-comparable layer used for display and ranking.
    normalized_cwe: str = ""
    cwe_family: str = ""
    canonical_name: str = ""
    normalized_severity: str = ""
    reported_severity: str = ""   # the model's original severity, preserved
    # Cross-run lifecycle (set by lifecycle.reconcile — Mode A): new / persisting
    # / regressed relative to the most recent prior report of the same target.
    finding_lifecycle: str = ""
    # Multi-sample hunt voting (Tranche 2/3): how many hunt samples independently
    # reported this finding's site, out of how many were run. 0/0 on a single-pass
    # run — a higher share is a stronger recall/confidence signal.
    votes: int = 0
    vote_samples: int = 0
    # True when this candidate came through the Phase-2b verification pass (the
    # confirmed spine) — a corroboration signal the quality battery reads.
    from_confirmed: bool = False
    # True when this record's assessment was INHERITED from its cluster canonical
    # rather than earned by its own checks — so a duplicate reading "supported"
    # while its own quality_checks failed is never mistaken for independent
    # substantiation.
    assessment_inherited: bool = False
    # Per-check results from the pre-report quality battery (quality.evaluate),
    # each {name, status, reason}. Explains why the candidate did or didn't clear
    # the statically-supported bar. Empty on old reports.
    quality_checks: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dict(asdict(self), potential_severity=self.severity)


def _clean(v: str) -> str:
    """Strip model markup so values can be re-wrapped without nesting."""
    return (v or "").replace("`", "").replace("**", "").strip()


def _cells(line: str) -> List[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _is_divider(cells: List[str]) -> bool:
    return bool(cells) and all(set(c) <= set("-: ") for c in cells)


# --- confirmed-set finding extraction (Phase 2b is authoritative) -----------
# The final finding count must reflect what Phase 2b CONFIRMED — not what Phase
# 3/4 had throughput to write up. A single Phase-3 agent asked to reproduce 20
# findings "completes" after documenting a handful, and the report used to parse
# that truncated README (20 confirmed → 7 reported). So the confirmed set (from
# the handoff / 2b) is the spine; Phase 3/4 only enrich detail.

# Source-file finding heading, e.g. "#### VULN-001 IDOR – ...", "## Finding 1 – ...",
# "## [VULN-001] ... (CWE-400)".
_SRC_HDR = re.compile(
    r"^#{2,5}\s*\[?(?P<id>(?:VULN[-\s]?\d+)|(?:Finding[\s\-]?\d+))\]?"
    r"\s*[–\-:]*\s*(?P<title>.*)$",
    re.IGNORECASE | re.MULTILINE)
_CLASS_LINE = re.compile(r"\*\*Class\*\*\s*:?\s*(?P<v>.+)", re.IGNORECASE)
_LOC_LINE = re.compile(r"\*\*Location[^*]*\*\*\s*:?\s*(?P<v>.+)", re.IGNORECASE)
_SEV_LINE = re.compile(r"\*\*(?:Severity|Risk)\*\*\s*:?\s*(?P<v>.+)", re.IGNORECASE)


def _norm_fid(s: str) -> str:
    """Normalise a finding id so 'VULN-001', 'Finding 1', 'sg-2-log-Finding1'
    all key consistently (VULN1 / FINDING1)."""
    m = re.search(r"(VULN|FINDING)\D*(\d+)", (s or "").upper())
    return "{0}{1}".format(m.group(1), int(m.group(2))) if m else (s or "").upper().strip()


def _extract_source_findings(path: Path) -> Dict[str, Dict[str, str]]:
    """Map local finding id -> {title, cwe, location} from a per-agent source file.

    Source files carry the richest per-finding detail (title in the heading,
    ``**Class**: CWE-…`` and ``**Location**: file:line`` bullets), so they are the
    best place to enrich a confirmed finding the downstream phases dropped."""
    try:
        text = normalize_text(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return {}
    out: Dict[str, Dict[str, str]] = {}
    heads = list(_SRC_HDR.finditer(text))
    for i, h in enumerate(heads):
        key = _norm_fid(h.group("id"))
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        block = text[h.start():end]
        title = (h.group("title") or "").strip().strip("–-: ")
        cwe = ""
        cm = _CWE.search(title)  # some titles carry the CWE, e.g. "(CWE-400)"
        clsm = _CLASS_LINE.search(block)
        if clsm:
            cc = _CWE.search(clsm.group("v"))
            if cc:
                cwe = "CWE-{0}".format(cc.group(1))
        if not cwe and cm:
            cwe = "CWE-{0}".format(cm.group(1))
        # Strip a trailing "(CWE-NNN)" from the title for cleanliness.
        title = re.sub(r"\s*\(?CWE-\d+\)?\s*$", "", title).strip()
        locm = _LOC_LINE.search(block)
        location = ""
        if locm:
            lm = re.search(r"([\w./\-]+\.\w+)\s*[:\s]\s*(\d+(?:[‑\-]\d+)?)",
                           locm.group("v"))
            location = lm.group(0).replace("‑", "-") if lm else _clean(locm.group("v"))[:80]
        sevm = _SEV_LINE.search(block)
        severity = ""
        if sevm:
            sm = _SEV_IN_TEXT.search(sevm.group("v"))
            severity = sm.group(1) if sm else ""
        out[key] = {"title": title, "cwe": cwe, "location": location,
                    "severity": severity}
        reason = re.search(r"(?im)^[-*]?\s*\*\*Root Cause\*\*\s*:\s*(.+)$", block)
        if reason:
            out[key]["hypothesis_reason"] = reason[1].strip()
    return out


def _confirmed_spine(results_dir: Path) -> List[Finding]:
    """The authoritative confirmed-finding list from Phase 2b, richly enriched.

    Built from the handoff's confirmed set (global VULN-NNN ids, each pointing at
    a source file + local id), enriched with title/CWE/location from that source
    file. Returns [] when no handoff/2b confirmed set is available (old runs)."""
    from .handoff import HANDOFF_FILE, parse_confirmed
    # Prefer the raw 2b output over the handoff: its rows carry the *local*
    # source id (e.g. "sg-11-nav-VULN-001" → VULN-001 in sg-11_nav.md) that keys
    # the source-file enrichment, whereas the handoff has already renumbered to a
    # global id, losing that link. The handoff is the fallback for runs where 2b
    # output is absent.
    text = ""
    p2b = results_dir / "phase2b_output.md"
    if p2b.exists():
        text = p2b.read_text(encoding="utf-8", errors="replace")
    if not text:
        src = results_dir / HANDOFF_FILE
        if src.exists():
            text = src.read_text(encoding="utf-8", errors="replace")
    if not text:
        return []
    items = parse_confirmed(text)
    if not items:
        return []

    # Cache source-file extractions.
    src_cache: Dict[str, Dict[str, Dict[str, str]]] = {}

    def src_detail(fname: str, local_id: str) -> Dict[str, str]:
        if not fname:
            return {}
        if fname not in src_cache:
            src_cache[fname] = _extract_source_findings(results_dir / "results" / fname)
        return src_cache[fname].get(_norm_fid(local_id), {})

    findings: List[Finding] = []
    for it in items:
        detail = src_detail(it.source, it.source_id)
        cwe = it.cwe or detail.get("cwe", "")
        title = detail.get("title", "") or (it.entry if it.entry != "(see source)" else "")
        # Prefer the handoff/2b severity; fall back to the source file's own
        # **Severity** line rather than leaving a real finding "Unrated".
        rank, label = _sev_key(it.severity)
        if rank == UNKNOWN_RANK and detail.get("severity"):
            rank, label = _sev_key(detail["severity"])
        findings.append(Finding(
            id=it.vuln, title=title or it.vuln,
            severity=label, severity_rank=rank,
            cwe=cwe, location=detail.get("location", ""),
            source=it.source or HANDOFF_FILE,
            hypothesis_reason=detail.get("hypothesis_reason", ""),
        ))
    return findings


# A "title" that is really an entry-point URL, a verdict fragment, or just the
# id — nothing an analyst can recognise the vulnerability from. When the spine's
# source-file enrichment fails (broken source links in the handoff), the title
# falls back to the entry point (e.g. "POST /ops/bundle/dispatch-thaw-172"); the
# Phase-4 README usually has the real name ("Pickle deserialization RCE").
_WEAK_TITLE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|WS)\b|^/|dispatch-|^(yes|no|n/?a)\b|"
    r"^\d+\s*/\s*\d+\b|^\(see source\)$",
    re.IGNORECASE)


def _is_weak_title(title: str, fid: str) -> bool:
    t = (title or "").strip()
    return (not t) or t.upper() == (fid or "").upper() or bool(_WEAK_TITLE.search(t))


_ROUTE_RE = re.compile(r"/[\w{}./-]+")


def _route_key(f: "Finding") -> str:
    """A normalized route (e.g. ``/ops/xml/dispatch-fold-450``) pulled from a
    finding's entry point, title, or data flow — the stable cross-stage handle
    when the ids don't align. The spine's weak title IS the route, and the
    README's entry point carries it too."""
    for src in (f.entry_point, f.title, f.data_flow):
        m = _ROUTE_RE.search((src or "").replace("`", ""))
        if m and len(m.group(0)) > 4:
            return m.group(0).rstrip("/").lower()
    return ""


def _enrich_spine_from_report(spine: List[Finding], results_dir: Path) -> None:
    """Overlay Phase 3/4 detail (better titles, locations, PoC, fix) onto the
    confirmed spine.

    Matches by global id first — the handoff assigns ids that Phase 3/4 follow,
    so VULN-005 is the same finding across stages — falling back to CWE +
    location when the ids don't align. A weak spine title (an entry-point URL
    from failed source enrichment) is replaced by the report's descriptive one.
    """
    detail_findings: List[Finding] = []
    for name in ("README.md", "phase3_output.md"):
        p = results_dir / name
        if not p.exists():
            continue
        head = p.read_text(encoding="utf-8", errors="replace")[:200]
        if "Consolidated Scan Report" in head:
            continue
        got = _from_summary_table(p)
        if got:
            if name == "README.md":
                _enrich_from_details(p, got)
            detail_findings.extend(got)
    if not detail_findings:
        return
    by_key: Dict[Tuple[str, str], Finding] = {}
    by_id: Dict[str, Finding] = {}
    by_route: Dict[Tuple[str, str], Finding] = {}
    for d in detail_findings:
        by_key.setdefault((d.cwe.upper(), _norm_loc(d.location)), d)
        by_id.setdefault(d.id.upper(), d)
        rk = _route_key(d)
        if rk:
            by_route.setdefault((d.cwe.upper(), rk), d)
    used: set = set()   # a report finding enriches at most one spine finding
    for f in spine:
        # Prefer an id match, but only when the CWEs are compatible (guards
        # against a mis-numbered report clobbering the wrong finding); then fall
        # back to CWE+location, then CWE+route (survives id misalignment across
        # stages — the spine's weak title is itself the route). Each report
        # finding is consumed once, so two spine findings can't both map to it
        # and become identical.
        candidates = [
            by_id.get(f.id.upper()),
            by_key.get((f.cwe.upper(), _norm_loc(f.location))),
            by_route.get((f.cwe.upper(), _route_key(f))) if _route_key(f) else None,
        ]
        d = None
        for c in candidates:
            if c is None or id(c) in used:
                continue
            if c is by_id.get(f.id.upper()) and c.cwe and f.cwe \
                    and c.cwe.upper() != f.cwe.upper():
                continue
            d = c
            break
        if not d:
            continue
        used.add(id(d))
        if d.title and _is_weak_title(f.title, f.id) and not _is_weak_title(d.title, d.id):
            f.title = d.title
        if not f.location and d.location:
            f.location = d.location
        for attr in ("entry_point", "data_flow", "fix", "poc", "exploit_test", "hypothesis_reason"):
            if not getattr(f, attr) and getattr(d, attr):
                setattr(f, attr, getattr(d, attr))


# Rows the model emits to pad a table to some expected count — never real
# findings. Phase 3 in particular fills its assignment table with
# "Placeholder for additional finding | Unrated". These must never reach the
# report; they inflate the count and read as unrated real findings.
_PLACEHOLDER_TITLE = re.compile(
    r"placeholder|additional finding|to be (added|determined|filled)|"
    r"\bt\.?b\.?d\b|\btodo\b|^n/?a$|^finding\s*\d+$|^vuln-?\d+$",
    re.IGNORECASE)


# Input-inventory rows the model emits in its recon/verify tables — a bare
# parameter, path variable, or DTO field, NOT a vulnerability. They carry no
# weakness class and no security claim; a location (where the input is read) is
# not a finding. The harness must keep inventories separate from candidates: an
# inventory row must never implicitly become a vulnerability. Examples seen in
# real runs: "payload.name (RegionCreate)", "Path parameter region_id (PUT)",
# "Query param q", "region_id path".
_INVENTORY_TITLE = re.compile(
    r"^(?:"
    r"payload\.[\w.]+"                                  # payload.name, payload.code
    r"|(?:path|query|body|header|cookie|form)\s+param(?:eter)?\b.*"
    r"|[\w.]+\s+(?:path|query|body|header)\s+param.*"
    r"|(?:path|query|body)\s+parameter\s+[\w.]+.*"
    r"|[\w.]+\s*\((?:Region|User|Customer|Order|[A-Z]\w*(?:Create|Update|Request|DTO|Body|Payload))[^)]*\)"
    r")\s*$",
    re.IGNORECASE)


def _is_inventory_row(f: "Finding") -> bool:
    """A leaked input-inventory row, not a candidate: no weakness class and a
    title that is just a parameter / path / DTO-field reference (an HTTP verb in
    parentheses is the tell). Dropped so it never inflates the finding list."""
    if f.cwe or f.normalized_cwe:
        return False
    title = _clean(f.title or "").strip()
    return bool(title) and bool(_INVENTORY_TITLE.match(title))


def _is_placeholder(f: "Finding") -> bool:
    """True for a padding/empty row that is not a real finding.

    Either the title is a known placeholder phrase, the finding is entirely
    contentless (no CWE, no location, and a title that is empty or just echoes
    its own id), or it is a leaked input-inventory row (a bare parameter/DTO
    reference with no weakness class) — none of which an analyst could act on."""
    title = _clean(f.title or "").strip()
    if title and _PLACEHOLDER_TITLE.search(title):
        return True
    if not f.cwe and not f.location and (not title or title.upper() == f.id.upper()):
        return True
    if _is_inventory_row(f):
        return True
    return False


def _drop_placeholders(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if not _is_placeholder(f)]


# --- hunt-evidence findings (deterministic, format-robust) ------------------
# The per-partition hunt outputs (results/sg-*.md) are the richest, most
# reliable finding source in a run: each carries descriptive titles, a
# ``**Class**: CWE-…`` line, a ``**Severity**`` line, and a Summary table. A
# fast local Phase 3/4 — or a truncated one that hit ``max_turns`` — can badly
# under-report them, so when the downstream phases are thin we parse the hunt
# evidence directly. Two robustness demands the GLM/gpt-oss outputs impose:
#   * heading styles vary: "### [VULN-001] t", "## 3. VULN-001 — t", "#### VULN-1: t"
#   * Summary-table column ORDER varies ("| ID | Title | CWE | Severity |" vs
#     "| ID | Finding | Severity | CWE |"), so the table parse is HEADER-AWARE —
#     a position-based parse silently swaps CWE and Severity on half the files.

# The class agents number findings with their own prefixes — VULN-001, but also
# NAV-01 / LOG-03 / INJ-02 / CRED-01 — and one file can carry both a write-up
# heading and a cross-reference index row for the same id. Recognizing every
# prefix lets the index row MERGE into the real write-up (whose title wins)
# instead of leaking through as a titleless fragment.
_HUNT_ID_PREFIX = r"(?:VULN|NAV|LOG|INJ|CRED|AUTHZ|FINDING)"
_HUNT_HDR = re.compile(
    r"^#{2,5}\s*(?:\d+(?:\.\d+)*\.?\s+)?\[?(?P<id>" + _HUNT_ID_PREFIX + r"[-\s]?\d+)\]?"
    r"\s*[–\-:.]*\s*(?P<title>.*)$",
    re.IGNORECASE | re.MULTILINE)
# Trailing "— CRITICAL" / "- HIGH" on a heading title carries the severity when
# there is no dedicated **Severity** line (the NAV/LOG heading style).
_TRAIL_SEV = re.compile(
    r"\s*[—\-–:]\s*(critical|high\+?|medium|moderate|low|informational|info)\s*$",
    re.IGNORECASE)
# "**Class**:" and "**Class:**" (colon inside or outside the bold); same for Severity.
_HUNT_CLASS = re.compile(r"\*\*\s*Class\s*:?\s*\*\*\s*:?\s*(?P<v>.+)", re.IGNORECASE)
_HUNT_SEV = re.compile(r"\*\*\s*(?:Severity|Risk)\s*:?\s*\*\*\s*:?\s*(?P<v>.+)",
                       re.IGNORECASE)
_HUNT_LOC = re.compile(r"\*\*\s*Location[^*]*\*\*\s*:?\s*(?P<v>.+)", re.IGNORECASE)
_FILE_LINE = re.compile(r"([\w./\-]+\.\w+)\s*:\s*(\d+(?:\s*[-–]\s*\d+)?)")

# Header cell → finding column. ``id`` matches exactly (so "Finding ID" is the id,
# not the title); the rest match as substrings. Order matters: the permissive
# ``title`` is resolved LAST so CWE/Severity/Location claim their own cells first
# and "Finding"/"Description" falls through to title.
_HUNT_COL_RX = {
    "id": re.compile(r"^(id|#|vuln(\s*id)?|finding\s*id)$", re.IGNORECASE),
    "cwe": re.compile(r"cwe|class|category", re.IGNORECASE),
    "severity": re.compile(r"sever|risk|impact", re.IGNORECASE),
    "location": re.compile(r"location|file|sink|site|path|line", re.IGNORECASE),
    "title": re.compile(r"title|finding|description|summary|issue|vulnerab|name",
                        re.IGNORECASE),
}
_HUNT_COL_ORDER = ("id", "cwe", "severity", "location", "title")


# Some agents prefix the title cell with its own severity/CWE ("High - CWE-639 -
# Object-level IDOR …"). Strip that leading metadata so the title is just the
# title (the severity/CWE are parsed into their own fields). Spaced separators
# only, so a real title like "Low-level cache poisoning" is never truncated.
_LEAD_META = re.compile(
    r"^\s*(?:(?:critical|high\+?|medium|moderate|low|informational|info)\s+[-–—:]\s+)?"
    r"(?:CWE[-\s]?\d+(?:\s*/\s*\d+)?\s*[-–—:]\s+)?",
    re.IGNORECASE)


def _strip_lead_meta(title: str) -> str:
    return _LEAD_META.sub("", title or "").strip()


def _norm_hunt_fid(s: str) -> str:
    """Normalise any class-agent finding id (VULN-001, NAV-01, LOG-3, INJ-02) so a
    write-up heading and its cross-reference index row key together."""
    m = re.search(_HUNT_ID_PREFIX + r"\D*(\d+)", (s or "").upper())
    if not m:
        return (s or "").upper().strip()
    prefix = re.match(_HUNT_ID_PREFIX, m.group(0), re.IGNORECASE).group(0).upper()
    return "{0}{1}".format(prefix, int(m.group(1)))


def _first_cwe(text: str) -> str:
    m = _CWE.search(text or "")
    return "CWE-{0}".format(m.group(1)) if m else ""


def _first_file_line(text: str) -> str:
    m = _FILE_LINE.search((text or "").replace("`", ""))
    if not m:
        return ""
    return "{0}:{1}".format(m.group(1), re.sub(r"\s", "", m.group(2)))


def _sev_word(text: str) -> str:
    m = _SEV_IN_TEXT.search(text or "")
    return m.group(1) if m else ""


def _iter_md_tables(text: str):
    """Yield (header_cells, [data_row_cells, ...]) for each pipe table."""
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if line.lstrip().startswith("|") and i + 1 < n \
                and _is_divider(_cells(lines[i + 1])):
            header = _cells(line)
            rows = []
            j = i + 2
            while j < n and lines[j].lstrip().startswith("|"):
                c = _cells(lines[j])
                if not _is_divider(c):
                    rows.append(c)
                j += 1
            yield header, rows
            i = j
        else:
            i += 1


def _map_hunt_columns(header: List[str]) -> Dict[str, int]:
    """Map role → column index by HEADER NAME (order-independent). Each header
    cell is claimed by at most one role; ``title`` resolves last."""
    idx: Dict[str, int] = {}
    used: set = set()
    for role in _HUNT_COL_ORDER:
        rx = _HUNT_COL_RX[role]
        for k, h in enumerate(header):
            if k in used:
                continue
            hh = _clean(h)
            if rx.search(hh) if role != "id" else rx.match(hh):
                idx[role] = k
                used.add(k)
                break
    return idx


def _parse_hunt_table(text: str) -> Dict[str, Dict[str, str]]:
    """Header-aware Summary-table parse → {norm_id: {title, cwe, severity, location}}.
    Only tables that actually describe findings (a title column plus a CWE,
    severity, or id column) are consumed — verdict/route tables are ignored."""
    out: Dict[str, Dict[str, str]] = {}
    for header, rows in _iter_md_tables(text):
        idx = _map_hunt_columns(header)
        if "title" not in idx or not ({"cwe", "severity", "id"} & set(idx)):
            continue

        def cell(role, row):
            k = idx.get(role)
            return row[k] if k is not None and k < len(row) else ""

        for r in rows:
            fid = _norm_hunt_fid(cell("id", r)) if "id" in idx else ""
            if not fid:
                continue
            title = _clean(cell("title", r))
            rec = out.setdefault(fid, {})
            if title and not rec.get("title"):
                rec["title"] = title
            if not rec.get("cwe"):
                rec["cwe"] = _first_cwe(cell("cwe", r)) or _first_cwe(title)
            if not rec.get("severity"):
                rec["severity"] = _sev_word(cell("severity", r))
            if not rec.get("location"):
                rec["location"] = _first_file_line(cell("location", r))
    return out


def _parse_hunt_blocks(text: str) -> List[Dict[str, str]]:
    """Per-finding write-up blocks → a LIST of complete, self-consistent
    observations ``{id, title, cwe, severity, location, hypothesis_reason,
    data_flow, entry_point}``, each field taken from the SAME block.

    Identity integrity: records are never assembled field-by-field across blocks
    that happen to reuse a local id. A partition's file is frequently rewritten by
    the model with shuffled/reused ``VULN-NNN`` ids (the same file can carry three
    numbering passes over the same candidates), and the old merge-by-id — which
    took title/cwe/location from the *first* occurrence but overwrote data_flow
    from the *last* — welded one candidate's title to another candidate's data
    flow and location. Each block is now emitted whole; de-duplication of blocks
    that genuinely describe the same candidate happens in ``_parse_hunt_file``."""
    obs: List[Dict[str, str]] = []
    heads = list(_HUNT_HDR.finditer(text))
    for i, h in enumerate(heads):
        fid = _norm_hunt_fid(h.group("id"))
        if not fid:
            continue
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        block = text[h.start():end]
        title = (h.group("title") or "").strip().strip("–-:. ")
        # A trailing "— CRITICAL" on the heading is the severity, not the title.
        trail = _TRAIL_SEV.search(title)
        head_sev = trail.group(1) if trail else ""
        if trail:
            title = title[:trail.start()].strip()
        title = re.sub(r"\s*\(?CWE-\d+\)?\s*$", "", title).strip()
        cm = _HUNT_CLASS.search(block)
        cwe = _first_cwe(cm.group("v")) if cm else ""
        if not cwe:
            cwe = _first_cwe(title)
        sm = _HUNT_SEV.search(block)
        sev = _sev_word(sm.group("v")) if sm else head_sev
        lm = _HUNT_LOC.search(block)
        loc = _first_file_line(lm.group("v")) if lm else ""
        rec = {"id": fid, "title": title, "cwe": cwe, "severity": sev, "location": loc}
        for label, key in (("Root Cause", "hypothesis_reason"),
                           ("Data Flow", "data_flow"), ("Entry Point", "entry_point")):
            match = re.search(r"(?im)^[-*]?\s*\*\*" + label + r"\*\*\s*:\s*(.+)$", block)
            if match:
                rec[key] = match[1].strip()
        obs.append(rec)
    return obs


def _parse_hunt_file(path: Path) -> List[Finding]:
    try:
        text = normalize_text(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []
    blocks = _parse_hunt_blocks(text)
    table = _parse_hunt_table(text)

    # Collapse only blocks that genuinely describe the SAME candidate — same id
    # AND same (cwe, location). A reused id pointing at a DIFFERENT candidate (a
    # different cwe or location) is kept as its own observation, never merged, so
    # one candidate's title can't inherit another's evidence. When the same
    # observation recurs we fill only fields the first copy left empty.
    kept: List[Dict[str, str]] = []
    index: Dict[tuple, Dict[str, str]] = {}
    for b in blocks:
        key = (b["id"], (b.get("cwe") or "").upper(), b.get("location") or "")
        cur = index.get(key)
        if cur is None:
            index[key] = b
            kept.append(b)
        else:
            for k, v in b.items():
                if v and not cur.get(k):
                    cur[k] = v
    block_ids = {b["id"] for b in kept}

    findings: List[Finding] = []
    for b in kept:
        # The Summary table only FILLS fields the write-up block lacks (typically
        # severity); it never overrides the block's own, self-consistent evidence.
        t = table.get(b["id"], {})
        sev = b.get("severity") or t.get("severity") or ""
        rank, label = _sev_key(sev)
        findings.append(Finding(
            id=b["id"],
            title=_strip_lead_meta(b.get("title") or t.get("title") or ""),
            severity=label, severity_rank=rank,
            cwe=b.get("cwe") or t.get("cwe") or "",
            location=b.get("location") or t.get("location") or "",
            source=path.name,
            hypothesis_reason=b.get("hypothesis_reason", ""),
            entry_point=b.get("entry_point", ""),
            data_flow=b.get("data_flow", ""),
        ))
    # Table-only ids (a Summary row with no write-up block) are kept as their own
    # findings — with no block evidence to (mis)attribute to them.
    for fid, t in table.items():
        if fid in block_ids:
            continue
        sev = t.get("severity") or ""
        rank, label = _sev_key(sev)
        findings.append(Finding(
            id=fid, title=_strip_lead_meta(t.get("title") or ""),
            severity=label, severity_rank=rank,
            cwe=t.get("cwe") or "", location=t.get("location") or "",
            source=path.name,
        ))
    return findings


_HUNT_REF_TITLE = re.compile(
    r"see\s*§|cross-?class.*(see|owned)|owned by\b|^\s*" + _HUNT_ID_PREFIX
    + r"[-_ ]?\d+\s*$", re.IGNORECASE)


def _is_hunt_noise(f: "Finding") -> bool:
    """A hunt row that is a cross-reference pointer or a bare id-code, not a
    finding of its own — no CWE, no location, and a title that only points
    elsewhere. (A pointer WITH a location/CWE is kept; dedup handles the rest.)"""
    if f.cwe or f.location:
        return False
    return bool(_HUNT_REF_TITLE.search(_clean(f.title).strip()))


def _hunt_evidence_findings(results_dir: Path) -> List[Finding]:
    """Every finding across the per-partition hunt outputs (results/sg-*.md),
    with fresh, unique display ids. Cross-partition duplicates are left for the
    downstream root-cause dedup (flag_duplicates) to collapse."""
    rdir = Path(results_dir) / "results"
    if not rdir.is_dir():
        return []
    found: List[Finding] = []
    for f in sorted(rdir.glob("sg-*.md")):
        found.extend(_parse_hunt_file(f))
    found = [f for f in _drop_placeholders(found) if not _is_hunt_noise(f)]
    for i, fn in enumerate(found, 1):
        fn.source_id = fn.id
        fn.id = "VULN-{0:03d}".format(i)
    return found


def _wellformed_count(findings: List[Finding]) -> int:
    """Findings an analyst could act on — a real CWE and a non-weak title. The
    signal for choosing between finding sources: a source with more well-formed
    findings is the better report, regardless of raw row count."""
    return sum(1 for f in findings
               if f.cwe and not _is_weak_title(f.title, f.id))


def parse_findings(results_dir: Path) -> List[Finding]:
    """Extract findings. Phase 2b's CONFIRMED set is authoritative for the LIST.

    Phase 4 does not always overwrite the boilerplate ``README.md`` (it is
    model-authored and sometimes a stub), and Phase 3/4 have limited throughput —
    a run confirming 20 findings routinely writes up only a handful. So the
    finding LIST comes from the confirmed set (handoff / Phase 2b), enriched with
    title/PoC/fix from Phase 3/4 where available. Falls back to the old README →
    phase3 → phase2b table parse for runs without a confirmed set.

    Placeholder/padding rows the model emits (e.g. Phase 3's "Placeholder for
    additional finding") are stripped from every source so they cannot inflate
    the report.
    """
    results_dir = Path(results_dir)

    from .verification import load_findings
    canonical = load_findings(results_dir)
    if canonical is not None:
        return canonical

    # Phase-4 report path (what a good Phase 4 produces: distinct, well-titled
    # findings with locations and detail).
    report_findings = _drop_placeholders(_parse_report_tables(results_dir))

    # Confirmed spine (from Phase 2b), enriched from source files / the report.
    spine = _confirmed_spine(results_dir)
    if spine:
        _enrich_spine_from_report(spine, results_dir)
        spine = _drop_placeholders(spine)

    # The spine is the RECOVERY mechanism for when Phase 3/4 dropped findings
    # (a run confirming 20 that writes up only 7). It should only override a
    # complete Phase-4 report when it recovers *substantially* more — otherwise
    # the report is better-formed (descriptive titles, distinct findings that the
    # spine's weaker identity can over-cluster). The margin keeps a well-titled
    # 14-finding report from being replaced by a 15-finding spine full of URLs.
    RECOVERY_MARGIN = 2
    if spine and len(spine) > len(report_findings) + RECOVERY_MARGIN:
        chosen = spine
    elif report_findings:
        chosen = report_findings
    else:
        chosen = spine or []

    # Hunt evidence (results/sg-*.md) is the richest, most reliable source. When
    # the downstream phases under-reported it — a fast local consolidation, a
    # truncated Phase 4 (max_turns), or a partial/cancelled run — the chosen set
    # is thin or full of table fragments. Parse the hunt evidence directly and
    # prefer it when it yields substantially more *well-formed* findings (real
    # CWE + descriptive title). Comparing well-formed counts (not raw rows) keeps
    # a good, complete Phase-4 report from being displaced by hunt duplicates,
    # while rescuing a report the model mangled. Cross-partition duplicates in
    # the hunt set collapse later in flag_duplicates.
    hunt = _hunt_evidence_findings(results_dir)
    if hunt and (not chosen or _wellformed_count(hunt) > _wellformed_count(chosen) + RECOVERY_MARGIN):
        return _mark_confirmed(hunt, spine)
    return _mark_confirmed(chosen, spine)


def _confirmed_key(location: str) -> str:
    """basename:line identity for matching a finding to the Phase-2b confirmed
    set across path-prefix differences (the spine often cites a shorter path)."""
    m = re.search(r"([\w./+\-]+\.\w+):(\d+)", location or "")
    return (Path(m.group(1)).name + ":" + m.group(2)) if m else ""


def _mark_confirmed(findings: List[Finding], spine: List[Finding]) -> List[Finding]:
    """Flag findings that came through Phase-2b verification. When the spine *is*
    the chosen set every finding is confirmed; otherwise match by cited location.
    This drives the quality battery's ``agreement`` corroboration signal — a
    finding that survived verification is independently corroborated."""
    if not spine:
        return findings
    if findings is spine:
        for f in findings:
            f.from_confirmed = True
        return findings
    keys = {k for k in (_confirmed_key(s.location) for s in spine) if k}
    if not keys:
        return findings
    for f in findings:
        if _confirmed_key(f.location) in keys:
            f.from_confirmed = True
    return findings


def authz_findings(meta: Dict[str, Any]) -> List[Finding]:
    """Harness-DERIVED findings from the authorization map: each cross-endpoint
    inconsistency (a resource guarded on one route, open on a sibling) is a
    broken-access-control bypass candidate the partitioned hunt cannot see. These
    are deterministic structural facts, not model claims, so they carry a
    ``source='authz-map'`` marker and assess_candidates substantiates them directly
    from the map rather than the model-claim quality battery."""
    repo = meta.get("repo")
    if not repo or not Path(repo).is_dir():
        return []
    try:
        from . import authz
        amap = authz.build_authz_map(repo)
    except Exception:  # pragma: no cover - defensive; never fail the report
        return []
    out: List[Finding] = []
    for inc in amap.get("inconsistencies") or []:
        guarded = inc["guarded"][0]
        gname = ", ".join(guarded.get("guards") or [])[:40] or "a guard"
        for u in inc["unguarded"]:
            rank, label = _sev_key("High")
            out.append(Finding(
                id="AUTHZ-{0:03d}".format(len(out) + 1),
                title="Cross-endpoint authorization gap: {0} {1} enforces no "
                      "guard while a sibling route enforces {2}".format(
                          inc["method"], u["path"], gname),
                cwe="CWE-862", severity=label, severity_rank=rank,
                location="{0}:{1}".format(u["file"], u["line"]),
                entry_point="{0} {1}".format(inc["method"], u["path"]),
                data_flow="{0} {1} reaches the same resource (`{2}`) as the guarded "
                          "route `{3}` but enforces no authorization guard".format(
                              inc["method"], u["path"], inc["resource_key"], guarded["path"]),
                source="authz-map",
            ))
    return out


def _parse_report_tables(results_dir: Path) -> List[Finding]:
    """Findings from the Phase-4 README (or phase3/2b fallback) summary tables."""
    readme = results_dir / "README.md"
    if readme.exists():
        # Skip a README that is our own consolidated backfill (see
        # write_consolidated) — parse the phase sources it was built from, not
        # the derived report, to avoid a confusing round-trip.
        head = readme.read_text(encoding="utf-8", errors="replace")[:200]
        if "Consolidated Scan Report" not in head:
            found = _from_summary_table(readme)
            if found:
                _enrich_from_details(readme, found)
                return found

    for fallback in ("phase3_output.md", "phase2b_output.md"):
        p = results_dir / fallback
        if p.exists():
            found = _from_summary_table(p)
            if found:
                return found
    return []


def _from_summary_table(path: Path) -> List[Finding]:
    text = normalize_text(path.read_text(encoding="utf-8", errors="replace"))
    out: Dict[str, Finding] = {}

    for m in _ROW.finditer(text):
        cells = _cells(m.group(0))
        if _is_divider(cells) or len(cells) < 2:
            continue
        idm = _VULN_ID.search(cells[0])
        if not idm:
            continue
        vid = idm.group(1).upper()
        if vid in out:
            continue

        joined = " | ".join(cells)
        sev_raw = ""
        for c in cells[1:]:
            sm = _SEV_IN_TEXT.fullmatch(c.strip()) or _SEV_IN_TEXT.fullmatch(
                c.strip().rstrip("."))
            if sm:
                sev_raw = sm.group(1)
                break
        if not sev_raw:
            sm = _SEV_IN_TEXT.search(joined)
            sev_raw = sm.group(1) if sm else ""
        rank, label = _sev_key(sev_raw)

        cwem = _CWE.search(joined)
        title = _pick_title(cells)

        out[vid] = Finding(
            id=vid, title=title, severity=label, severity_rank=rank,
            cwe="CWE-{0}".format(cwem.group(1)) if cwem else "",
            status=cells[-1] if len(cells) > 3 else "",
            source=path.name,
        )
    return list(out.values())


def _enrich_from_details(readme: Path, findings: List[Finding]) -> None:
    """Pull Location / Entry Point / Data Flow / PoC out of the detail sections."""
    text = normalize_text(readme.read_text(encoding="utf-8", errors="replace"))
    by_id = {f.id: f for f in findings}

    heads = list(_DETAIL_HDR.finditer(text))
    for i, h in enumerate(heads):
        vid = h.group(1).upper()
        f = by_id.get(vid)
        if not f:
            continue
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        block = text[h.end():end]

        if not f.title:
            f.title = (h.group("title") or "").strip()

        for fm in _FIELD.finditer(block):
            key = fm.group("k").strip().lower()
            val = fm.group("v").strip()
            if not val:
                continue
            if key == "location" and not f.location:
                f.location = val
            elif key == "root cause" and not f.hypothesis_reason:
                f.hypothesis_reason = val
            elif key.startswith("entry") and not f.entry_point:
                f.entry_point = val
            elif key.startswith("data flow") and not f.data_flow:
                f.data_flow = val
            elif key == "poc" and not f.poc:
                f.poc = val
            elif key.startswith("exploit test") and not f.exploit_test:
                f.exploit_test = val
            elif key == "fix" and not f.fix:
                f.fix = val
            elif key == "severity" and f.severity_rank == UNKNOWN_RANK:
                f.severity_rank, f.severity = _sev_key(val)
            elif key == "cwe" and not f.cwe:
                cm = _CWE.search(val)
                if cm:
                    f.cwe = "CWE-{0}".format(cm.group(1))


def _norm_loc(text: str) -> str:
    """File:line signature used for duplicate detection."""
    m = re.search(r"([\w./-]+\.\w+)\s*:?\s*(\d+)?", text or "")
    return "{0}:{1}".format(m.group(1), m.group(2) or "") if m else ""


def _loc_file(text: str) -> str:
    """Just the file path from a location string — no line number.

    Two reports of the same defect often disagree on the exact line (the model
    points at the decorator vs. the call vs. the sink). Keying duplicate
    detection on file+function rather than file:line stops that drift from
    splitting one root cause into two headline findings.
    """
    m = re.search(r"([\w./-]+\.\w+)", text or "")
    return m.group(1) if m else ""


def _norm_file(text: str) -> str:
    """The file IDENTITY for dedup/ledger keys: the basename, so inconsistent path
    spellings of ONE file (``dispatch_operations.py`` vs
    ``backend/app/dispatch_operations.py``) collapse to a single root cause instead
    of publishing as separate findings. (The full path is kept for display and
    location resolution; only the grouping key is normalized.)"""
    f = _loc_file(text)
    return f.rsplit("/", 1)[-1] if f else ""


_FUNC = re.compile(r"([A-Za-z_]\w*)\s*\(")


def _func_hint(f: "Finding") -> str:
    """Best-effort sink function name, so same-file/different-function defects
    stay distinct while line drift within one function collapses."""
    for src in (f.location, f.data_flow):
        calls = _FUNC.findall(src or "")
        if calls:
            return calls[-1].lower()   # the sink is the last call in the chain
    return ""


# Actual ATTACKER-INPUT parameter names — the discriminating part of a flow. This
# reads the real source operation (a request accessor, a query-string key, or an
# explicit "param X"), NOT arbitrary ``word =`` assignments: keying on assignment
# targets made two reports of one defect look distinct because the model happened
# to name intermediate variables differently ("target" vs "in"), which split root
# causes and inflated the finding count (audit-2 #5).
_PARAM = re.compile(
    r"""(?:query_params|args|form|params|payload|body|json|cookies|headers|request|data)"""
    r"""\s*(?:\.\s*get\s*\(|\[)\s*['"]([A-Za-z_]\w*)['"]"""   # accessor("x") / accessor["x"]
    r"""|[?&]([A-Za-z_]\w*)="""                               # ?x= / &x=
    r"""|\b(?:query[-\s]?)?param(?:eter)?s?\s+[`"']?([A-Za-z_]\w+)""",  # "param x"
    re.I)


def _flow_signature(f: "Finding") -> str:
    """Distinguishing fingerprint for a finding's *path*, not just its sink.

    Two different inputs reaching one sink are distinct vulnerabilities, not
    duplicates — the ``q`` and ``status`` parameters of the same search endpoint
    both reach the same ``execute()`` and each needs its own fix. Keying only on
    (CWE, sink) collapsed them, which is exactly the "collapsing findings"
    failure the methodology warns about.
    """
    return ",".join(sorted(_flow_params(f)))


def _flow_params(f: "Finding") -> set:
    """The set of input/parameter names in a finding's path (the discriminating
    part of _flow_signature). Two findings whose param sets are non-empty and
    disjoint are distinct inputs to one sink (q vs status); overlapping/empty sets
    are the same defect."""
    blob = " ".join([_clean(f.entry_point), _clean(f.data_flow), _clean(f.title)])
    names = set()
    for m in _PARAM.finditer(blob):
        names.add((m.group(1) or m.group(2) or m.group(3) or "").lower())
    names.discard("")
    names -= {"path", "url", "get", "post", "http", "https", "args", "request",
              "filter", "data", "body", "json", "payload"}
    return names


# Vulnerability family keywords, used when a CWE is absent or when two reports
# of one defect chose different-but-related CWEs (e.g. CWE-943 vs CWE-89 for the
# same NoSQL injection). Keeps clustering from depending on taxonomy precision.
_FAMILY_WORDS = [
    ("xxe", "xxe"), ("xml external", "xxe"),
    ("ssti", "ssti"), ("server-side template", "ssti"), ("template injection", "ssti"),
    ("sql", "sqli"), ("nosql", "nosqli"),
    ("pickle", "deser"), ("deserial", "deser"),
    ("open redirect", "redirect"),
    ("path traversal", "traversal"), ("directory traversal", "traversal"),
    ("command inj", "cmdi"), ("os command", "cmdi"),
    ("eval", "eval"),
    ("ssrf", "ssrf"), ("xss", "xss"),
]


def _family(f: "Finding") -> str:
    """A coarse vulnerability family for clustering.

    Prefer the CWE, NORMALIZED to its weakness family, so sibling labels for one
    defect cluster (CWE-94 vs CWE-95 eval; CWE-330 vs CWE-338 randomness) instead
    of splitting on the exact number the model happened to pick. Fall back to a
    keyword from the title when there is no CWE. Deliberately coarse — precision
    comes from the location and (real-input) flow signature, not the family.
    """
    if f.cwe or getattr(f, "normalized_cwe", ""):
        from .knowledge import family_of, normalized_cwe
        cwe = f.cwe or f.normalized_cwe
        fam = family_of(cwe)
        return fam.key if fam is not None else (normalized_cwe(cwe) or cwe).upper()
    blob = (f.title or "").lower()
    for needle, fam in _FAMILY_WORDS:
        if needle in blob:
            return fam
    return ""


_TITLE_STOP = {"via", "in", "the", "an", "of", "on", "and", "or", "to", "with",
               "additional", "instance", "endpoint", "vulnerability", "unvalidated",
               "unrestricted", "insecure", "improper", "missing", "for", "from",
               "using", "due", "by", "critical", "arbitrary"}
_IDENT_RE = re.compile(r"`([A-Za-z_][\w./{}-]{2,})`")   # backtick func/route
_ROUTE_RE = re.compile(r"(/[A-Za-z0-9_./{}-]{3,})")


def _title_signature(f: "Finding") -> str:
    """A stable dedup token when the model omitted file:line. Prefers a
    backtick-quoted function/route identifier (stable across samples), then a
    route path, then a normalized bag of significant title words. Used only in the
    location-less fallback so multi-sample duplicates still collapse."""
    for src in (f.title, f.entry_point, f.data_flow):
        m = _IDENT_RE.search(src or "")
        if m:
            return m.group(1).lower()
    for src in (f.entry_point, f.title):
        m = _ROUTE_RE.search(src or "")
        if m:
            return m.group(1).lower()
    words = re.findall(r"[a-z0-9]+", (f.title or "").lower())
    sig = [w for w in words if w not in _TITLE_STOP and len(w) > 2]
    return " ".join(sorted(set(sig))[:6]) if sig else ""


def _root_cause_key(f: "Finding") -> str:
    """Stable fingerprint clustering reports of one underlying defect.

    ``family : file : sink-function : flow-signature`` — line-number-free so a
    line disagreement does not split a root cause, but flow-signature-bearing so
    two distinct inputs reaching one sink stay separate (the ``q`` vs ``status``
    case)."""
    fam = _family(f)
    fil = _norm_file(f.location) or _norm_file(f.data_flow)
    if fam and fil:
        return "{0}:{1}:{2}:{3}".format(fam, fil, _func_hint(f), _flow_signature(f))
    # Degraded fallback: the model reported findings by function name with no
    # file:line (seen on some runs). Without a location the precise key is empty
    # and dedup is DISABLED — which, combined with multi-sample hunting, repeats
    # every finding N×. Fall back to family + a stable title/route identifier so
    # those samples still collapse. Only fires when the location is missing, so
    # precise dedup is unchanged when the model does cite file:line.
    sig = _title_signature(f)
    if fam and sig:
        return "{0}::{1}".format(fam, sig)
    return ""


_LINE_PROXIMITY = 20  # lines; two same-key findings farther apart are distinct


def _loc_start_line(f: "Finding") -> Optional[int]:
    for src in (f.location, f.data_flow):
        m = re.search(r"\.\w+[\s:]+(\d+)", src or "")
        if m:
            return int(m.group(1))
    return None


def _line_proximate(a: "Finding", b: "Finding") -> bool:
    """Whether two same-key findings are close enough to be the same defect.

    Both have line info → within the proximity window. If either lacks a line we
    cannot tell them apart, so we cluster (the historical behaviour) rather than
    risk showing the same defect twice."""
    la, lb = _loc_start_line(a), _loc_start_line(b)
    if la is None or lb is None:
        return True
    return abs(la - lb) <= _LINE_PROXIMITY


_BF_FILELINE = re.compile(r"([\w./+\-]+\.[A-Za-z0-9]{1,6}):(\d+)")
_BF_CWE = re.compile(r"CWE[-\s]?(\d{1,4})", re.IGNORECASE)
# The hunt/2b artifacts reference their own scratch files (sg-1_inj.md:214,
# phase2b_output.md, README.md); those are NOT source locations. Only real source
# code counts as a finding location.
_BF_DOC_EXT = {"md", "markdown", "txt", "json", "jsonl", "sarif", "html", "htm",
               "log", "csv", "out"}


def _bf_is_source(fpath: str) -> bool:
    ext = fpath.rsplit(".", 1)[-1].lower() if "." in fpath else ""
    return ext != "" and ext not in _BF_DOC_EXT
_BF_BT = re.compile(r"`([A-Za-z_][\w./{}()\-]{1,})`")
_BF_ROUTE = re.compile(r"(/[A-Za-z0-9_./{}\-]{3,})")
_BF_SNAKE = re.compile(r"\b([a-z][a-z0-9]*_[a-z0-9_]{2,})\b")
_BF_WORD = re.compile(r"[a-z0-9]{4,}")
_BF_STOP = {"insecure", "unrestricted", "unsafe", "improper", "missing", "via",
            "with", "from", "endpoint", "injection", "arbitrary", "vulnerability",
            "additional", "instance", "duplicate", "validation", "critical",
            "attacker", "controlled", "server", "side", "request", "generation"}


def _bf_index(results_dir) -> List[tuple]:
    """(location, lowercased-context) per candidate block cited in the raw hunt
    output and the 2b/3 artifacts. The hunt samples carry the file:line the model
    drops later, so this is the source of truth. Split by markdown headers so one
    candidate's context can't bleed into another's; the primary location is the
    LAST file:line in the block (the sink at the end of a data-flow chain)."""
    entries = []
    root = Path(results_dir)
    files = sorted((root / "results").glob("*.md")) if (root / "results").is_dir() else []
    files += [root / n for n in ("phase2b_output.md", "phase3_output.md",
                                 "phase2b_handoff.md", "phase3d_output.md")]
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for block in re.split(r"(?m)(?=^#)", text):
            b = block.strip()
            if not b:
                continue
            locs = [(fp, ln) for (fp, ln) in _BF_FILELINE.findall(b)
                    if _bf_is_source(fp)]
            if not locs:
                continue
            cm = _BF_CWE.search(b)
            cwe = "CWE-" + cm.group(1) if cm else ""
            # The sink is the file:line the block discusses most; a router-mount /
            # reachability reference (e.g. main.py:117) appears once. Pick the most
            # frequent, tie-broken by latest — NOT simply the last, which grabbed
            # the mount line and both mis-located findings and split dedup.
            counts = Counter(locs)
            best_pair, best_key = locs[0], (-1, -1)
            for i, p in enumerate(locs):
                k = (counts[p], i)
                if k > best_key:
                    best_key, best_pair = k, p
            primary = "{0}:{1}".format(best_pair[0], best_pair[1])
            entries.append((primary, cwe, b.lower()))
    return entries


def _bf_idents(f: "Finding"):
    strong, weak = set(), set()
    for src in (getattr(f, "title", ""), getattr(f, "entry_point", ""),
                getattr(f, "data_flow", "")):
        s = src or ""
        for m in _BF_BT.finditer(s):
            strong.add(m.group(1).lower().strip("()"))
        for m in _BF_ROUTE.finditer(s):
            strong.add(m.group(1).lower())
        sl = s.lower()
        for m in _BF_SNAKE.finditer(sl):
            strong.add(m.group(1))
        for w in _BF_WORD.findall(sl):
            if w not in _BF_STOP:
                weak.add(w)
    cwe = (getattr(f, "cwe", "") or getattr(f, "normalized_cwe", "") or "")
    cweset = set()
    nm = re.search(r"(\d+)", cwe)
    if nm:
        cweset.add("cwe-" + nm.group(1))
    return {i for i in strong if len(i) > 2}, weak, cweset


def _bf_relpath(loc: str, repo: str) -> str:
    """Trim an absolute path to repo-relative for a clean report location."""
    if repo:
        name = Path(repo).name
        i = loc.find("/" + name + "/")
        if i != -1:
            return loc[i + len(name) + 2:]
    return loc


# Unambiguous title-keyword -> CWE, checked in order (specific before generic).
# A conservative last resort when the evidence block carried no CWE either.
_BF_TITLE_CWE = [
    ("template injection", "CWE-94"), ("ssti", "CWE-94"),
    ("deserializ", "CWE-502"), ("pickle", "CWE-502"),
    ("code execution", "CWE-94"), ("eval", "CWE-94"), ("code injection", "CWE-94"),
    ("xml external", "CWE-611"), ("xxe", "CWE-611"),
    ("sql injection", "CWE-89"), ("nosql", "CWE-943"),
    ("command injection", "CWE-78"), ("os command", "CWE-78"),
    ("path traversal", "CWE-22"), ("arbitrary file write", "CWE-22"),
    ("arbitrary file read", "CWE-22"), ("directory traversal", "CWE-22"),
    ("open redirect", "CWE-601"),
    ("ssrf", "CWE-918"), ("server-side request", "CWE-918"),
    ("cross-site script", "CWE-79"), ("xss", "CWE-79"),
    ("idor", "CWE-639"), ("insecure direct object", "CWE-639"),
    ("privilege escalation", "CWE-269"), ("priv esc", "CWE-269"),
    ("missing authoriz", "CWE-862"), ("missing authentication", "CWE-306"),
    ("cors", "CWE-942"),
    ("race condition", "CWE-362"), ("toctou", "CWE-362"),
    ("weak crypto", "CWE-327"), ("insecure crypto", "CWE-327"),
    ("hardcoded", "CWE-798"), ("weak random", "CWE-330"),
    ("resource exhaustion", "CWE-400"), ("denial of service", "CWE-400"),
]


def _bf_title_cwe(f) -> str:
    blob = ((getattr(f, "title", "") or "") + " " +
            (getattr(f, "data_flow", "") or "")).lower()
    for needle, cwe in _BF_TITLE_CWE:
        if needle in blob:
            return cwe
    return ""


def _bf_has_loc(f) -> bool:
    return bool(_BF_FILELINE.search(getattr(f, "location", "") or ""))


def _bf_has_cwe(f) -> bool:
    return bool((getattr(f, "cwe", "") or "").strip())


def backfill_locations(findings: List["Finding"], results_dir, repo: str = "",
                       restore_location: bool = True, restore_cwe: bool = True) -> int:
    """Restore each finding's missing file:line AND CWE from the raw hunt/2b
    evidence.

    The model routinely abbreviates the Phase-4 report ("the rest follow the same
    structure"), dropping the file:line and/or CWE for most findings — which breaks
    dedup, votes, chains, and the canonical-severity labelling. Both still exist in
    the hunt samples, so match each incomplete finding to its evidence block by
    identifier (function/route/keyword + CWE) and restore whatever's missing. Only
    fills on a confident match — a distinctive identifier, or the CWE plus a
    keyword — never guesses. Returns the number of fields restored."""
    needy = [f for f in findings
             if (restore_location and not _bf_has_loc(f))
             or (restore_cwe and not _bf_has_cwe(f))]
    if not needy:
        return 0
    restored = 0
    entries = _bf_index(results_dir)
    if entries:
        for f in needy:
            strong, weak, cweset = _bf_idents(f)
            if not strong and not (cweset and weak):
                continue
            best, best_score, best_strong = None, 0, 0
            for loc, cwe, ctx in entries:
                ss = sum(1 for i in strong if i in ctx)
                sw = sum(1 for i in weak if i in ctx)
                sc = sum(1 for i in cweset if i in ctx)
                score = 3 * ss + sc * 2 + sw
                if score > best_score:
                    best_score, best, best_strong = score, (loc, cwe), ss
            confident = best and (best_strong >= 1 or (best_score >= 3 and cweset))
            if not confident:
                continue
            loc, cwe = best
            if restore_location and not _bf_has_loc(f) and loc:
                f.location = _bf_relpath(loc, repo)
                restored += 1
            if restore_cwe and not _bf_has_cwe(f) and cwe:
                f.cwe = cwe
                restored += 1
    # Last resort for any still-CWE-less finding: an unambiguous title keyword.
    if restore_cwe:
        for f in needy:
            if not _bf_has_cwe(f):
                tc = _bf_title_cwe(f)
                if tc:
                    f.cwe = tc
                    restored += 1
    return restored


def flag_duplicates(findings: List[Finding]) -> None:
    """Cluster reports of one defect under a canonical finding.

    Members sharing a root-cause key (family + file + sink function + flow
    signature) **and** located close together are clustered; the lowest-id member
    is canonical and the rest are marked ``duplicate_of`` it. The line-proximity
    check keeps two *distinct* findings in one file (e.g. an IDOR at :81 and
    another at :141) from being wrongly merged, while small line drift on the
    same defect still clusters. We *cluster, never delete* — duplicate reporting
    is a quality signal — but noncanonical members are excluded from headline
    counts and severity aggregation so totals reflect unique root causes.
    """
    groups: Dict[str, List[Finding]] = {}
    for f in sorted(findings, key=lambda x: x.id):
        key = _root_cause_key(f)
        f.root_cause_key = key
        if not key:
            f.cluster_id = f.id
            continue
        canon = None
        for c in groups.get(key, []):
            if _line_proximate(f, c):
                canon = c
                break
        if canon is not None:
            f.duplicate_of = canon.id
            f.cluster_id = canon.id
        else:
            groups.setdefault(key, []).append(f)
            f.cluster_id = f.id
    _merge_near_duplicates(findings)


def _merge_near_duplicates(findings: List[Finding]) -> None:
    """Second pass: collapse same-(family, file) findings that are line-proximate
    but whose ``func:flow`` keys differ only because the model worded the flow
    differently across multi-sample runs. Kept safe by the param-set test — two
    findings with non-empty *disjoint* parameter sets are distinct inputs to one
    sink (the ``q`` vs ``status`` case) and are never merged."""
    canon = [f for f in findings if not f.duplicate_of]
    groups: Dict[tuple, List[Finding]] = {}
    for f in canon:
        fam = _family(f)
        fil = _norm_file(f.location) or _norm_file(f.data_flow)
        if fam and fil:
            groups.setdefault((fam, fil), []).append(f)
    for grp in groups.values():
        grp.sort(key=lambda x: x.id)
        for i, a in enumerate(grp):
            if a.duplicate_of:
                continue
            pa = _flow_params(a)
            for b in grp[i + 1:]:
                if b.duplicate_of or not _line_proximate(a, b):
                    continue
                pb = _flow_params(b)
                if pa and pb and pa.isdisjoint(pb):
                    continue   # distinct inputs to one sink — keep both
                b.duplicate_of = a.id
                b.cluster_id = a.id


def rank(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (f.severity_rank, f.cwe or "zzz", f.id))


def apply_normalized_severity(findings: List[Finding]) -> None:
    """Make the deterministic family severity canonical, so counts, the meter,
    and ranking are stable run-to-run. The model's original tier is preserved as
    ``reported_severity`` and surfaced in the report when it differs. Run after
    ``knowledge.apply_knowledge`` (which sets ``normalized_severity``) and before
    ``rank``."""
    for f in findings:
        if _is_substantiated(f.classification):
            f.exploitability = "Runtime exploitability has not been established; see the finding-specific evidence and preconditions."
        else:
            f.exploitability = "Not established; this hypothesis requires further investigation."
        ns = getattr(f, "normalized_severity", "")
        if ns and ns != f.severity:
            f.reported_severity = f.severity
            f.severity_rank, f.severity = _sev_key(ns)


def _location_resolves(location: str, repo: Optional[Path]) -> bool:
    """Whether a finding's cited ``file:line`` names a file that actually exists
    in the scanned tree. A citation against a file that is not present is a red
    flag (a fabricated or stale reference), so it does not clear the gate. When no
    repo is available (an old report re-render), we cannot check — treat as OK so
    we never invent an unresolved verdict from missing context."""
    if not repo or not location:
        return True
    from .quality import _resolve_source
    return _resolve_source(location, repo) is not None


def assess_candidates(findings: List[Finding], meta: Dict[str, Any]) -> None:
    """Assign each candidate a publication tier from the strongest evidence it
    clears — ``reviewed`` (a source-grounded review record) > ``statically_supported``
    (the harness's own quality battery — see quality.py) > ``hypothesis`` (clears
    neither). Confidence never exceeds evidence, so a bigger candidate pool never
    reads as verified yield; but a well-formed, corroborated finding is still
    useful default output rather than being collapsed to a bare hypothesis."""
    from .evidence import candidate_key, review_support
    from . import quality
    raw_repo = meta.get("repo")
    repo = Path(raw_repo).resolve() if raw_repo and Path(raw_repo).is_dir() else None
    level = quality.normalize_level(meta.get("quality_strictness"))
    for f in findings:
        f.candidate_key = candidate_key(f, meta.get("git_commit", ""))
        if f.verification_status:
            # Decisions have been schema/evidence checked against this checkout
            # by verification.load_findings. Model review is static, not execution.
            f.classification = CLASS_STATICALLY_SUPPORTED if f.verification_status == "supported" else CLASS_HYPOTHESIS
            f.assessment = ASSESS_SUPPORTED if f.verification_status == "supported" else ASSESS_UNRESOLVED
            f.assessment_reason = f.verification_reason
            f.quality_checks = quality.evaluate(f, repo, level).checks_as_dicts()
            continue
        reviewed, review_reason = review_support(f, meta)
        if reviewed:
            f.classification = CLASS_REVIEWED
            f.assessment = ASSESS_SUPPORTED
            f.assessment_reason = review_reason
            # Still record the battery, so the report can show corroboration
            # alongside the review.
            f.quality_checks = quality.evaluate(f, repo, level).checks_as_dicts()
            continue
        # The pre-report quality battery: corroborate the claim against the actual
        # source at the configured strictness, rather than accepting metadata
        # completeness as evidence.
        q = quality.evaluate(f, repo, level)
        f.quality_checks = q.checks_as_dicts()
        if q.substantiated:
            f.classification = CLASS_STATICALLY_SUPPORTED
            f.assessment = ASSESS_SUPPORTED
        else:
            f.classification = CLASS_HYPOTHESIS
            f.assessment = ASSESS_UNRESOLVED
        f.assessment_reason = q.reason
    by_id = {f.id: f for f in findings}
    for f in findings:
        if not f.duplicate_of:
            continue
        canonical = by_id.get(f.duplicate_of)
        if canonical and not canonical.duplicate_of:
            f.assessment = canonical.assessment
            f.classification = canonical.classification
            # Make the inheritance explicit: a duplicate's tier is the canonical's,
            # NOT a verdict on its own (often weaker) evidence. Its own
            # quality_checks are preserved so the difference stays visible.
            f.assessment_inherited = True
            f.assessment_reason = "Assessment inherited from canonical {0}: {1}".format(
                canonical.id, canonical.assessment_reason)


def assessment_totals(findings: List[Finding]) -> Dict[str, int]:
    """Separate totals so a larger candidate pool never reads as verified yield:
    candidates (canonical, non-duplicate), the two substantiated tiers
    (``statically_supported`` and ``reviewed``), hypotheses, and reproduced.
    ``supported`` (= statically_supported + reviewed) and ``unresolved`` are kept
    for back-compat with earlier readers."""
    canon = [f for f in findings if not f.duplicate_of]
    return {
        "candidates": len(canon),
        "supported": sum(1 for f in canon if f.assessment == ASSESS_SUPPORTED),
        "unresolved": sum(1 for f in canon if f.assessment == ASSESS_UNRESOLVED),
        "statically_supported": sum(
            1 for f in canon if f.classification == CLASS_STATICALLY_SUPPORTED),
        "reviewed": sum(1 for f in canon if f.classification == CLASS_REVIEWED),
        "hypotheses": sum(1 for f in canon if f.classification == CLASS_HYPOTHESIS),
        "reproduced": sum(1 for f in canon if f.finding_state == STATE_DYNAMIC_CONFIRMED),
    }


def apply_validation(findings: List[Finding], meta: Dict[str, Any]) -> None:
    """Set harness-owned validation state on each finding.

    Model PASS/Confirmed prose is not a verdict. Unsubstantiated claims remain
    unresolved; reviewed source evidence can establish static support. Runtime
    confirmation additionally requires an executor-owned impact observation
    bound to this candidate and revision, not merely a successful process exit.

    The dynamic branch is intentionally inert: even with ``bash_enabled`` we only
    report ``passed`` when an execution record proves it. There is no executor in
    the default harness (declined by design — dynamic reproduction, if ever
    added, is a separate opt-in component), so no finding can reach ``passed``
    here. This function never fabricates a pass.
    """
    dynamic = bool(meta.get("bash_enabled"))
    records = meta.get("execution_records") or {}
    for f in findings:
        f.poc_status = POC_AUTHORED if (_clean(f.poc) or _clean(f.exploit_test)) else POC_NONE
        # A candidate that failed the evidence gate is never promoted to
        # "supported" — it stays unresolved regardless of what the model wrote.
        if f.assessment != ASSESS_SUPPORTED:
            f.test_status = TEST_NOT_RUN
            f.validation_method = VALIDATION_STATIC
            f.finding_state = STATE_UNRESOLVED
            continue
        rec = records.get(f.id) if isinstance(records, dict) else None
        if dynamic and isinstance(rec, dict) and rec.get("exit_code") is not None:
            passed = (rec.get("exit_code") == 0
                      and rec.get("security_property_violated") is True
                      and rec.get("candidate_key") == f.candidate_key
                      and rec.get("revision") == meta.get("git_commit"))
            f.test_status = TEST_PASSED if passed else TEST_FAILED
            f.validation_method = VALIDATION_DYNAMIC
            f.finding_state = STATE_DYNAMIC_CONFIRMED if passed else STATE_STATIC_SUPPORTED
        else:
            f.test_status = TEST_NOT_RUN
            f.validation_method = VALIDATION_STATIC
            f.finding_state = STATE_STATIC_SUPPORTED


def coverage_ledger(results_dir: Path, meta: Dict[str, Any],
                    findings: List[Finding]):
    """Build the harness-owned coverage ledger, or None when unavailable.

    Requires the scanned repo to still be present (it is, on the machine that
    ran the scan). Returns None otherwise — we never fabricate coverage over a
    surface we cannot enumerate.
    """
    repo = meta.get("repo")
    if not repo:
        return None
    repo_path = Path(repo)
    if not repo_path.is_dir():
        return None
    try:
        from .inventory import build_coverage_ledger
        finding_files = [_loc_file(f.location) or _loc_file(f.data_flow)
                         for f in findings]
        return build_coverage_ledger(Path(results_dir), repo_path,
                                     finding_files=[f for f in finding_files if f])
    except Exception:  # pragma: no cover - ledger must never break the report
        return None


_SRC_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php", ".cs",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".rs", ".kt", ".scala", ".swift", ".m",
    ".mm", ".sh", ".pl", ".ex", ".exs", ".erl", ".clj", ".groovy", ".lua", ".r",
    ".dart", ".vue", ".svelte",
}
_SRC_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "third_party", "third-party", "external",
    "deps", "dist", "build", "target", "__pycache__", ".venv", "venv", ".tox",
    "site-packages", "bower_components",
}


def _repo_source_file_count(repo, cap: int = 5000) -> int:
    """Rough count of first-party source files (skips vendored trees, caps the
    walk). Used only to judge whether a shallow partition/entry-point count is a
    coverage concern — a single-partition pass over 2,400 files is not 'complete'.
    Returns 0 for a missing/unreadable repo so the shallowness checks stay inert."""
    if not repo:
        return 0
    p = Path(repo)
    if not p.is_dir():
        return 0
    n = 0
    try:
        for dp, dns, fns in os.walk(p):
            dns[:] = [d for d in dns if d not in _SRC_SKIP_DIRS]
            for f in fns:
                if os.path.splitext(f)[1].lower() in _SRC_EXT:
                    n += 1
                    if n >= cap:
                        return n
    except OSError:
        pass
    return n


# A requested phase's primary deliverable — the file (or results dir) it must
# produce. A phase the engine marked "completed" that left an empty/missing
# deliverable did NOT run to completion: publication depends on valid content, so
# such a phase is not counted toward execution completeness.
_PHASE_DELIVERABLE = {
    "1": ("phase1_output.md", "file"),
    "2": ("results", "dir"),
    "2b": ("phase2b_output.md", "file"),
    "3": ("phase3_output.md", "file"),
    "3d": ("phase3d_output.md", "file"),
    "4": ("README.md", "file"),
}


def _empty_deliverables(results_dir, req) -> List[str]:
    """Requested phases whose deliverable is missing or empty (0 bytes / a results
    dir with no non-empty ``sg-*.md``). Used to keep a phase that wrote nothing
    from reading as complete."""
    out: List[str] = []
    root = Path(results_dir)
    for ph in req:
        spec = _PHASE_DELIVERABLE.get(ph)
        if not spec:
            continue
        rel, kind = spec
        p = root / rel
        try:
            if kind == "dir":
                ok = p.is_dir() and any(
                    c.is_file() and c.stat().st_size > 0 for c in p.glob("*.md"))
            else:
                ok = p.is_file() and p.stat().st_size > 0
        except OSError:
            ok = False
        if not ok:
            out.append(ph)
    return out


_P2B_CLAIM = re.compile(
    r"(?:total\s+candidates?(?:\s+findings?)?|all)\s*[:\s]\s*\*{0,2}\s*(\d+)", re.I)
# A CONCRETE per-candidate disposition row: a table row citing a numbered VULN id
# anywhere in it (an aggregate "All VULN-*" row has no VULN-<digits> and is also
# excluded by _P2B_AGGREGATE below).
_P2B_ROW = re.compile(r"^\|.*\bVULN[\-‑‐_ ]?0*\d+\b", re.I)
_ELLIPSIS = re.compile(r"[…]|\.\.\.")
# Explicit aggregate/hand-wave phrasing — "All VULN-*", "no individual rows", etc.
_P2B_AGGREGATE = re.compile(
    r"all\s+vuln|no\s+individual\s+(rows|findings)|due\s+to\s+the\s+large\s+number|"
    r"each\s+of\s+the\s+\d+", re.I)


def _phase2b_disposition_gap(results_dir):
    """Detect a Phase-2b review that CLAIMS more dispositions than it supplies —
    a hand-waved "all 215 confirmed" with one aggregate row and no per-candidate
    verdicts, or N claimed backed by a handful of rows plus an "… remaining"
    ellipsis. Returns ``(claimed, actual)`` when the shortfall is material, else
    None. An aggregate statement is not a review — every candidate needs its own
    disposition and evidence."""
    p = Path(results_dir) / "phase2b_output.md"
    try:
        text = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
    except OSError:
        return None
    if not text:
        return None
    claims = [int(m.group(1)) for m in _P2B_CLAIM.finditer(text)]
    claimed = max(claims) if claims else 0
    # Count concrete per-candidate rows, excluding an aggregate "All VULN-*" row.
    actual = sum(1 for line in text.splitlines()
                 if _P2B_ROW.match(line) and not _P2B_AGGREGATE.search(line))
    if not claimed:
        return None
    aggregate = bool(_P2B_AGGREGATE.search(text))
    # Material shortfall: an aggregate/ellipsis hand-wave, or fewer than half the
    # claimed candidates actually dispositioned (0 rows counts — the worst case).
    if aggregate or _ELLIPSIS.search(text) or actual * 2 < claimed:
        if actual < claimed:
            return claimed, actual
    return None


def compute_run_status(meta: Dict[str, Any], ledger=None,
                       results_dir=None) -> Dict[str, Any]:
    """Three orthogonal status axes, deliberately not collapsed into one field.

    * ``execution_status`` — did the requested phases run to completion *and
      produce valid (non-empty) deliverables*?
    * ``coverage_status`` — did the run actually reach the whole attack surface,
      or was it degraded (single-partition fallback, unfinished agents, skipped
      phases)?
    * ``validation_mode`` — were findings confirmed statically or by execution?

    A run can be execution=complete yet coverage=degraded (every phase finished,
    but the partitioner collapsed to one whole-repo pass). Overloading these
    onto a single "Partial/Completed" label is exactly what let a narrow run
    look thorough.
    """
    req = list(meta.get("phases_requested") or [])
    done = set(meta.get("phases_completed") or [])
    agents = meta.get("agents") or []
    incomplete = [a for a in agents
                  if a.get("stopped_reason") not in ("complete", None, "")]

    # A phase that wrote an empty/missing deliverable did not really complete, even
    # if the engine recorded it as done — publication depends on valid content.
    empties = _empty_deliverables(results_dir, req) if results_dir is not None else []
    # An aggregate Phase-2b ("all confirmed", no per-candidate dispositions) is not
    # a valid verification: it cannot count toward completion, so dependent work is
    # explicitly partial rather than reading as fully verified.
    disp_gap = _phase2b_disposition_gap(results_dir) if results_dir is not None else None
    contract_errors = []
    if results_dir is not None:
        from . import verification
        manifest = verification.read_json(Path(results_dir) / verification.MANIFEST)
        if (Path(results_dir) / verification.MANIFEST).exists() and ("2b" in req or verification.manifest_problem(manifest)):
            reconciliation = verification.reconcile(manifest,
                verification.read_json(Path(results_dir) / verification.DECISIONS),
                verification.target_repo(manifest, results_dir))
            contract_errors += [("2b", e) for e in reconciliation["errors"]]
        if manifest is not None and "3" in done:
            contract_errors += [("3", e) for e in verification.validate_artifacts(results_dir)]
    invalid = set(empties) | {ph for ph, _ in contract_errors}
    if disp_gap:
        invalid.add("2b")
    effective_done = done - invalid

    if meta.get("aborted"):
        execution = "aborted"
    elif meta.get("cancelled"):
        execution = "cancelled"
    elif req and effective_done >= set(req):
        execution = "complete"
    elif effective_done:
        execution = "partial"
    elif req:
        execution = "incomplete"
    else:
        execution = "unknown"

    if contract_errors and execution == "complete":
        execution = "partial"
    reasons: List[str] = ["Phase {} quality failure: {}".format(ph, e) for ph, e in contract_errors]
    if empties:
        reasons.append(
            "phase(s) {0} produced an empty or missing deliverable — recorded as "
            "run but not counted as complete".format(", ".join(empties)))
    if disp_gap:
        reasons.append(
            "Phase 2b claimed {0} candidates reviewed but supplied only {1} "
            "per-candidate verdict rows — an aggregate/hand-waved disposition is "
            "not a review; execution is partial and its confirmations do not "
            "substitute for per-candidate evidence".format(disp_gap[0], disp_gap[1]))
    parts = meta.get("partitions") or []
    if meta.get("partition_fallback"):
        if meta.get("partition_collapsed"):
            reasons.append("partition table could not be parsed and no route "
                           "structure was found — a single whole-repo partition "
                           "was used")
        else:
            reasons.append("partition table could not be parsed — deterministic "
                           "subsystem partitioning was used as a fallback")
    elif "2" in req and len(parts) <= 1 and (meta.get("max_partitions") or 0) > 1:
        reasons.append("only one partition was analysed (attack surface not "
                       "subdivided)")

    # Shallowness signals — a run that mapped no attack surface, or hunted a large
    # tree as a single blob, must never read as "complete". These fire regardless
    # of max_partitions: a deliberate one-partition pass over 2,400 files is still
    # shallow coverage, not a clean bill of health. (The gvisor case: recon
    # enumerated 0 entry points and the run reported complete.)
    repo_files = _repo_source_file_count(meta.get("repo"))
    ep_total = getattr(ledger, "total", None) if ledger is not None else None
    if "2" in req and ep_total == 0 and repo_files >= 40:
        reasons.append(
            "recon enumerated no entry points across a codebase of {0}{1} source "
            "files — the attack surface was not mapped, so most of the code was "
            "not analysed (this target may need scoping to a subsystem, or the "
            "PASTA threat model to surface non-web attack surface)".format(
                repo_files, "+" if repo_files >= 5000 else ""))
    if ("2" in req and len(parts) <= 1 and repo_files >= 150
            and not meta.get("threat_model_partitions")):
        reasons.append(
            "a codebase of {0}{1} source files was analysed in a single partition "
            "— the attack surface was not subdivided".format(
                repo_files, "+" if repo_files >= 5000 else ""))
    if meta.get("hunt_halted_reason"):
        # The circuit breaker stopped the hunt fan-out; this is the most important
        # coverage caveat, so state it first and verbatim.
        reasons.insert(0, meta["hunt_halted_reason"])
    if incomplete:
        reasons.append("{0} agent(s) did not finish cleanly".format(len(incomplete)))
    if req and not done >= set(req):
        missing = [k for k in req if k not in done]
        reasons.append("requested phase(s) did not complete: "
                       + ", ".join(missing))
    if ledger is not None and ledger.not_reviewed > 0:
        reasons.append("{0} of {1} enumerated entry points were not reviewed"
                       .format(ledger.not_reviewed, ledger.total))

    if reasons:
        coverage = "degraded"
    elif execution == "complete":
        coverage = "complete"
    else:
        coverage = "partial"

    return {
        "execution_status": execution,
        "coverage_status": coverage,
        "coverage_degraded_reasons": reasons,
        "validation_mode": VALIDATION_DYNAMIC if meta.get("bash_enabled")
        else VALIDATION_STATIC,
    }


def load_meta(results_dir: Path) -> Dict[str, Any]:
    p = results_dir / SCAN_META_FILE
    if not p.exists():
        return {}
    try:
        meta = json.loads(p.read_text(encoding="utf-8"))
        reviews = results_dir / "verification_records.json"
        if reviews.exists():
            try:
                records = json.loads(reviews.read_text(encoding="utf-8"))
                meta["verification_records"] = records if isinstance(records, dict) else {}
            except (OSError, ValueError):
                meta["verification_records"] = {}
        return meta
    except Exception:
        return {}


def _fmt_dur(seconds: float) -> str:
    s = int(max(0, seconds or 0))
    if s < 60:
        return "{0}s".format(s)
    if s < 3600:
        return "{0}m {1}s".format(s // 60, s % 60)
    return "{0}h {1}m".format(s // 3600, (s % 3600) // 60)


def _fmt_ts(ts: float) -> str:
    if not ts:
        return "unknown"
    return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _bar(n: int, total: int, width: int = 24) -> str:
    if total <= 0:
        return ""
    filled = int(round(width * n / float(total)))
    return "█" * filled + "░" * (width - filled)


def _update_bank(findings, results_dir, meta):
    """Merge this run into the per-target vulnerability ledger and return the
    recall summary — only when the run opted in (meta['ledger']). Never fails the
    report. Idempotent, so calling from both render() and write_consolidated() is
    safe (the merge happens once)."""
    if not meta.get("ledger"):
        return None
    try:
        from .membank import update_ledger
        return update_ledger(results_dir, findings, meta)
    except Exception as exc:  # pragma: no cover - defensive
        import logging
        logging.getLogger(__name__).warning("vulnerability ledger update failed: %s", exc)
        return None


def _apply_votes(findings, results_dir) -> None:
    """Attach each finding's multi-sample vote count from hunt_votes.json (present
    only on a sampled run). Matched by location bucket. Never fails the report."""
    try:
        from .votes import load_votes, votes_for
        vm = load_votes(results_dir)
        if not vm:
            return
        for f in findings:
            v, n = votes_for(getattr(f, "location", "") or "", vm)
            if v:
                f.votes = v
                f.vote_samples = n
    except Exception:  # pragma: no cover - defensive
        pass


def _maybe_redact(findings, meta) -> int:
    """Mask secret/PII values in finding fields when the run opted into redaction.
    Applied in both render() and write_consolidated() so the markdown, JSON, SARIF,
    and ledger all derive from the same masked findings. Never fails the report."""
    if not meta.get("redact"):
        return 0
    try:
        from .redact import redact_findings
        return redact_findings(findings)
    except Exception as exc:  # pragma: no cover - defensive
        import logging
        logging.getLogger(__name__).warning("redaction failed: %s", exc)
        return 0


def _sbom_summary(results_dir, meta):
    """SBOM summary for the Application Intelligence section — from the written
    sbom.cdx.json if present (re-render), else built fresh from the repo. Never
    fails the report."""
    try:
        from .sbom import SBOM_FILE, build_sbom, summary
        p = Path(results_dir) / SBOM_FILE
        if p.exists():
            return summary(json.loads(p.read_text("utf-8")))
        repo = meta.get("repo")
        if repo and Path(repo).is_dir():
            return summary(build_sbom(repo))
    except Exception:  # pragma: no cover - defensive
        pass
    return None


def _build_chains_safe(findings):
    """Deterministic exploit-chain analysis; never fails the report."""
    try:
        from .chains import build_chains
        return build_chains([f.to_dict() for f in findings if _is_substantiated(f.classification)])
    except Exception:  # pragma: no cover - defensive
        return []


def render(results_dir: Path) -> str:
    meta = load_meta(results_dir)
    findings = parse_findings(results_dir)
    if not (results_dir / "candidate_manifest.json").exists():
        findings += authz_findings(meta)
    # Restore CWE + file:line the model dropped, then dedup (which keys on
    # family:file:func).
    backfill_locations(findings, results_dir, meta.get("repo", ""))
    if not (results_dir / "candidate_manifest.json").exists():
        flag_duplicates(findings)
    # Votes are applied before assessment: the quality battery's agreement check
    # reads them (≥2 independent hunt samples is a corroboration signal).
    _apply_votes(findings, results_dir)
    assess_candidates(findings, meta)
    apply_validation(findings, meta)
    apply_knowledge(findings)
    apply_normalized_severity(findings)
    findings = rank(findings)
    red_count = _maybe_redact(findings, meta)
    # Mode A: label each finding new/persisting/regressed vs the prior report.
    lifecycle = reconcile_lifecycle(findings, results_dir, meta)
    # Vulnerability ledger (opt-in memory bank): merge + recall vs all prior runs.
    bank = _update_bank(findings, results_dir, meta)
    ledger = coverage_ledger(results_dir, meta, findings)
    rs = compute_run_status(meta, ledger=ledger, results_dir=results_dir)

    unique = [f for f in findings if not f.duplicate_of]
    dupes = [f for f in findings if f.duplicate_of]

    counts: Dict[str, int] = {}
    for f in unique:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    L: List[str] = []
    A = L.append

    A("# Consolidated Scan Report")
    A("")
    A("*Generated {0} by vhlocal{1}. All scan metadata is recorded by the engine, "
      "not authored by the model.*".format(
          _fmt_ts(_dt.datetime.now().timestamp()),
          " " + meta["engine_version"] if meta.get("engine_version") else ""))
    A("")

    # ---------------- 1. Scan summary ----------------
    A("## 1. Scan summary")
    A("")
    dur = (meta.get("finished_at", 0) or 0) - (meta.get("started_at", 0) or 0)
    A("| Field | Value |")
    A("|---|---|")
    A("| Target | `{0}` |".format(meta.get("repo") or "unknown"))
    # Three orthogonal axes, never collapsed. See compute_run_status.
    A("| Execution status | **{0}** |".format(rs["execution_status"]))
    A("| Coverage status | **{0}** |".format(rs["coverage_status"]))
    A("| Validation mode | {0} |".format(
        "dynamic (execution)" if rs["validation_mode"] == VALIDATION_DYNAMIC
        else "static (reasoning only — no code executed)"))
    A("| Started | {0} |".format(_fmt_ts(meta.get("started_at", 0))))
    A("| Finished | {0} |".format(_fmt_ts(meta.get("finished_at", 0))))
    A("| Duration | **{0}** |".format(_fmt_dur(dur)))
    A("| Scan engine | vhlocal {0} (local, offline) |".format(
        meta.get("engine_version") or "—"))
    A("| Hunt model | `{0}` |".format(meta.get("model") or "—"))
    A("| Falsification model | `{0}` |".format(
        meta.get("verify_model") or meta.get("model") or "—"))
    A("| Inference host | {0} |".format(meta.get("host") or "—"))
    A("| Results directory | `{0}` |".format(meta.get("results_dir") or str(results_dir)))
    if meta.get("git_commit"):
        commit = meta["git_commit"][:12]
        if meta.get("git_branch"):
            commit += " ({0})".format(meta["git_branch"])
        if meta.get("git_dirty"):
            commit += " +uncommitted changes"
        A("| Commit scanned | `{0}` |".format(commit))
    A("")
    # Mode A — how this run compares to the previous report of the same target.
    if lifecycle.get("comparison_note"):
        A("> " + lifecycle["comparison_note"])
        A("")
    if lifecycle.get("has_prior"):
        A("### Change since previous scan")
        A("")
        A("Compared against `{0}`{1}.".format(
            lifecycle["prior_report"],
            " (commit `{0}`)".format(lifecycle["prior_commit"][:12])
            if lifecycle.get("prior_commit") else ""))
        A("")
        A("| Lifecycle | Count |")
        A("|---|---|")
        A("| 🆕 New this scan | {0} |".format(lifecycle["new"]))
        A("| ➡️ Persisting | {0} |".format(lifecycle["persisting"]))
        A("| 🔁 Reappeared (not observed last scan, present now) | {0} |".format(
            lifecycle["regressed"]))
        A("| ◽ No longer observed | {0} |".format(lifecycle["fixed"]))
        A("")
        A("*“No longer observed” is not evidence of a fix — run-to-run hunt "
          "detection varies, so a finding can disappear without the code changing. "
          "A fix is only established by re-review against the current source.*")
        A("")
    else:
        A("> **Baseline scan** — no prior report of this target was found, so "
          "there is nothing to compare against yet. The next scan will track "
          "new / persisting / no-longer-observed findings against this one.")
        A("")
    if meta.get("seeded_from_prior"):
        A("> **Seeded run (Mode B).** Phase 1 was seeded with the findings of "
          "`{0}` as hot spots to re-verify. This run is therefore **correlated "
          "with that prior scan and is not an independent sample** — exclude it "
          "from union-recall benchmarking.".format(meta["seeded_from_prior"]))
        A("")
    if rs["coverage_degraded_reasons"]:
        A("> **Coverage is degraded — treat coverage-dependent numbers as "
          "provisional.** " + "; ".join(rs["coverage_degraded_reasons"]) + ".")
        A("")

    if bank:
        A("### Vulnerability ledger")
        A("")
        newnote = ", **{0} new** to the ledger".format(bank["new"]) if bank["new"] else ""
        A("This target's ledger holds **{0}** known finding(s) "
          "({1} reliable) across {2} recorded run(s). This run reproduced "
          "**{3} of {4}** open finding(s) — recall **{5}%**{6}.".format(
              bank["total_known"], bank["reliable"], bank["runs_recorded"],
              bank["found"], bank["open_known"], bank["recall_pct"], newnote))
        A("")
        if bank["missed"]:
            A("Previously-confirmed findings this run did **not** reproduce "
              "(a possible regression in coverage — not necessarily a fix):")
            A("")
            A("| Missed finding | CWE | Confidence | Runs | Location |")
            A("|---|---|---|---|---|")
            for m in bank["missed"][:20]:
                title = _clean(m.get("title") or "—").replace("|", "\\|")[:70]
                loc = _clean(m.get("location") or "—").replace("|", "\\|")
                A("| {0} | {1} | {2} | {3} | {4} |".format(
                    title or "—", m.get("cwe") or "—", m.get("confidence") or "—",
                    m.get("confirmed_count") or 1, loc or "—"))
            if bank["missed_count"] > 20:
                A("")
                A("_…and {0} more._".format(bank["missed_count"] - 20))
            A("")

    # ---------------- 2. Checks enabled ----------------
    A("## 2. Checks enabled")
    A("")
    parts = meta.get("partitions") or []
    agents = meta.get("agents") or []
    req = meta.get("phases_requested") or []
    done = set(meta.get("phases_completed") or [])
    skipped = set(meta.get("phases_skipped") or [])
    timings = meta.get("phase_timings") or {}
    if req:
        A("### Phases")
        A("")
        A("| Phase | Check | Status | Duration |")
        A("|---|---|---|---|")
        for k in req:
            if k in done:
                st = "Completed"
            elif k in skipped:
                st = "Skipped (resume)"
            else:
                st = "Not completed"
            A("| {0} | {1} | {2} | {3} |".format(
                k, PHASE_TITLES.get(k, k), st,
                _fmt_dur(timings.get(k, 0)) if timings.get(k) else "—"))
        A("")

    # Only claim class coverage if the hunt phase actually ran. Listing
    # INJ/NAV/LOG for a recon-only run would assert checks that never executed.
    classes = meta.get("vuln_classes") or []
    hunt_requested = "2" in req
    hunt_done = "2" in done
    if classes and hunt_requested:
        A("### Vulnerability classes")
        A("")
        if not hunt_done:
            A("> Phase 2 did not complete — the coverage below was requested "
              "but not fully exercised.")
            A("")
        agents_by_class: Dict[str, int] = {}
        for a in agents:
            vc = a.get("vuln_class")
            if vc:
                agents_by_class[vc] = agents_by_class.get(vc, 0) + 1
        A("| Class | Agents | Coverage |")
        A("|---|---|---|")
        for c in list(classes) + ["SINK"]:
            A("| {0} | {1} | {2} |".format(
                c, agents_by_class.get(c, 0), CLASS_TITLES.get(c, c)))
        A("")
    elif classes and not hunt_requested:
        A("### Vulnerability classes")
        A("")
        A("*Phase 2 (hunt) was not part of this run, so no vulnerability-class "
          "checks were performed.*")
        A("")

    A("### Scan configuration")
    A("")
    A("| Setting | Value |")
    A("|---|---|")
    A("| Partitions analysed | {0}{1} |".format(
        len(parts), " (" + ", ".join(parts) + ")" if parts else ""))
    A("| Agents dispatched | {0} |".format(len(agents)))
    A("| Max partitions | {0} |".format(meta.get("max_partitions") or "—"))
    A("| Context window | {0:,} tokens |".format(meta.get("num_ctx") or 0))
    A("| Tool envelope | {0} |".format(", ".join(meta.get("tool_envelope") or []) or "—"))
    A("| Code execution | {0} |".format(
        "Enabled" if meta.get("bash_enabled") else
        "**Disabled** — static analysis only"))
    usage = meta.get("usage") or {}
    if usage:
        A("| Model calls | {0:,} |".format(usage.get("calls", 0)))
        A("| Tokens (prompt / completion) | {0:,} / {1:,} |".format(
            usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)))
        A("| Peak context used | {0:,} tokens |".format(
            usage.get("peak_prompt_tokens", 0)))
    A("")

    incomplete = [a for a in agents
                  if a.get("stopped_reason") not in ("complete", None, "")]
    if incomplete:
        A("> **{0} of {1} agents did not finish cleanly.** Coverage for the "
          "affected areas is reduced.".format(len(incomplete), len(agents)))
        A(">")
        for a in incomplete[:12]:
            A("> - `{0}` — {1} (after {2} turns)".format(
                a.get("label"), a.get("stopped_reason"), a.get("turns")))
        A("")

    # ---------------- 3. Findings by severity ----------------
    A("## 3. Hypotheses and substantiated vulnerabilities")
    A("")
    if not unique:
        A("**No hypotheses or substantiated vulnerabilities were reported.**")
        A("")
        if not (results_dir / "README.md").exists():
            A("> The final report (`README.md`) is absent, so this may reflect an "
              "incomplete scan rather than a clean result. Check section 2.")
            A("")
    else:
        total = len(unique)
        # Keep evidence status visible independently of potential severity.
        at = assessment_totals(unique)
        A("**{0} substantiated findings** ({1} reviewed, {2} statically-supported) · "
          "**{3} hypotheses worth investigating**.".format(
              at["supported"], at["reviewed"], at["statically_supported"], at["unresolved"]))
        A("")
        A("*Substantiated* means a finding cleared the harness's static gate (weakness "
          "class + concrete claim + a source location that resolves); *reviewed* adds a "
          "source-grounded review record. Severity below describes potential impact; it "
          "does not establish that a hypothesis is a vulnerability.")
        A("")
        A("| Severity | Count | Distribution |")
        A("|---|---|---|")
        for _k, label in SEVERITY_ORDER:
            n = counts.get(label, 0)
            if n:
                A("| **{0}** | {1} | `{2}` |".format(label, n, _bar(n, total)))
        other = sum(v for k, v in counts.items()
                    if k not in {lbl for _k, lbl in SEVERITY_ORDER})
        if other:
            A("| Unrated | {0} | `{1}` |".format(other, _bar(other, total)))
        A("| | **{0} total** | |".format(total))
        A("")

        A("## 4. Investigation priorities")
        A("")
        A("| # | ID | Potential severity | CWE | Title | Location |")
        A("|---|---|---|---|---|---|")
        for i, f in enumerate(unique, start=1):
            A("| {0} | {1} | **{2}** | {3} | {4} | {5} |".format(
                i, f.id, f.severity, f.normalized_cwe or f.cwe or "—",
                (f.title or "—")[:70],
                "`{0}`".format(_clean(f.location)) if f.location else "—"))
        A("")

        A("## 5. Evidence and assessment")
        A("")
        for i, f in enumerate(unique, start=1):
            A("### {0}. [{1}] {2}".format(i, f.severity.upper(), f.title or f.id))
            A("")
            A("| Field | Value |")
            A("|---|---|")
            A("| Candidate ID | {0} |".format(f.id))
            A("| Assessment | {0} |".format(_assessment_label(f.classification)))
            A("| Why the scanner flagged this | {0} |".format(
                _clean(f.hypothesis_reason or f.data_flow or "No candidate-specific explanation was provided.").replace("|", "\\|")))
            A("| Evidence assessment | {0} |".format(_clean(f.assessment_reason).replace("|", "\\|")))
            if f.verification_status:
                A("| Verification disposition | {0} |".format(f.verification_status))
            if f.quality_checks:
                A("| Quality checks | {0} |".format(
                    _format_quality_checks(f.quality_checks).replace("|", "\\|")))
            # Severity is the deterministic family baseline (stable across runs);
            # the model's own tier is preserved beside it when it differed.
            if f.reported_severity and f.reported_severity != f.severity:
                A("| Severity | **{0}** (scanner-assessed: {1}) |".format(
                    f.severity, f.reported_severity))
            else:
                A("| Severity | **{0}** |".format(f.severity))
            # CWE: the model's reported CWE, then the canonical family roll-up used
            # for cross-run comparison when it differs.
            A("| CWE | {0} |".format(f.cwe or "—"))
            if f.normalized_cwe and f.normalized_cwe != f.cwe:
                fam = " ({0})".format(f.canonical_name) if f.canonical_name else ""
                A("| Normalized CWE | {0}{1} |".format(f.normalized_cwe, fam))
            elif f.canonical_name:
                A("| Family | {0} |".format(f.canonical_name))
            if f.description:
                A("| Description | {0} |".format(f.description))
            if f.exploitability and _is_substantiated(f.classification):
                # Class-level exploitability paired with this finding's own
                # static-confirmation basis, so nothing overstates what was proven.
                basis = ("statically confirmed (source→sink); not runtime-tested"
                         if f.validation_method == VALIDATION_STATIC
                         else "runtime-verified" if f.validation_method == VALIDATION_DYNAMIC
                         else "static reasoning")
                A("| Exploitability | {0} — basis: {1} |".format(
                    f.exploitability, basis))
            if f.location:
                A("| Location | `{0}` |".format(_clean(f.location)))
            if f.votes and f.vote_samples:
                A("| Votes | {0} of {1} hunt samples reported this site |".format(
                    f.votes, f.vote_samples))
            if f.entry_point:
                A("| Entry point | {0} |".format(f.entry_point))
            if f.data_flow:
                A("| Data flow | {0} |".format(f.data_flow))
            if f.fix:
                A("| Proposed fix | {0} |".format(f.fix))
            if f.poc:
                A("| Proof of concept | {0} |".format(_clean(f.poc)))
            # Harness-owned validation state — NOT the model's PASS/Confirmed
            # claim. See apply_validation. The model's raw claim is shown below,
            # explicitly marked unverified, so nothing is hidden.
            A("| PoC status | {0} |".format(
                "authored" if f.poc_status == POC_AUTHORED else "none"))
            A("| Test status | {0} |".format(
                {"not_run": "not run (no code executed)",
                 "passed": "passed (execution record)",
                 "failed": "failed (execution record)"}.get(
                     f.test_status, f.test_status or "not run")))
            A("| Validation method | {0} |".format(
                "dynamic execution" if f.validation_method == VALIDATION_DYNAMIC
                else "static reasoning"))
            A("| Finding state | {0} |".format(
                f.finding_state.replace("_", " ") or "hypothesis"))
            if f.finding_lifecycle:
                A("| Lifecycle | {0} |".format({
                    "new": "🆕 new this scan",
                    "persisting": "➡️ persisting since last scan",
                    "regressed": "🔁 reappeared (not observed last scan, present now)",
                }.get(f.finding_lifecycle, f.finding_lifecycle)))
            reported = " / ".join(
                x for x in (_clean(f.status), _clean(f.exploit_test))
                if x and x.lower() not in ("—", "n/a"))
            if reported:
                A("| Scanner-reported (unverified) | {0} |".format(reported))
            if f.reference:
                A("| Reference | {0} |".format(f.reference))
            # CVE is deliberately N/A for first-party code findings — a CVE names
            # a released product's vuln, not application source (see knowledge.py).
            A("| CVE | {0} |".format(f.cve or "—"))
            A("")

    # Findings present in the prior report and absent now. Disappearance is NOT a
    # fix — hunt detection varies run to run — so these are reported as "no longer
    # observed", not "fixed", and a fix requires re-review against current source.
    fixed = lifecycle.get("fixed_findings") or []
    if fixed:
        A("## 5a. No longer observed since previous scan")
        A("")
        A("These were reported in `{0}` and are not present in this scan. This is "
          "**not** evidence of a fix — a finding can disappear through run-to-run "
          "detection variance without the code changing; confirm against the "
          "current source. If one reappears later it is flagged **reappeared**.".format(
              lifecycle.get("prior_report", "the prior report")))
        A("")
        A("| Prior ID | Title | CWE | Location |")
        A("|---|---|---|---|")
        for ff in fixed:
            A("| {0} | {1} | {2} | `{3}` |".format(
                ff.get("id") or "—", (ff.get("title") or "—")[:70],
                ff.get("cwe") or "—", _clean(ff.get("location") or "") or "—"))
        A("")

    if dupes:
        A("## 6. Duplicate findings (clustered)")
        A("")
        A("Each of these shares a root cause — family, file, sink function **and** "
          "data-flow signature — with a canonical finding above: the same defect "
          "reported more than once, not two inputs reaching one sink. They are "
          "clustered rather than deleted (duplicate reporting is a scan-quality "
          "signal worth seeing) and are **excluded from the headline counts and "
          "severity totals**, which reflect unique root causes only.")
        A("")
        A("| ID | Clustered under | CWE | Location |")
        A("|---|---|---|---|")
        for f in dupes:
            A("| {0} | {1} | {2} | `{3}` |".format(
                f.id, f.cluster_id or f.duplicate_of, f.cwe or "—",
                _clean(f.location) or "—"))
        A("")

    # ---------------- Coverage ledger ----------------
    if ledger is not None and ledger.total:
        A("## 7. Entry-point coverage ledger")
        A("")
        A("The attack surface below is enumerated by the harness from the "
          "source, not reported by the model — so a route cannot be omitted from "
          "the denominator by being overlooked. Each entry is dispositioned from "
          "produced artifacts: a finding at its file, a reference in the "
          "analysis, or **not reviewed**.")
        A("")
        added = meta.get("coverage_partitions_added") or []
        if added:
            A("> **Harness-enforced coverage** added {0} deterministic "
              "partition(s) ({1}) for {2} route file(s) the model's partition "
              "plan omitted, so Phase 2 traced them instead of leaving them "
              "unreviewed.".format(
                  len(added), ", ".join(added),
                  len(meta.get("coverage_files_added") or [])))
            A("")
        A("| Disposition | Count |")
        A("|---|---|")
        for disp, label in (("finding_emitted", "Finding emitted"),
                            ("reviewed_no_issue", "Reviewed — no issue"),
                            ("not_reviewed", "**Not reviewed**")):
            n = ledger.counts.get(disp, 0)
            if n:
                A("| {0} | {1} |".format(label, n))
        A("| | **{0} entry points** |".format(ledger.total))
        A("")
        if ledger.not_reviewed:
            A("> **{0} of {1} entry points were never referenced by any "
              "produced artifact.** A run cannot be considered complete-coverage "
              "while these remain — they are listed below.".format(
                  ledger.not_reviewed, ledger.total))
            A("")
            A("| Method | Path | Location |")
            A("|---|---|---|")
            for e in ledger.entries:
                if e.disposition == "not_reviewed":
                    A("| {0} | `{1}` | `{2}:{3}` |".format(
                        e.method, e.path, e.file, e.line))
            A("")
        else:
            A("*All {0} enumerated entry points were reached by the analysis.*"
              .format(ledger.total))
            A("")

    # ---------------- Limitations ----------------
    A("## Scope and limitations")
    A("")
    A("- **Evidence levels are separate from severity.** Hypotheses are potential vulnerabilities requiring further investigation. A substantiated vulnerability requires an explicit review with matching source evidence. Authored tests and model-written PASS claims do not prove execution or security impact.")
    A("- **Excluded from analysis by design:** test code, build scripts, vendored "
      "and third-party directories, generated code, and documentation.")
    if not meta.get("verify_model") and meta.get("model"):
        A("- **Falsification ran on the same model as the hunt phase.** Phase 2b "
          "is meant to disprove weak candidates; running it on the same local "
          "model that produced them tends to rubber-stamp rather than refute. "
          "Re-run with `--verify-model` pointed at a stronger model to raise "
          "precision.")
    if skipped or (req and not set(req) <= done):
        A("- **Not every requested phase completed.** See section 2; findings may "
          "be partial.")
    A("- Severities are as reported by the scanner and are not CVSS scores.")
    A("")

    # ---------------- Exploit chains ----------------
    chains = _build_chains_safe(unique)
    if chains:
        A("## Exploit chains")
        A("")
        A("Deterministically composed from the confirmed findings — how defects "
          "combine into a higher-impact attack path than any one alone.")
        A("")
        for c in chains:
            A("### {0} — {1} [{2}]".format(c["id"], c["title"], c.get("severity") or "—"))
            A("")
            A("**Findings:** {0}".format(", ".join(c.get("finding_ids") or [])))
            A("")
            A(c.get("rationale") or "")
            A("")

    # ---------------- Remediation ----------------
    if meta.get("remediate"):
        with_fix = [f for f in unique if f.fix]
        A("## Remediation")
        A("")
        A("Report-only remediation DTOs were written under `remediation/` — one "
          "`remediate.json` + `summary.md` per finding. **No source was modified.** "
          "{0} of {1} finding(s) carry a proposed fix.".format(
              len(with_fix), len(unique)))
        A("")
        if with_fix:
            A("| Finding | Severity | Proposed fix | Status |")
            A("|---|---|---|---|")
            for f in with_fix[:40]:
                A("| {0} | {1} | {2} | proposed |".format(
                    f.id, f.severity,
                    _clean(f.fix).replace("|", "\\|")[:90]))
            A("")

    # ---------------- Application Intelligence ----------------
    sbom = _sbom_summary(results_dir, meta)
    if sbom and sbom.get("total"):
        A("## Application Intelligence")
        A("")
        A("### Software Bill of Materials")
        A("")
        eco = ", ".join("{0} {1}".format(v, k)
                        for k, v in sorted(sbom["by_ecosystem"].items()))
        A("**{0}** direct dependencies across {1} ecosystem(s) ({2}). Full "
          "CycloneDX 1.5 SBOM in `{3}`.".format(
              sbom["total"], len(sbom["by_ecosystem"]), eco, "sbom.cdx.json"))
        A("")
        A("| Component | Version | Ecosystem | License |")
        A("|---|---|---|---|")
        for c in sbom["components"][:60]:
            nm = ("{0}/{1}".format(c["group"], c["name"]) if c.get("group") else c["name"])
            A("| {0} | {1} | {2} | {3} |".format(
                _clean(nm), c.get("version") or "—", c.get("ecosystem") or "—",
                c.get("license") or "—"))
        if sbom["total"] > 60:
            A("")
            A("_…and {0} more — see `sbom.cdx.json`._".format(sbom["total"] - 60))
        A("")

    # ---------------- Scan Health ----------------
    agents = meta.get("agents") or []
    incomplete = [a for a in agents
                  if a.get("stopped_reason") not in ("complete", None, "")]
    reasons = list(rs.get("coverage_degraded_reasons") or [])
    A("## Scan Health")
    A("")
    if not reasons and not incomplete and not meta.get("hunt_halted_reason") \
            and not meta.get("budget_halted_reason"):
        A("✅ **Clean run.** Execution completed and no coverage was lost. "
          "Every dispatched agent finished cleanly.")
    else:
        A("⚠️ **This run lost or degraded coverage** — treat coverage-dependent "
          "numbers as provisional.")
        A("")
        if meta.get("budget_halted_reason"):
            A("- **Halted on budget:** {0}".format(meta["budget_halted_reason"]))
        if meta.get("hunt_halted_reason"):
            A("- **Hunt halted early:** {0}".format(meta["hunt_halted_reason"]))
        for r in reasons:
            A("- {0}".format(r))
        if incomplete:
            by_reason: Dict[str, int] = {}
            for a in incomplete:
                by_reason[a.get("stopped_reason") or "?"] = \
                    by_reason.get(a.get("stopped_reason") or "?", 0) + 1
            breakdown = ", ".join("{0}×{1}".format(v, k)
                                  for k, v in sorted(by_reason.items()))
            A("- **{0} of {1} agents did not finish cleanly** ({2}).".format(
                len(incomplete), len(agents), breakdown))
        A("")
        A("_Per-run recoverable errors are logged to `errors.jsonl`._")
    if red_count:
        A("")
        A("🔒 **Redaction on** — {0} secret/PII value(s) were masked in this "
          "report's artifacts.".format(red_count))
    samples = meta.get("hunt_samples") or 1
    if samples and samples > 1:
        A("")
        A("🗳️ **Multi-sample hunt** — each hunt agent ran **{0}×** and the "
          "candidates were unioned for recall before verification.".format(samples))
    spent = meta.get("budget_spent_usd") or 0
    cap = meta.get("max_budget_usd") or 0
    if spent or cap:
        A("")
        A("💵 **Spend** — ${0:.2f}{1}.".format(
            float(spent), " of ${0:.2f} cap".format(float(cap)) if cap else ""))
    A("")
    A("---")
    A("")
    A("*Raw artifacts — per-agent hunt output, PoCs, exploit tests — are in this "
      "directory. `results/` is pre-falsification and intentionally noisy; "
      "`phase2b_output.md` is the filtered set.*")

    return "\n".join(L) + "\n"


def write_consolidated(results_dir: Path) -> Tuple[Path, Path]:
    """Write SCAN_REPORT.md and findings.json. Returns both paths."""
    results_dir = Path(results_dir)
    meta = load_meta(results_dir)
    findings = parse_findings(results_dir)
    if not (results_dir / "candidate_manifest.json").exists():
        findings += authz_findings(meta)
    # Restore CWE + file:line the model dropped, then dedup (which keys on
    # family:file:func).
    backfill_locations(findings, results_dir, meta.get("repo", ""))
    if not (results_dir / "candidate_manifest.json").exists():
        flag_duplicates(findings)
    # Votes feed the quality battery's agreement check — apply before assessment.
    _apply_votes(findings, results_dir)
    assess_candidates(findings, meta)
    apply_validation(findings, meta)
    apply_knowledge(findings)
    apply_normalized_severity(findings)
    findings = rank(findings)
    # Mask secrets/PII in the finding objects so findings.json, SARIF, and the
    # ledger all derive from masked values (render() redacts its own copy for the
    # markdown/HTML). No-op unless the run opted into redaction.
    red_count = _maybe_redact(findings, meta)
    lifecycle = reconcile_lifecycle(findings, results_dir, meta)
    # render() below merges the run into the vuln ledger; this call is idempotent
    # and just returns the coverage summary for the machine-readable block.
    vuln_bank = _update_bank(findings, results_dir, meta)

    # Application Intelligence: write the CycloneDX SBOM before render() so the
    # report reads it back. Deterministic, never fails the report.
    sbom_sum = None
    try:
        from .sbom import write_sbom
        ts = None
        fin = meta.get("finished_at")
        if isinstance(fin, (int, float)) and fin:
            ts = _dt.datetime.utcfromtimestamp(fin).strftime("%Y-%m-%dT%H:%M:%SZ")
        sbom_sum = write_sbom(results_dir, meta.get("repo", ""), ts)
    except Exception as exc:  # pragma: no cover - defensive
        import logging
        logging.getLogger(__name__).warning("SBOM generation failed: %s", exc)

    report_md = render(results_dir)
    md = results_dir / SCAN_REPORT_FILE
    md.write_text(report_md, encoding="utf-8")

    # The published README must be CANONICAL — rendered from harness records and
    # metadata, never trusted from the model. A model-authored Phase-4 README has
    # been observed inventing a git commit, naming the wrong model, and reporting
    # PASS exploit tests the harness never ran (no executor exists). The consolidated
    # report is derived entirely from findings.json + scan_meta, so it always
    # overwrites the model's README. parse_findings skips a README carrying the
    # "Consolidated Scan Report" marker, so the phase sources — not this file —
    # remain the finding inputs on any re-render. (findings were already parsed
    # above, so overwriting here never affects this run's own extraction.)
    readme = results_dir / "README.md"
    try:
        readme.write_text(report_md, encoding="utf-8")
    except OSError:
        pass

    # Machine-readable coverage ledger for external scoring/aggregation.
    ledger = coverage_ledger(results_dir, meta, findings)
    if ledger is not None:
        (results_dir / "coverage_ledger.json").write_text(
            json.dumps(ledger.to_dict(), indent=2), encoding="utf-8")

    # Authorization map (deterministic, cross-endpoint) for inspection/aggregation.
    try:
        from . import authz
        repo = meta.get("repo")
        if repo and Path(repo).is_dir():
            (results_dir / "authz_map.json").write_text(
                json.dumps(authz.build_authz_map(repo), indent=2), encoding="utf-8")
    except Exception as exc:  # pragma: no cover - defensive
        import logging
        logging.getLogger(__name__).warning("authz map failed: %s", exc)

    # HTML is the presentation layer; failure to render it must not lose the
    # markdown + JSON that already succeeded.
    try:
        from .render_html import write_html
        write_html(results_dir)
    except Exception as exc:  # pragma: no cover - defensive
        import logging
        logging.getLogger(__name__).warning("HTML report failed: %s", exc)

    run_status = compute_run_status(meta, ledger=ledger, results_dir=results_dir)
    counts = _counts(findings)
    finding_dicts = [f.to_dict() for f in findings]
    unique_dicts = [d for d in finding_dicts if not d.get("duplicate_of")]
    try:
        from .chains import build_chains
        chains = build_chains([d for d in unique_dicts if _is_substantiated(d.get("classification", ""))])
    except Exception:  # pragma: no cover - defensive
        chains = []

    # Report-only remediation DTOs (opt-in): structured proposed-fix records under
    # remediation/<VULN-NNN>/. Never edits the scanned repo.
    remediation_summary = None
    if meta.get("remediate"):
        try:
            from .remediation import write_remediation
            remediation_summary = write_remediation(results_dir, findings)
        except Exception as exc:  # pragma: no cover - defensive
            import logging
            logging.getLogger(__name__).warning("remediation DTOs failed: %s", exc)

    from . import verification
    js = results_dir / FINDINGS_JSON_FILE
    js.write_text(json.dumps({
        "meta": meta,
        # Name each model role explicitly. The measured system is a pipeline,
        # not a single model, and benchmark records must not attribute the whole
        # result to the hunt model alone (audit 7.4).
        "attribution": {
            "hunt_model": meta.get("model") or "",
            "falsification_model": meta.get("verify_model") or meta.get("model") or "",
            "orchestrator": "vhlocal " + (meta.get("engine_version") or ""),
        },
        "run_status": run_status,
        "coverage": {
            "total_entry_points": ledger.total,
            "reviewed": ledger.reviewed,
            "not_reviewed": ledger.not_reviewed,
            "complete": ledger.complete,
        } if ledger is not None else None,
        "counts": counts,
        # Harness assessment totals — candidates vs supported vs unresolved vs
        # reproduced — kept distinct from the severity counts so a larger
        # candidate pool never reads as improved verified yield (proposal §7).
        "assessment": assessment_totals(findings),
        "verification": verification.refresh(results_dir),
        "vulnerability_counts": _counts([f for f in findings if _is_substantiated(f.classification)]),
        "hypothesis_counts": _counts([f for f in findings if f.classification == CLASS_HYPOTHESIS]),
        # Mode A cross-run lifecycle: new/persisting/regressed vs the prior
        # report, the now-fixed findings, and the fixed keys the next run reads
        # back to detect regressions.
        "lifecycle": lifecycle,
        # Vulnerability ledger (opt-in memory bank): recall of this run against
        # the union of all prior opted-in runs of this target. null when the run
        # did not opt in.
        "vulnerability_ledger": vuln_bank,
        # Deterministic exploit chains composed from the confirmed findings.
        "chains": chains,
        # Report-only remediation coverage (null unless the run opted in).
        "remediation": remediation_summary,
        # Application intelligence — deterministic SBOM (+ future: architecture,
        # threat model). Full CycloneDX is in sbom.cdx.json.
        "application_intelligence": {"sbom": sbom_sum},
        "findings": finding_dicts,
    }, indent=2), encoding="utf-8")

    # SARIF 2.1.0 (machine-ingestible) and an operator-facing audit manifest.
    # Both derive from the same (possibly redacted) findings + meta; failures are
    # non-fatal so the markdown + JSON that already succeeded are never lost.
    try:
        from .sarif import write_sarif
        write_sarif(results_dir, finding_dicts, meta, run_status)
    except Exception as exc:  # pragma: no cover - defensive
        import logging
        logging.getLogger(__name__).warning("SARIF export failed: %s", exc)
    try:
        from .manifest import write_manifest
        redaction = {"enabled": bool(meta.get("redact")), "masked": red_count} \
            if meta.get("redact") else None
        write_manifest(results_dir, meta, run_status,
                       _counts([f for f in findings if _is_substantiated(f.classification)]), redaction)
    except Exception as exc:  # pragma: no cover - defensive
        import logging
        logging.getLogger(__name__).warning("run_manifest failed: %s", exc)

    _write_errors_jsonl(results_dir, meta)

    # Post-hoc redaction pass: the markdown/HTML/phase artifacts were built by
    # other code paths (render, write_html, the phase agents) rather than from the
    # masked finding objects, so scrub them once more. Idempotent and cheap.
    if meta.get("redact"):
        try:
            from .redact import redact_file
            for name in (SCAN_REPORT_FILE, "README.md", "SCAN_REPORT.html",
                         "phase1_output.md", "phase2b_output.md",
                         "phase3_output.md", "phase3d_output.md"):
                redact_file(results_dir / name)
        except Exception as exc:  # pragma: no cover - defensive
            import logging
            logging.getLogger(__name__).warning("artifact redaction failed: %s", exc)

    return md, js


def _write_errors_jsonl(results_dir: Path, meta: Dict[str, Any]) -> None:
    """Structured per-run recoverable-error log — one JSON object per line for the
    agents that did not finish cleanly. Written only when there is something to
    report (a clean run omits the file, mirroring the Scan Health section)."""
    rows = []
    for a in (meta.get("agents") or []):
        reason = a.get("stopped_reason")
        if reason in ("complete", None, ""):
            continue
        rows.append({
            "phase": a.get("phase") or "",
            "label": a.get("label") or "",
            "stopped_reason": reason,
            "error_kind": a.get("error_kind") or "",
            "turns": a.get("turns"),
            "partition": a.get("partition") or "",
            "vuln_class": a.get("vuln_class") or "",
        })
    if meta.get("hunt_halted_reason"):
        rows.append({"phase": "2", "stopped_reason": "circuit_breaker",
                     "message": meta["hunt_halted_reason"]})
    path = results_dir / "errors.jsonl"
    if not rows:
        return
    try:
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n",
                        encoding="utf-8")
    except OSError:
        pass


def _counts(findings: List[Finding]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        if f.duplicate_of:
            continue
        out[f.severity] = out.get(f.severity, 0) + 1
    return out
