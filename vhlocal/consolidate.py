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
import re
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
POC_AUTHORED = "authored"
POC_NONE = "none"


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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


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
        for attr in ("entry_point", "data_flow", "fix", "poc", "exploit_test"):
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


def _is_placeholder(f: "Finding") -> bool:
    """True for a padding/empty row that is not a real finding.

    Either the title is a known placeholder phrase, or the finding is entirely
    contentless (no CWE, no location, and a title that is empty or just echoes
    its own id) — nothing an analyst could act on."""
    title = _clean(f.title or "").strip()
    if title and _PLACEHOLDER_TITLE.search(title):
        return True
    if not f.cwe and not f.location and (not title or title.upper() == f.id.upper()):
        return True
    return False


def _drop_placeholders(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if not _is_placeholder(f)]


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
        return spine
    if report_findings:
        return report_findings
    return spine or []


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


_FUNC = re.compile(r"([A-Za-z_]\w*)\s*\(")


def _func_hint(f: "Finding") -> str:
    """Best-effort sink function name, so same-file/different-function defects
    stay distinct while line drift within one function collapses."""
    for src in (f.location, f.data_flow):
        calls = _FUNC.findall(src or "")
        if calls:
            return calls[-1].lower()   # the sink is the last call in the chain
    return ""


_PARAM = re.compile(r"[?&]?\b([A-Za-z_]\w*)\s*=|\b(?:param|parameter)\s+[`\"']?(\w+)")


def _flow_signature(f: "Finding") -> str:
    """Distinguishing fingerprint for a finding's *path*, not just its sink.

    Two different inputs reaching one sink are distinct vulnerabilities, not
    duplicates — the ``q`` and ``status`` parameters of the same search endpoint
    both reach the same ``execute()`` and each needs its own fix. Keying only on
    (CWE, sink) collapsed them, which is exactly the "collapsing findings"
    failure the methodology warns about.
    """
    blob = " ".join([_clean(f.entry_point), _clean(f.data_flow), _clean(f.title)]).lower()
    names = set()
    for m in _PARAM.finditer(blob):
        names.add((m.group(1) or m.group(2) or "").lower())
    names.discard("")
    # Drop tokens that appear in nearly every flow and carry no discrimination.
    names -= {"path", "url", "get", "post", "http", "https", "args", "request"}
    return ",".join(sorted(names))


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

    Prefer the CWE; fall back to a keyword from the title so a missing or
    slightly-different CWE does not prevent two reports of one defect from
    clustering. This is deliberately coarse — precision comes from the location
    and flow signature, not from the family.
    """
    if f.cwe:
        return f.cwe.upper()
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
    fil = _loc_file(f.location) or _loc_file(f.data_flow)
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
            primary = "{0}:{1}".format(locs[-1][0], locs[-1][1])
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


def backfill_locations(findings: List["Finding"], results_dir, repo: str = "") -> int:
    """Restore each finding's missing file:line AND CWE from the raw hunt/2b
    evidence.

    The model routinely abbreviates the Phase-4 report ("the rest follow the same
    structure"), dropping the file:line and/or CWE for most findings — which breaks
    dedup, votes, chains, and the canonical-severity labelling. Both still exist in
    the hunt samples, so match each incomplete finding to its evidence block by
    identifier (function/route/keyword + CWE) and restore whatever's missing. Only
    fills on a confident match — a distinctive identifier, or the CWE plus a
    keyword — never guesses. Returns the number of fields restored."""
    needy = [f for f in findings if not _bf_has_loc(f) or not _bf_has_cwe(f)]
    if not needy:
        return 0
    entries = _bf_index(results_dir)
    if not entries:
        return 0
    restored = 0
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
        # Confident only when a distinctive identifier hit, or the CWE plus a
        # keyword did — not a lone generic word.
        confident = best and (best_strong >= 1 or (best_score >= 3 and cweset))
        if not confident:
            continue
        loc, cwe = best
        if not _bf_has_loc(f) and loc:
            f.location = _bf_relpath(loc, repo)
            restored += 1
        if not _bf_has_cwe(f) and cwe:
            f.cwe = cwe
            restored += 1

    # Last resort for any still-CWE-less finding: an unambiguous title keyword.
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


def rank(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (f.severity_rank, f.cwe or "zzz", f.id))


def apply_normalized_severity(findings: List[Finding]) -> None:
    """Make the deterministic family severity canonical, so counts, the meter,
    and ranking are stable run-to-run. The model's original tier is preserved as
    ``reported_severity`` and surfaced in the report when it differs. Run after
    ``knowledge.apply_knowledge`` (which sets ``normalized_severity``) and before
    ``rank``."""
    for f in findings:
        ns = getattr(f, "normalized_severity", "")
        if ns and ns != f.severity:
            f.reported_severity = f.severity
            f.severity_rank, f.severity = _sev_key(ns)


def apply_validation(findings: List[Finding], meta: Dict[str, Any]) -> None:
    """Set harness-owned validation state on each finding.

    The authoritative test status comes from a fact the engine owns — whether
    code execution was enabled — never from the model's "PASS"/"Confirmed"
    prose. With no shell tool nothing ran, so every finding is
    ``not_run`` / ``static_reasoning`` / ``statically_supported`` regardless of
    what the model wrote. The model's claim survives verbatim in ``status`` /
    ``exploit_test`` for transparency, but it is not a verdict.

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
        rec = records.get(f.id) if isinstance(records, dict) else None
        if dynamic and isinstance(rec, dict) and rec.get("exit_code") is not None:
            passed = rec.get("exit_code") == 0
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


def compute_run_status(meta: Dict[str, Any], ledger=None) -> Dict[str, Any]:
    """Three orthogonal status axes, deliberately not collapsed into one field.

    * ``execution_status`` — did the requested phases run to completion?
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

    if meta.get("aborted"):
        execution = "aborted"
    elif meta.get("cancelled"):
        execution = "cancelled"
    elif req and done >= set(req):
        execution = "complete"
    elif done:
        execution = "partial"
    elif req:
        execution = "incomplete"
    else:
        execution = "unknown"

    reasons: List[str] = []
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
        return json.loads(p.read_text(encoding="utf-8"))
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


def _build_chains_safe(findings):
    """Deterministic exploit-chain analysis; never fails the report."""
    try:
        from .chains import build_chains
        return build_chains([f.to_dict() for f in findings])
    except Exception:  # pragma: no cover - defensive
        return []


def render(results_dir: Path) -> str:
    meta = load_meta(results_dir)
    findings = parse_findings(results_dir)
    # Restore file:line the model dropped in the report, so dedup/votes/
    # chains work (they key on location).
    backfill_locations(findings, results_dir, meta.get("repo", ""))
    flag_duplicates(findings)
    apply_validation(findings, meta)
    apply_knowledge(findings)
    apply_normalized_severity(findings)
    findings = rank(findings)
    _apply_votes(findings, results_dir)
    red_count = _maybe_redact(findings, meta)
    # Mode A: label each finding new/persisting/regressed vs the prior report.
    lifecycle = reconcile_lifecycle(findings, results_dir, meta)
    # Vulnerability ledger (opt-in memory bank): merge + recall vs all prior runs.
    bank = _update_bank(findings, results_dir, meta)
    ledger = coverage_ledger(results_dir, meta, findings)
    rs = compute_run_status(meta, ledger=ledger)

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
        A("| 🔁 Regressed (returned after being fixed) | {0} |".format(
            lifecycle["regressed"]))
        A("| ✅ Fixed since last scan | {0} |".format(lifecycle["fixed"]))
        A("")
    else:
        A("> **Baseline scan** — no prior report of this target was found, so "
          "there is nothing to compare against yet. The next scan will track "
          "new / persisting / fixed findings against this one.")
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
    A("## 3. Findings by severity")
    A("")
    if not unique:
        A("**No findings were reported.**")
        A("")
        if not (results_dir / "README.md").exists():
            A("> The final report (`README.md`) is absent, so this may reflect an "
              "incomplete scan rather than a clean result. Check section 2.")
            A("")
    else:
        total = len(unique)
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

        A("## 4. Findings ranked by priority")
        A("")
        A("| # | ID | Severity | CWE | Title | Location |")
        A("|---|---|---|---|---|---|")
        for i, f in enumerate(unique, start=1):
            A("| {0} | {1} | **{2}** | {3} | {4} | {5} |".format(
                i, f.id, f.severity, f.normalized_cwe or f.cwe or "—",
                (f.title or "—")[:70],
                "`{0}`".format(_clean(f.location)) if f.location else "—"))
        A("")

        A("## 5. Finding detail")
        A("")
        for i, f in enumerate(unique, start=1):
            A("### {0}. [{1}] {2}".format(i, f.severity.upper(), f.title or f.id))
            A("")
            A("| Field | Value |")
            A("|---|---|")
            A("| Finding ID | {0} |".format(f.id))
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
            if f.exploitability:
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
                f.finding_state.replace("_", " ") or "statically supported"))
            if f.finding_lifecycle:
                A("| Lifecycle | {0} |".format({
                    "new": "🆕 new this scan",
                    "persisting": "➡️ persisting since last scan",
                    "regressed": "🔁 regressed (returned after being fixed)",
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

    # Findings present in the prior report and absent now — resolved or no longer
    # detected. Listed so a fix (or a detection regression) is visible, not silent.
    fixed = lifecycle.get("fixed_findings") or []
    if fixed:
        A("## 5a. Fixed since previous scan")
        A("")
        A("These were reported in `{0}` and are not present in this scan — "
          "resolved, or no longer detected. If one reappears later it will be "
          "flagged **regressed**.".format(lifecycle.get("prior_report", "the prior report")))
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
    A("- **Static analysis only.** This harness has no shell tool: exploit tests "
      "were written but never executed, and the target's dependencies were never "
      "installed. Every finding is *statically supported* — confirmed by "
      "reasoning, not by running code. Any `PASS` / `Confirmed` text carried "
      "over from the scan model is the model's own claim, shown as "
      "*Scanner-reported (unverified)*; the harness never ran the tests, so no "
      "finding is marked as an executed pass.")
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
    # Restore file:line the model dropped in the report, so dedup/votes/
    # chains work (they key on location).
    backfill_locations(findings, results_dir, meta.get("repo", ""))
    flag_duplicates(findings)
    apply_validation(findings, meta)
    apply_knowledge(findings)
    apply_normalized_severity(findings)
    findings = rank(findings)
    _apply_votes(findings, results_dir)
    # Mask secrets/PII in the finding objects so findings.json, SARIF, and the
    # ledger all derive from masked values (render() redacts its own copy for the
    # markdown/HTML). No-op unless the run opted into redaction.
    red_count = _maybe_redact(findings, meta)
    lifecycle = reconcile_lifecycle(findings, results_dir, meta)
    # render() below merges the run into the vuln ledger; this call is idempotent
    # and just returns the coverage summary for the machine-readable block.
    vuln_bank = _update_bank(findings, results_dir, meta)

    report_md = render(results_dir)
    md = results_dir / SCAN_REPORT_FILE
    md.write_text(report_md, encoding="utf-8")

    # Phase 4 is model-authored and sometimes leaves README.md as the boilerplate
    # stub (findings confirmed upstream but never written to the final report).
    # Backfill it with the deterministic consolidated report so the primary
    # human artifact is never a misleading empty page. Only when README lacks a
    # real findings table — never clobber a genuine Phase-4 report.
    readme = results_dir / "README.md"
    try:
        rd = readme.read_text(encoding="utf-8", errors="replace") if readme.exists() else ""
    except OSError:
        rd = ""
    # A real Phase-4 report has a findings table (VULN-NNN ids); the boilerplate
    # stub does not. Keying on the id pattern avoids a false "not a stub" from the
    # word "Vulnerability" in the stub's own heading.
    readme_is_stub = (not rd.strip()) or (
        len(rd) < 1500 and not re.search(r"VULN-\d", rd, re.IGNORECASE))
    if findings and readme_is_stub:
        try:
            readme.write_text(report_md, encoding="utf-8")
        except OSError:
            pass

    # Machine-readable coverage ledger for external scoring/aggregation.
    ledger = coverage_ledger(results_dir, meta, findings)
    if ledger is not None:
        (results_dir / "coverage_ledger.json").write_text(
            json.dumps(ledger.to_dict(), indent=2), encoding="utf-8")

    # HTML is the presentation layer; failure to render it must not lose the
    # markdown + JSON that already succeeded.
    try:
        from .render_html import write_html
        write_html(results_dir)
    except Exception as exc:  # pragma: no cover - defensive
        import logging
        logging.getLogger(__name__).warning("HTML report failed: %s", exc)

    run_status = compute_run_status(meta, ledger=ledger)
    counts = _counts(findings)
    finding_dicts = [f.to_dict() for f in findings]
    unique_dicts = [d for d in finding_dicts if not d.get("duplicate_of")]
    try:
        from .chains import build_chains
        chains = build_chains(unique_dicts)
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
        write_manifest(results_dir, meta, run_status, counts, redaction)
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
