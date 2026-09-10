"""Pre-report quality checks — corroborate a candidate against the actual source
before it is published as a substantiated finding.

The gap this closes: the harness used to promote a candidate to a substantiated
finding on *metadata completeness alone* (a CWE, a concrete title, a file that
exists). A model could write "SQL injection at users.py:81 (CWE-89)" and it would
publish even if nothing near line 81 executes a query. That over-reports. The
opposite extreme — demanding an external source-grounded review for everything —
under-reports (every scan becomes zero findings). This module is the happy medium:
a battery of *deterministic* checks the harness runs against the real code, so the
"statically supported" tier is earned by corroboration, not by filled-in fields.

Three checks corroborate a claim, none of which trust model prose:

* ``source_corroborated`` — read the cited source (a window around the line) and
  test whether it contains a sink pattern for the finding's CWE (reusing the
  ``sweep`` pattern table, plus any call token named in the data flow). N/A for
  logic/authorization classes (IDOR, missing-authz, TOCTOU), which have no
  syntactic sink to match.
* ``flow_described`` — the finding describes a real source→sink / ownership-gap
  data flow, not a one-word stub.
* ``agreement`` — independent corroboration: ≥2 hunt samples reported the same
  site (``votes``) or the finding came through the Phase-2b verification pass
  (``from_confirmed``).

How much corroboration the middle tier demands is the ``level`` dial:

* ``lenient``  — any one corroboration signal (for any class).
* ``balanced`` — sink classes MUST show a source pattern (a checked-and-absent
  pattern demotes to hypothesis); logic classes need flow + a line-precise
  location + agreement. When the source can't be checked (no checkout / no
  derivable pattern) the benefit of the doubt falls back to flow-or-agreement.
* ``strict``   — sink classes need a source pattern AND a second signal; logic
  classes need flow + precise location + agreement.

All checks are deterministic and side-effect free, so the result is reproducible
and unit-testable.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional, Tuple

from .sweep import _LOGIC_CWES, sink_patterns

LENIENT = "lenient"
BALANCED = "balanced"
STRICT = "strict"
LEVELS = (LENIENT, BALANCED, STRICT)
DEFAULT_LEVEL = BALANCED

# Lines of context each side of the cited line to scan for a sink pattern. The
# model's line number drifts, and the sink often sits a few lines from the cited
# entry point, so a small window is more robust than an exact-line match.
_SOURCE_WINDOW = 8

# Check status values.
PASS = "pass"
FAIL = "fail"
NA = "na"

# Captures a file and its cited line — or line RANGE (``file:50-62``). The range
# end matters: a sink can sit anywhere in the range the finding cites, so
# corroboration must scan the whole span, not just around the start line.
_LOC = re.compile(r"([\w./+\-]+\.[A-Za-z0-9]{1,6}):(\d+)(?:\s*[-–—]\s*(\d+))?")
_FILE = re.compile(r"([\w./+\-]+\.[A-Za-z0-9]{1,6})")


def normalize_level(level: Optional[str]) -> str:
    """Coerce any input to a known strictness level; unknown/empty → default."""
    return level if level in LEVELS else DEFAULT_LEVEL


@dataclass
class Check:
    name: str
    status: str          # PASS | FAIL | NA
    reason: str

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "reason": self.reason}


@dataclass
class QualityResult:
    substantiated: bool
    level: str
    reason: str                       # one-line summary for the report
    checks: List[Check] = field(default_factory=list)

    def checks_as_dicts(self) -> List[dict]:
        return [c.to_dict() for c in self.checks]


# --- individual checks ------------------------------------------------------
# Each takes the finding (a consolidate.Finding or any object with the same
# attributes) and returns a Check. Structural checks reuse consolidate's own
# predicates (lazy import avoids a circular dependency at module load).

def _clean(text: str) -> str:
    return (text or "").strip()


def _cwe_num(cwe: str) -> str:
    return (cwe or "").upper().replace("CWE-", "").strip()


def _is_logic_cwe(finding) -> bool:
    for cwe in (getattr(finding, "cwe", ""), getattr(finding, "normalized_cwe", "")):
        if _cwe_num(cwe) in _LOGIC_CWES:
            return True
    return False


def _resolve_source(location: str, repo: Optional[Path]) -> Optional[Path]:
    """The cited file inside the repo, or a basename match anywhere in the tree
    (the model often omits a leading package dir). None if unavailable."""
    if repo is None:
        return None
    m = _FILE.search(location or "")
    if not m:
        return None
    rel = m.group(1).strip()
    cand = repo / rel
    if cand.is_file():
        return cand
    name = Path(rel).name
    try:
        for p in repo.rglob(name):
            if p.is_file():
                return p
    except OSError:
        pass
    return None


def check_weakness_class(finding) -> Check:
    if _clean(getattr(finding, "cwe", "")) or _clean(getattr(finding, "normalized_cwe", "")):
        return Check("weakness_class", PASS, "a weakness class (CWE) is assigned")
    return Check("weakness_class", FAIL, "no weakness class (CWE) assigned")


# A title that is a verdict fragment or a bare id-echo carries no claim on its own.
# (A precise endpoint slug like ``dispatch-fan-304`` is SPECIFIC, not generic, so
# it is deliberately NOT treated as weak here — claim completeness is judged by the
# structured fields, per the audit, not by title wording.)
_NON_CLAIM_TITLE = re.compile(r"^(yes|no|n/?a|true|false|confirmed|pass|fail|"
                              r"unverified|unknown)\b|^[-–—\s]*$", re.I)


def check_concrete_claim(finding) -> Check:
    from .consolidate import _is_placeholder
    if _is_placeholder(finding):
        return Check("concrete_claim", FAIL,
                     "reads as an input-inventory / placeholder row, not a weakness claim")
    title = _clean(getattr(finding, "title", ""))
    fid = getattr(finding, "id", "") or ""
    # The claim is carried by a real title OR by structured evidence (a described
    # data flow). Only a bare verdict/id-echo with no flow fails to name a weakness.
    if (not title or title.upper() == fid.upper() or _NON_CLAIM_TITLE.match(title)) \
            and not _clean(getattr(finding, "data_flow", "")):
        return Check("concrete_claim", FAIL,
                     "no specific weakness claim (a verdict/placeholder title and no data flow)")
    return Check("concrete_claim", PASS, "names a specific weakness (title or structured evidence)")


def check_location_resolves(finding, repo: Optional[Path]) -> Check:
    from .consolidate import _location_resolves
    loc = _clean(getattr(finding, "location", ""))
    if not loc:
        return Check("location_resolves", FAIL, "no source location was cited")
    if _location_resolves(loc, repo):
        # _location_resolves is lenient when the checkout is unavailable.
        if repo is None:
            return Check("location_resolves", PASS,
                         "location cited (checkout unavailable to verify)")
        return Check("location_resolves", PASS, "cited file resolves against the scanned tree")
    return Check("location_resolves", FAIL, "cited file does not resolve against the scanned tree")


def check_location_precise(finding) -> Check:
    if _LOC.search(getattr(finding, "location", "") or ""):
        return Check("location_precise", PASS, "location is line-precise")
    return Check("location_precise", FAIL, "location names a file but no line")


def check_source_corroborated(finding, repo: Optional[Path]) -> Check:
    """Does the real source at the cited location contain a sink for this CWE?"""
    if _is_logic_cwe(finding):
        return Check("source_corroborated", NA,
                     "authorization/logic class — no syntactic sink to corroborate")
    cwe = getattr(finding, "cwe", "") or getattr(finding, "normalized_cwe", "")
    # AUTHORITATIVE patterns only — never call tokens pulled from the model's own
    # data-flow prose. Otherwise a narrative naming ``find_one`` lets a Mongo call
    # corroborate an SSRF label; corroboration must test the operation the CWE
    # actually describes.
    pats, note = sink_patterns(cwe)
    if not pats:
        return Check("source_corroborated", NA,
                     note or "no authoritative sink pattern for this class")
    if repo is None:
        return Check("source_corroborated", NA, "source unavailable (no checkout) to corroborate")
    src = _resolve_source(getattr(finding, "location", ""), repo)
    if src is None:
        return Check("source_corroborated", NA, "cited source file not found to corroborate")
    try:
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return Check("source_corroborated", NA, "cited source could not be read")
    m = _LOC.search(getattr(finding, "location", "") or "")
    if m:
        # Scan the WHOLE cited range (start..end), padded by a small window — the
        # sink can be anywhere the finding pointed at, not just the first line.
        start = int(m.group(2))
        end = int(m.group(3)) if m.group(3) else start
        if end < start:
            start, end = end, start
        lo = max(0, start - 1 - _SOURCE_WINDOW)
        hi = min(len(lines), end + _SOURCE_WINDOW)
        window = "\n".join(lines[lo:hi])
    else:
        window = "\n".join(lines)   # no line: scan the whole cited file
    for p in pats:
        try:
            if re.search(p, window):
                return Check("source_corroborated", PASS,
                             "a sink pattern for {0} is present at the cited location".format(
                                 cwe or "this class"))
        except re.error:
            continue
    return Check("source_corroborated", FAIL,
                 "no sink pattern for {0} near the cited location".format(cwe or "this class"))


_FLOW_CONNECTIVE = re.compile(
    r"->|→|\b(reach(es|ed)?|flows?\s+to|passed?\s+(to|unchanged|into)|"
    r"propagat\w*|concatenat\w*|interpolat\w*|used\s+(in|as)|into\s+the?)\b", re.I)


def check_flow_described(finding) -> Check:
    """A data flow corroborates only if it actually *traces* attacker input to an
    operation — a causal connective linking two parts. Length/word-count is not
    evidence (a long paragraph of prose describing a maybe-bug is not a flow), so
    it no longer passes on its own."""
    df = _clean(getattr(finding, "data_flow", ""))
    if not df or len(df) < 12:
        return Check("flow_described", FAIL, "no data flow described")
    if _FLOW_CONNECTIVE.search(df):
        return Check("flow_described", PASS,
                     "the data flow traces attacker input through to an operation")
    return Check("flow_described", FAIL,
                 "the data flow does not trace input to an operation (prose, not a flow)")


def check_agreement(finding) -> Check:
    votes = int(getattr(finding, "votes", 0) or 0)
    samples = int(getattr(finding, "vote_samples", 0) or 0)
    if votes >= 2:
        return Check("agreement", PASS,
                     "{0} of {1} independent hunt samples reported this site".format(
                         votes, samples or votes))
    if getattr(finding, "from_confirmed", False):
        return Check("agreement", PASS, "confirmed by the Phase-2b verification pass")
    return Check("agreement", FAIL, "a single, unverified report")


# --- tier decision ----------------------------------------------------------

def _decide(level: str, is_logic: bool, src: str, flow: bool, agree: bool,
            precise: bool) -> Tuple[bool, str]:
    """Return (substantiated, why) from the check outcomes for a strictness level.

    ``src`` is the source_corroborated status (PASS/FAIL/NA). PASS = a sink was
    found; FAIL = checked and absent (the discriminating demotion); NA = could not
    check (no checkout, no derivable pattern, or a logic class)."""
    src_pass = src == PASS
    src_fail = src == FAIL

    if level == LENIENT:
        ok = src_pass or flow or agree
        return ok, ("a corroborating signal is present" if ok
                    else "no corroborating signal (source, data flow, or agreement)")

    if is_logic:
        ok = flow and precise and agree
        if ok:
            return True, "logic finding: a data flow, a precise location, and independent agreement"
        missing = []
        if not flow:
            missing.append("a described data flow")
        if not precise:
            missing.append("a line-precise location")
        if not agree:
            missing.append("independent agreement (votes or Phase-2b)")
        return False, "logic finding lacks " + ", ".join(missing)

    # Sink class.
    if level == BALANCED:
        if src_pass:
            return True, "the cited source contains a matching sink"
        if src_fail:
            return False, "the cited source contains no matching sink for this class"
        ok = flow or agree           # couldn't check the source → other signals
        return ok, ("source uncheckable; carried by a data flow or agreement" if ok
                    else "source uncheckable and no data flow or agreement to corroborate")

    # STRICT sink class.
    if src_pass:
        ok = flow or agree
        return ok, ("a matching sink plus a second corroborating signal" if ok
                    else "a matching sink but no second corroborating signal")
    if src_fail:
        return False, "the cited source contains no matching sink for this class"
    ok = flow and agree              # couldn't check the source → require both
    return ok, ("source uncheckable; carried by a data flow and agreement" if ok
                else "source uncheckable without both a data flow and agreement")


def evaluate(finding, repo: Optional[Path], level: Optional[str]) -> QualityResult:
    """Run the full quality battery and decide whether ``finding`` is
    substantiated at the given strictness ``level``."""
    level = normalize_level(level)
    checks: List[Check] = [
        check_weakness_class(finding),
        check_concrete_claim(finding),
        check_location_resolves(finding, repo),
        check_location_precise(finding),
        check_source_corroborated(finding, repo),
        check_flow_described(finding),
        check_agreement(finding),
    ]
    by_name = {c.name: c for c in checks}

    # Structural floor — fail any of these and it is a bare hypothesis, at every
    # level. (location_precise is not a floor; it feeds the logic-class rule.)
    for name in ("weakness_class", "concrete_claim", "location_resolves"):
        if by_name[name].status == FAIL:
            return QualityResult(False, level,
                                 "Hypothesis — " + by_name[name].reason, checks)

    is_logic = _is_logic_cwe(finding)
    src = by_name["source_corroborated"].status
    flow = by_name["flow_described"].status == PASS
    agree = by_name["agreement"].status == PASS
    precise = by_name["location_precise"].status == PASS

    ok, why = _decide(level, is_logic, src, flow, agree, precise)
    if ok:
        reason = "Statically supported ({0} checks): {1}.".format(level, why)
    else:
        reason = "Hypothesis ({0} checks): {1}.".format(level, why)
    return QualityResult(ok, level, reason, checks)
