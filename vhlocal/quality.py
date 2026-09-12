"""Deterministic source checks used by reporting and structured verification.

A matching sink is a corroborating signal, not proof of exploitability. In new
scans, verification.py requires a candidate-bound decision, source quotes, full
function context and reasoning before publication. These checks veto structural
or source contradictions in those decisions.

Legacy report replays retain the lenient/balanced/strict sink policies. Logic and
authorization claims remain hypotheses without a source-grounded review; sample
agreement and recognized guard names do not establish effective permissions.
"""

import ast
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
    # Sub-kind for an NA source result, so the decision can tell "the checker has
    # no rule for this class" (uncovered — retain uncertainty, do not substantiate
    # on prose) apart from "the checkout wasn't available to look" (unavailable —
    # a re-render, keep the tier via other signals). "" for non-source checks.
    kind: str = ""

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
    """Resolve only in-tree, unambiguous paths; never choose the first basename hit."""
    if repo is None:
        return None
    m = _FILE.search(location or "")
    if not m:
        return None
    repo = Path(repo).resolve()
    rel = m[1]
    if Path(rel).is_absolute() or ".." in Path(rel).parts:
        return None
    candidate = (repo / rel).resolve()
    if candidate.is_relative_to(repo) and candidate.is_file():
        return candidate
    matches = [p.resolve() for p in repo.rglob(Path(rel).name)
               if p.is_file() and p.as_posix().endswith("/" + rel)
               and p.resolve().is_relative_to(repo)]
    return matches[0] if len(matches) == 1 else None


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


def _source_window(finding, repo: Optional[Path]) -> Optional[str]:
    """The cited source text — the whole cited line range padded by a small window,
    or the whole file when no line is given. None when it can't be read."""
    if repo is None:
        return None
    src = _resolve_source(getattr(finding, "location", ""), repo)
    if src is None:
        return None
    try:
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    m = _LOC.search(getattr(finding, "location", "") or "")
    if not m:
        return "\n".join(lines)
    start = int(m.group(2))
    end = int(m.group(3)) if m.group(3) else start
    if end < start:
        start, end = end, start
    lo = max(0, start - 1 - _SOURCE_WINDOW)
    hi = min(len(lines), end + _SOURCE_WINDOW)
    return "\n".join(lines[lo:hi])


def _enclosing_function_source(finding, repo: Optional[Path]) -> Optional[str]:
    """Just the source of the function CONTAINING the cited line — so a
    context check (e.g. HTML vs JSON response) can't bleed into a neighbouring
    handler the way a fixed line window can. None when unavailable / not in a
    function."""
    if repo is None:
        return None
    src = _resolve_source(getattr(finding, "location", ""), repo)
    if src is None:
        return None
    m = _LOC.search(getattr(finding, "location", "") or "")
    if not m:
        return None
    line = int(m.group(2))
    try:
        text = src.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text)
    except (OSError, SyntaxError, ValueError):
        return None
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            if node.lineno <= line <= end and (best is None or node.lineno > best.lineno):
                best = node
    if best is None:
        return None
    try:
        return ast.get_source_segment(text, best)
    except (ValueError, TypeError):
        return None


def check_source_corroborated(finding, repo: Optional[Path]) -> Check:
    """Does the real source at the cited location contain a sink for this CWE?

    The NA ``kind`` matters downstream: ``logic`` (no syntactic sink — the logic
    path handles it), ``uncovered`` (the checker has no rule for this class — it
    CANNOT assess, so prose must not substantiate it), or ``unavailable`` (the
    checkout could not be read — a re-render; keep the tier via other signals)."""
    if _is_logic_cwe(finding):
        return Check("source_corroborated", NA,
                     "authorization/logic class — no syntactic sink to corroborate",
                     kind="logic")
    cwe = getattr(finding, "cwe", "") or getattr(finding, "normalized_cwe", "")
    # AUTHORITATIVE, family-normalized patterns only — never call tokens pulled
    # from the model's own data-flow prose. Otherwise a narrative naming
    # ``find_one`` lets a Mongo call corroborate an SSRF label.
    pats, note = sink_patterns(cwe)
    if not pats:
        return Check("source_corroborated", NA,
                     note or "the checker has no rule for this class", kind="uncovered")
    if repo is None:
        return Check("source_corroborated", NA,
                     "source unavailable (no checkout) to corroborate", kind="unavailable")
    window = _source_window(finding, repo)
    if window is None:
        return Check("source_corroborated", NA,
                     "cited source file not found or unreadable", kind="unavailable")
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


# --- class-specific evidence (agreement is not proof) -----------------------
# Some weakness classes need more than "a sink is present": the value must reach a
# security-sensitive consumer, or a declared defense must be absent. Model
# agreement (votes / Phase-2b) never substitutes for this.

_RANDOM_CWES = {"330", "338"}
_RACE_UNIQUE_CWES = {"362", "367"}
# Broken-access-control classes — an IDOR / missing-authz claim can be REFUTED when
# the accused handler demonstrably enforces an authorization guard (authz.py). We
# refute on present evidence only; absence of a guard does not prove the intended
# permission (that stays model-bound), so a missing guard is NA, not a pass.
_ACCESS_CONTROL_CWES = {"639", "862", "863", "284", "285", "638", "1220", "807", "566", "668"}
_XSS_CWES = {"79", "80", "83", "116"}
_CORS_CWES = {"942", "346"}
# Classes where class_evidence is the PRIMARY evidence (there is no syntactic sink
# to corroborate): a PASS establishes the security consequence and substantiates on
# its own; anything else is a hypothesis. (Contrast the VETO classes, where
# class_evidence only demotes on contradicting evidence.)
_PRIMARY_EVIDENCE_CWES = _CORS_CWES

# XSS: an HTML/unescaped sink vs a JSON response (which auto-escapes → not XSS).
_HTML_SINK = re.compile(
    r"(?i)HTMLResponse\s*\(|render_template_string|mark_safe|\bMarkup\s*\(|"
    r"\|\s*safe\b|text/html|\.write\s*\(\s*['\"]?<")
_JSON_RESPONSE = re.compile(
    r"(?i)JSONResponse|\bjsonify\s*\(|application/json|return\s+[\{\[]|"
    r"response_model\s*=|media_type\s*=\s*['\"]application/json")

# CORS: credentialed + wildcard/reflected origin is the exploitable shape.
_CORS_MW = re.compile(r"CORSMiddleware|add_middleware|CORS\s*\(", re.I)
_CORS_CREDS = re.compile(r"allow_credentials\s*=\s*True|supports_credentials\s*=\s*True", re.I)
_CORS_WILDCARD = re.compile(
    r"allow_origins\s*=\s*\[?\s*['\"]\*['\"]|origins\s*=\s*\[?\s*['\"]\*['\"]|"
    r"allow_origin_regex\s*=\s*['\"]\.?\*|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*", re.I)


_CORS_CACHE: dict = {}


def _cors_danger(repo: Optional[Path]):
    """Scan the repo for a CORS middleware config and classify it. Returns
    ``(dangerous, detail)`` or ``None`` when no CORS config is found. Dangerous =
    credentials allowed AND a wildcard/reflected origin (credentialed cross-origin
    data theft); a restrictive or credential-less CORS is not exploitable that way.
    Cached per repo (scanned once per assess pass)."""
    if repo is None:
        return None
    key = str(repo)
    if key in _CORS_CACHE:
        return _CORS_CACHE[key]
    result = None
    try:
        for p in Path(repo).rglob("*.py"):
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not _CORS_MW.search(text):
                continue
            creds = bool(_CORS_CREDS.search(text))
            wild = bool(_CORS_WILDCARD.search(text))
            if creds and wild:
                result = (True, "allow_credentials=True with a wildcard/reflected origin")
                break
            # Remember a found-but-safe config; keep scanning for a dangerous one.
            if result is None:
                result = (False, "CORS configured without credentialed wildcard access")
    except OSError:
        pass
    _CORS_CACHE[key] = result
    return result

# A weak-random value only matters where a security DECISION depends on it. This
# requires an actual use site — the value STORED INTO a security-sensitive name, or
# reaching a security sink — not a security word appearing in a route/variable name
# or a comment. Names (`nonce`, `token`, `secret`) alone cannot establish it.
_SEC_NAME = (r"token|secret|password|passwd|api[_-]?key|apikey|private[_-]?key|"
             r"nonce|csrf|xsrf|session[_-]?id|otp|mfa|2fa|salt|reset[_-]?token|"
             r"signature|hmac|jwt|credential|auth[_-]?code|access[_-]?code")
_SECURITY_CONSUMER = re.compile(
    # stored into a security-sensitive name: `token =`, `self.reset_token =`, `otp:`
    r"(?:\b|\.)(?:" + _SEC_NAME + r")\w*\s*[=:]"
    # or reaching a security sink
    r"|set_cookie|session\[|\.session\b|jwt\.(encode|decode)|hmac\.|"
    r"hashlib\.\w+\(|secrets\.compare_digest|check_password|verify_password|"
    r"set_password|headers\[['\"]?authorization|Authorization\s*:", re.I)

# A declared uniqueness/atomicity defense that refutes a "missing uniqueness /
# duplicate-insert race" claim.
_UNIQUE_DEFENSE = re.compile(
    r"(?i)unique\s*=\s*true|UniqueConstraint|@unique\b|unique\s+index|"
    r"primary_key\s*=\s*true|select_for_update|with_for_update|for\s+update")
# A field reference the claim is about (e.g. User.email, `email`), used to scope
# the repo search for its uniqueness declaration.
_FIELD_REF = re.compile(r"\b([A-Za-z_]\w{2,})\.([A-Za-z_]\w{2,})\b")


def _repo_declares_unique(repo: Optional[Path], field: str) -> bool:
    """Whether the repo declares a uniqueness/atomicity defense on ``field``
    (best-effort, conservative — only a same-line unique declaration counts)."""
    if repo is None or not field:
        return False
    pat = re.compile(re.escape(field) + r".{0,80}(unique\s*=\s*true|UniqueConstraint)"
                     r"|(UniqueConstraint|unique\s*=\s*true).{0,80}" + re.escape(field),
                     re.I)
    try:
        for p in repo.rglob("*.py"):
            if not p.is_file():
                continue
            try:
                if pat.search(p.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                continue
    except OSError:
        pass
    return False


def check_class_evidence(finding, repo: Optional[Path]) -> Check:
    """Class-specific evidence for classes where a sink alone (or agreement) does
    not establish a vulnerability. Returns NA for classes without a rule."""
    num = _cwe_num(getattr(finding, "cwe", "") or getattr(finding, "normalized_cwe", ""))
    ctx = "{0} {1}".format(getattr(finding, "data_flow", "") or "",
                           getattr(finding, "title", "") or "")

    if re.search(r"template injection|\bSSTI\b", getattr(finding, "title", ""), re.I):
        import textwrap
        source = _enclosing_function_source(finding, repo)
        try:
            tree = ast.parse(textwrap.dedent(source)) if source else None
        except SyntaxError:
            tree = None
        templates = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                     and (getattr(n.func, "id", "") == "Template"
                          or getattr(n.func, "attr", "") == "from_string")] if tree else []
        if templates and all(n.args and isinstance(n.args[0], ast.Constant)
                             and isinstance(n.args[0].value, str) for n in templates):
            return Check("class_evidence", FAIL,
                         "template source is constant; rendering attacker data does not "
                         "evaluate it as template source (HTML injection needs a separate claim)")

    if num in _RANDOM_CWES:
        # A security word appearing SOMEWHERE (a route name, a comment) does not
        # establish that a security decision depends on the value. Require a real
        # USE SITE: the value stored into a security-sensitive name, or reaching a
        # security sink (cookie/session/jwt/hmac/…). If the source can't be read,
        # the required relationship cannot be established → not supported.
        window = _source_window(finding, repo)
        if window is None:
            return Check("class_evidence", FAIL,
                         "cannot establish a security-sensitive consumer for the "
                         "weak-random value without the source")
        m = _SECURITY_CONSUMER.search(window)
        if m:
            return Check("class_evidence", PASS,
                         "the weak-random value reaches a security-sensitive consumer "
                         "(`{0}`)".format(m.group(0).strip()[:40]))
        return Check("class_evidence", FAIL,
                     "no security-sensitive USE SITE for the weak-random value (a "
                     "security word in a route/variable name is not a consumer) — "
                     "weak randomness with no security decision is not a vulnerability")

    if num in _ACCESS_CONTROL_CWES:
        if repo is None:
            return Check("class_evidence", NA,
                         "cannot check for an authorization guard without the checkout")
        from . import authz
        route = authz.guard_for_location(
            authz.authz_routes_cached(repo), getattr(finding, "location", ""))
        guards = ", ".join(route.authz_guards) if route else ""
        return Check("class_evidence", NA,
                     "authorization requires a source-grounded review of the claimed "
                     "permission, object/tenant scope, and complete control flow; "
                     + ("declared guards ({0}) do not establish that scope".format(guards)
                        if guards else "guard-name detection cannot establish effective permissions"))

    if num in _XSS_CWES:
        # XSS needs an HTML context. A value reflected into a JSON response is
        # auto-escaped by the serializer — not XSS in a browser. Scope to the
        # CONTAINING function (not a line window) so a neighbouring handler's
        # HTMLResponse can't be mistaken for this one's response.
        window = _enclosing_function_source(finding, repo)
        if window is None:
            return Check("class_evidence", NA,
                         "cannot determine the response context (not inside a "
                         "readable function)")
        if _HTML_SINK.search(window):
            return Check("class_evidence", PASS,
                         "the value reaches an HTML/unescaped response context")
        if _JSON_RESPONSE.search(window):
            return Check("class_evidence", FAIL,
                         "the value is reflected into a JSON response (auto-escaped) "
                         "with no HTML sink — not XSS in a browser context")
        return Check("class_evidence", NA,
                     "response context undeterminable (no clear HTML or JSON sink)")

    if num in _CORS_CWES:
        # Primary evidence: a CORS misconfig is only exploitable for credentialed
        # cross-origin theft when credentials are allowed AND the origin is
        # wildcard/reflected. Establish that from the middleware config.
        cors = _cors_danger(repo)
        if cors is None:
            return Check("class_evidence", NA,
                         "no CORS middleware configuration found to assess"
                         if repo is not None else
                         "cannot check the CORS configuration without the checkout")
        dangerous, detail = cors
        if dangerous:
            return Check("class_evidence", PASS, detail)
        return Check("class_evidence", FAIL,
                     detail + " — not exploitable for credentialed cross-origin theft")

    if num in _RACE_UNIQUE_CWES and re.search(r"(?i)uniqu|duplicat", ctx):
        for m in _FIELD_REF.finditer(ctx):
            field = m.group(2)
            if field.lower() in ("get", "post", "json", "body", "data", "query"):
                continue
            if _repo_declares_unique(repo, field):
                return Check("class_evidence", FAIL,
                             "the cited codebase declares a uniqueness constraint on "
                             "`{0}` — the claimed missing-uniqueness gap is enforced".format(field))
        return Check("class_evidence", PASS,
                     "no declared uniqueness/atomicity defense refutes the claim")

    return Check("class_evidence", NA, "no class-specific rule for this weakness class")


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
                     "{0} of {1} hunt samples reported this site (agreement is not proof)".format(
                         votes, samples or votes))
    return Check("agreement", FAIL, "a single, unverified report")


# --- tier decision ----------------------------------------------------------

def _decide(level: str, is_logic: bool, src: str, src_kind: str, flow: bool,
            agree: bool, precise: bool) -> Tuple[bool, str]:
    """Return (substantiated, why) from the check outcomes for a strictness level.

    ``src`` is the source_corroborated status; ``src_kind`` distinguishes the NA
    cases. PASS = a sink was found; FAIL = checked and absent; NA/uncovered = the
    checker has no rule for this class (CANNOT assess — prose must not substantiate
    it, retain uncertainty / review); NA/unavailable = the checkout couldn't be
    read (a re-render — keep the tier via other signals)."""
    src_pass = src == PASS
    src_fail = src == FAIL
    uncovered = src == NA and src_kind == "uncovered"

    if level == LENIENT:
        # Even lenient does not let prose substantiate a class the checker cannot
        # assess — that is "unknown", not "supported".
        if uncovered and not src_pass:
            return False, ("the checker has no rule for this class — cannot assess; "
                           "retained as a hypothesis for review")
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

    # Sink class. An uncovered class can never be substantiated statically — the
    # checker cannot confirm the operation matches the claim, so prose/agreement do
    # not promote it; it is a hypothesis pending review or a new detector rule.
    if uncovered:
        return False, ("the checker has no rule for this weakness class — it cannot "
                       "assess whether the source performs the claimed operation; "
                       "retained as a hypothesis for review, not supported on prose")

    if level == BALANCED:
        if src_pass:
            return True, "the cited source contains a matching sink"
        if src_fail:
            return False, "the cited source contains no matching sink for this class"
        ok = flow or agree           # source unavailable (re-render) → other signals
        return ok, ("source unavailable to check; carried by a data flow or agreement" if ok
                    else "source unavailable and no data flow or agreement to corroborate")

    # STRICT sink class.
    if src_pass:
        ok = flow or agree
        return ok, ("a matching sink plus a second corroborating signal" if ok
                    else "a matching sink but no second corroborating signal")
    if src_fail:
        return False, "the cited source contains no matching sink for this class"
    ok = flow and agree              # source unavailable (re-render) → require both
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
        check_class_evidence(finding, repo),
    ]
    by_name = {c.name: c for c in checks}

    # Structural floor — fail any of these and it is a bare hypothesis, at every
    # level. (location_precise is not a floor; it feeds the logic-class rule.)
    for name in ("weakness_class", "concrete_claim", "location_resolves"):
        if by_name[name].status == FAIL:
            return QualityResult(False, level,
                                 "Hypothesis — " + by_name[name].reason, checks)

    # Class-specific evidence is a VETO — a class whose specific requirement is
    # contradicted (a weak-random value with no security-sensitive consumer; a
    # declared uniqueness constraint; an IDOR handler that in fact enforces authz;
    # a reflected value returned as JSON) is not substantiated, regardless of how
    # many runs agreed. Agreement prioritises review; it does not replace evidence.
    class_ev = by_name["class_evidence"]
    if class_ev.status == FAIL:
        return QualityResult(False, level,
                             "Hypothesis — " + class_ev.reason, checks)

    # Primary-evidence classes have no syntactic sink to corroborate — the
    # class-specific check IS the evidence (a credentialed wildcard CORS config).
    # A PASS establishes the consequence and substantiates; anything else stays a
    # hypothesis, never promoted on prose.
    num = _cwe_num(getattr(finding, "cwe", "") or getattr(finding, "normalized_cwe", ""))
    if num in _PRIMARY_EVIDENCE_CWES:
        if class_ev.status == PASS:
            return QualityResult(True, level,
                                 "Statically supported ({0} checks): {1}.".format(
                                     level, class_ev.reason), checks)
        return QualityResult(False, level,
                             "Hypothesis ({0} checks): the security consequence for "
                             "this class was not established ({1}).".format(
                                 level, class_ev.reason), checks)

    is_logic = _is_logic_cwe(finding)
    if is_logic:
        return QualityResult(False, level,
                             "Hypothesis — authorization and business-logic claims require "
                             "a source-grounded review of defenses and security impact; "
                             "prose and sample agreement are insufficient", checks)
    src_check = by_name["source_corroborated"]
    src = src_check.status
    flow = by_name["flow_described"].status == PASS
    agree = by_name["agreement"].status == PASS
    precise = by_name["location_precise"].status == PASS

    ok, why = _decide(level, is_logic, src, src_check.kind, flow, agree, precise)
    if ok:
        reason = "Statically supported ({0} checks): {1}.".format(level, why)
    else:
        reason = "Hypothesis ({0} checks): {1}.".format(level, why)
    return QualityResult(ok, level, reason, checks)
