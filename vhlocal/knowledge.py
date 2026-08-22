"""Deterministic per-CWE knowledge: description, exploitability, reference.

The scanner finds weaknesses in the target's OWN source code — first-party bugs,
not vulnerabilities in a released product. So the correct identifier is the
**CWE** (weakness class), never a **CVE** (which names a specific product+version
vuln). Matching a first-party finding to a CVE by weakness type would attach an
unrelated product's CVE to it — e.g. a SQLi CVE from some library stapled onto a
SQLi the app's developers wrote. That is why the `cve` field on a code finding is
"N/A": real CVEs come from dependency (SCA) scanning keyed on package+version,
which is a different capability.

This table encodes reference security knowledge as data (like sweep.py's sink
patterns), so the fields are reproducible and don't depend on the model. The
exploitability tier reflects the weakness *class*; the report pairs it with the
finding's own static-confirmation basis so nothing overstates what was proven.
"""

import re
from typing import Dict, List, Optional

# Exploitability tiers for a weakness class:
#   known       — well-documented, reliable exploitation (RCE / injection).
#   likely      — exploitable with modest effort in typical conditions.
#   conditional — needs specific timing/config/state (races, some crypto).
#   limited     — real but lower-impact on its own (redirect, info disclosure).
_TIER_LABEL = {
    "known": "Known-exploitable",
    "likely": "Likely exploitable",
    "conditional": "Conditionally exploitable",
    "limited": "Exploitable (limited impact)",
    "unknown": "See CWE reference",
}


class _Info:
    __slots__ = ("name", "description", "tier", "note")

    def __init__(self, name, description, tier, note):
        self.name = name
        self.description = description
        self.tier = tier
        self.note = note


CWE_INFO: Dict[str, _Info] = {
    "94": _Info(
        "Improper Control of Code Generation (Code Injection)",
        "Attacker-controlled input is executed as code (e.g. eval/exec), letting "
        "an attacker run arbitrary code in the application process.",
        "known", "Direct remote code execution; among the highest-impact bugs."),
    "95": _Info(
        "Improper Neutralization of Directives in Dynamically Evaluated Code (eval Injection)",
        "Input reaches eval()/exec()-style evaluation, enabling arbitrary code "
        "execution.",
        "known", "Direct remote code execution via a crafted expression."),
    "502": _Info(
        "Deserialization of Untrusted Data",
        "Attacker-controlled data is deserialized (pickle.loads, yaml.load, etc.), "
        "allowing instantiation of arbitrary objects and typically code execution.",
        "known", "Reliable RCE via crafted payloads; public gadget chains exist "
        "for common libraries."),
    "78": _Info(
        "OS Command Injection",
        "Input is incorporated into an OS command (os.system, subprocess), letting "
        "an attacker run shell commands.",
        "known", "Direct command execution on the host."),
    "89": _Info(
        "SQL Injection",
        "Untrusted input is concatenated into a SQL query, allowing an attacker to "
        "alter query logic, read/modify data, or in some engines execute commands.",
        "known", "Well-understood, tool-automatable (sqlmap); data theft and "
        "auth bypass are routine."),
    "943": _Info(
        "Improper Neutralization of Data within Query Logic (NoSQL Injection)",
        "Attacker-controlled data shapes a NoSQL query object/operator, allowing "
        "query-logic manipulation, auth bypass, or data disclosure.",
        "known", "Operator injection ($where, $ne) is a documented, reliable "
        "technique."),
    "611": _Info(
        "Improper Restriction of XML External Entity Reference (XXE)",
        "An XML parser resolves external entities/DTDs from untrusted input, "
        "enabling file disclosure, SSRF, or denial of service.",
        "known", "File read and SSRF are standard XXE outcomes."),
    "79": _Info(
        "Cross-site Scripting (XSS)",
        "Untrusted input is reflected into HTML/template output without escaping, "
        "letting an attacker run script in a victim's browser.",
        "known", "Session theft and account actions in the victim's context; "
        "extremely common and well-tooled."),
    "1336": _Info(
        "Server-Side Template Injection (SSTI)",
        "Untrusted input is evaluated by a server-side template engine, commonly "
        "escalating to remote code execution.",
        "known", "Frequently escalates to RCE via template sandbox escapes."),
    "22": _Info(
        "Path Traversal",
        "Attacker-controlled path components reach filesystem operations, allowing "
        "reads or writes outside the intended directory.",
        "known", "Arbitrary file read/write; ../ traversal is trivially exploited."),
    "601": _Info(
        "URL Redirection to Untrusted Site (Open Redirect)",
        "A redirect destination is taken from untrusted input without validation, "
        "sending users to an attacker-chosen URL.",
        "limited", "Phishing/OAuth-token theft aid; lower direct impact but a "
        "reliable primitive."),
    "918": _Info(
        "Server-Side Request Forgery (SSRF)",
        "The server makes a request to a URL derived from untrusted input, letting "
        "an attacker reach internal services or metadata endpoints.",
        "known", "Cloud metadata/internal-service access is a documented, "
        "high-impact technique."),
    "338": _Info(
        "Use of Cryptographically Weak PRNG",
        "Security-sensitive values (tokens, nonces) are generated with a non-"
        "cryptographic RNG (random module), making them predictable.",
        "conditional", "Exploitable when an attacker can observe/seed outputs; "
        "predicts tokens but requires effort."),
    "330": _Info(
        "Use of Insufficiently Random Values",
        "Predictable values are used where unpredictability is required.",
        "conditional", "Impact depends on how the value is used and observed."),
    "327": _Info(
        "Use of a Broken or Risky Cryptographic Algorithm",
        "A weak or broken algorithm/mode (MD5, SHA1, DES, ECB) is used for a "
        "security purpose.",
        "conditional", "Exploitability depends on the use (collision/forgery vs "
        "confidentiality)."),
    "367": _Info(
        "Time-of-check Time-of-use (TOCTOU) Race Condition",
        "A check and the action it guards are not atomic, so state can change in "
        "between, bypassing the check.",
        "conditional", "Requires winning a timing window; reliability varies with "
        "the target."),
    "362": _Info(
        "Concurrent Execution using Shared Resource without Proper Synchronization (Race Condition)",
        "Concurrent operations on shared state without synchronization allow an "
        "attacker to induce an inconsistent or unauthorized state.",
        "conditional", "Timing-dependent; often exploitable under concurrency."),
    "639": _Info(
        "Authorization Bypass Through User-Controlled Key (IDOR)",
        "A resource is selected by an attacker-supplied identifier without an "
        "ownership/authorization check, exposing other users' data or actions.",
        "known", "Direct, deterministic access to other principals' resources."),
    "284": _Info(
        "Improper Access Control",
        "An operation is reachable without the authorization the app's own model "
        "requires, letting an attacker act beyond their privileges.",
        "likely", "Directly exploitable when the missing check gates a sensitive "
        "operation."),
    "285": _Info(
        "Improper Authorization",
        "Authorization is missing or incorrect for an operation.",
        "likely", "Impact scales with the operation the check should have gated."),
    "862": _Info(
        "Missing Authorization",
        "A sensitive operation has no authorization check.",
        "likely", "Directly exploitable by any caller who can reach it."),
    "306": _Info(
        "Missing Authentication for Critical Function",
        "A critical function is reachable without authentication.",
        "likely", "Exploitable by any party who can reach the endpoint."),
    "269": _Info(
        "Improper Privilege Management",
        "Privilege state is assignable/escalatable in a way the app did not intend.",
        "likely", "Privilege escalation to a higher-authority role."),
    "532": _Info(
        "Insertion of Sensitive Information into Log File",
        "Secrets (tokens, passwords) are written to logs, exposing them to anyone "
        "who can read the logs.",
        "conditional", "Exploitable given log access; a strong second-order "
        "primitive (e.g. reset-token capture)."),
    "200": _Info(
        "Exposure of Sensitive Information",
        "Sensitive data is disclosed to an actor not authorized to see it.",
        "limited", "Impact depends on what is exposed; often an aid to other "
        "attacks."),
    "400": _Info(
        "Uncontrolled Resource Consumption",
        "An attacker can drive unbounded resource use (memory, DB rows, CPU), "
        "degrading or denying service.",
        "conditional", "Denial of service; impact depends on limits and scale."),
    "321": _Info(
        "Use of Hard-coded Cryptographic Key",
        "A cryptographic/signing key is hard-coded in source, so anyone with the "
        "code (or the shipped artifact) can forge or decrypt.",
        "conditional", "Enables token forgery once the key is known; requires "
        "code/secret disclosure."),
    "942": _Info(
        "Permissive Cross-domain Policy (CORS misconfiguration)",
        "An over-permissive CORS policy lets untrusted origins read authenticated "
        "responses.",
        "conditional", "Cross-origin data theft when credentials are allowed."),
}

_MITRE = "https://cwe.mitre.org/data/definitions/{0}.html"


def _cwe_num(cwe: str) -> str:
    return (cwe or "").upper().replace("CWE-", "").strip()


def describe(cwe: str) -> str:
    info = CWE_INFO.get(_cwe_num(cwe))
    if not info:
        return ""
    return "{0} ({1}): {2}".format(
        info.name, "CWE-" + _cwe_num(cwe), info.description)


def exploitability(cwe: str) -> str:
    """Class-level exploitability label + note. The report pairs this with the
    finding's own static-confirmation basis so it never overstates proof."""
    info = CWE_INFO.get(_cwe_num(cwe))
    if not info:
        return "See CWE reference — class not in the local knowledge base."
    return "{0} — {1}".format(_TIER_LABEL.get(info.tier, info.tier), info.note)


def reference(cwe: str) -> str:
    n = _cwe_num(cwe)
    if not n:
        return ""
    info = CWE_INFO.get(n)
    name = info.name if info else "CWE-" + n
    return "CWE-{0} ({1}) — {2}".format(n, name, _MITRE.format(n))


# First-party code findings do not have CVEs (a CVE names a specific
# product+version vuln, not application source). Kept explicit so a report field
# never fuzzy-matches an unrelated product's CVE.
CVE_NA = "N/A — first-party code finding (CVEs identify released products; use a dependency/SCA scan for library CVEs)"


# ---------------------------------------------------------------------------
# Standardized labelling: canonical CWE family + deterministic severity.
#
# The model relabels the same defect run-to-run (IDOR as CWE-639 / CWE-862 /
# CWE-284; CORS as CWE-346 / CWE-942) and swings the severity tier. We map each
# CWE to a canonical *family* — related CWEs (often parent/child in the MITRE
# tree) collapse to one family with one canonical CWE, name, and baseline
# severity. The model's reported cwe/severity are preserved; the normalized layer
# is derived deterministically so labels and ranking are stable across runs.
#
# Each tuple: (family_key, canonical name, canonical CWE, baseline severity,
#             member CWE numbers). A CWE listed in more than one family binds to
#             the first — order accordingly.
# ---------------------------------------------------------------------------
_FAMILIES = [
    ("code-injection", "Code Injection", "CWE-94", "High+", ["94", "95", "96"]),
    ("template-injection", "Server-Side Template Injection", "CWE-1336", "High+",
     ["1336", "917"]),
    ("deserialization", "Insecure Deserialization", "CWE-502", "High+", ["502"]),
    ("command-injection", "OS Command Injection", "CWE-78", "High+", ["78", "77"]),
    ("sql-injection", "SQL Injection", "CWE-89", "High", ["89"]),
    ("nosql-injection", "NoSQL Injection", "CWE-943", "High", ["943"]),
    ("xxe", "XML External Entity (XXE)", "CWE-611", "High", ["611", "827", "776"]),
    ("path-traversal", "Path Traversal", "CWE-22", "High", ["22", "23", "36", "73"]),
    ("ssrf", "Server-Side Request Forgery", "CWE-918", "High", ["918"]),
    ("mass-assignment", "Mass Assignment", "CWE-915", "High", ["915"]),
    ("xss", "Cross-Site Scripting", "CWE-79", "Medium", ["79", "80", "83", "116"]),
    ("open-redirect", "Open Redirect", "CWE-601", "Low", ["601"]),
    ("privilege-escalation", "Privilege Escalation", "CWE-269", "High",
     ["269", "266", "267", "250", "648"]),
    ("missing-auth", "Missing Authentication", "CWE-306", "High",
     ["306", "287", "288", "294", "302"]),
    ("access-control", "Broken Access Control", "CWE-284", "High",
     ["284", "285", "639", "862", "863", "638", "1220", "807"]),
    ("weak-auth", "Weak Authentication / Credential Handling", "CWE-640", "Medium",
     ["640", "620", "521", "522", "308", "384"]),
    ("weak-random", "Insufficient Randomness", "CWE-330", "Medium",
     ["330", "338", "331", "337", "340"]),
    ("weak-crypto", "Weak Cryptography", "CWE-327", "Medium",
     ["327", "326", "328", "916", "759", "760"]),
    ("hardcoded-secret", "Hard-coded Secret", "CWE-798", "Medium",
     ["798", "321", "259", "260", "547"]),
    ("race-condition", "Race Condition (TOCTOU)", "CWE-362", "Medium",
     ["362", "367", "364", "366", "543"]),
    ("cors", "CORS Misconfiguration", "CWE-942", "Medium", ["942", "346"]),
    ("rate-limiting", "Missing Rate Limiting", "CWE-799", "Low", ["799", "307"]),
    ("resource-exhaustion", "Uncontrolled Resource Consumption", "CWE-400", "Medium",
     ["400", "770", "834", "1050"]),
    ("timing", "Observable Timing Discrepancy", "CWE-208", "Low",
     ["208", "203", "1254"]),
    ("csrf", "Cross-Site Request Forgery", "CWE-352", "Medium", ["352"]),
    ("transport", "Improper Transport / Certificate Handling", "CWE-319", "Medium",
     ["319", "295", "297", "311", "523"]),
    ("info-disclosure", "Sensitive Information Exposure", "CWE-200", "Medium",
     ["200", "201", "209", "215", "532", "538", "215", "213"]),
]


class _Family:
    __slots__ = ("key", "name", "canonical_cwe", "severity")

    def __init__(self, key, name, canonical_cwe, severity):
        self.key = key
        self.name = name
        self.canonical_cwe = canonical_cwe
        self.severity = severity


_CWE_TO_FAMILY: Dict[str, _Family] = {}
for _key, _name, _ccwe, _sev, _members in _FAMILIES:
    _fam = _Family(_key, _name, _ccwe, _sev)
    for _m in _members:
        _CWE_TO_FAMILY.setdefault(_m, _fam)   # first family wins

# Tiers ordered most→least severe, for the precondition adjustment.
_SEV_TIERS = ["Critical", "High+", "High", "Medium", "Low", "Informational"]
_SEV_INDEX = {s: i for i, s in enumerate(_SEV_TIERS)}

# Signals in a finding's text that it requires a credential to reach — an
# auth/token gate is a precondition that narrows the attacker profile, so a gated
# finding is one tier below its unauthenticated baseline (see phase2b_verify.md:
# a gate adjusts severity, it does not eliminate the finding).
_GATED = re.compile(
    r"requires? .*(token|credential|auth|login|session)|internal[- ]?ops|"
    r"ops[-_ ]?admin|x-internal-token|_wrk_gate|authenticated (user|caller|api)",
    re.IGNORECASE)


def family_of(cwe: str):
    return _CWE_TO_FAMILY.get(_cwe_num(cwe))


def normalized_cwe(cwe: str) -> str:
    fam = family_of(cwe)
    return fam.canonical_cwe if fam else (("CWE-" + _cwe_num(cwe)) if _cwe_num(cwe) else "")


def canonical_name(cwe: str) -> str:
    fam = family_of(cwe)
    if fam:
        return fam.name
    info = CWE_INFO.get(_cwe_num(cwe))
    return info.name if info else ""


def normalized_severity(cwe: str, gated_text: str = "") -> str:
    """Deterministic severity: the family baseline, dropped one tier when the
    finding is gated behind authentication (a precondition, not a mitigation)."""
    fam = family_of(cwe)
    if not fam:
        return ""
    base = fam.severity
    if gated_text and _GATED.search(gated_text):
        i = min(_SEV_INDEX.get(base, 3) + 1, len(_SEV_TIERS) - 1)
        return _SEV_TIERS[i]
    return base


def apply_knowledge(findings) -> None:
    """Populate the deterministic reference + normalized-label fields on each
    finding. Preserves the model's reported cwe/severity (in .cwe/.severity);
    adds the normalized layer used for stable display and ranking."""
    for f in findings:
        if not getattr(f, "description", ""):
            f.description = describe(f.cwe)
        if not getattr(f, "exploitability", ""):
            f.exploitability = exploitability(f.cwe)
        if not getattr(f, "reference", ""):
            f.reference = reference(f.cwe)
        if not getattr(f, "cve", ""):
            f.cve = CVE_NA
        # Standardized labels — always recomputed (deterministic).
        f.normalized_cwe = normalized_cwe(f.cwe)
        fam = family_of(f.cwe)
        f.cwe_family = fam.key if fam else ""
        f.canonical_name = canonical_name(f.cwe)
        gated = " ".join(str(x) for x in (
            f.exploitability, f.data_flow, f.entry_point, f.status, f.title))
        f.normalized_severity = normalized_severity(f.cwe, gated)
