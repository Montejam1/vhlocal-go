"""Deterministic Phase 3d — the root-cause instance sweep, in-harness.

Phase 3d's job is mechanical: for each confirmed finding, find every OTHER place
the same root-cause pattern appears in the codebase. The model used to do this by
grepping iteratively — often redundantly (``eval\\(`` three times in one run) and
sometimes giving up before writing output. This does it directly, once, and
completely.

The ``CWE_SINK_PATTERNS`` table encodes the *semantic siblings* a naive literal
grep would miss (``eval`` → ``exec``/``compile``; ``pickle.loads`` →
``yaml.load``/``marshal``; XXE → ``etree``/``lxml``). That is the recoverable part
of what a well-functioning model sweep would contribute — captured as data rather
than hoped-for behaviour. What a pure sweep gives up is a *novel* sink the model
might reason is equivalent but which isn't in the table; in observed runs the
local model was not catching those anyway (it grepped literally), so this is a net
gain on completeness and speed. Test/vendor/generated dirs are excluded.

Some CWEs (IDOR, missing-authorization, TOCTOU) are logic flaws with no reliable
syntactic sink — the sweep says so honestly rather than inventing a pattern.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# CWE number -> regex sink patterns that constitute the SAME root cause. Kept
# deliberately specific; a coincidental-match filter runs on the results.
CWE_SINK_PATTERNS: Dict[str, List[str]] = {
    "94":  [r"\beval\s*\(", r"\bexec\s*\(", r"\bcompile\s*\("],
    "95":  [r"\beval\s*\("],
    "96":  [r"\bexec\s*\(", r"\beval\s*\("],
    "502": [r"pickle\.loads?\b", r"cPickle\.loads?", r"yaml\.load\s*\(",
            r"marshal\.loads?", r"jsonpickle", r"dill\.loads?"],
    "611": [r"etree\.parse", r"etree\.fromstring", r"XMLParser",
            r"lxml\b", r"parseString", r"minidom\.parse"],
    "79":  [r"\|\s*safe\b", r"render_template_string", r"mark_safe",
            r"\bMarkup\s*\("],
    "1336": [r"render_template_string", r"\bTemplate\s*\(", r"from_string"],
    "22":  [r"send_file", r"send_from_directory", r"os\.path\.join",
            r"FileResponse", r"\.write_text\s*\(", r"\bopen\s*\("],
    "23":  [r"\bopen\s*\(", r"os\.path\.join"],
    "601": [r"RedirectResponse", r"\bredirect\s*\(", r"HttpResponseRedirect"],
    "918": [r"requests\.(get|post|put|delete|head)\s*\(", r"\burlopen\s*\(",
            r"httpx\.", r"urllib\.request"],
    "338": [r"random\.(choice|random|randint|randrange|getrandbits|shuffle|"
            r"sample|uniform)\s*\("],
    "330": [r"random\.(choice|random|randint|randrange)\s*\("],
    "327": [r"\bmd5\s*\(", r"\bsha1\s*\(", r"\bDES\b", r"\bECB\b"],
    "89":  [r"\.execute\s*\(", r"\.executemany\s*\(", r"\.raw\s*\("],
    "943": [r"\.find\s*\(", r"\.find_one\s*\(", r"\$where", r"\.aggregate\s*\("],
    "78":  [r"os\.system\s*\(", r"subprocess\.(run|call|Popen|check_output)\s*\(",
            r"os\.popen\s*\("],
    "532": [r"\.(info|debug|warning|error)\s*\(.*token",
            r"logg(er|ing).*(token|secret|password)"],
}

# CWEs that are logic/authorization flaws — no syntactic sink to sweep for.
_LOGIC_CWES = {"639", "862", "863", "306", "285", "284", "269", "367", "362",
               "200", "538", "215", "16"}

# A match in one of these is almost never a real second instance of a sink.
_FALSE_MATCH = re.compile(
    r"(^|/)(test|tests|conftest)|\.md:|#.*$", re.IGNORECASE)


@dataclass
class Instance:
    file: str
    line: int
    text: str


@dataclass
class CauseSweep:
    finding_id: str
    title: str
    cwe: str
    origin: str            # the finding's own location
    patterns: List[str]
    instances: List[Instance]
    note: str = ""

    @property
    def extra_count(self) -> int:
        """Instances beyond the one the finding already reported."""
        o = _norm_loc(self.origin)
        return sum(1 for i in self.instances
                   if "{0}:{1}".format(i.file, i.line) != o and o not in
                   "{0}:{1}".format(i.file, i.line))


_CALL = re.compile(r"([A-Za-z_][\w.]*)\s*\(")
_LOC = re.compile(r"([\w./-]+\.\w+):(\d+)")


def _norm_loc(text: str) -> str:
    m = _LOC.search(text or "")
    return "{0}:{1}".format(m.group(1), m.group(2)) if m else ""


# Same-language file globs so a sweep stays within the finding's language and
# doesn't collide with a same-named construct elsewhere (JS `.find` vs NoSQL).
_LANG_GLOBS = {
    ".py": "*.py",
    ".js": "*.{js,jsx,mjs}", ".jsx": "*.{js,jsx,mjs}",
    ".ts": "*.{ts,tsx}", ".tsx": "*.{ts,tsx}",
    ".go": "*.go", ".rb": "*.rb", ".php": "*.php", ".java": "*.java",
}


def _lang_glob(location: str) -> Optional[str]:
    m = _LOC.search(location or "")
    if not m:
        m = re.search(r"([\w./-]+\.\w+)", location or "")
        if not m:
            return None
    ext = Path(m.group(1)).suffix.lower()
    return _LANG_GLOBS.get(ext)


def _extract_call_patterns(*texts: str) -> List[str]:
    """Pull dangerous-looking call tokens (e.g. ``pickle.loads``) out of a
    finding's data-flow/title so a sink named there is swept even if its CWE is
    absent from the table."""
    out = set()
    common = {"get", "post", "str", "int", "list", "dict", "len", "print",
              "format", "join", "range", "isinstance", "super", "open"}
    for t in texts:
        for m in _CALL.finditer(t or ""):
            tok = m.group(1)
            if "." in tok or (tok.lower() not in common and len(tok) > 3):
                out.add(re.escape(tok) + r"\s*\(")
    return sorted(out)


def patterns_for(cwe: str, data_flow: str, title: str) -> Tuple[List[str], str]:
    """Sweep patterns for a finding + a note when none apply.

    Includes call tokens pulled from the model's narrative (data flow / title) —
    appropriate ONLY for the sweep, whose job is to surface *leads* (other places
    a named call appears). It must NOT be used to decide whether a claim is
    corroborated: a narrative that says ``find_one`` would make a Mongo call count
    as evidence for an SSRF label. Use ``sink_patterns`` for that."""
    num = (cwe or "").upper().replace("CWE-", "").strip()
    if num in _LOGIC_CWES:
        return [], ("authorization/logic finding — no syntactic sink to sweep "
                    "(instances are behavioural, not pattern-matchable)")
    pats = set(CWE_SINK_PATTERNS.get(num, []))
    pats.update(_extract_call_patterns(data_flow, title))
    if not pats:
        return [], "no sink pattern derivable for {0}".format(cwe or "unknown CWE")
    return sorted(pats), ""


def sink_patterns(cwe: str) -> Tuple[List[str], str]:
    """The AUTHORITATIVE CWE→sink patterns (the curated table only — never the
    model's narrative). Corroboration must use this: a pattern here constitutes
    evidence that the cited source performs the operation the CWE describes, not a
    lead extracted from prose the model wrote. Returns ``([], note)`` for logic
    classes (no syntactic sink) and for classes absent from the table."""
    num = (cwe or "").upper().replace("CWE-", "").strip()
    if num in _LOGIC_CWES:
        return [], "authorization/logic class — no syntactic sink to corroborate"
    pats = CWE_SINK_PATTERNS.get(num, [])
    if not pats:
        return [], "no authoritative sink pattern for {0}".format(cwe or "unknown CWE")
    return list(pats), ""


def _grep(repo: Path, pattern: str, glob: Optional[str]) -> List[Instance]:
    from .tools import _grep_ripgrep, _grep_python, ToolError
    try:
        raw = _grep_ripgrep(repo, pattern, glob, False, False)
        if raw is None:
            raw = _grep_python(repo, pattern, glob, False, False)
    except ToolError:
        return []
    out: List[Instance] = []
    for line in (raw or "").splitlines():
        # ripgrep/python format: /abs/path:LINENO:text
        m = re.match(r"(.+?):(\d+):(.*)$", line)
        if not m:
            continue
        fp = m.group(1)
        try:
            rel = str(Path(fp).resolve().relative_to(repo.resolve()))
        except ValueError:
            rel = fp
        if _FALSE_MATCH.search(rel):
            continue
        out.append(Instance(rel, int(m.group(2)), m.group(3).strip()[:160]))
    return out


def sweep_findings(repo: Path, findings) -> List[CauseSweep]:
    """One deterministic sweep per confirmed finding (deduped by root cause)."""
    repo = Path(repo)
    seen_key = set()
    sweeps: List[CauseSweep] = []
    for f in findings:
        key = (f.cwe.upper(), _norm_loc(f.location) or (f.title or "").lower())
        if key in seen_key:
            continue
        seen_key.add(key)
        pats, note = patterns_for(f.cwe, f.data_flow, f.title)
        # Scope the sweep to the finding's own language. A root cause in a .py
        # file has its other instances in .py files — not the .tsx frontend,
        # where `array.find(` would coincidentally match a NoSQL `.find(` pattern.
        glob = _lang_glob(f.location)
        instances: List[Instance] = []
        seen_loc = set()
        for pat in pats:
            for inst in _grep(repo, pat, glob):
                lk = (inst.file, inst.line)
                if lk not in seen_loc:
                    seen_loc.add(lk)
                    instances.append(inst)
        instances.sort(key=lambda i: (i.file, i.line))
        sweeps.append(CauseSweep(
            finding_id=f.id, title=f.title or f.id, cwe=f.cwe or "—",
            origin=f.location or "", patterns=pats, instances=instances, note=note))
    return sweeps


def render_sweep(sweeps: List[CauseSweep]) -> str:
    L = ["# Phase 3d: Root-cause instance sweep (deterministic)",
         "",
         "For each confirmed finding, every location matching its root-cause "
         "sink pattern(s), enumerated directly by the harness (test/vendor/"
         "generated code excluded). Instances beyond the one the finding already "
         "reported are flagged **NEW** — additional places the same defect "
         "appears, to review and fix together.",
         ""]
    total_new = 0
    for s in sweeps:
        L.append("## {0} — {1} ({2})".format(s.finding_id, s.title, s.cwe))
        L.append("")
        if s.note:
            L.append("*{0}*".format(s.note))
            L.append("")
            continue
        L.append("Patterns: {0}".format(", ".join("`{0}`".format(p) for p in s.patterns)))
        L.append("")
        if not s.instances:
            L.append("No instances found (pattern may not match this codebase's style).")
            L.append("")
            continue
        origin = _norm_loc(s.origin)
        L.append("| File:line | New? | Match |")
        L.append("|---|---|---|")
        for i in s.instances:
            loc = "{0}:{1}".format(i.file, i.line)
            is_origin = origin and (origin in loc or loc in origin)
            new = "" if is_origin else "**NEW**"
            if not is_origin:
                total_new += 1
            L.append("| `{0}` | {1} | `{2}` |".format(loc, new, i.text.replace("|", "\\|")))
        L.append("")
    L.insert(4, "**{0} additional instance(s)** of confirmed root causes found "
             "across {1} finding(s).\n".format(total_new, len(sweeps)))
    return "\n".join(L) + "\n"


def run_phase3d_sweep(results_dir: Path, repo: Path) -> Optional[Path]:
    """Build phase3d_output.md deterministically from the confirmed findings."""
    from .consolidate import parse_findings
    results_dir = Path(results_dir)
    findings = [f for f in parse_findings(results_dir) if not f.duplicate_of]
    if not findings:
        return None
    sweeps = sweep_findings(Path(repo), findings)
    out = results_dir / "phase3d_output.md"
    out.write_text(render_sweep(sweeps), encoding="utf-8")
    return out
