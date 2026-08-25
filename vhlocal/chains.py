"""Deterministic exploit-chain analysis.

A vulnerability report lists findings in isolation, but real impact often comes
from *composing* them: an access-control gap in front of a dangerous sink lets an
unauthorized attacker reach code that a single finding rates only in isolation.
This module links confirmed findings into chains using conservative, deterministic
rules (no model call — like the Phase-3d sweep), so the report surfaces the
higher real-world severity a chain implies.

Two high-precision rules:

* **authz-amplified-sink** — an access-control finding co-located (same file) with
  a dangerous injection/RCE sink: the missing authorization removes the
  precondition guarding the sink, so an unauthorized attacker reaches it.
* **shared-surface** — two or more findings on the same entry point: one request
  surface exposes several defects.

Stdlib only, deterministic.
"""

import re
from typing import Any, Dict, List

# CWE numbers, by role in a chain.
_ACCESS_CONTROL = {"284", "285", "287", "306", "352", "639", "862", "863", "1390"}
_DANGEROUS_SINK = {"77", "78", "79", "89", "90", "91", "94", "95", "98", "502",
                   "611", "776", "917", "918", "943", "1236"}
_FILE_RE = re.compile(r"([\w./+\-]+\.[A-Za-z0-9]{1,6})")


def _val(f: Any, name: str) -> str:
    v = f.get(name) if isinstance(f, dict) else getattr(f, name, None)
    return v if isinstance(v, str) else ("" if v is None else str(v))


def _num(f: Any) -> str:
    for field in ("normalized_cwe", "cwe"):
        m = re.search(r"(\d+)", _val(f, field))
        if m:
            return m.group(1)
    return ""


def _file(f: Any) -> str:
    m = _FILE_RE.search(_val(f, "location")) or _FILE_RE.search(_val(f, "data_flow"))
    return m.group(1).split("/")[-1] if m else ""


def _rank(f: Any) -> int:
    r = f.get("severity_rank") if isinstance(f, dict) else getattr(f, "severity_rank", None)
    try:
        return int(r)
    except (TypeError, ValueError):
        return 0


def _dup(f: Any) -> bool:
    return bool(_val(f, "duplicate_of"))


def _fid(f: Any) -> str:
    return _val(f, "id")


def _sev(f: Any) -> str:
    return _val(f, "severity") or "Unrated"


def build_chains(findings: List[Any]) -> List[Dict[str, Any]]:
    """Return chains, most-severe first. Each: {id, kind, title, severity,
    finding_ids, rationale}. Empty when nothing composes."""
    real = [f for f in findings if not _dup(f) and _fid(f)]
    chains: List[Dict[str, Any]] = []
    seen = set()   # frozenset(member ids) -> dedup identical chains

    def _add(kind, title, members, rationale):
        ids = [_fid(m) for m in members]
        key = (kind, frozenset(ids))
        if len(set(ids)) < 2 or key in seen:
            return
        seen.add(key)
        top = max(members, key=_rank)
        chains.append({
            "kind": kind, "title": title, "finding_ids": ids,
            "severity": _sev(top),
            "_rank": _rank(top),
            "rationale": rationale,
        })

    # Rule A — authz-amplified sink (co-located in one file).
    by_file: Dict[str, List[Any]] = {}
    for f in real:
        fil = _file(f)
        if fil:
            by_file.setdefault(fil, []).append(f)
    for fil, group in by_file.items():
        ac = [f for f in group if _num(f) in _ACCESS_CONTROL]
        sinks = [f for f in group if _num(f) in _DANGEROUS_SINK
                 and _num(f) not in _ACCESS_CONTROL]
        # One access-control gap can expose *several* co-located sinks — group them
        # into a single chain rather than emitting a noisy pair per sink.
        for a in ac:
            reached = [s for s in sinks if _fid(s) != _fid(a)]
            if not reached:
                continue
            sink_cwes = ", ".join(sorted({_val(s, "cwe") or "sink" for s in reached}))
            _add("authz-amplified-sink",
                 "Unauthorized reach to {0} sink(s) in {1}".format(len(reached), fil),
                 [a] + reached,
                 "The access-control flaw {0} ({1}) removes the authorization "
                 "precondition guarding {2} dangerous sink(s) ({3}) co-located in "
                 "{4}, so an unauthorized attacker can reach them — a higher "
                 "real-world severity than any finding alone.".format(
                     _fid(a), _val(a, "cwe") or "access control",
                     len(reached), sink_cwes, fil))

    # Rule B — shared entry-point surface.
    by_ep: Dict[str, List[Any]] = {}
    for f in real:
        ep = _val(f, "entry_point").strip()
        if ep:
            by_ep.setdefault(ep, []).append(f)
    for ep, group in by_ep.items():
        if len(group) >= 2:
            _add("shared-surface",
                 "Multiple flaws reachable via {0}".format(ep),
                 group,
                 "{0} findings are reachable through the same entry point ({1}); "
                 "one request surface exposes several defects, easing a combined "
                 "attack.".format(len(group), ep))

    chains.sort(key=lambda c: -c["_rank"])
    for i, c in enumerate(chains, 1):
        c["id"] = "CHAIN-{0}".format(i)
    return chains
