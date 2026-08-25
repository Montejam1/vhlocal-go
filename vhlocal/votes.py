"""Hunt vote counts: how many multi-sample hunt runs independently reported a
candidate at a given location.

Multi-sample voting (Tranche 2) unions candidates across N hunt samples and tags
each block with `votes: k/N`. This module carries that signal to readiness: the
merge records a location-keyed vote map (`hunt_votes.json`), and consolidate looks
each final finding's location up in it so the vote count reaches findings.json,
SARIF (`properties.votes`), and the report. A finding confirmed by 3/3 samples is
more solid than one seen once — that is the confidence signal voting exists to
produce. Stdlib only, deterministic.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

VOTES_FILE = "hunt_votes.json"
_BUCKET = 20   # lines; a finding within one bucket of a candidate is the same site
_FILE_LINE = re.compile(r"([\w./+\-]+\.[A-Za-z0-9]{1,6})[:\s]+(\d+)")


def _key(fname: str, line: int) -> str:
    return "{0}:@{1}".format(fname.split("/")[-1], line // _BUCKET)


def location_keys(text: str) -> Set[str]:
    """Every (basename:line-bucket) key from any file:line citation in text."""
    out: Set[str] = set()
    for m in _FILE_LINE.finditer(text or ""):
        try:
            out.add(_key(m.group(1), int(m.group(2))))
        except (TypeError, ValueError):
            continue
    return out


def merge_votes(acc: Dict[str, Dict[str, int]],
                entries: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """Fold per-block vote entries into an accumulator, keeping the highest vote
    seen for each location key. entries: [{'keys': set, 'votes': k, 'samples': N}]."""
    for e in entries:
        votes = int(e.get("votes") or 0)
        samples = int(e.get("samples") or 0)
        for k in e.get("keys") or ():
            cur = acc.get(k)
            if cur is None or votes > cur["votes"]:
                acc[k] = {"votes": votes, "samples": samples}
    return acc


def write_votes(results_dir, vote_map: Dict[str, Dict[str, int]]) -> None:
    if not vote_map:
        return
    try:
        (Path(results_dir) / VOTES_FILE).write_text(
            json.dumps(vote_map, indent=2), encoding="utf-8")
    except OSError:
        pass


def load_votes(results_dir) -> Dict[str, Dict[str, int]]:
    try:
        return json.loads((Path(results_dir) / VOTES_FILE).read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def votes_for(location: str, vote_map: Dict[str, Dict[str, int]]) -> Tuple[int, int]:
    """(votes, samples) for a finding location — the best-matching candidate site.
    (0, 0) when the run wasn't multi-sampled or no candidate matched."""
    best = (0, 0)
    if not vote_map or not location:
        return best
    for k in location_keys(location):
        v = vote_map.get(k)
        if v and int(v.get("votes") or 0) > best[0]:
            best = (int(v["votes"]), int(v.get("samples") or 0))
    return best
