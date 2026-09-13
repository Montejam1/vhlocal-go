"""Replay a FROZEN candidate set through each publication policy.

The count of published findings changed between the balanced and strict runs — but
those were *separate hunts* with different candidates and execution conditions. That does not isolate the reporting threshold. This tool replays ONE
frozen candidate set (the parsed observations of a single results dir) through
every ``quality_strictness`` level, so the only variable is the policy.

By construction this separates the three things the audit said must be tracked
apart: **validated yield** (what each policy publishes) is measured here; **hunt
reasoning cost** and **transport failures** cannot change the frozen comparison.
Recorded verification throughput is displayed separately; no model is called.

Separately reports pre-verification discovery matching and publication recall
against a known-defects file: a small JSON list of
ground-truth defects (``{"cwe": "...", "file": "...", "line": N}``) — e.g. the
worker-status-bypass and reset-token-invalidation defects — so a policy that
suppresses a real bug is visible, not just its headline count.

    python -m vhlocal.policy_bench <results_dir> [known_defects.json]
"""

import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

LEVELS = ("lenient", "balanced", "strict")


def _frozen_candidates(results_dir: Path):
    """Parse + enrich ONE run's candidates exactly as the pipeline does, up to but
    not including assessment — so every policy sees identical inputs."""
    from . import consolidate as C
    meta = C.load_meta(results_dir)
    findings = C.parse_findings(results_dir)
    C.backfill_locations(findings, results_dir, meta.get("repo", ""))
    if not (results_dir / "candidate_manifest.json").exists():
        C.flag_duplicates(findings)
    C._apply_votes(findings, results_dir)
    return meta, findings


def _loc_match(finding, defect: Dict[str, Any]) -> bool:
    """Location/CWE matching is a discovery proxy, not an independent correctness verdict."""
    import re
    location = getattr(finding, "location", "").replace("`", "")
    match = re.fullmatch(r"(.+?):(\d+)(?:[-–](\d+))?", location)
    path = match[1] if match else location
    want = str(defect.get("file", "")).strip("/")
    cwe = str(defect.get("cwe", "")).upper()
    if not want or not cwe:
        return False
    if path != want and not path.endswith("/" + want):
        return False
    if (getattr(finding, "cwe", "") or "").upper() != cwe:
        return False
    line = defect.get("line", 0)
    if line:
        return bool(match and int(match[2]) <= int(line) <= int(match[3] or match[2]))
    return True


def replay(results_dir, known_defects: Optional[List[Dict[str, Any]]] = None,
           levels=LEVELS) -> Dict[str, Any]:
    """Replay the frozen candidate set through each policy. Returns per-policy
    yield counts and, when known defects are supplied, per-policy recall."""
    from . import consolidate as C
    results_dir = Path(results_dir)
    meta, base = _frozen_candidates(results_dir)

    discovery = None
    if known_defects is not None:
        matches = [{"defect": defect,
                    "candidate_ids": [f.id for f in base if _loc_match(f, defect)]}
                   for defect in known_defects]
        detected = sum(bool(m["candidate_ids"]) for m in matches)
        discovery = {"known_defects_total":len(matches), "discovered":detected,
                     "not_discovered":len(matches)-detected, "matches":matches,
                     "matching_basis":"file, CWE, and line when supplied; location proxy, not semantic validation"}
    from .verification import read_json
    verification_metrics = read_json(results_dir / "verification_metrics.json")

    policies: List[Dict[str, Any]] = []
    for level in levels:
        findings = copy.deepcopy(base)
        C.assess_candidates(findings, dict(meta, quality_strictness=level))
        canon = [f for f in findings if not f.duplicate_of]
        row = {
            "policy": level,
            "candidates": len(canon),
            "statically_supported": sum(
                1 for f in canon if f.classification == "statically_supported"),
            "reviewed": sum(1 for f in canon if f.classification == "reviewed"),
            "hypotheses": sum(1 for f in canon if f.classification == "hypothesis"),
        }
        row["substantiated"] = row["statically_supported"] + row["reviewed"]
        if known_defects:
            found = []
            for i, dfct in enumerate(known_defects):
                hit = next((f for f in canon
                            if f.classification in ("statically_supported", "reviewed")
                            and _loc_match(f, dfct)), None)
                found.append(bool(hit))
            row["known_defects_total"] = len(known_defects)
            row["known_defects_substantiated"] = sum(found)
            row["known_defects_recall_pct"] = round(
                100.0 * sum(found) / len(known_defects))
        policies.append(row)

    return {
        "results_dir": str(results_dir),
        "repo": meta.get("repo", ""),
        "git_commit": meta.get("git_commit", ""),
        "frozen_candidates": len([f for f in base if not f.duplicate_of]),
        "note": ("Same frozen candidate set through every policy — differences are "
                 "the reporting threshold ALONE, not the hunt, timing, or transport."),
        "policies": policies,
        "discovery": discovery,
        "verification_throughput": verification_metrics,
    }


def render(report: Dict[str, Any]) -> str:
    L = ["# Policy replay — frozen candidate set", "",
         report["note"], "",
         "Repo: `{0}`  ·  revision: `{1}`  ·  frozen candidates: {2}".format(
             report["repo"] or "?", (report["git_commit"] or "?")[:12],
             report["frozen_candidates"]),
         ""]
    discovery = report.get("discovery")
    if discovery is not None:
        L += ["Discovery before verification: {}/{} known defects matched; {} not discovered.".format(
            discovery["discovered"], discovery["known_defects_total"], discovery["not_discovered"]),
            discovery["matching_basis"], ""]
    throughput = report.get("verification_throughput")
    if throughput:
        L += ["Verification: {}/{} accepted decisions; {} incomplete; {} accepted decisions/minute.".format(
            throughput["accepted_decisions"], throughput["candidates"], throughput["incomplete"],
            throughput["accepted_decisions_per_minute"]), ""]
    has_recall = any("known_defects_total" in p for p in report["policies"])
    head = "| Policy | Substantiated | statically-supported | reviewed | Hypotheses |"
    sep = "|---|---|---|---|---|"
    if has_recall:
        head += " Known-defect publication recall |"
        sep += "---|"
    L += [head, sep]
    for p in report["policies"]:
        row = "| {0} | {1} | {2} | {3} | {4} |".format(
            p["policy"], p["substantiated"], p["statically_supported"],
            p["reviewed"], p["hypotheses"])
        if has_recall:
            row += " {0}/{1} ({2}%) |".format(
                p.get("known_defects_substantiated", 0),
                p.get("known_defects_total", 0), p.get("known_defects_recall_pct", 0))
        L.append(row)
    L.append("")
    return "\n".join(L)


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m vhlocal.policy_bench <results_dir> [known_defects.json]")
        return 2
    results_dir = argv[0]
    known = None
    if len(argv) > 1:
        try:
            known = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print("could not read known-defects file: {0}".format(exc))
            return 2
    report = replay(results_dir, known_defects=known)
    print(render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
