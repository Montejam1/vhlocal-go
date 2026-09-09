"""Publication gate for source-grounded reviews; hunter prose is not a verdict."""

import hashlib
import json
import re
from pathlib import Path


def candidate_key(finding, revision):
    identity = [revision, finding.title, finding.cwe, finding.location]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()


def review_support(finding, meta):
    """Return a validated review rationale, or why the claim remains a hypothesis.

    Review records are supplied explicitly by a reviewer/integration, never
    inferred from a Markdown CONFIRMED label or a generic CWE description.
    Matching quotes validate provenance, not the correctness of the reviewer's
    security reasoning. Preserve the reviewer and rationale for inspection.
    """
    records = meta.get("verification_records") or {}
    record = records.get(finding.candidate_key) if isinstance(records, dict) else None
    if not isinstance(record, dict):
        return False, "Further investigation required: no substantiated review is recorded."
    required = ("reviewer", "rationale", "entry_point", "attacker_control",
                "preconditions", "defenses_reviewed", "security_impact")
    if record.get("verdict") != "supported" or any(
        not isinstance(record.get(k), str) or not record[k].strip() for k in required
    ):
        return False, "Further investigation required: the review decision or supporting reasoning is incomplete."
    revision = meta.get("git_commit")
    if not revision or record.get("revision") != revision:
        return False, "Further investigation required: the review does not identify this target revision."
    raw_repo = meta.get("repo")
    if not raw_repo or not Path(raw_repo).is_dir():
        return False, "Further investigation required: source evidence cannot be checked without the target checkout."
    repo = Path(raw_repo).resolve()
    location = re.fullmatch(r"(.+?):(\d+)(?:[-–‑](\d+))?", finding.location.strip())
    if not location:
        return False, "Further investigation required: the candidate has no exact source location."
    primary = (repo / location[1]).resolve()
    primary_line = int(location[2])
    primary_end = int(location[3] or location[2])
    covered = False
    evidence = record.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return False, "Further investigation required: the review has no source evidence."
    for item in evidence:
        try:
            path = item["path"]
            start, end, quote = item["start_line"], item["end_line"], item["quote"]
            if not isinstance(path, str) or Path(path).is_absolute():
                raise ValueError()
            source = (repo / path).resolve()
            source.relative_to(repo)
            if type(start) is not int or type(end) is not int or not isinstance(quote, str) or not quote.strip():
                raise ValueError()
            lines = source.read_text(encoding="utf-8").splitlines()
            if not 1 <= start <= end <= len(lines) or quote.strip() != "\n".join(lines[start - 1:end]).strip():
                raise ValueError()
            if source == primary and start <= primary_line <= primary_end <= end:
                covered = True
        except (KeyError, TypeError, ValueError, OSError, UnicodeError):
            return False, "Further investigation required: a source citation is missing, invalid, or no longer matches the code."
    if not covered:
        return False, "Further investigation required: the evidence does not cover the candidate's cited location."
    return True, record["rationale"].strip()
