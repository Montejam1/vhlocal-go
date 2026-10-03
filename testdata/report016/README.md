# report016 — frozen acceptance fixture for feature 016 (T002)

Sanitized records from one real completed scan, used as the fixed acceptance corpus for
[Actionable Vulnerability Reports](../../specs/016-actionable-vulnerability-reports/spec.md).
Regenerate with:

```bash
go run ./testdata/report016/gen/main.go <source-results-dir>
```

## What is here

Records only: `report_model.json`, `findings.json`, `remediation_groups.json`,
`verification_metrics.json`, `verification_sessions.json`,
`verification_reconciliation.json`, `coverage_ledger.json`, `review_units.json` and
`scan_meta.json`. `baseline.json` holds the measured before-state of the report this
feature replaces. `SOURCE_FINGERPRINTS.txt` records the sha256 of every record as read
from the source, before sanitizing.

`prompts.jsonl` is deliberately absent: it carries model transcripts and no acceptance
check reads it. The scanned source tree is not shipped either, so the fixture exercises
record handling and presentation, not source resolution. Tests needing real source use
`testdata/coverage100` or `testdata/vulnapp`.

Sanitizing rewrote the results directory to `testdata/report016`, the scanned
repository to `testdata/report016/target`, and the inference host to
`http://127.0.0.1:11434`. Any other absolute operator path became `<redacted-path>`.
Model-authored prose such as titles, rationales and reasons is kept verbatim, because
the presentation must be exercised on real text. Regeneration is deterministic for the
same input.

## Source provenance

The source scan at freeze time, verified unchanged before and after generation:

```text
SCAN_REPORT.md          893949a5dc13f01d6139998fe86e3b9e9eb4df0b4aea8cf5b11134ca53db1a9b
report_model.json       72cd37863f12a52b44aca0e8e87d7d25bde7d9d949b0c7e0ec58fa7069fb7d4c
remediation_groups.json 7b7ffd08ab54a6bcf5ac4b6a2e985c1aa44119543934bf904716e2f9ed8a84e8
```

Per-record fingerprints are in `SOURCE_FINGERPRINTS.txt`. The source scan is read only.
Nothing in this feature modifies, regenerates or deletes it, and no test may read the
operator's live stores or depend on a path inside a home directory (FR-028).

## Preserved relationships

These are the acceptance targets in spec SC-002 and SC-010. Each was re-read from the
fixture's own records, not carried over from a description:

| Quantity | Value |
| --- | ---: |
| Candidates examined | 64 |
| Supported detections | 49 |
| Established groups | 34 |
| Group member rows / unique members | 49 / 49 |
| Rejected (dismissed) | 8 |
| Inconclusive decisions | 1 |
| Incomplete assessments | 6 |
| Needs review total | 7 |
| Entry points with completed review | 40 of 100 |
| Entry points exposed to review | 90 |
| Findings with an empty recommended fix | 49 of 49 |

Group severity, once the existing `High+` rating folds into High for display, is 13
High, 19 Medium and 2 Low, with no Critical, Informational or Unrated. The underlying
per-finding ratings are 6 `High+`, 16 High, 24 Medium and 3 Low. The fold is a
documented presentation mapping, not a reassessment.

The corpus also contains two separate established groups describing unsafe
deserialization at one route, and two weaknesses (CWE-754 and CWE-90) that belong to no
known weakness family. Both are deliberate: the first must not be merged, and the second
must take the honest investigation branch rather than borrowing another family's advice.

## What this fixture does not establish

It is one scan from one model against one target. It proves the pipeline, the counting
and the presentation. It is not evidence of detection quality, and the 34 groups are not
a claim that the application contains exactly 34 distinct defects.
