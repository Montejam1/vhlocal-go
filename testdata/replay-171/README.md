# replay-171 — sanitized records of the first live feature-014 run (feature 015, T002)

Source: the operator's completed scan `843875fb0919` (gpt-oss:120b, 2026-09-28, ≈3 h) — 171 non-duplicate
candidates: **43 supported / 7 rejected / 121 unresolved** (8 of them explicit `unresolved` verdicts, 113
sessions with no decision), **438 agent rows**, 100 entry points with 93 read-overlap "no issue" dispositions
(review units **v1**), 277 valid hunt deliverables, 8 artifact errors, and a threat model whose diagram is
invalid at fence lines 48–52.

## What is here

Records only — **no prompts, no model transcripts, no operator paths or hosts**:
`scan_meta.json`, `findings.json`, `candidate_manifest.json`, `verification_decisions.json`,
`verification_sessions.json`, `verification_reconciliation.json`, `verification_metrics.json`,
`review_units.json` (v1, no `semantics_version`), `coverage_ledger.json`, `hunt_execution.json`,
`artifact_manifest.json`, `threat_model.md`.

Sanitization: the repository path is rewritten to `testdata/replay-171/target`, the results path to
`testdata/replay-171`, the inference host to `http://127.0.0.1:11434`; any other absolute operator path is
`<redacted-path>`. Model-authored prose (titles, rationales, reasons) is kept verbatim because the report
model must be exercised on real text.

`target/` is a **stub source tree** synthesized from the captured evidence quotes: every cited line range
contains exactly the quoted text (so `verification.Reconcile` byte-matches), other lines are `# stub line N`.
It has 14 files and **no recognizable routes** — it supports evidence validation, not route enumeration.
Tests that need routes use `testdata/coverage100` or `testdata/vulnapp`.

## What it is for

- US1/US2 (scenarios 1–2): build `report_model.json` and render Markdown/HTML from these records; assert
  the summary comes first, ≤ 300 words / ≤ 5 leading items, counts 43/7/121/171 and supported-only severity
  totals; byte-identical regeneration.
- US3: `threat_model.md` is the audited malformed diagram (also mirrored in `testdata/diagrams/03-…`).
- US4: a v1 `review_units.json` that must stay v1-labelled on regeneration.
- US8: `verification_sessions.json` and the reconciliation reasons carry the audited failure mix
  (45 exact-location, 29 entry-point mismatch, 10 evidence span, 5 repo-relative path; 17 of 27 turn-limit
  sessions with other classes).

Never re-run this scan against a model; it is replayed from records only.
