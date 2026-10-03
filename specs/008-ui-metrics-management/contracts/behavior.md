# Contracts — metrics, report-dir guard, apps/ledger management

Testable invariants. IDs are referenced by tasks and map to the spec's success
criteria. Backend items are offline-testable (`go test ./...`); UI items run against
the served surface with seeded data (operator-owned, per feature 007).

## Dashboard metrics (US1)

- **C-M1 (full metric set)**: the stats aggregate returns non-zero, real values for
  `total_tokens`, `avg_tokens_per_scan`, `total_seconds`, `avg_seconds_per_scan`,
  `with_usage`, `scans`, `findings` when the report set recorded usage/timing (SC-001).
- **C-M2 (integer findings average)**: `avg_findings_per_scan` is an integer for both
  whole-number and fractional underlying ratios (e.g., 7 findings / 2 scans → 4, not
  3.5) (FR-004/SC-002).
- **C-M3 (partial data)**: with a mix of runs (some without usage/timing),
  `avg_tokens_per_scan` and `avg_seconds_per_scan` are computed only over the runs
  that recorded the datum, and `with_usage` reflects that subset (FR-005).
- **C-M4 (zero scans)**: with no reports, every metric is 0 — no `NaN`, no
  divide-by-zero, no blank (FR-006/SC-003).
- **C-M5 (real per-model tokens)**: `by_model[*].tokens` reflects recorded tokens, not
  a hardcoded 0 (FR-007).

## Report-directory guard / phantom apps (US2)

- **C-P1 (guard)**: a directory that neither matches the results-dir name pattern nor
  contains a recognized deliverable is NOT returned as a report by the report index.
- **C-P2 (report-only preserved)**: a real report dir (has `scan_meta.json` /
  `findings.json` / `README.md`) IS returned, so report-only application discovery
  still works (FR-010/SC-007).
- **C-P3 (no phantom apps, restart-stable)**: given a data dir with N real
  applications and some stray non-report subdirectories, the applications list returns
  exactly N; re-deriving (as a restart does) adds zero (FR-008/009/SC-004).
- **C-P4 (non-destructive)**: applying the guard never deletes or alters any on-disk
  directory or file (FR-011/SC-006).

## Applications management (US3)

- **C-A1 (list layout)**: the served Applications view offers a list showing per app:
  name, repository, scan count, latest outcome/time, threat/SBOM availability (FR-012).
- **C-A2 (confirmed delete)**: deleting an application from the view requires an
  explicit confirm; on confirm it calls the existing forget-delete and the app leaves
  the list (FR-013/SC-005).
- **C-A3 (reports preserved / re-scan)**: after a delete, the app's report files still
  exist on disk, and re-scanning its repository makes it reappear with history
  (FR-014/SC-006).

## Ledger management (US4)

- **C-L1 (list layout)**: the served Ledger view offers a list showing per ledger:
  name/target, tracked total, open count, last updated (FR-015).
- **C-L2 (confirmed delete)**: deleting a ledger requires an explicit confirm; on
  confirm it calls the existing clear-delete, the ledger leaves the list, and other
  ledgers are unaffected (FR-016).
- **C-L3 (reports preserved)**: deleting a ledger removes only its tracking data; report
  files remain (FR-017/SC-006).

## Cross-cutting

- **C-X1 (recorded-data only)**: metrics derive solely from recorded usage/timings/
  findings; no new scan-time measurement (FR-018).
- **C-X2 (preservation)**: no existing report, application name, or unrelated ledger is
  lost by using any view in this feature (FR-019/SC-006).
- **C-X3 (loading/empty/error distinct)**: every affected view distinguishes loading,
  empty, and error; a load failure is not rendered as empty success (FR-020).
