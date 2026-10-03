# Phase 1 Data Model: Dashboard metrics & application/ledger management

Entities and fields, derived from the spec + research. Field names match what the UI
already consumes (`web-react/src/lib/types.ts`).

## DashboardStats

The aggregate over the report set (served at the stats endpoint). Every field must be
populated from recorded data; averages carry the contributing-run count.

| Field | Type | Rule |
|---|---|---|
| `scans` | int | number of real reports |
| `findings` | int | total substantiated findings across reports |
| `avg_findings_per_scan` | int | **rounded integer** = round(findings / scans); 0 when scans==0 |
| `prompt_tokens` | int | sum of per-run prompt tokens |
| `completion_tokens` | int | sum of per-run completion tokens |
| `total_tokens` | int | prompt + completion |
| `with_usage` | int | # runs that recorded usage (tokens > 0) |
| `avg_tokens_per_scan` | int | round(total_tokens / with_usage); 0 when with_usage==0 |
| `total_seconds` | number | sum of per-run durations (finished−started) |
| `avg_seconds_per_scan` | number | total_seconds / (# runs with a duration); 0 when none |
| `by_model` | map | model → `{scans:int, tokens:int, findings:int}` — tokens from **real** data, never a hardcoded 0 |

Rules: no `NaN`/divide-by-zero at zero scans or zero-with-usage (FR-006); averages
computed only over runs that have the datum (FR-005); `avg_findings_per_scan` is an
integer everywhere it is shown (FR-004).

## Report (extended)

Existing `reports.Report` gains per-run cost/time so the aggregate can be computed:

| Field | Type | Source |
|---|---|---|
| `prompt_tokens` | int | `scan_meta.json` `usage.prompt_tokens` |
| `completion_tokens` | int | `scan_meta.json` `usage.completion_tokens` |
| `duration_seconds` | number | `finished_at − started_at` (0 if either missing) |
| `has_usage` | bool | true when recorded tokens > 0 |

**Report validity (the phantom-app fix):** a directory is a Report only if its name
matches the results-dir pattern **or** it contains a recognized deliverable
(`scan_meta.json`, `findings.json`, `SCAN_REPORT.md`, `README.md`, `phase1_output.md`).
Directories failing this are not reports and never become applications.

## Application (list item) — unchanged shape, real-only

The feature-007 `AppSummary` is unchanged; the fix is upstream (only real reports feed
discovery), so only real applications (a name, or a real report, or a ledger) appear.
List view shows: name, repository, scans, latest outcome/time, threat/SBOM
availability. Delete = forget (hide; reports preserved; re-scan un-hides).

## Ledger (list item) — unchanged shape

The existing ledger summary: name/target, tracked total, open count, last updated.
Delete = clear the ledger `<slug>.json` only; reports untouched.

## Relationships

- DashboardStats aggregates over Reports (real ones only).
- Application 1—N Report (by slug); Application 0/1 Ledger (by slug).
- Deleting an Application (forget) hides it + clears its ledger, keeps reports.
- Deleting a Ledger removes only that ledger.
