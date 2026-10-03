# Phase 0 Research: Dashboard metrics & application/ledger management

All findings from **reading** the Go source and the Python reference (`../vhlocal`,
read-only). No Python executed; no scan run.

## R1 — Dashboard metrics: compute the missing aggregates from recorded data

**Decision**: Surface per-run tokens + duration on the report record and compute the
full metric set in the stats aggregation; format the vulnerabilities average as an
integer; report per-model tokens from real data.

**Evidence**:
- `internal/server/handlers.go` `handleStats` returns `{scans, findings, by_model{scans,tokens:0,findings}, avg_findings_per_scan: float}` — it omits `total_tokens`, `avg_tokens_per_scan`, `total_seconds`, `avg_seconds_per_scan`, `with_usage`; per-model `tokens` is hardcoded `0`; the findings average is a `float64` (the decimal the operator sees).
- The UI `Stats` type (`web-react/src/lib/types.ts`) already declares every field, and `Dashboard.tsx` renders `s.total_tokens`, `s.avg_tokens_per_scan`, `s.total_seconds`, `s.avg_seconds_per_scan`, `s.with_usage`, `s.avg_findings_per_scan` — so they show blank/zero purely because the API omits them.
- The data exists per run in `scan_meta.json`: `usage` (map incl. `prompt_tokens`/`completion_tokens`/`calls`) and `started_at`/`finished_at` (`internal/engine/record.go`). `reports.Report` does NOT currently carry usage or duration.

**Approach**: add `PromptTokens`, `CompletionTokens`, `DurationSeconds`, and a
`HasUsage` signal to `reports.Report`, populated in `reports.Load` from
`scan_meta.json`. Rewrite `handleStats` to aggregate: `total_tokens` (prompt+
completion), `with_usage` (# runs with usage recorded), `avg_tokens_per_scan` (over
`with_usage`), `total_seconds`, `avg_seconds_per_scan` (over runs with a duration),
`avg_findings_per_scan` as a **rounded integer**, and per-model real `tokens`.

**Rationale**: reuses recorded data (FR-018; Principle I — no fabrication, and it
removes the always-zero placeholder). Averages over the subset that has data (FR-005)
and a clean zero state when there are no scans (FR-006).

**Alternatives considered**: computing tokens/time from `jobs.json` — rejected;
reports are the durable per-scan record and already the stats source, and job state
is transient.

## R2 — Phantom applications: restore the report-directory guard

**Decision**: Gate `reports.Load`/`Index` so a directory is treated as a report only
when its name matches the results-dir pattern **or** it contains a recognized
deliverable — mirroring the reference `is_report_dir`.

**Evidence (root cause, confirmed)**:
- `reports.Load` returns `(Report, true)` for **any** directory (it only returns
  `false` when the path is not a directory). So `reports.Index` turns every
  subdirectory under the reports dir into a `Report`; one with no `scan_meta.json`
  has `Repo=""` → `Slug=""` and is grouped by the aggregation under its directory
  name → a phantom "application" with no real data, re-derived on every restart.
- The reference guards this: `is_report_dir(p)` = `DIR_RE.match(p.name)` OR the dir
  holds a recognized `PHASE_FILES` deliverable (`reports.py:274`). Go dropped it.

**Approach**: add `isReportDir(dir)` = name matches `dirRE` OR any of a recognized
deliverable set exists (`scan_meta.json`, `findings.json`, `SCAN_REPORT.md`,
`README.md`, `phase1_output.md`); `Load` returns `false` otherwise, and `Index`
skips it. This removes phantom reports → phantom apps and is **restart-stable**.

**Report-only discovery preserved (FR-010)**: a real report dir created before this
feature carries `scan_meta.json`/`findings.json`/`README.md`, so it still qualifies.
Nothing on disk is deleted (FR-011) — phantoms simply stop being listed.

**Rationale**: precise, reference-aligned, and idempotent (Principle VI). Alternatives
(filtering empty apps at the aggregation layer) were rejected as treating the symptom
downstream while `reports.Index` still fabricates non-report rows for other callers
(e.g., `/api/reports`).

## R3 — Applications list view + delete (reuse existing capability)

**Decision**: Add a **list** layout to the served Applications view and surface the
**existing** forget-delete per row behind a confirm step.

**Evidence**: the served legacy UI (`vhlocal/web/index.html`) renders applications as
**cards** (`appCard`, `<div class="cards">`) and already has a working
`forgetApplication(slug,…)` → `DELETE /api/applications/{slug}` (→ `apps.Forget`,
which hides the app and clears its ledger but **keeps reports**), currently only in
the app **detail**. The delete capability and endpoint already exist; this feature
adds the list layout and a per-row delete affordance with confirmation.

**Rationale**: no new destructive capability (FR-013/014); reuses `apps.Forget`
semantics (reports preserved; re-scan un-hides). The React `Applications.tsx` is
updated in parallel for when `/app` is embedded.

## R4 — Ledger list view + delete (reuse existing capability)

**Decision**: Add a **list** layout to the served Ledger view and surface the
**existing** clear-delete per row behind a confirm step.

**Evidence**: the served UI already has `clearLedger(slug,…)` → `DELETE
/api/ledgers/{slug}` (removes only the ledger `<slug>.json`; reports untouched),
currently in the ledger detail. `/api/ledgers` returns the summaries to list.

**Rationale**: reuses the existing clear semantics (FR-016/017); reports never
removed. React `Ledger.tsx` updated in parallel.

## R5 — Surfaces & validation

**Decision**: The **served legacy `index.html` is the primary UI target** (React
`/app` is not embedded — feature 007 R11/T048); `web-react` pages are updated in
parallel. Backend changes (stats aggregation, report-dir guard) serve both. Acceptance
is offline-first (seeded fixtures for the stats aggregation, the report-dir guard, and
preservation); browser confirmation of the list/delete UIs is operator-owned.

**Rationale**: matches what the operator actually sees today and the feature-007
acceptance posture. No Python executed; no new runtime dependency.

## Post-design constitution re-check

The design adds no target execution, no provider fallback, no new runtime dependency,
and no status-axis coupling; it computes metrics only from recorded data, makes
discovery restart-stable, and preserves all on-disk evidence. **Constitution Check
remains PASS after design.**
