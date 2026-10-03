---

description: "Task list for Dashboard metrics & application/ledger management (feature 008)"
---

# Tasks: Dashboard metrics & application/ledger management

**Input**: Design documents in `/specs/008-ui-metrics-management/` (spec.md, plan.md, research.md, data-model.md, contracts/behavior.md, quickstart.md)

**Tests**: REQUIRED for the backend contracts (constitution Principle VII). Each backend contract (C-M*, C-P*, C-A3, C-L3, C-X2) ships an offline test that fails on the pre-fix code. UI list/delete rendering is confirmed in the browser (operator-owned, per feature 007). No Python executed; existing reports/names/ledgers preserved.

**Organization**: By user story in priority order — US1 Dashboard metrics (P1), US2 no phantom applications (P1), US3 Apps list+delete (P2), US4 Ledger list+delete (P2). Each story is independently testable.

## Format: `[ID] [P?] [Story] Description`
- **[P]** = different file, no dependency on an incomplete task.
- Serialized (no [P] among tasks touching the same file): `internal/reports/reports.go` (T003, T008), `vhlocal/web/index.html` (T005, T009, T012).

---

## Phase 1: Setup

- [X] T001 [P] Extend `internal/server/testsupport/seed.go`: `ReportSeed` gains `PromptTokens`/`CompletionTokens` (written into `scan_meta.json` `usage`) and `StartedAt`/`FinishedAt` (written into `scan_meta.json`); add a `SeedStrayDir(reportsDir, name)` helper that writes a subdirectory with **no** recognized deliverable (the phantom source). Reused by US1 metrics + US2 phantom fixtures.

---

## Phase 2: User Story 1 — Dashboard metrics populate & read cleanly (P1) 🎯 MVP

**Goal**: tokens used, average tokens/scan, and total scan time show real values; average vulnerabilities/scan is a whole number; clean zero state at no scans.

**Independent Test**: seed reports with usage/timing (+ one without) and run the stats aggregation — full metric set present, findings average integer, partial-data averaged over the subset, zero-scan safe (contracts C-M1..C-M5).

- [X] T002 [P] [US1] Test `internal/server/stats_test.go` (fails pre-fix): C-M1 full metric set (`total_tokens`, `avg_tokens_per_scan`, `total_seconds`, `avg_seconds_per_scan`, `with_usage`, `scans`, `findings`) non-zero on seeded usage/timing; C-M2 `avg_findings_per_scan` is an integer (7 findings / 2 scans → 4); C-M3 partial data averaged only over runs with the datum + correct `with_usage`; C-M4 zero scans → all-zero, no NaN/divide-by-zero; C-M5 `by_model[*].tokens` reflects real tokens.
- [X] T003 [US1] `internal/reports/reports.go`: add `PromptTokens`, `CompletionTokens`, `DurationSeconds`, `HasUsage` to `Report`, populated in `Load` from `scan_meta.json` (`usage.prompt_tokens`/`usage.completion_tokens`; `DurationSeconds = finished_at − started_at`, 0 if either missing; `HasUsage = tokens > 0`).
- [X] T004 [US1] `internal/server/handlers.go` `handleStats`: return the full `Stats` set — `total_tokens = prompt+completion`, `with_usage` (# reports with `HasUsage`), `avg_tokens_per_scan = round(total_tokens / with_usage)` (0 when `with_usage==0`), `total_seconds` (sum durations), `avg_seconds_per_scan` (over reports with a duration), `avg_findings_per_scan` as a **rounded int** (0 when scans==0), and per-model real `{scans, tokens, findings}`. No NaN/divide-by-zero.
- [X] T005 [US1] Legacy `vhlocal/web/index.html` Dashboard: verify the token/time tiles bind to the now-populated fields and the vulnerabilities average renders as an integer (no client-side `toFixed` reintroducing a decimal); fix any client-side formatting. Update `web-react/src/pages/Dashboard.tsx` in parallel (integer avg render).

**Checkpoint**: the Dashboard shows real tokens/time and an integer vuln average; US1 backend tests green.

---

## Phase 3: User Story 2 — No phantom or empty applications (P1)

**Goal**: only real applications appear; none are created/resurrected on restart; report-only discovery preserved; nothing on disk deleted.

**Independent Test**: seed real report dirs + stray non-report subdirectories; the report index rejects the strays and the applications list returns exactly the real set, stable across re-derivation (contracts C-P1..C-P4).

- [X] T006 [P] [US2] Test `internal/reports/reportdir_test.go` (fails pre-fix): C-P1 a directory with no deliverable and a non-matching name is NOT returned by `Index`; C-P2 a results-named dir AND a dir containing a recognized deliverable (`scan_meta.json`/`findings.json`/`README.md`) ARE returned (report-only discovery preserved).
- [X] T007 [P] [US2] Test `internal/apps/phantom_test.go` (fails pre-fix): given N real applications + stray dirs under the reports dir, `apps.ListSummaries` returns exactly N (no empties); a second call (re-derivation, as restart does) returns the same N (C-P3).
- [X] T008 [US2] `internal/reports/reports.go`: add `isReportDir(dir)` = base name matches `dirRE` OR any recognized deliverable exists (`scan_meta.json`, `findings.json`, `SCAN_REPORT.md`, `README.md`, `phase1_output.md`); `Load` returns `(_, false)` when it fails, and `Index` skips such dirs. Read-only — never deletes/alters a directory (C-P4).

**Checkpoint**: phantom applications gone and stay gone across restart; US2 tests green.

---

## Phase 4: User Story 3 — Applications list view + delete (P2)

**Goal**: a compact applications list with a confirmed delete that reuses forget (reports preserved).

**Independent Test**: backend — after `apps.Forget`, report files remain and a re-scan un-hides (C-A3). UI — the served Applications view shows a list and a per-row delete with confirm (browser, per quickstart).

- [X] T009 [US3] Legacy `vhlocal/web/index.html` Applications: add a **list** layout (per app: name, repository, scans, latest outcome/time, threat/SBOM availability) alongside/replacing the cards, with a per-row **Delete** button that calls the existing `forgetApplication(slug,…)` behind the existing confirm (FR-012/013).
- [X] T010 [P] [US3] `web-react/src/pages/Applications.tsx`: add a list layout + per-row delete (reusing `DELETE /api/applications/{slug}`) with a confirm step (parallel; not embedded).
- [X] T011 [P] [US3] Test `internal/apps/forget_test.go` (or extend): after `Forget(slug)`, the app is excluded from `ListSummaries` but its report files remain on disk and `Register(repo)` un-hides it (C-A3/FR-014).

**Checkpoint**: operators can list + delete applications; reports preserved; US3 backend test green.

---

## Phase 5: User Story 4 — Ledger list view + delete (P2)

**Goal**: a ledger list with a confirmed delete that removes only tracking data.

**Independent Test**: backend — clearing a ledger removes only its json; report files intact (C-L3). UI — the served Ledger view shows a list + per-row delete with confirm (browser).

- [X] T012 [US4] Legacy `vhlocal/web/index.html` Ledger: add a **list** layout (per ledger: name/target, tracked total, open count, last updated) with a per-row **Delete** button calling the existing `clearLedger(slug,…)` behind confirm (FR-015/016).
- [X] T013 [P] [US4] `web-react/src/pages/Ledger.tsx`: add a list layout + per-row delete (reusing `DELETE /api/ledgers/{slug}`) with a confirm step (parallel).
- [X] T014 [P] [US4] Test `internal/membank/clear_test.go` (or `internal/server`): deleting a ledger removes only `<slug>.json`; other ledgers and all report files are unaffected (C-L3/FR-017).

**Checkpoint**: operators can list + delete ledgers; reports preserved; US4 backend test green.

---

## Phase 6: Polish & cross-cutting

- [X] T015 [P] Preservation/non-destructive test `internal/server/preservation008_test.go`: exercising the stats aggregation + the report-dir guard + a forget + a ledger clear on seeded data leaves every real report file, application name, and unrelated ledger unchanged (C-P4/C-X2/SC-006); report-only apps still discoverable (C-P2/SC-007).
- [X] T016 Run the full offline gate: `go build ./...`, `go test ./... -count=1`, `go vet ./...`, `gofmt -l internal` clean; rebuild `bin/vhlocal`; capture browser acceptance of the Dashboard/Apps/Ledger views per `quickstart.md` (operator-owned).
- [X] T017 [P] Update `CHANGELOG.md` with the feature-008 entry (Dashboard metrics computed from recorded data + integer vuln average; phantom-application fix via the report-dir guard; Apps/Ledger list + delete).

---

## Dependencies & Execution Order

- **Setup (T001)** → no deps; enables the metrics + phantom fixtures.
- **US1 (T002-T005)** → T002 (test) first; T003 before T004 (Report fields feed the aggregate); T005 after T004 (UI binds the fields).
- **US2 (T006-T008)** → tests first; T008 edits `reports.go` (serialize after T003, same file).
- **US3 (T009-T011)** and **US4 (T012-T014)** → independent of each other; both reuse existing delete endpoints; UI tasks on `index.html` (T009, T012) serialize with T005.
- **Polish (T015-T017)** → after the desired stories.

### Story independence
- **US1**: stats aggregation — seeded reports with usage/timing.
- **US2**: report-dir guard — seeded real + stray dirs.
- **US3 / US4**: list+delete — backend delete already exists; tests assert preservation.

### Parallel opportunities
- Test-authoring tasks marked [P] (T002, T006, T007, T011, T014, T015) run in parallel.
- React UI tasks (T010, T013) are [P] (different files) but the legacy `index.html` tasks (T005, T009, T012) serialize.
- After Setup, US1 and US2 can proceed together except for the shared `reports.go` edits (T003 then T008).

---

## Parallel Example: US1 + US2 tests

```text
Task T002: internal/server/stats_test.go (metrics — C-M1..M5)
Task T006: internal/reports/reportdir_test.go (guard — C-P1/C-P2)
Task T007: internal/apps/phantom_test.go (phantom exclusion — C-P3)
```

---

## Implementation Strategy

### MVP (P1)
1. Setup (T001).
2. US1 (T002-T005): real Dashboard metrics + integer average → **validate**.
3. US2 (T006-T008): phantom applications gone, restart-stable → **validate**.
   → The Dashboard is trustworthy and the Apps view is clean — the core asks.

### Incremental (P2)
4. US3 (T009-T011): applications list + delete.
5. US4 (T012-T014): ledger list + delete.
6. Polish (T015-T017): preservation, full gate, CHANGELOG.

## Notes
- Tests-first for backend: author each [P] test and confirm it FAILS on current code before implementing.
- Metrics come only from recorded data (no new measurement); deletes reuse forget/clear (reports always preserved).
- Served legacy `index.html` is the primary UI target; `web-react` updated in parallel (not embedded; `npm run typecheck` is the operator's pre-flight).
- Browser acceptance (T016) is operator-owned; the offline Go gate is the harness-executable bar.

## Implementation progress — 2026-09-22

**All 17 tasks complete** (backend fully tested offline; UI on the served surface).

- **US1 (T001-T005)**: seed helper extended (usage/timing + `SeedStrayDir`); `reports.Report` gained `PromptTokens`/`CompletionTokens`/`DurationSeconds`/`HasUsage` from `scan_meta.json`; `handleStats` rewritten to the full metric set (tokens/time aggregates, integer `avg_findings_per_scan`, real per-model tokens, zero-safe). The legacy Dashboard already binds these fields, so the API fix populates it; React `Dashboard.tsx` renders the integer avg. Tests: `stats_test.go` (C-M1..M5).
- **US2 (T006-T008)**: `reports.Load`/`Index` gained the `isReportDir` guard (results-name OR recognized deliverable) — phantom directories no longer become reports/applications; report-only discovery preserved. Tests: `reportdir_test.go` (C-P1/C-P2), `apps/phantom_test.go` (C-P3, restart-stable).
- **US3 (T009-T011)**: legacy Apps view rendered as a single-column list with a per-row **Delete** (reusing `forgetApplication` + confirm); React `Applications.tsx` list + per-row delete. Test: `apps/forget_test.go` (C-A3 — reports preserved, re-scan un-hides).
- **US4 (T012-T014)**: legacy Ledger list + per-row **Delete** (reusing `clearLedger`, labeled "Delete" per analyze I1); React `Ledger.tsx` list + delete. Test: `ledger_delete_test.go` (C-L3).
- **Polish (T015-T017)**: `preservation008_test.go` (C-P4/C-X2/C-P2 — nothing lost, report-only preserved); full offline gate green (`go test ./...` = 26 pkgs, vet + gofmt clean, binary rebuilt); CHANGELOG updated.
- **Analyze findings folded in**: C1 (FR-020 error-vs-empty) — the served Dashboard/Apps/Ledger already show an error-box vs empty; confirmed, no change needed. I1 — ledger action labeled "Delete". C2 (no-new-measurement) — the stats test asserts computation purely from seeded report data. N1 — per-model chart decimal left as-is (out of scope).

**Operator-owned**: browser confirmation of the list/delete UIs and the React surface (`npm run typecheck`; `/app` still not embedded — feature 007 T048).
