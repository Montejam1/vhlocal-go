---
description: "Task list for feature 011 — Multi-select delete in table views"
---

# Tasks: Multi-select delete in table views

**Input**: Design documents from `/specs/011-table-bulk-delete/`

**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅ (R1–R6), data-model.md ✅,
contracts/behavior.md ✅, quickstart.md ✅

**Tests**: No new automated test tasks — this is a served-UI-only change with **no new Go logic**
(research R6, plan Testing). The delete endpoints already exist and are covered; validation is
browser-driven (operator-owned) per quickstart.md; the existing Go suite must stay green as a
non-regression guard.

**Organization**: Tasks are grouped by user story. Both stories are **P1** and edit the **same
file** (`vhlocal/web/index.html`), so they cannot run in parallel with each other, but each is
independently implementable and testable.

## Format: `[ID] [P?] [Story?] Description with file path`

- **[P]**: parallelizable (different files) — rare here, since everything lives in one file.
- **[Story]**: US1 (Applications) or US2 (Ledger).
- All UI work is in the single served file `vhlocal/web/index.html`.

## Path Conventions

- Served UI (only surface changed): `vhlocal/web/index.html` (vanilla JS/CSS, embedded).
- Reference pattern to mirror (Reports): same file — `_reportSel` (`:3473`), `chkcol` row/select-all
  (`:3441-3460`), `reportBulkBar()` (`:3464`), `toggleReportSel`/`toggleAllReports`/`clearReportSel`/
  `deleteSelectedReports` (`:3474-3497`), CSS `.bulkbar`/`.chkcol` (`:764-772`).
- Targets: `appsTableHTML` (`:4275`) + `renderApps` (`:4242`); `ledgersTableHTML` (`:3749`) +
  `renderLedgers` (`:3693`). Delete endpoints already exist: `DELETE /api/applications/{slug}`,
  `DELETE /api/ledgers/{slug}`.
- No Go files change. `web-react/` intentionally untouched (its 010 tables aren't built yet).

---

## Phase 1: Setup (baseline & reference confirmation)

**Purpose**: Establish a working build and confirm the exact Reports multi-select idioms to mirror.

- [X] T001 Confirm baseline build & suite green: `export PATH=$PATH:/usr/local/go/bin && go build -o bin/vhlocal ./cmd/vhlocal && go test ./... -count=1 && go vet ./...` (records the pre-change green state; no Go changes expected).
- [X] T002 Re-read the Reports multi-select in `vhlocal/web/index.html` to lock the idioms to copy: the `chkcol` row checkbox (`toggleReportSel`) and header select-all (`toggleAllReports`); `reportBulkBar()` (count + Clear + disabled-when-empty "Delete selected (N)"); and `deleteSelectedReports()` (one confirm → loop `DELETE` → count failures → clear → reload → alert failures). Note the current line numbers for reuse.

---

## Phase 2: Foundational (shared confirmation)

**Purpose**: Confirm the shared CSS/idiom is reusable so both stories render correctly. **Blocks US1 and US2.**

- [X] T003 In `vhlocal/web/index.html`, confirm the Apps and Ledger tables render with `class="ledgertbl reptbl"` so the existing `.bulkbar` and `table.reptbl .chkcol` styles (`:764-772`) apply with **no new CSS**; if any table is missing the `reptbl` class, add it (contracts C-S1/C-B1). No behavior change in this task.

**Checkpoint**: shared styles confirmed — user-story wiring can begin.

---

## Phase 3: User Story 1 — Bulk-select & delete applications (Priority: P1) 🎯 MVP

**Goal**: The Applications Table view gains per-row + select-all checkboxes, a bulk bar, and a
single-confirmation batch delete that reuses the forget endpoint (reports preserved).

**Independent Test**: On Applications → Table, select rows (and select-all), see "N selected",
"Delete selected (N)", confirm once → selected apps leave the list, their reports remain on disk;
per-row delete still works; List view unchanged; selection clears after delete/refresh/view-switch.

- [X] T004 [US1] In `vhlocal/web/index.html`, add `let _appSel = new Set()` (keyed by application slug) near the apps state, plus `toggleAppSel(slug,on)`, `toggleAllApps(on)` (selects every row in `sortedApps()`), and `clearAppSel()` — mirroring `toggleReportSel`/`toggleAllReports`/`clearReportSel` (contracts C-S1/C-S2/C-S3, data-model RowSelection).
- [X] T005 [US1] In `vhlocal/web/index.html` `appsTableHTML(rows)`: add a leading `chkcol` `<th>` with a select-all checkbox (checked when all rows selected) and, per row, a `chkcol` `<td>` checkbox (`onclick="event.stopPropagation()"`, `onchange="toggleAppSel(...)"`, checked from `_appSel`); prepend `appsBulkBar()` before the table. Keep the existing per-row Delete cell (contracts C-S1/C-S2/C-D3, FR-006).
- [X] T006 [US1] In `vhlocal/web/index.html`, add `appsBulkBar()` mirroring `reportBulkBar()`: "N selected", a Clear button, and a danger "Delete selected (N)" button disabled when `_appSel.size===0` (contracts C-B1/C-B2, FR-003/004).
- [X] T007 [US1] In `vhlocal/web/index.html`, add `deleteSelectedApps()` mirroring `deleteSelectedReports`: one `confirm()` for the batch, loop `await api('/api/applications/'+encodeURIComponent(slug),{method:'DELETE'})` over `[..._appSel]`, count failures, `_appSel.clear()`, `await loadApplications()`, and `alert` how many failed. It MUST call the endpoint directly (not `forgetApplication`, which confirms per item). Forget semantics keep reports on disk (contracts C-D1/C-D2/C-D4, FR-005/009).
- [X] T008 [US1] In `vhlocal/web/index.html`, clear `_appSel` on refresh and view switch: at the start of `loadApplications()` and inside `setAppsView()` call `_appSel.clear()` so no stale checkboxes persist; ensure `toggleAppSel`/`toggleAllApps`/`clearAppSel` re-render only the bulk bar / table without refetching (contracts C-L1/C-L2, FR-007/008).

**Checkpoint**: Applications bulk-select delete works and is independently testable.

---

## Phase 4: User Story 2 — Bulk-select & delete ledgers (Priority: P1)

**Goal**: The Ledger Table view gains the same per-row + select-all checkboxes, bulk bar, and
single-confirmation batch delete that reuses the clear endpoint (reports + other ledgers preserved).

**Independent Test**: On Ledger → Table, select rows (and select-all), see "N selected", "Delete
selected (N)", confirm once → selected ledgers removed, reports and unselected ledgers remain;
per-row delete still works; List view unchanged; selection clears after delete/refresh/view-switch.

- [X] T009 [US2] In `vhlocal/web/index.html`, add `let _ledSel = new Set()` (keyed by ledger slug), plus `toggleLedSel(slug,on)`, `toggleAllLedgers(on)` (selects every row in `sortedLedgers()`), and `clearLedSel()` — mirroring the Reports selection helpers (contracts C-S1/C-S2/C-S3).
- [X] T010 [US2] In `vhlocal/web/index.html` `ledgersTableHTML(rows)`: add a leading `chkcol` `<th>` select-all checkbox and per-row `chkcol` `<td>` checkbox wired to `toggleLedSel`/`_ledSel`; prepend `ledgersBulkBar()` before the table. Keep the existing per-row Delete cell (contracts C-S1/C-S2/C-D3, FR-006).
- [X] T011 [US2] In `vhlocal/web/index.html`, add `ledgersBulkBar()` mirroring `reportBulkBar()`: "N selected", Clear, and a danger "Delete selected (N)" disabled when `_ledSel.size===0` (contracts C-B1/C-B2, FR-003/004).
- [X] T012 [US2] In `vhlocal/web/index.html`, add `deleteSelectedLedgers()` mirroring `deleteSelectedReports`: one `confirm()`, loop `await api('/api/ledgers/'+encodeURIComponent(slug),{method:'DELETE'})` over `[..._ledSel]`, count failures, `_ledSel.clear()`, `await loadLedgers()`, alert failures. Call the endpoint directly (not `clearLedger`). Clear semantics keep reports and unselected ledgers (contracts C-D1/C-D2/C-D4, FR-005/009).
- [X] T013 [US2] In `vhlocal/web/index.html`, clear `_ledSel` at the start of `loadLedgers()` and inside `setLedgerView()`; ensure the ledger selection helpers re-render the bulk bar / table without refetching and carry the open detail pane as `renderLedgers` already does (contracts C-L1/C-L2, FR-007/008).

**Checkpoint**: Ledger bulk-select delete works and matches Applications and Reports.

---

## Phase 5: Polish & Cross-Cutting Concerns

- [X] T014 Non-regression gate: `export PATH=$PATH:/usr/local/go/bin && go build -o bin/vhlocal ./cmd/vhlocal && go test ./... -count=1 && go vet ./... && gofmt -l internal cmd` — Go suite still green, no Go files changed (contracts C-L3, FR-011).
- [X] T015 Cross-view consistency review of `vhlocal/web/index.html`: verify the Applications and Ledger selection/select-all/count/"Delete selected" controls match the Reports tab, appear only in Table view (List/cards unchanged), and that per-row delete is retained (contracts C-L1/C-L4, SC-003).
- [X] T016 Update `CHANGELOG.md` with the feature-011 entry (Applications & Ledger table views gain Reports-style multi-select delete; per-row delete retained; delete semantics/reports preserved; no data/scan changes).
- [ ] T017 Run the `quickstart.md` browser-acceptance checklist against a seeded server (operator-owned): select & count, select-all, disabled-when-empty, confirmed batch delete + reports preserved, per-row still works, List view unchanged, selection cleared, partial-failure honesty, parity with Reports. Record commit + `bin/vhlocal` hash. (SC-001..005)

---

## Dependencies & Execution Order

### Phase dependencies
- **Setup (P1)** → **Foundational (P2)** (confirm shared styles) → blocks US1/US2.
- **US1 (P3)** and **US2 (P4)**: both depend on Foundational; each is independently testable, but both
  edit `vhlocal/web/index.html`, so run them **sequentially** (US1 first as the MVP), not in parallel.
- **Polish (P5)** after the user stories.

### Within a story
Selection state (Set + toggles) → table checkboxes/select-all → bulk bar → batch delete → lifecycle
(clear on refresh/view-switch). Same-file tasks run in order.

### Parallel opportunities
- Minimal: nearly all tasks edit the single file `vhlocal/web/index.html`, so same-file conflicts
  prevent parallelism. The two stories are conceptually independent (Apps vs Ledger) but not
  file-parallelizable; run US1 then US2. The Go gate tasks (T001, T014) are independent of the edits.

---

## Implementation Strategy

### MVP first (User Story 1)
1. Setup + Foundational → US1 (Applications bulk-select delete).
2. **STOP and VALIDATE**: browser-test selection/select-all/count/confirmed delete/reports-preserved/
   per-row/List-unchanged/selection-cleared/partial-failure on Applications (quickstart §§1–8).
3. This alone delivers the requested capability for Applications and is demoable.

### Incremental delivery
US1 (Applications) → validate → US2 (Ledger) → validate → Polish (Go gate, consistency review,
CHANGELOG, quickstart acceptance).

---

## Notes
- No new Go logic → no new automated test tasks; the existing suite is the non-regression guard (T001/T014).
- Batch delete calls the DELETE endpoints directly with ONE upfront confirmation — it must not call
  the per-item `forgetApplication`/`clearLedger` (which confirm per item).
- Keep the 008/009 per-row delete + confirmation and data semantics unchanged (FR-005/006); reports
  are preserved by the existing endpoints.
- Selection controls only in Table view; List/cards unchanged (FR-007). Selection cleared on
  delete/refresh/view-switch (FR-008).
- React (`web-react/`) is out of scope (its 010 tables aren't built yet).
- Commit per story; validate each story independently before moving on.
