---
description: "Task list for feature 009 — Table/List view toggle for Applications & Ledger"
---

# Tasks: Table/List view toggle for Applications & Ledger

**Input**: Design documents from `/specs/009-apps-ledger-view-toggle/`

**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅, data-model.md ✅, contracts/behavior.md ✅, quickstart.md ✅

**Tests**: No new automated test tasks — this is a served-UI-only change with **no new Go logic** (research R4, plan Testing). Validation is browser-driven (operator-owned) per quickstart.md; the existing Go suite must stay green as a non-regression guard.

**Organization**: Tasks are grouped by user story. Both stories are **P1** and edit the **same file** (`vhlocal/web/index.html`), so they cannot run in parallel with each other, but each is independently implementable and testable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies) — rare here, since nearly everything lives in one file.
- **[Story]**: US1 (Applications) or US2 (Ledger).
- All UI work is in the single served file `vhlocal/web/index.html`.

## Path Conventions

- Served UI (only surface changed): `vhlocal/web/index.html` (vanilla JS/CSS, embedded in the binary).
- Reference pattern to mirror (Reports): same file — `reportsView()` (~:3275), `setReportsView` (~:3283), `sortReports`/`_RSORT` (~:3289, :3311), `renderReports` (~:3486), toggle buttons `rvCards`/`rvTable` (~:3104-3107).
- No Go files change. `web-react/` is intentionally untouched (its Reports page has no toggle to mirror — research R2).

---

## Phase 1: Setup (baseline & reference confirmation)

**Purpose**: Establish a working build and confirm the exact Reports mechanism to mirror before editing.

- [X] T001 Confirm baseline build & suite green: `export PATH=$PATH:/usr/local/go/bin && go build -o bin/vhlocal ./cmd/vhlocal && go test ./... -count=1 && go vet ./...` (records the pre-change green state; no Go changes expected in this feature).
- [X] T002 Re-read the Reports toggle implementation in `vhlocal/web/index.html` to lock exact idioms to copy: the `rvCards`/`rvTable` control markup + `.on`/`aria-pressed` states, `reportsView()`/`setReportsView()` localStorage read/persist/re-render, `sortReports()`/`sortedReports()`/`_RSORT` accessor map + clickable `<th>` headers, and how `renderReports()` carries the open detail pane across a switch. Note their current line numbers for reuse.

---

## Phase 2: Foundational (shared toggle/table scaffolding)

**Purpose**: Shared CSS + the removal of the previous sprint's fixed single-column layout, needed before either view's toggle renders correctly. **Blocks US1 and US2.**

**⚠️ CRITICAL**: No user-story rendering work should land before this phase.

- [X] T003 In `vhlocal/web/index.html` CSS, add table styling for the Applications/Ledger tables reusing the Reports table's classes/idiom (sortable-header affordance, row hover, the per-row Delete cell), so both new tables inherit the Reports look. (contracts C-T3, C-V1)
- [X] T004 In `vhlocal/web/index.html`, remove the feature-008 forced single-column layout: delete the `.cards.applist{grid-template-columns:1fr}` rule and the `applist` class usage on the Applications cards container so List (cards) mode matches the Reports cards grid. Keep the `.approw-del`/`.ledrow-del` delete-button styles. (FR-011, research R3)

**Checkpoint**: Table CSS present and the old single-column list layout gone — user-story rendering can begin.

---

## Phase 3: User Story 1 — Applications Table/List toggle like Reports (Priority: P1) 🎯 MVP

**Goal**: The Applications view gains a Reports-style Table/List toggle: sortable table rows or cards, choice persisted (`vhlocal.apps.view`, default `cards`), delete available in both modes.

**Independent Test**: On Applications, toggle to Table → sortable rows; toggle to List → cards; reload → last-chosen view restored; delete an application from each view (report files remain).

- [X] T005 [US1] In `vhlocal/web/index.html`, add `appsView()` and `setAppsView(v)` mirroring `reportsView()`/`setReportsView()`, keyed on `localStorage['vhlocal.apps.view']`, defaulting to `cards` (List) with the same read-once/cache + invalid-value fallback behavior; `setAppsView` persists and re-renders Applications. (FR-005/006, data-model ViewPreference, C-V3/C-V4)
- [X] T006 [US1] In `vhlocal/web/index.html`, add the Table/List segmented control to the Applications view header (two buttons mirroring `rvCards`/`rvTable`), wired to `setAppsView('cards'|'table')`, with the active button getting `.on` + `aria-pressed`. (FR-001, C-V1)
- [X] T007 [US1] In `vhlocal/web/index.html`, add an Applications sort mechanism mirroring `sortReports`/`sortedReports`/`_RSORT`: per-view sort state `{key,dir}`, a click handler that sets/reverses, and an accessor map for the columns — name (lowercased string), repository (string), scans (number), latest outcome/time (time/number), threat/SBOM availability, open findings (number). Default sort matches the current natural order (most-recent first). (FR-003, C-T3, data-model sort state)
- [X] T008 [US1] In `vhlocal/web/index.html`, add `appsTableHTML(rows)` that renders the sortable table with clickable `<th>` headers and, per row, at least: name, repository, scan count, latest outcome/time, threat/SBOM availability, open findings — plus a Delete cell calling the existing `forgetApplication(...)` with `event.stopPropagation()`. (FR-007/FR-008, C-T1, C-D1/C-D2)
- [X] T009 [US1] In `vhlocal/web/index.html`, branch `loadApplications()` on `appsView()`: render `appsTableHTML(sortedApps())` for `table` vs the existing `appCard` cards for `cards`; set the toggle button states; keep the empty state and error state distinct in **both** modes (no empty table shown as broken; a failed load shows an error, not empty); and carry any open detail pane across a switch without re-fetching. (FR-004/FR-010, C-V2, C-S1/C-S2)

**Checkpoint**: Applications toggle fully functional and independently testable — matches Reports.

---

## Phase 4: User Story 2 — Ledger Table/List toggle like Reports (Priority: P1)

**Goal**: The Ledger view gains the same Reports-style Table/List toggle: sortable table rows or cards, choice persisted (`vhlocal.ledger.view`, default `cards`), delete available in both modes.

**Independent Test**: On Ledger, toggle to Table → sortable rows; toggle to List → cards; reload → restoration; delete a ledger from each view (other ledgers and reports preserved).

- [X] T010 [US2] In `vhlocal/web/index.html`, add `ledgerView()` and `setLedgerView(v)` mirroring the Reports getter/setter, keyed on `localStorage['vhlocal.ledger.view']`, defaulting to `cards`, with the same fallback behavior; `setLedgerView` persists and re-renders Ledger. (FR-005/006, C-V3/C-V4)
- [X] T011 [US2] In `vhlocal/web/index.html`, add the Table/List segmented control to the Ledger view header (two buttons mirroring `rvCards`/`rvTable`), wired to `setLedgerView('cards'|'table')`, with active-state `.on` + `aria-pressed`. (FR-002, C-V1)
- [X] T012 [US2] In `vhlocal/web/index.html`, add a Ledger sort mechanism mirroring the Reports one: per-view `{key,dir}` state, click-to-sort/reverse, and an accessor map for the columns — name/target (lowercased string), tracked total (number), open (number), runs recorded (number), last updated (time/number). Default sort matches the current natural order. (FR-003, C-T3)
- [X] T013 [US2] In `vhlocal/web/index.html`, add `ledgersTableHTML(rows)` rendering the sortable table with clickable `<th>` headers and, per row, at least: name/target, tracked total, open count, runs recorded, last updated — plus a Delete cell calling the existing `clearLedger(...)` with `event.stopPropagation()`. (FR-007/FR-009, C-T2, C-D1/C-D2)
- [X] T014 [US2] In `vhlocal/web/index.html`, branch `loadLedgers()` on `ledgerView()`: render `ledgersTableHTML(sortedLedgers())` for `table` vs the existing ledger cards for `cards`; set toggle button states; keep empty/error states distinct in both modes; carry any open detail across a switch without re-fetching. (FR-004/FR-010, C-V2, C-S1/C-S2)

**Checkpoint**: Ledger toggle fully functional and independently testable — matches Reports and US1.

---

## Phase 5: Polish & Cross-Cutting Concerns

**Purpose**: Consistency verification, non-regression, and provenance.

- [X] T015 Non-regression gate: `export PATH=$PATH:/usr/local/go/bin && go build -o bin/vhlocal ./cmd/vhlocal && go test ./... -count=1 && go vet ./... && gofmt -l vhlocal` — confirm the Go suite is still green and no Go files changed (C-S3, FR-011).
- [X] T016 Cross-view consistency review of `vhlocal/web/index.html`: verify the Applications and Ledger toggles use the same control markup, default (`cards`), persistence idiom, and sort behavior as Reports (a reviewer should find them consistent). (SC-006)
- [X] T017 Update `CHANGELOG.md` with the feature-009 entry (Applications & Ledger gain the Reports-style Table/List toggle; per-row delete retained; 008 fixed single-column layout replaced; no data/metrics/scan changes).
- [X] T018 Run the `quickstart.md` browser-acceptance checklist against a seeded server (operator-owned): toggle & switch, per-view persistence + default, column sort/reverse, delete in both modes, empty/error states, open-detail carried across switch. Record commit + `bin/vhlocal` hash used. (SC-001..006)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies — start immediately.
- **Foundational (Phase 2)**: depends on Setup; **blocks US1 and US2** (shared CSS + removal of the old single-column layout).
- **US1 (Phase 3)** and **US2 (Phase 4)**: both depend on Foundational. Each is independently testable, but both edit `vhlocal/web/index.html`, so they should be done **sequentially** (US1 first as the MVP), not in parallel.
- **Polish (Phase 5)**: depends on the user stories being complete.

### Within Each User Story

- Getter/setter (state) → toggle control → sort mechanism → table renderer → wire the render branch. Later tasks in a story depend on the earlier ones in that story.

### Parallel Opportunities

- Limited: nearly all tasks touch the single file `vhlocal/web/index.html`, so same-file conflicts prevent parallelism between them.
- The two stories are independent in *concept* (Apps vs Ledger) but not file-parallelizable; run US1 then US2.
- The Go gate tasks (T001, T015) are independent of the UI edits and can be run at their phase boundaries.

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. Phase 1 Setup → Phase 2 Foundational → Phase 3 US1 (Applications toggle).
2. **STOP and VALIDATE**: browser-test Applications toggle/persist/sort/delete independently (quickstart §§1–5, Applications).
3. This alone corrects the previous sprint for Applications and is demoable.

### Incremental Delivery

1. Setup + Foundational → shared scaffolding ready.
2. US1 (Applications) → validate → demo (MVP).
3. US2 (Ledger) → validate → demo.
4. Polish: Go gate, consistency review, CHANGELOG, quickstart acceptance.

---

## Notes

- No new Go logic → no new automated test tasks; the existing suite is the non-regression guard (T001/T015).
- All UI changes are in `vhlocal/web/index.html`; keep the feature-008 per-row Delete + confirmation and its data semantics unchanged (FR-007).
- Keep loading/empty/error states distinct in both modes (FR-010) — do not render a failed load as an empty table/list.
- React (`web-react/`) is out of scope (no Reports toggle to mirror — research R2).
- Commit after each user story; validate each story independently before moving on.
