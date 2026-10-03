# Phase 0 Research: Multi-select delete in table views

Findings from reading the served UI (`vhlocal/web/index.html`). No backend involved — the delete
endpoints already exist.

## R1 — The Reports multi-select is the pattern to reuse (served UI)

**Decision**: Reuse the Reports tab's multi-select/bulk-delete mechanism verbatim for the
Applications and Ledger Table views.

**Evidence** (`vhlocal/web/index.html`):
- **Selection state**: `let _reportSel = new Set()` holds selected ids (`:3473`).
- **Row + select-all checkboxes**: a `chkcol` `<td>`/`<th>` — per-row `toggleReportSel(id, checked)`
  (`:3441-3442`) and a header select-all `toggleAllReports(checked)` (`:3459-3460`).
- **Bulk bar**: `reportBulkBar()` renders "N selected", a Clear button, and a
  "Delete selected (N)" danger button, all disabled when nothing is selected (`:3464-3470`).
- **Batch delete**: `deleteSelectedReports()` confirms once, loops `DELETE /api/reports/{id}`,
  counts failures, clears the set, reloads, and alerts how many could not be deleted (`:3485-3497`).
- **CSS**: `.bulkbar*` and `table.reptbl .chkcol` styles already exist (`:764-772`). The Apps/Ledger
  tables already render with `class="ledgertbl reptbl"`, so these styles apply with **no new CSS**.

**Approach**: replicate per view — `_appSel` (keyed by application slug) and `_ledSel` (keyed by
ledger slug); a `chkcol` column + select-all in `appsTableHTML`/`ledgersTableHTML`; `appsBulkBar()`
/`ledgersBulkBar()`; `toggle*Sel`/`toggleAll*`/`clear*Sel`; and `deleteSelectedApps()`/
`deleteSelectedLedgers()` mirroring `deleteSelectedReports` (one confirm → loop the existing DELETE
→ clear → reload → report failures).

**Rationale**: FR-001..004, FR-011 ask for parity with Reports. Reusing the exact idiom gives an
identical feel and minimal new surface.

**Alternatives considered**: a shared generic multi-select component — rejected as over-engineering
for a self-contained vanilla-JS page; matching the existing Reports idiom is simpler and consistent.

## R2 — Apply to the Table view only; reuse existing per-row deletes

**Decision**: Add the selection column/bulk bar in `appsTableHTML` and `ledgersTableHTML` only
(the Table view). The List (cards) view is unchanged and keeps its per-row delete (FR-007). The
per-row Table delete stays alongside the checkboxes (FR-006).

**Evidence**: `appsTableHTML` (`:4275`) renders `ai-approw` rows with a per-row
`forgetApplication(slug,…)` delete cell; `ledgersTableHTML` (`:3749`) rows with `clearLedger(slug,…)`.
`renderApps` (`:4242`) and `renderLedgers` (`:3693`) branch table-vs-cards. The batch delete must
**not** call `forgetApplication`/`clearLedger` (each of those confirms per item); it calls the
existing endpoints directly in a loop after one upfront confirmation, as `deleteSelectedReports` does.

**Rationale**: keeps the change scoped to the table renderer and reuses the delete endpoints without
double-confirmation.

## R3 — Delete semantics inherited; partial failures honest

**Decision**: Bulk delete reuses `DELETE /api/applications/{slug}` (forget — keeps reports) and
`DELETE /api/ledgers/{slug}` (clear — keeps reports and other ledgers), unchanged (FR-005). A single
confirmation covers the batch; each failed item is counted and reported, and the reloaded list shows
the true result — nothing is shown as deleted that was not (FR-009).

**Evidence**: those endpoints exist and are what the per-row deletes already call; `deleteSelectedReports`
already models the confirm-once + count-failures + reload flow.

**Rationale**: FR-005/FR-009; no new backend behavior.

## R4 — Selection lifecycle

**Decision**: Selection is transient per view, keyed by slug. Clear it after a bulk delete, on a
refresh (`loadApplications`/`loadLedgers`), and on a view switch (`setAppsView`/`setLedgerView`), so
no stale checkboxes persist (FR-008/FR-010). Selection is stable across in-view re-renders (sort,
toggle) — held in the Set — matching how Reports keeps its selection during a re-render.

**Rationale**: FR-008/FR-010; avoids acting on rows the operator can no longer see.

## R5 — Served UI is the target; React is out of scope now

**Decision**: Scope to `vhlocal/web/index.html`. Leave `web-react` untouched.

**Evidence**: The React Apps/Ledger **table** views are part of feature 010 and are not yet built
(no `vhlocal/web/app` output); there is no React table here to add multi-select to. The served
`index.html` is the shipped surface (features 008/009).

**Consequence**: React multi-select follows the same pattern once the feature-010 tables ship.

## R6 — Testing posture

**Decision**: Browser-verify selection/select-all/count/confirmed-batch-delete/per-row-still-works/
partial-failure/reports-preserved/selection-cleared on the served UI (operator-owned, as in prior
served-UI features); keep `go test ./...` green (no Go changes). No new offline unit surface is
created because there is no new Go logic.

**Rationale**: the change is entirely client-side; the constitution's test requirement is met by
browser acceptance for the UI layer, and the existing backend suite guards the delete endpoints.

## Post-design constitution re-check

A client-side selection + bulk-delete over existing endpoints adds no target execution, no provider
calls, no new runtime dependency, and no data change beyond the deletions the operator requests, with
honest failure reporting. **Constitution Check remains PASS after design.**
