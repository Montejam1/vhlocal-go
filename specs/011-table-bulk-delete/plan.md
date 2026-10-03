# Implementation Plan: Multi-select delete in table views

**Branch**: `011-table-bulk-delete` | **Date**: 2026-09-25 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/011-table-bulk-delete/spec.md`

## Summary

Bring the Applications and Ledger **Table** views to parity with the Reports tab's existing
multi-select delete: a selection checkbox on each row, a select-all checkbox in the header, a
bulk bar ("N selected" / Clear / "Delete selected (N)"), and one confirmed batch delete. This is
a **served-UI (`vhlocal/web/index.html`) change only** — the Reports mechanism already lives there
and is the reference. It reuses the existing per-row delete operations and endpoints unchanged
(forget application keeps reports; clear ledger keeps reports and other ledgers); the per-row
delete stays, and the selection controls appear only in the Table view (the List/cards view is
untouched).

Reuse the exact Reports mechanism, per view:
- a per-view selection set keyed by the row's id (application slug / ledger slug);
- a `chkcol` checkbox on each table row and a select-all checkbox in the header;
- a `bulkBar()` showing the selected count with a disabled-when-empty "Delete selected (N)";
- a confirmed batch delete that loops the existing DELETE endpoint, tolerates partial failure,
  clears the selection, reloads the list, and reports how many failed.

No Go, no backend, no new endpoints or data; delete semantics are inherited from features 008/009.

## Technical Context

**Language/Version**: Front-end only — the served self-contained `vhlocal/web/index.html` (vanilla
JS/CSS, no build step, embedded in the binary). Go backend unchanged.

**Primary Dependencies**: none new. Reuses existing helpers (`esc`, `escA`, `api`) and the
Reports multi-select CSS already present (`.bulkbar`, `table.reptbl .chkcol`) — the Apps/Ledger
tables already render with `class="ledgertbl reptbl"`, so those styles apply with no new CSS.

**Storage**: none. Selection is transient in-memory client state (a JS `Set` per view); nothing
is persisted. No server storage change.

**Testing**: browser acceptance on the served UI (operator-owned, as in prior served-UI work):
selection, select-all, count, confirmed batch delete, per-row-delete-still-works, partial-failure
reporting, reports preserved, selection cleared after delete/refresh/view-switch. There is **no new
Go logic**, so no new offline unit surface; `go test ./...` must remain green (unchanged).

**Target Platform**: loopback single-binary server; the served browser UI.

**Project Type**: web service; this feature touches only the served UI layer.

**Performance Goals**: n/a — client-side selection over small lists (dozens of rows); batch delete
issues one existing DELETE per selected row.

**Constraints**: reuse the Reports multi-select behavior verbatim (control, select-all, count,
confirmed delete) for a consistent feel; keep the 008/009 per-row delete and its data semantics
unchanged; selection controls only in Table view; clear selection after a delete, a refresh, or a
view switch; partial failures reported honestly (no item shown as deleted when it was not); UI
stays self-contained/offline; no scan-behavior or safety-boundary impact.

**Scale/Scope**: small, single-file UI change (`vhlocal/web/index.html`): two per-view selection
sets, checkbox columns + select-all in the two existing table renderers, two bulk bars, and two
batch-delete functions, wired into the existing `renderApps`/`renderLedgers` and refresh/toggle
paths.

**Confirmed reference (this planning pass):**
- Reports multi-select: `_reportSel` Set (`index.html:3473`); row/select-all checkboxes in the
  `chkcol` column (`:3441-3442`, `:3459-3460`); `reportBulkBar()` (`:3464-3470`); `toggleReportSel`
  (`:3474`), `toggleAllReports` (`:3479`), `clearReportSel` (`:3484`), `deleteSelectedReports`
  (confirm once → loop `DELETE /api/reports/{id}` → clear → `loadReports` → report failures,
  `:3485-3497`). CSS `.bulkbar`/`.chkcol` (`:764-772`).
- Targets: `appsTableHTML` (`:4275`) with per-row `forgetApplication(slug,…)`; `ledgersTableHTML`
  (`:3749`) with per-row `clearLedger(slug,…)`; branch points `renderApps` (`:4242`) and
  `renderLedgers` (`:3693`); delete endpoints `DELETE /api/applications/{slug}` and
  `DELETE /api/ledgers/{slug}` already exist.
- No `NEEDS CLARIFICATION` remain.

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after Phase 1. Constitution v1.1.0.*

- **I. Evidence Integrity** — unaffected: a selection/bulk-delete UI changes no evidence; the batch
  reports true outcomes (partial failures surfaced), never a false "deleted" (FR-009). PASS.
- **II. Orthogonal Status Reporting** — unaffected. PASS.
- **III. Static-Only Safety Boundary** — no execution; UI-only; deletes reuse existing endpoints
  that already confine to the reports/ledger stores. PASS.
- **IV. Provenance / V. Explicit Failure** — no model calls; a failed delete is surfaced, not
  swallowed (FR-009). PASS.
- **VI. Resumable/Idempotent** — n/a to a client selection; each delete is the existing idempotent
  endpoint call. PASS.
- **VII. Testable Acceptance** — pure front-end with no Go logic; acceptance is browser-verified
  (operator-owned) as in prior served-UI work; the Go suite stays green. PASS (front-end-testing
  note recorded).
- **Safety & Technical Constraints** — self-contained UI (no CDN), no new runtime dependency,
  deterministic rendering, no egress. PASS.

**Gate result: PASS. No violations → Complexity Tracking omitted.** Re-check after Phase 1: still PASS.

## Project Structure

### Documentation (this feature)

```text
specs/011-table-bulk-delete/
├── plan.md          # this file
├── research.md      # Phase 0 output
├── data-model.md    # Phase 1 output
├── quickstart.md    # Phase 1 output
├── contracts/       # Phase 1 output (UI behavior contract)
└── tasks.md         # /speckit-tasks (not created here)
```

### Source Code (repository root)

```text
vhlocal/web/index.html   # ALL changes here:
                         #  - _appSel / _ledSel selection Sets (keyed by slug)
                         #  - chkcol checkbox column + select-all header in appsTableHTML / ledgersTableHTML
                         #  - appsBulkBar() / ledgersBulkBar() (N selected / Clear / Delete selected (N))
                         #  - toggle/toggleAll/clear + deleteSelectedApps() / deleteSelectedLedgers()
                         #    (confirm once → loop existing DELETE → clear → reload → report failures)
                         #  - clear selection in loadApplications/loadLedgers (refresh) and
                         #    setAppsView/setLedgerView (view switch); keep the 008/009 per-row delete
```

No Go files change. `web-react` is intentionally untouched (its Apps/Ledger tables from feature 010
are not yet built; multi-select there follows the same pattern once they ship).

**Structure Decision**: single served-UI file. A faithful reuse of the Reports multi-select/bulk-
delete pattern applied to two existing table renderers; no backend, no new dependency, no data change.

## Complexity Tracking

No constitution violations — section intentionally omitted.
