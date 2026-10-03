# Phase 1 Data Model: Multi-select delete in table views

No server data changes. The only new state is transient client-side row selection; the rows
themselves reuse the existing feature-009 table data.

## RowSelection (client-only, per view)

The set of rows the operator has ticked in a table view, driving the bulk action.

| Item | Value | Rule |
|---|---|---|
| Applications selection | a set of application slugs | in-memory `Set` (`_appSel`); not persisted |
| Ledger selection | a set of ledger slugs | in-memory `Set` (`_ledSel`); not persisted |

Rules:
- Toggling a row's checkbox adds/removes its slug; select-all adds every row currently shown (and
  unticking clears); a Clear action empties the set.
- The set is **cleared** after a bulk delete, on a refresh (`loadApplications`/`loadLedgers`), and on
  a view switch (`setAppsView`/`setLedgerView`) — no stale checkboxes (FR-008/FR-010).
- It is **stable across in-view re-renders** (sort, single toggle) — held in the `Set` — so the
  operator's selection is not lost while they keep working in the same view.
- It is **per view**: the Applications selection is independent of the Ledger selection (FR-010).

## Bulk action bar (derived, per view)

Rendered from the selection set, mirroring the Reports bulk bar.

- Shows the selected count ("N selected").
- A "Delete selected (N)" action, **disabled when the set is empty** (FR-004), enabled otherwise.
- A Clear action to empty the selection.

## Application row / Ledger row (reused, unchanged data)

The existing feature-009 Table rows, now each carrying a leading selection checkbox and (unchanged)
the per-row delete action.

- **Applications**: slug, name, repository, scans, latest severity, last scan, threat/SBOM, open —
  plus a selection checkbox and the existing Delete.
- **Ledger**: application/target, tracked total, open, runs, last updated — plus a selection checkbox
  and the existing Delete.

## Batch delete (behavior, per view)

- One confirmation covers the whole batch.
- Reuses the existing delete endpoint per selected slug: `DELETE /api/applications/{slug}` (forget —
  keeps reports) / `DELETE /api/ledgers/{slug}` (clear — keeps reports and other ledgers). Semantics
  unchanged from features 008/009 (FR-005).
- Counts failures; reports how many could not be deleted; reloads the list to the true post-operation
  state (FR-009). No item is shown as deleted that was not.

## Relationships

- RowSelection is independent per view and per viewer; it is transient and never written to disk.
- Row content and the delete endpoints are the same data + semantics as features 008/009; only the
  ability to select and delete several rows at once is added.
