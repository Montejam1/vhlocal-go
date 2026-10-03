# Contracts — Multi-select delete behavior (served UI)

UI behavior invariants for the Applications and Ledger **Table** views, matching the Reports tab.
All are browser-verified on the served `vhlocal/web/index.html` (operator-owned); there is no new
backend logic. IDs are referenced by tasks and map to success criteria.

## Selection controls

- **C-S1 (row checkboxes)**: In Table view, each Applications row and each Ledger row shows a
  selection checkbox in a leading `chkcol`, identical in placement/interaction to the Reports table
  (FR-001/002, SC-001/003).
- **C-S2 (select-all)**: A header checkbox selects every row currently shown; unticking it clears the
  selection, consistent with Reports (FR-001/002, SC-001).
- **C-S3 (scoped)**: Selection is per view — an Applications selection is independent of a Ledger
  selection (FR-010).

## Bulk bar

- **C-B1 (count + action)**: A bulk bar shows "N selected" and a "Delete selected (N)" action,
  matching Reports (FR-003, SC-001/003).
- **C-B2 (disabled when empty)**: With nothing selected, "Delete selected" is disabled; with one or
  more selected it is enabled (FR-004, SC-004).

## Delete

- **C-D1 (confirmed batch)**: "Delete selected" deletes all selected rows as one operator action
  behind a single confirmation, reusing the existing delete operations (FR-005, SC-001).
- **C-D2 (semantics unchanged)**: Deleting selected applications forgets them and keeps their reports;
  deleting selected ledgers removes only their tracking data and keeps reports and unselected ledgers
  — unchanged from features 008/009 (FR-005, SC-002).
- **C-D3 (per-row retained)**: The per-row delete remains available in Table view alongside the
  checkboxes (FR-006).
- **C-D4 (partial failure honest)**: If one or more selected items fail to delete, the operator is
  told how many failed and the reloaded list shows the true result — no item is shown as deleted that
  was not (FR-009, SC-005).

## Lifecycle & scope

- **C-L1 (Table only)**: Selection controls appear only in Table view; the List (cards) view is
  unchanged and keeps its per-row delete (FR-007).
- **C-L2 (selection cleared)**: After a bulk delete, a refresh, or a view switch, the selection is
  cleared (no stale checkboxes) (FR-008).
- **C-L3 (no other change)**: The feature changes no data other than performing the requested
  deletions, and the Reports tab's existing multi-select is unchanged (FR-010/011).
- **C-L4 (parity)**: A reviewer comparing the Applications/Ledger selection-and-delete controls to
  the Reports tab finds the checkbox, select-all, selected-count, and "Delete selected" behavior
  consistent (SC-003).
