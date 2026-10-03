# Feature Specification: Multi-select delete in table views

**Feature Branch**: `011-table-bulk-delete`

**Created**: 2026-09-25

**Status**: Draft

**Input**: User description: "I would like to add a checkbox to the table views of tabs so I can delete multiple entries at once."

## Overview

The Reports tab already lets an operator select multiple rows with checkboxes and delete them
in one action ("Delete selected (N)"). The Applications and Ledger tabs gained a Table view in
the previous sprint (feature 009) with a **per-row** delete, but no way to act on several rows
at once. This feature brings the Applications and Ledger **table views** to parity with Reports:
a selection checkbox on each row, a select-all control, and a bulk "Delete selected" action
behind a single confirmation — matching the Reports control exactly.

Scope discipline: this is a view-interaction change on existing table views. It reuses the
existing delete operations and their data semantics unchanged (forgetting an application keeps
its reports; deleting a ledger keeps reports). The per-row delete stays. The List (cards) view
is unchanged. No change to underlying data, metrics, or scanning.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Bulk-select and delete applications from the table view (Priority: P1)

An operator on the Applications **Table** view can tick a checkbox on one or more rows (or a
select-all checkbox in the header), see how many are selected, and delete them all at once with
a single confirmation — the same way the Reports tab works. Each forgotten application keeps its
reports on disk.

**Why this priority**: Directly fulfills the request and removes the tedium of deleting
applications one at a time; it mirrors an interaction operators already know from Reports.

**Independent Test**: On the Applications Table view, select several rows (and try select-all),
confirm the selected count is shown, click "Delete selected", confirm once, and verify those
applications are removed from the list while their report files remain on disk.

**Acceptance Scenarios**:

1. **Given** the Applications Table view with multiple rows, **When** the operator ticks the
   checkboxes on two rows, **Then** a bulk action bar shows "2 selected" and an enabled "Delete
   selected (2)" action (mirroring Reports).
2. **Given** some rows selected, **When** the operator clicks "Delete selected" and confirms,
   **Then** all selected applications are forgotten in one action, their reports are preserved on
   disk, and they disappear from the list.
3. **Given** the Applications Table view, **When** the operator ticks the header select-all
   checkbox, **Then** all rows in the current view are selected; unticking it clears the
   selection.
4. **Given** no rows are selected, **When** the operator views the bulk action bar, **Then** the
   "Delete selected" action is disabled (nothing to delete).
5. **Given** the List (cards) view, **When** the operator uses it, **Then** it is unchanged and
   still offers the per-row delete (no selection checkboxes there).
6. **Given** a completed bulk delete, **When** the list refreshes, **Then** the selection is
   cleared and the remaining rows are shown.

---

### User Story 2 - Bulk-select and delete ledgers from the table view (Priority: P1)

An operator on the Ledger **Table** view can select multiple ledgers (or select-all) and delete
them in one confirmed action, the same as Reports and Applications. Deleting a ledger removes
only its tracking data; reports and other ledgers are preserved.

**Why this priority**: The same correction for the Ledger view; paired with US1 so both feature-009
tables reach parity with Reports.

**Independent Test**: On the Ledger Table view, select several rows (and try select-all), confirm
the count, click "Delete selected", confirm once, and verify those ledgers are removed while
reports and unselected ledgers remain.

**Acceptance Scenarios**:

1. **Given** the Ledger Table view with multiple rows, **When** the operator selects two rows,
   **Then** a bulk action bar shows "2 selected" and an enabled "Delete selected (2)" action.
2. **Given** some ledgers selected, **When** the operator clicks "Delete selected" and confirms,
   **Then** all selected ledgers are cleared in one action, reports and unselected ledgers are
   preserved, and the selected rows disappear.
3. **Given** the Ledger Table view, **When** the operator ticks select-all, **Then** all rows in
   the current view are selected; unticking clears the selection.
4. **Given** the List (cards) view, **When** the operator uses it, **Then** it is unchanged and
   still offers the per-row delete.

---

### Edge Cases

- No rows / one row: the select-all control and bulk action behave correctly (nothing selected →
  disabled action; one selected → "Delete selected (1)").
- A row's individual delete still works independently of the selection.
- A bulk delete where one or more items fail to delete: the operator is told how many could not
  be deleted, and the list reflects what actually happened (no false "deleted").
- Switching from Table to List view, or refreshing, clears the pending selection rather than
  leaving stale checkboxes.
- Selection is per view and does not carry across tabs (an Applications selection is separate
  from a Ledger selection).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The Applications Table view MUST provide a selection checkbox on each row and a
  select-all checkbox in the header, matching the Reports tab's control and placement.
- **FR-002**: The Ledger Table view MUST provide the same per-row and select-all selection
  checkboxes as the Reports tab.
- **FR-003**: Each table view MUST show a bulk action bar indicating the number of selected rows
  and offering a "Delete selected (N)" action, consistent with Reports.
- **FR-004**: The "Delete selected" action MUST be disabled when no rows are selected and enabled
  when one or more are selected.
- **FR-005**: Deleting the selected rows MUST happen as one operator action behind a single
  confirmation, and MUST use the existing delete operations with unchanged semantics — forgetting
  an application keeps its reports; deleting a ledger removes only its tracking data and keeps
  reports and other ledgers.
- **FR-006**: The per-row delete added in the previous sprint MUST remain available in the Table
  view alongside the new selection checkboxes.
- **FR-007**: The selection controls MUST appear only in the Table view; the List (cards) view is
  unchanged and retains its per-row delete.
- **FR-008**: After a bulk delete (or on refresh or switching view), the selection MUST be cleared
  and the list MUST reflect the current set of entries.
- **FR-009**: If one or more selected items fail to delete, the system MUST report how many failed
  and MUST NOT indicate that failed items were deleted.
- **FR-010**: Selection state MUST be scoped per view (Applications selection independent of Ledger
  selection) and MUST NOT change any data other than performing the requested deletions.
- **FR-011**: The Reports tab's existing multi-select delete is the reference behavior and remains
  unchanged; this feature brings Applications and Ledger to parity with it.

### Key Entities *(include if feature involves data)*

- **Row selection**: The set of rows an operator has ticked in a given table view (Applications or
  Ledger), used to drive the bulk action; transient (not persisted) and cleared after the action
  or a refresh/view switch.
- **Application row / Ledger row**: An entry rendered in the Table view (from feature 009), now
  carrying a selection checkbox. Underlying data is unchanged.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On both the Applications and Ledger Table views, an operator can select multiple
  rows (individually and via select-all) and delete them in a single confirmed action.
- **SC-002**: Deleting N selected applications in one action removes exactly those N from the list
  and leaves 100% of their report files on disk; deleting N selected ledgers removes exactly those
  N and leaves reports and unselected ledgers intact.
- **SC-003**: A reviewer comparing the Applications/Ledger selection-and-delete controls to the
  Reports tab finds the checkbox, select-all, selected-count, and "Delete selected" behavior
  consistent.
- **SC-004**: With no rows selected the bulk delete cannot be triggered; after a bulk delete the
  selection is cleared.
- **SC-005**: When some selected items cannot be deleted, the operator is told how many failed and
  the list shows the true post-operation state (no item is shown as deleted when it was not).

## Assumptions

- **"Table views of tabs" means the Applications and Ledger Table views** (from feature 009), which
  have a per-row delete but no multi-select. The Reports tab already has multi-select delete and is
  therefore the reference, not a target for change.
- **Reuse the Reports multi-select pattern**: the row/select-all checkboxes, the selected-count
  bulk bar, and the "Delete selected (N)" confirmed action follow the established Reports behavior
  so the tabs feel identical. This is a UX-consistency change, not a redesign.
- **Delete semantics are inherited, not re-specified**: bulk delete reuses the per-row delete
  operations from features 008/009 (forget application / clear ledger) and their confirmations and
  data semantics; only the ability to act on several rows at once is added.
- **Primary surface is the shipped served UI** (the self-contained `index.html`), consistent with
  features 008/009. The React app is updated in parallel where present; no new data, endpoints, or
  scan behavior.
- **The upcoming Findings table (feature 010)** is out of scope here; multi-select there can follow
  once that table ships, reusing the same pattern.
- **Validation** of selection/bulk-delete/confirmation/preservation is confirmed in the browser
  (operator-owned, as in prior served-UI features); no new backend logic is introduced (the delete
  endpoints already exist), so there is no new offline unit surface beyond what already exists.
