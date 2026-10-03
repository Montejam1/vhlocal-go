# Contracts — Table/List toggle behavior (served UI)

UI behavior invariants for Applications and Ledger, matching the Reports view. All are
browser-verified on the served `vhlocal/web/index.html` (operator-owned); there is no
new backend logic. IDs are referenced by tasks and map to success criteria.

## Toggle & persistence

- **C-V1 (toggle present)**: The Applications view and the Ledger view each show a
  Table/List segmented control identical in placement and interaction to the Reports
  view's (C-A/C-L parity with Reports) (FR-001/002, SC-001).
- **C-V2 (switch layout)**: Selecting Table renders rows; selecting List renders cards;
  the switch is immediate and does not re-fetch data (FR-003/004, SC-001).
- **C-V3 (persistence)**: The chosen view persists across navigation away/back and a
  full reload, per view, using a stored preference like Reports (`vhlocal.apps.view`,
  `vhlocal.ledger.view`) (FR-005, SC-002).
- **C-V4 (default)**: With no stored preference, both views default to the same mode
  Reports defaults to (List/cards) (FR-006).

## Table & sort

- **C-T1 (apps columns)**: The Applications table shows per row: name, repository,
  scans, latest outcome/time, threat/SBOM availability, open findings (FR-008, SC-...).
- **C-T2 (ledger columns)**: The Ledger table shows per row: name/target, tracked
  total, open, runs recorded, last updated (FR-009).
- **C-T3 (sortable)**: In Table view, clicking a column sorts by it and clicking again
  reverses, consistent with the Reports table (FR-003, SC-003).

## Delete (retained from feature 008)

- **C-D1 (delete both modes)**: The per-row Delete is available in both Table and List
  views, behind the existing confirmation (FR-007, SC-004).
- **C-D2 (semantics unchanged)**: Deleting an application forgets it and keeps its
  reports; deleting a ledger removes only its tracking data — unchanged from feature
  008 (FR-007, SC-004).

## States & scope

- **C-S1 (empty/error)**: With no items, both Table and List show the same clean empty
  state (no broken empty-table); a failed load shows an error, not empty (FR-010,
  SC-005).
- **C-S2 (selection carried)**: Switching views does not close or re-fetch an opened
  detail pane (edge case), matching Reports.
- **C-S3 (scope)**: No application/ledger data, metrics, delete semantics, endpoints, or
  scan behavior change; the Go suite (`go test ./...`) remains green (FR-011).
