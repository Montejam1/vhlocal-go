# Feature Specification: Table/List view toggle for Applications & Ledger

**Feature Branch**: `009-apps-ledger-view-toggle`

**Created**: 2026-09-22

**Status**: Draft

**Input**: User description: "The Apps and Ledger views should have the option for Table and List view the way that Reports does, not what the previous sprint implemented."

## Overview

The Reports view lets the operator switch between a **Table** view (dense, sortable columns) and a **List** view (cards), remembering their choice. The previous sprint gave Applications and Ledger only a single fixed list layout. This feature brings Applications and Ledger to parity with Reports: each gets a Table/List view toggle that behaves exactly like the Reports one — same control, same persistence of the chosen view, same sortable table — while keeping the per-row delete added previously. It replaces the fixed single-column list, not the delete capability or any data.

Scope discipline: this is a view-layout/UX change on existing views. No change to the underlying application/ledger data, the metrics, the delete semantics, scanning, or the safety boundary.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Applications Table/List toggle like Reports (Priority: P1)

An operator on the Applications view can switch between a Table view and a List view using the same control Reports offers. The Table view shows applications as sortable rows; the List view shows them as cards. Their chosen view is remembered the next time they open Applications. Deleting an application works in both views.

**Why this priority**: Direct correction of the previous sprint — the operator asked for the Reports-style Table/List choice, not the fixed list they got.

**Independent Test**: On Applications, toggle to Table and confirm sortable rows; toggle to List and confirm cards; reload and confirm the last-chosen view is restored; delete an application from each view.

**Acceptance Scenarios**:

1. **Given** the Applications view, **When** the operator selects the Table view, **Then** applications render as a table whose columns can be sorted (mirroring the Reports table behavior).
2. **Given** the Applications view, **When** the operator selects the List view, **Then** applications render as cards (the list layout).
3. **Given** the operator chose a view, **When** they navigate away and return, or reload, **Then** the same view is shown (the preference persists, the way Reports remembers its view).
4. **Given** either view, **When** the operator deletes an application (with confirmation), **Then** it is removed and the reports on disk are preserved (unchanged from the previous sprint).
5. **Given** the Table view, **When** it lists applications, **Then** each row shows the key facts (name, repository, scan count, latest outcome/time, threat/SBOM availability, open findings).

---

### User Story 2 - Ledger Table/List toggle like Reports (Priority: P1)

An operator on the Ledger view can switch between a Table view and a List view using the same control Reports offers, with the choice remembered and a sortable table. Deleting a ledger works in both views.

**Why this priority**: The same correction for the Ledger view; paired with US1.

**Independent Test**: On Ledger, toggle to Table and confirm sortable rows; toggle to List and confirm cards; reload and confirm restoration; delete a ledger from each view.

**Acceptance Scenarios**:

1. **Given** the Ledger view, **When** the operator selects the Table view, **Then** ledgers render as a sortable table.
2. **Given** the Ledger view, **When** the operator selects the List view, **Then** ledgers render as cards.
3. **Given** the operator chose a view, **When** they return or reload, **Then** the same view is shown.
4. **Given** either view, **When** the operator deletes a ledger (with confirmation), **Then** it is removed, other ledgers and all reports are preserved.
5. **Given** the Table view, **When** it lists ledgers, **Then** each row shows the key facts (name/target, tracked total, open count, runs, last updated).

---

### Edge Cases

- No applications / no ledgers: both the Table and List views show the same clean empty state (an empty table is not shown as if it were broken).
- A single item: the toggle still works and the table renders one row.
- Switching views must not lose the current selection/opened detail or re-trigger a data reload that flickers.
- A first-time operator (no saved preference) sees the same default view Reports defaults to, for consistency.
- Loading and error states remain distinguishable in both views (a failed load is not shown as an empty table/list) — unchanged from prior behavior.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The Applications view MUST offer a Table/List view toggle using the same control and interaction pattern as the Reports view.
- **FR-002**: The Ledger view MUST offer the same Table/List view toggle as the Reports view.
- **FR-003**: In Table view, applications and ledgers MUST render as rows with sortable columns, consistent with how the Reports table sorts (clicking a column sorts by it; clicking again reverses).
- **FR-004**: In List view, applications and ledgers MUST render as cards (the list layout).
- **FR-005**: The chosen view (Table or List) MUST persist across navigation and reload, per view, in the same way the Reports view remembers its choice.
- **FR-006**: The default view for a first-time operator MUST match the Reports default, for a consistent experience.
- **FR-007**: The per-row delete added in the previous sprint MUST remain available in both views, behind the existing confirmation, with unchanged semantics (forget an application keeping its reports; delete a ledger keeping reports).
- **FR-008**: The Applications Table MUST show, per row, at least: name, repository, scan count, latest outcome/time, threat/SBOM availability, and open findings.
- **FR-009**: The Ledger Table MUST show, per row, at least: name/target, tracked total, open count, runs recorded, and last updated.
- **FR-010**: Both views MUST show a clean empty state when there are no items, and keep loading/empty/error states distinguishable (a failed load MUST NOT appear as an empty table/list).
- **FR-011**: This feature MUST replace the previous sprint's fixed single-column list layout with the toggle; it MUST NOT change application/ledger data, metrics, delete semantics, or scanning behavior.

### Key Entities *(include if feature involves data)*

- **View preference**: The operator's chosen layout (Table or List) for a given view (Applications, Ledger), remembered across sessions — mirroring how the Reports view stores its preference.
- **Application row / card**: An application rendered in either layout (fields per FR-008). Data is unchanged from the previous sprint.
- **Ledger row / card**: A ledger rendered in either layout (fields per FR-009). Data unchanged.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On both Applications and Ledger, the operator can switch between Table and List with a single control, and the layout changes accordingly (2 views × 2 surfaces all switch correctly).
- **SC-002**: After choosing a view and reloading (or navigating away and back), the same view is restored 100% of the time, matching Reports' persistence.
- **SC-003**: In Table view, every listed column sorts on click and reverses on a second click, consistent with the Reports table.
- **SC-004**: Deleting an application and a ledger works from both the Table and the List view, and in every case the corresponding report files remain on disk.
- **SC-005**: With no items, both the Table and List views show the same clean empty state (no broken/empty-table artifact), and a simulated load failure is shown as an error, not as empty.
- **SC-006**: A reviewer comparing the Applications/Ledger toggle to the Reports toggle finds the control, defaulting, persistence, and sort behavior consistent.

## Assumptions

- **"Table and List" maps to the Reports two-mode toggle**: Reports switches between a dense sortable **table** and a **cards** layout, remembering the choice. "List view" here is that non-table cards layout; "Table view" is the sortable table. No third mode is introduced.
- **Reuse the Reports toggle pattern**: the control, its default, and its per-view persistence follow the established Reports behavior so the three views feel identical; this is a UX-consistency requirement, not a redesign.
- **Delete is retained, not re-specified**: the per-row delete + confirmation and its data semantics come from the previous sprint and are unchanged; this feature only ensures it remains reachable in both layouts.
- **Primary surface is the shipped served UI**; the browser app is updated in parallel where present, consistent with prior features. No new data, endpoints, or scan behavior.
- **Validation**: layout/toggle/persistence/sort are confirmed in the browser (operator-owned, as in prior UI work); no new backend logic is introduced, so there is no new offline unit surface beyond what already exists.
