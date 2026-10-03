# Feature Specification: Dashboard metrics & application/ledger management

**Feature Branch**: `008-ui-metrics-management`

**Created**: 2026-09-22

**Status**: Draft

**Input**: User description: "Update the interface. The Dashboard tokens used, average tokens/scan, and total scan time are not populating. Average vulnerabilities per scan should be a whole number. The Apps tab needs a list view and a way to delete applications, and empty sample applications that reappear on every server restart must be fixed. The Ledger needs a list view and a way to delete ledgers."

## Overview

Operator-facing polish on top of feature 007: the Dashboard's usage/time metrics are blank, one metric shows a distracting decimal, phantom empty applications reappear after every restart (eroding trust in the Apps view), and the Apps and Ledger views lack a compact list layout and a way to remove entries. This feature makes the Dashboard metrics truthful and complete, removes the phantom applications, and gives the operator list + delete management for applications and ledgers — reusing the existing data and delete capabilities, not introducing new scan behavior.

Scope discipline: metrics come from data the tool already records (no new measurement); deletions reuse the existing forget/clear semantics (reports are preserved); no changes to scanning, verification, reporting, or the safety boundary.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Dashboard metrics populate and read cleanly (Priority: P1)

An operator opens the Dashboard and sees real values for total tokens used, average tokens per scan, and total scan time, alongside scan and finding counts. The average vulnerabilities-per-scan reads as a whole number, not a decimal.

**Why this priority**: These headline metrics are currently blank or awkwardly formatted, so the Dashboard looks broken and gives the operator no sense of cost or effort.

**Independent Test**: With seeded scan history that carries usage and timing, open the Dashboard and confirm tokens-used, average-tokens-per-scan, and total-scan-time show non-zero real values and average vulnerabilities-per-scan is an integer.

**Acceptance Scenarios**:

1. **Given** scan history whose runs recorded token usage and duration, **When** the operator opens the Dashboard, **Then** total tokens used, average tokens per scan, and total scan time all display real aggregated values (not blank or zero).
2. **Given** the same history, **When** the average vulnerabilities-per-scan is shown, **Then** it is a whole number (no decimal places).
3. **Given** history where some older runs recorded no usage/timing, **When** the metrics are computed, **Then** averages are based on the runs that have data and the display never shows a misleading value (e.g., not "NaN" or a spurious 0 that hides real data from other runs).
4. **Given** no scans exist yet, **When** the Dashboard renders, **Then** the metrics show a clean empty/zero state rather than broken values.

---

### User Story 2 - No phantom or empty applications (Priority: P1)

The Applications view shows only real analyzed repositories. Empty placeholder applications do not appear, and none are re-created when the server restarts.

**Why this priority**: Phantom empty applications reappearing on every restart make the Apps view untrustworthy and clutter the operator's real history.

**Independent Test**: Start the server against seeded data containing only real applications, confirm the Applications list shows exactly those; restart the server and confirm no additional empty applications have appeared.

**Acceptance Scenarios**:

1. **Given** a data directory with N real applications and no empty ones, **When** the operator opens Applications, **Then** exactly N applications are listed and none are empty/placeholder.
2. **Given** the server is restarted, **When** the operator reopens Applications, **Then** the count is unchanged and no new empty applications have been created.
3. **Given** an application has a real name and at least one real report or ledger, **When** the list renders, **Then** it appears; an entry with no name, no reports, and no ledger does not appear as an application.
4. **Given** a previously created empty/placeholder application exists on disk, **When** the view loads, **Then** it is not shown (and is not resurrected on restart).

---

### User Story 3 - Applications list view with delete (Priority: P2)

An operator can view applications as a compact list and delete (forget) an application they no longer want to track, from that view.

**Why this priority**: The operator needs to manage the application inventory; a list is easier to scan than cards and delete removes clutter. Valuable but below fixing broken/untrustworthy data.

**Independent Test**: Open the Applications list, delete one application, and confirm it disappears from the list while its saved report files remain on disk.

**Acceptance Scenarios**:

1. **Given** several applications, **When** the operator opens the Applications view, **Then** they can see them in a list layout showing each application's key facts (name, repository, scan count, latest outcome, threat/SBOM availability).
2. **Given** an application in the list, **When** the operator deletes it and confirms, **Then** it is removed from the list.
3. **Given** an application was deleted, **When** its report files are inspected, **Then** they still exist on disk (delete forgets the application, it does not destroy scan evidence).
4. **Given** a deleted application's repository is scanned again, **When** the scan completes, **Then** the application reappears with its history intact.
5. **Given** the operator initiates a delete, **When** the confirmation is shown, **Then** an accidental click cannot delete without an explicit confirm step.

---

### User Story 4 - Ledger list view with delete (Priority: P2)

An operator can view vulnerability-tracking ledgers as a list and delete a ledger they no longer want.

**Why this priority**: Parallel management need for ledgers; lower frequency than applications.

**Independent Test**: Open the Ledger view, see the ledgers as a list, delete one, and confirm it is removed while unrelated ledgers and all report files remain.

**Acceptance Scenarios**:

1. **Given** one or more ledgers exist, **When** the operator opens the Ledger view, **Then** they are shown in a list with each ledger's key facts (name/target, tracked totals, open count, last updated).
2. **Given** a ledger in the list, **When** the operator deletes it and confirms, **Then** it is removed from the list and the others are unaffected.
3. **Given** a ledger is deleted, **When** report files for that repository are inspected, **Then** they still exist (deleting a ledger removes tracking data only).
4. **Given** the operator initiates a ledger delete, **When** the confirmation is shown, **Then** an explicit confirm step is required.

---

### Edge Cases

- Runs that recorded no usage or duration must not corrupt the aggregates (excluded from averages; totals reflect only what was recorded).
- A single scan (or zero scans) must not produce a divide-by-zero or "NaN" in any average.
- Deleting the last application/ledger leaves a clean empty state, not a broken view.
- Deleting an application that has a ledger, or a ledger whose application still has reports, leaves the other artifacts consistent and never removes report files.
- The phantom-application fix must not hide legitimate applications that are known only from on-disk reports (report-only discovery must still work).
- A stale/empty placeholder already persisted on disk must stop appearing without destroying any real data.

## Requirements *(mandatory)*

### Functional Requirements

**Dashboard metrics (US1)**

- **FR-001**: The Dashboard MUST display total tokens used across scans, computed from recorded per-run usage.
- **FR-002**: The Dashboard MUST display average tokens per scan, computed over the runs that recorded usage.
- **FR-003**: The Dashboard MUST display total scan time, computed from recorded per-run durations.
- **FR-004**: Average vulnerabilities per scan MUST be presented as a whole number (no decimal places).
- **FR-005**: When some runs lack recorded usage/timing, averages MUST be computed only over runs that have the data, and the count of runs contributing to each average MUST be derivable (so a partial-data average is not mistaken for a whole-history average).
- **FR-006**: With zero scans, every Dashboard metric MUST render a clean zero/empty state (no "NaN", no divide-by-zero, no blank where a number belongs).
- **FR-007**: Per-model breakdown metrics that are shown MUST reflect real recorded values or be omitted — a metric column MUST NOT display a hardcoded placeholder (e.g., always-zero tokens) as if it were real.

**Phantom applications (US2)**

- **FR-008**: The Applications view MUST list only real applications — those with a name, or at least one real report, or a ledger; an entry with none of these MUST NOT appear.
- **FR-009**: No empty/placeholder application MUST be created or resurrected by a server restart; the application count MUST be stable across restarts absent real new scans.
- **FR-010**: The fix MUST NOT suppress legitimate applications discoverable only from on-disk reports (report-only discovery is preserved).
- **FR-011**: Any empty/placeholder application already persisted MUST stop being shown without deleting or altering real reports, ledgers, or named applications.

**Applications management (US3)**

- **FR-012**: The Applications view MUST offer a list layout showing, per application, at least: name, repository, scan count, latest report outcome/time, and threat/SBOM availability.
- **FR-013**: The operator MUST be able to delete (forget) an application from the view, behind an explicit confirmation step.
- **FR-014**: Deleting an application MUST preserve its report files on disk and MUST allow the application to reappear if its repository is scanned again.

**Ledger management (US4)**

- **FR-015**: The Ledger view MUST offer a list layout showing, per ledger, at least: name/target, tracked total, open count, and last-updated time.
- **FR-016**: The operator MUST be able to delete a ledger from the view, behind an explicit confirmation step, without affecting other ledgers.
- **FR-017**: Deleting a ledger MUST remove only its tracking data and MUST NOT delete report files.

**Cross-cutting**

- **FR-018**: Metrics MUST come from data the tool already records (usage, timings, findings); this feature MUST NOT introduce new scan-time measurement or change scan behavior.
- **FR-019**: Existing scan history, reports, application names, and ledger data MUST be preserved; the only removals are operator-initiated deletes.
- **FR-020**: All views MUST distinguish loading, empty, and error states (a load failure MUST NOT render as an empty success), consistent with the feature-007 behavior.

### Key Entities *(include if feature involves data)*

- **Dashboard metrics**: Aggregate view over scan history — scan count, total/average tokens, total/average scan time, total findings, average findings per scan (integer), and per-model breakdowns; each average carries the number of contributing runs.
- **Application (list item)**: A real analyzed repository — name, repository, scan count, latest outcome/time, threat/SBOM availability; only real applications qualify (name or report or ledger).
- **Ledger (list item)**: A vulnerability-tracking record for a repository — name/target, tracked total, open count, last updated.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On seeded history that recorded usage and timing, 100% of the Dashboard headline metrics (tokens used, average tokens per scan, total scan time, scans, findings) display real non-zero values; none is blank.
- **SC-002**: Average vulnerabilities per scan is displayed as an integer in 100% of cases (verified across whole-number and fractional underlying averages).
- **SC-003**: With zero scans, no Dashboard metric renders "NaN", a divide-by-zero, or a blank where a number belongs.
- **SC-004**: Starting the server against seeded data with only real applications shows exactly that set, and a restart adds zero empty applications (count unchanged).
- **SC-005**: An operator can delete an application and a ledger from their list views in at most two interactions each (action + confirm); after deletion each is gone from its list and the corresponding report files still exist on disk.
- **SC-006**: No existing report file, application name, or unrelated ledger is lost by using any view in this feature (verified before/after).
- **SC-007**: Report-only applications (no registry entry, no ledger) remain discoverable after the phantom-application fix.

## Assumptions

- **Metrics data source (confirmed)**: Per-run usage (prompt/completion tokens) and timing are already recorded in run metadata; the Dashboard metrics computation currently omits the token and time aggregates and treats per-model tokens as zero, and formats the vulnerabilities average as a decimal — this feature computes the missing aggregates and formats the average as an integer. Findings counts already populate.
- **Phantom applications (confirmed symptom, root cause to confirm in planning)**: empty applications appear in the Applications list and recur across restarts; the fix is to exclude entries that are not real applications (no name, no report, no ledger) from discovery/listing, without suppressing report-only discovery or deleting anything on disk. The exact source (stray on-disk directory treated as a report, or an empty registry/discovery entry) is identified during planning.
- **Deletes reuse existing semantics**: forgetting an application and clearing a ledger already exist as capabilities and preserve report files; this feature surfaces them in the list views behind a confirmation step. No new destructive capability is added.
- **Surfaces**: the changes apply to the operator's shipped views (the served UI, and the browser app if/when embedded); both consume the same metrics/list/delete contracts.
- **No scan-behavior change**: scanning, verification, reproduction, reporting, coverage, and the static-only safety boundary are unchanged; this is presentation + management + a data-hygiene fix.
- **Offline-first validation**: acceptance is driven by seeded on-disk fixtures; browser confirmation remains operator-owned, consistent with feature 007.
