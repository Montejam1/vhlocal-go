# Phase 0 Research: Table/List view toggle for Applications & Ledger

Findings from reading the served UI (`vhlocal/web/index.html`) and the React app. No
backend involved.

## R1 — The Reports toggle is the pattern to reuse (served UI)

**Decision**: Reuse the Reports view-toggle mechanism verbatim for Applications and
Ledger.

**Evidence** (`vhlocal/web/index.html`):
- **Control**: two segmented buttons — `rvCards` / `rvTable` — calling
  `setReportsView('cards'|'table')` (`:3104-3107`); the active one gets `.on` +
  `aria-pressed`.
- **Getter/persistence**: `reportsView()` returns the current mode, reading and
  caching `localStorage['vhlocal.reports.view']`, defaulting to `cards` (`:3275`).
- **Setter**: `setReportsView(v)` persists the choice and re-renders (`:3283`).
- **Render branch**: `renderReports()` sets the button states, shows an empty state,
  then renders `reportsTableHTML(sortedReports())` (table) or
  `reportsCardsHTML(sortedReports())` (cards), and **carries the open detail pane**
  across a switch so it isn't closed or re-fetched (`:3486`).
- **Sort**: `sortReports(key)` toggles/reverses sort; `sortedReports()` applies it via
  the `_RSORT` accessor map; table headers are clickable (`:3289`, `:3311`).

**Approach**: replicate this per view — `appsView()/setAppsView()` keyed on
`vhlocal.apps.view`, `ledgerView()/setLedgerView()` keyed on `vhlocal.ledger.view`,
both defaulting to `cards` (List) like Reports; a two-button toggle in each header;
`appsTableHTML()`/`ledgersTableHTML()` sortable renderers with their own sort state;
`loadApplications()`/`loadLedgers()` branch table-vs-cards and carry any open detail.

**Rationale**: FR-001..006 explicitly ask for parity with the Reports toggle
(control, default, persistence, sortable table). Reusing the exact pattern gives an
identical feel and minimal new surface.

**Alternatives considered**: a shared generic toggle component — rejected as
over-engineering for a self-contained vanilla-JS page; matching the existing Reports
idiom is simpler and consistent.

## R2 — Served UI is the target; React has no toggle to mirror

**Decision**: Scope the feature to the served `vhlocal/web/index.html`. Leave
`web-react` untouched.

**Evidence**: `web-react/src/pages/Reports.tsx` renders an always-on `<table>`; its
only `toggle` is a row-selection checkbox — there is **no** Table/List view toggle in
the React Reports page. Feature 007 established the served surface is the legacy
`index.html` (React `/app` is not embedded). So "the way that Reports does" refers to
the legacy toggle, on the operator's actual surface.

**Consequence**: React Applications/Ledger keep their feature-008 list + delete; adding
a toggle there has no Reports counterpart and is deferred (a follow-up only if the
React app is ever embedded and its Reports page gains a toggle first).

**Rationale**: implement where the referenced pattern exists and the operator works;
avoid inventing a React toggle with no parity anchor.

## R3 — Preserve the feature-008 delete; replace only the layout

**Decision**: Keep the per-row Delete (forget application / clear ledger) and its
confirmation and data semantics from feature 008; this feature replaces only the fixed
single-column `applist` layout with the Table/List toggle, offering Delete in both
modes.

**Evidence**: 008 added `appCard`/ledger-card Delete buttons + `forgetApplication`
/`clearLedger` (confirm + reuse existing DELETE endpoints, reports preserved). The
`applist` class forced a single column. This feature: List mode = the cards (delete
retained), Table mode = new sortable rows (delete as a row action); drop the forced
single-column styling.

**Rationale**: FR-007/FR-011 — delete + data unchanged; only the layout choice changes.

## R4 — Testing posture

**Decision**: Browser-verify the toggle/persistence/sort/delete/empty/error on the
served UI (operator-owned, as in prior UI-only features); keep `go test ./...` green
(no Go changes). No new offline unit surface is created because there is no new Go
logic.

**Rationale**: the change is entirely client-side rendering; the constitution's test
requirement is met by browser acceptance for the UI layer, and the existing backend
suite remains the guard for everything it already covers (aggregation, guard, deletes).

## Post-design constitution re-check

A client-side view toggle adds no target execution, no provider calls, no new runtime
dependency, no data change, and keeps loading/empty/error distinct. **Constitution
Check remains PASS after design.**
