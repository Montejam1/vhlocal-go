# Implementation Plan: Table/List view toggle for Applications & Ledger

**Branch**: `009-apps-ledger-view-toggle` | **Date**: 2026-09-22 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/009-apps-ledger-view-toggle/spec.md`

## Summary

Bring the Applications and Ledger views to parity with the Reports view's **Table ⇄ List** toggle, replacing feature 008's fixed single-column list while keeping its per-row delete. This is a **served-UI (`vhlocal/web/index.html`) change only** — the Reports toggle lives there, and that is the operator's shipped surface. The React `web-react` Reports page has **no** view toggle (its `<table>` is always-on; its only "toggle" is a row-selection checkbox), so there is no Reports counterpart to mirror in React; React is out of scope for this feature (its 008 list+delete stays as-is).

Reuse the exact Reports mechanism, per view:
- a two-button segmented control (`rvCards`/`rvTable` equivalent) calling a `set…View('cards'|'table')` setter;
- a `…View()` getter that reads/persists the choice in `localStorage` (a per-view key, mirroring `vhlocal.reports.view`), defaulting to `cards` (List) like Reports;
- a render that branches to a sortable **table** or the existing **cards**, carrying any open detail pane across a switch (no re-fetch/flicker);
- sortable table columns using the Reports sort mechanism (`sort…`/`sorted…`/accessor map, clicking a column sorts, clicking again reverses).

No Go, no backend, no new data or endpoints; delete + data semantics are inherited from feature 008.

## Technical Context

**Language/Version**: Front-end only — the served self-contained `vhlocal/web/index.html` (vanilla JS/CSS, no build step, embedded in the binary). Go 1.23+ backend unchanged.

**Primary Dependencies**: none new. The web UI stays self-contained (no CDN); reuses existing helpers (`esc`, `escA`, `localStorage`, the Reports `_sevScore`/sort utilities as reference).

**Storage**: browser `localStorage` for the per-view preference (client-only), mirroring `vhlocal.reports.view`. No server storage change.

**Testing**: browser acceptance on the served UI (operator-owned, as in prior UI-only work): toggle, persistence, sort, delete-in-both-views, empty/error states. There is **no new Go logic**, so no new offline unit surface; `go test ./...` must remain green (unchanged).

**Target Platform**: loopback single-binary server; the served browser UI.

**Project Type**: web service; this feature touches only the served UI layer.

**Performance Goals**: n/a — client-side rendering of small lists (≈dozens of apps/ledgers); switching views must not re-fetch.

**Constraints**: reuse the Reports toggle behavior verbatim (control, default, per-view persistence, sortable table) for a consistent feel; keep the 008 delete + confirmation and data semantics unchanged; keep loading/empty/error states distinct; UI stays self-contained/offline; no scan-behavior or safety-boundary impact.

**Scale/Scope**: small, single-file UI change (`vhlocal/web/index.html`): two view getters/setters, two toggle controls, two table renderers with sort, wired into the existing `loadApplications`/`loadLedgers` renders.

**Confirmed reference (this planning pass):**
- Reports toggle: buttons `rvCards`/`rvTable` → `setReportsView` (`index.html:3104-3107, 3283`); `reportsView()` persists `localStorage['vhlocal.reports.view']` default `cards` (`:3275`); `renderReports` branches `reportsTableHTML(sortedReports())` vs `reportsCardsHTML(...)` and carries the open pane (`:3486`); `sortReports`/`sortedReports`/`_RSORT` provide sortable columns (`:3289`, `:3311`).
- Apps/Ledger currently render cards only (`loadApplications` `:4065` → `appCard`; `loadLedgers` `:3625` → card map), each with the 008 per-row Delete.
- No `NEEDS CLARIFICATION` remain.

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after Phase 1. Constitution v1.1.0.*

- **I. Evidence Integrity** — unaffected: a view toggle changes layout only; the same data is shown either way; no fabrication. PASS.
- **II. Orthogonal Status Reporting** — unaffected. PASS.
- **III. Static-Only Safety Boundary** — no execution; UI-only. PASS.
- **IV. Provenance / V. Explicit Failure** — unaffected (no model calls); loading/empty/error stay distinct (FR-010). PASS.
- **VI. Resumable/Idempotent** — n/a to a client view toggle; the preference is a per-viewer convenience in `localStorage`. PASS.
- **VII. Testable Acceptance** — this is pure front-end with no Go logic; acceptance is browser-verified (operator-owned) as in prior UI work; the Go suite stays green. The plan states this explicitly (no new offline unit surface). PASS (with the front-end-testing note recorded).
- **Safety & Technical Constraints** — self-contained UI (no CDN), no new runtime dependency, deterministic rendering, no egress. PASS.

**Gate result: PASS. No violations → Complexity Tracking omitted.** Re-check after Phase 1: still PASS.

## Project Structure

### Documentation (this feature)

```text
specs/009-apps-ledger-view-toggle/
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
                         #  - appsView()/setAppsView(), ledgerView()/setLedgerView()
                         #    (localStorage: vhlocal.apps.view / vhlocal.ledger.view; default cards)
                         #  - a Table/List segmented toggle in the Apps and Ledger headers
                         #  - appsTableHTML()/ledgersTableHTML() sortable renderers + sort state
                         #  - loadApplications()/loadLedgers() branch table-vs-cards, carry detail,
                         #    keep the 008 per-row Delete in both modes
                         #  - remove the 008 forced single-column `applist` layout
```

No Go files change. `web-react` is intentionally untouched (no Reports toggle to mirror there).

**Structure Decision**: single served-UI file. The feature is a faithful reuse of the Reports view-toggle/table/sort pattern applied to two more views; no backend, no new dependency, no data change.

## Complexity Tracking

No constitution violations — section intentionally omitted.
