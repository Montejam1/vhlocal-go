# Phase 1 Data Model: Table/List view toggle for Applications & Ledger

No server data changes. The only new state is a client-side view preference; the row
and card content reuse the existing application/ledger summary data.

## ViewPreference (client-only)

The operator's chosen layout for a view, remembered in the browser (mirroring the
Reports preference).

| Item | Value | Rule |
|---|---|---|
| Applications preference | `cards` \| `table` | stored under `vhlocal.apps.view`; default `cards` (List) — matching the Reports default |
| Ledger preference | `cards` \| `table` | stored under `vhlocal.ledger.view`; default `cards` |

Rules: read once and cached like `reportsView()`; a `set…View` persists and re-renders;
a missing/invalid stored value falls back to `cards`; the store is a per-viewer
convenience — its absence never breaks the view.

## Application row/card (reused, unchanged data)

Rendered in either layout from the existing `AppSummary`.

- **Table columns** (sortable): name, repository, scans, latest outcome/time,
  threat/SBOM availability, open findings, plus a Delete action.
- **Card**: the existing feature-008 card (name, repo, scans, badges, Delete).

## Ledger row/card (reused, unchanged data)

Rendered in either layout from the existing ledger summary.

- **Table columns** (sortable): name/target, tracked total, open, runs recorded, last
  updated, plus a Delete action.
- **Card**: the existing feature-008 ledger card (target, totals, badges, Delete).

## Sort state (client-only, per view)

Mirrors the Reports sort: `{ key, dir }` per view; clicking a column sets/reverses it;
an accessor map maps each sortable column to a comparable value (name → lowercased
string; counts/times → numbers). Default sort matches the view's natural order (e.g.,
most-recent first), consistent with Reports.

## Relationships

- ViewPreference is independent per view (Applications, Ledger) and per viewer.
- Row/card content and the delete action are the same data + semantics as feature 008;
  only the layout differs by ViewPreference.
