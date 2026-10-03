# Quickstart & Validation Guide: Apps/Ledger Table–List toggle

A served-UI (`vhlocal/web/index.html`) change with no backend logic. Validation is
browser-driven on a seeded local server (operator-owned, as in prior UI-only
features); the Go suite must stay green (nothing new to unit-test on the Go side).

## Prerequisites

- `export PATH=$PATH:/usr/local/go/bin`; `go build -o bin/vhlocal ./cmd/vhlocal`.
- A reports dir seeded with several applications and ledgers (reuse
  `internal/server/testsupport/seed.go`) so both views have multiple rows to sort.

## Automated gate (unchanged backend)

```bash
export PATH=$PATH:/usr/local/go/bin
go build ./...
go test ./... -count=1     # must remain green (no Go changes)
go vet ./...
```

There is **no new offline unit surface** — the feature is entirely client-side
rendering. The gate confirms the backend/aggregation/delete behavior is unregressed.

## Browser acceptance (served UI, seeded data)

```bash
bin/vhlocal serve --reports <seeded-dir>
```

Compare each behavior directly against the **Reports** view for consistency:

1. **Toggle & switch** (C-V1/C-V2): On Applications, use the Table/List control — Table
   shows rows, List shows cards; the switch is instant and does not reload. Repeat on
   Ledger.
2. **Persistence** (C-V3/C-V4): Choose Table on Applications; navigate away and back —
   still Table; full-reload — still Table. Clear the stored preference (or first-time)
   → defaults to List, like Reports. Repeat for Ledger (independent preference).
3. **Sort** (C-T1/C-T2/C-T3): In Table view, click each column header — it sorts;
   click again — it reverses. Confirm the columns listed in the contract are present.
4. **Delete in both modes** (C-D1/C-D2): Delete an application from Table view and one
   from List view (confirm each) → gone from the list; its report files remain. Same
   for a ledger (only its tracking removed).
5. **States** (C-S1/C-S2): Empty reports dir → both modes show a clean empty state, not
   a broken table. Open an application/ledger detail, then switch view → the open pane
   is preserved (not re-fetched). Force a failed load → an error is shown, not empty.

Record the built provenance (commit + `bin/vhlocal` hash) used for acceptance.

## Success-criteria coverage

SC-001↔C-V1/C-V2; SC-002↔C-V3; SC-003↔C-T3; SC-004↔C-D1/C-D2; SC-005↔C-S1;
SC-006↔direct comparison to the Reports toggle across all of the above.
