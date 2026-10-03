# Quickstart & Validation Guide: Multi-select delete in table views

A served-UI (`vhlocal/web/index.html`) change with no backend logic. Validation is browser-driven on
a seeded local server (operator-owned, as in prior served-UI features); the Go suite must stay green
(nothing new to unit-test on the Go side).

## Prerequisites

- `export PATH=$PATH:/usr/local/go/bin`; `go build -o bin/vhlocal ./cmd/vhlocal`.
- A reports dir seeded with several applications and several ledgers (reuse
  `internal/server/testsupport/seed.go`) so both Table views have multiple rows to select.

## Automated gate (unchanged backend)

```bash
export PATH=$PATH:/usr/local/go/bin
go build ./...
go test ./... -count=1     # must remain green (no Go changes)
go vet ./...
gofmt -l internal cmd      # clean
```

There is **no new offline unit surface** — the feature is entirely client-side selection over
existing delete endpoints. The gate confirms the delete endpoints and aggregation are unregressed.

## Browser acceptance (served UI, seeded data)

```bash
bin/vhlocal serve --reports <seeded-dir>   # (subcommand: `server`)
```

Compare each behavior directly against the **Reports** tab for consistency:

1. **Select & count** (C-S1/C-B1): On Applications → Table view, tick two rows — a bulk bar shows
   "2 selected" and an enabled "Delete selected (2)". Repeat on Ledger.
2. **Select-all** (C-S2): Tick the header checkbox → all shown rows selected; untick → cleared.
3. **Disabled when empty** (C-B2): With nothing selected, "Delete selected" is disabled.
4. **Confirmed batch delete + preservation** (C-D1/C-D2): Select several applications, "Delete
   selected", confirm once → they leave the list and their report files remain on disk. Repeat for
   ledgers → only their tracking is removed; reports and unselected ledgers remain.
5. **Per-row still works** (C-D3): The individual row Delete still deletes just that row.
6. **List view unchanged** (C-L1): Switch to List (cards) — no selection checkboxes; per-row delete
   present.
7. **Selection cleared** (C-L2): After a delete, after Refresh, and after switching Table↔List, the
   selection is empty (no stale checkboxes).
8. **Partial failure honest** (C-D4): Force a delete to fail (e.g. remove a ledger file underneath)
   → the operator is told how many could not be deleted, and the list shows the true result.
9. **Parity** (C-L4): The controls match the Reports tab's checkbox/select-all/count/"Delete
   selected" behavior.

Record the built provenance (commit + `bin/vhlocal` hash) used for acceptance.

## Success-criteria coverage

SC-001↔C-S1/C-S2/C-B1/C-D1; SC-002↔C-D2; SC-003↔C-L4; SC-004↔C-B2/C-L2; SC-005↔C-D4.
