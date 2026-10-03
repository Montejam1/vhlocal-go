# Quickstart & Validation Guide: Dashboard metrics & app/ledger management

Offline-first. Backend behavior is pinned by `go test ./...`; the list/delete UIs are
confirmed in the browser against a seeded local server (operator-owned, per feature
007). No new scan is required; no Python.

## Prerequisites

- `export PATH=$PATH:/usr/local/go/bin`; `go build -o bin/vhlocal ./cmd/vhlocal`.
- A scratch reports dir seeded with the fixtures below (reuse
  `internal/server/testsupport/seed.go`); point the server at it (loopback default).

## Seed fixtures (offline)

- **Metrics**: ≥2 report dirs whose `scan_meta.json` carries `usage`
  (prompt/completion tokens) and `started_at`/`finished_at`; include one older run
  with **no** usage/timing (for the partial-data average) and vary findings so the
  findings average is fractional (e.g., 7 findings over 2 scans → 4).
- **Phantom apps**: alongside the real report dirs, add a **stray subdirectory** with
  no deliverable (the phantom source) and confirm it must not become an application.
- **Apps/Ledger**: ≥2 real applications (one ledger-disabled, one with a ledger) and
  ≥1 ledger for the list + delete flows.

## Automated offline checks (the gate)

```bash
export PATH=$PATH:/usr/local/go/bin
go build ./...
go test ./... -count=1        # reports, server, apps, engine, parity
go vet ./...
gofmt -l internal 2>/dev/null
```

| Area | Checks |
|---|---|
| Metrics | C-M1..C-M5 (full set; integer findings avg; partial-data; zero-scan; real by-model tokens) |
| Report-dir guard / phantom apps | C-P1..C-P4 (guard; report-only preserved; N-real apps stable across re-derive; non-destructive) |
| Apps management | C-A3 (reports preserved / re-scan) — the backend half; list/delete UI is browser |
| Ledger management | C-L3 (reports preserved) — backend half |
| Preservation | C-X2 (no report/name/ledger lost) |

Suggested new tests: `internal/server/stats_test.go` (C-M1..C-M5 via seeded reports +
`handleStats`), `internal/reports/reportdir_test.go` (C-P1/C-P2 guard),
`internal/apps` or `internal/server` phantom-exclusion (C-P3), and extend the
preservation test (C-P4/C-X2).

## Browser acceptance (served UI, seeded data)

```bash
bin/vhlocal serve --reports <seeded-dir>
```

1. **Dashboard**: tokens used, average tokens/scan, and total scan time show real
   values; average vulnerabilities/scan is a whole number; with an empty reports dir,
   metrics show a clean zero state (C-M1..C-M4).
2. **Applications**: the tab shows a **list**; the stray subdirectory does **not**
   appear as an application; restart the server and confirm the app count is
   unchanged (no new empties). Delete an application (confirm), see it leave the list,
   and confirm its report files remain on disk (C-P3, C-A1..C-A3).
3. **Ledger**: the tab shows a **list**; delete a ledger (confirm), see it leave the
   list with others unaffected and report files intact (C-L1..C-L3).

## Success-criteria coverage

SC-001↔C-M1; SC-002↔C-M2; SC-003↔C-M4; SC-004↔C-P3; SC-005↔C-A2/C-L2; SC-006↔C-A3/
C-L3/C-X2/C-P4; SC-007↔C-P2.
