# Quickstart — Offline validation: Functional scan options

Runnable, **offline** validation that each advertised scan option is functional end to end. No live
model, no target execution, `../vhlocal` read-only. Details live in [contracts/options-matrix.md](./contracts/options-matrix.md),
[contracts/api.md](./contracts/api.md), and [data-model.md](./data-model.md).

## Prerequisites

- Go 1.23+ on PATH: `export PATH=$PATH:/usr/local/go/bin`
- Static build: `CGO_ENABLED=0`
- No network; providers are fakes/recording/barrier doubles (`internal/client/testsupport`).

## Offline gate (must stay green)

```sh
export PATH=$PATH:/usr/local/go/bin
gofmt -l .            # empty
go vet ./...
go build ./...
CGO_ENABLED=0 go build -o bin/vhlocal ./cmd/vhlocal
go test ./...
go test -race ./internal/engine/... ./internal/server/...   # concurrency
```

## Validation scenarios → success criteria

| # | Scenario (offline) | Proves |
|---|---|---|
| 1 | Recording provider + per-form/API/CLI launch: each accepted option's effect reaches engine/calls; `effective_config` requested vs applied | SC-005/010, FR-002/005/007 |
| 2 | `seed_routes` on/off across Python+Go+mixed fixtures: recon input carries the 012 inventory only when on; 201 alone insufficient | SC-001, FR-008 |
| 3 | `seed_prior` on/off across no-prior/malformed/wrong-repo/changed-source/phase-omitted: leads seeded + provenance; verification never bypassed | SC-002, FR-009..011 |
| 4 | `enforce_coverage` true→augments incomplete plan; false→no augmentation but unassigned/unreviewed disclosed truthfully | SC-003, FR-012 |
| 5 | Barrier provider: `concurrency>1` real overlap never exceeding limit; `1` strictly serial; `-race` clean; cancel/fail/sampling correct | SC-004, FR-013/014/015 |
| 6 | Budget: cap stops new work at boundary, in-flight accounted, missing pricing disclosed (`priced=false`), never zero-cost/false ceiling | SC-006, FR-021 |
| 7 | Validator: implemented values accepted (incl. `seed_routes=true`, `concurrency=2` regression); invalid rejected pre-queue, field-specific, deterministic; false/0/omitted/null distinct | SC-007/008, FR-003/004/023 |
| 8 | Per-form launch (main/classic/legacy HTML + React NewScan + profiles) submits enabled controls; no disabled/stripped control counts as done | SC-008, FR-023/024 |
| 9 | Build-identity check: validation evidence names source vs embedded vs running vs older page vs profile vs alternate client | SC-011, FR-025 |
| 10 | Full existing suite + 012 parity (`tests/parity/...`) stay green; historical data reads unchanged | SC-009, FR-027 |

## Provider doubles (offline)

- **Recording**: captures per-call role/model/backend/host + temperature/reasoning/ctx/output → assert effective config.
- **Barrier**: gate N concurrent calls to observe max active vs `Concurrency` (bounded-overlap proof), `-race`.
- **Fake usage**: emit `client.Usage` to drive budget accounting (known + unknown pricing).

## Operator-owned (not in this offline gate)

React `npm run build` + a browser check of the shipped `/app` build, and any live-model run — performed by
the operator after these offline gates pass. This guide never launches a live scan.
