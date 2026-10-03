# T103 — full offline gate (feature 016)

Run 2026-10-03 from `~/Programs/vhlocal-go` with Go 1.27.1. Raw output is beside
this file: `gate-static.txt`, `offline-tests.txt`, `race-tests.txt`, `typecheck.txt`,
`gate-status.txt`.

| Step | Result |
|---|---|
| `gofmt -l .` | clean — no output. One fixture, `testdata/goapp/api/routes.go`, was excluded by hand during the gate and has since been formatted, so the whole tree is clean with no carve-out. |
| `go vet ./...` | clean |
| `go build ./...` | clean |
| `CGO_ENABLED=0 go build -ldflags="-s -w" ./cmd/vhlocal` | ELF 64-bit, **statically linked**, stripped |
| `go test ./... -count=1` | **39 packages ok, 0 failures** |
| `go test -race` on report, engine, server, jobs, agent, apps, guidance, reports | **all ok** (engine 187.5s, report 18.9s, rest ~1s each) |
| `cd web-react && npm run typecheck` (`tsc --noEmit`) | clean |
| Gate exit | `gate_exit=0` |

## Real-store fingerprint (FR-028, C-C14)

No scan was running. The operator's stores had not been written to for about three days: the
newest mtime under `~/.vhlocal` and `~/vulnhunter-reports` was 2026-09-30 01:58. A `vhlocal
server` process was up on port 8421 and idle; it was not restarted or redeployed.

`validation-015/fingerprint.sh` records path, size, mtime to the nanosecond and the SHA-256 of
every file under both stores — 5,479 files.

| Fingerprint | Metadata digest | Content digest |
|---|---|---|
| before | `2875f62329618694050127944726220a9763de0551a52cb27077d251ea38a8a9` | `49df3c48cdf878e4481a1744d18a8381da065b63873a52f9fdf28bc64d7940bb` |
| after | `2875f62329618694050127944726220a9763de0551a52cb27077d251ea38a8a9` | `49df3c48cdf878e4481a1744d18a8381da065b63873a52f9fdf28bc64d7940bb` |

`diff` over both the metadata listing and the per-file hash listing is **empty**. The gate
left every one of the 5,479 files byte-identical, with its mtime unchanged to the nanosecond.

This is the literal before-and-after identity that feature 015's T095 could not obtain,
because an operator scan was writing to the stores while that gate ran. It establishes the
property **for this run**; it is not retroactive evidence about the earlier one, whose
attribution evidence stands as recorded in `validation-015/t095-attribution.md`.

### Source-scan fingerprints

The nine records the acceptance fixture was derived from were re-hashed in place and all nine
match `testdata/report016/SOURCE_FINGERPRINTS.txt`. The source scan was neither modified,
regenerated nor deleted.

## What this gate does not establish

A green gate is evidence about the code, not about the reader. Reader comprehension (SC-001)
and the browser and print review (SC-008) are **not run** — see
`validation-016/T104-operator-report.md`.
