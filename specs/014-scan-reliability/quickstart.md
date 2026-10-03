# Quickstart — Offline validation: Reliable scan evidence and review completion

Runnable, **offline**, **fully isolated** validation. No live model, no target execution, `../vhlocal`
read-only. Details in [contracts/evidence-api.md](./contracts/evidence-api.md),
[contracts/records.md](./contracts/records.md), [data-model.md](./data-model.md).

## Prerequisites

- Go 1.23+: `export PATH=$PATH:/usr/local/go/bin`; static build `CGO_ENABLED=0`.
- Isolated storage for every test: `VHLOCAL_LEDGER_DIR`, reports dir, log file, jobs path, profiles dir →
  temp (set in `TestMain`). Verify afterwards that `~/.vhlocal/applications.json` and `~/vulnhunter-reports`
  are byte-identical to before (SC-011).

## Offline gate (must stay green)

```sh
export PATH=$PATH:/usr/local/go/bin
gofmt -l .            # empty (excluding pre-existing fixtures)
go vet ./...
go build ./...
CGO_ENABLED=0 go build -o bin/vhlocal ./cmd/vhlocal
go test ./...
go test -race ./internal/engine/... ./internal/jobs/... ./internal/server/... ./internal/agent/...
```

## Validation scenarios → success criteria

| # | Scenario (offline, isolated) | Proves |
|---|---|---|
| 1 | Delayed fake provider: artifact + prompt record + tagged log line exist **before** finish and are visible via API and open UI tab ≤5 s while `running` | SC-001, FR-001/003/005/006 |
| 2 | Disconnect/reconnect (SSE drop) does not stop the run; switching scans mid-request never mixes evidence (sequence guard); server restart → `interrupted`, evidence intact, no duplication | SC-002, FR-004/008 |
| 3 | Concurrent writers (`-race`), temporarily partial JSONL line tolerated, large output bounded (paging/tail), permission/read failure → `unavailable`, unknown id → 404, legacy scan → "not recorded by this version", final refresh on terminal | SC-003, FR-002/007/009 |
| 4 | `testdata/coverage100` (Py/Go/JS-TS, siblings, duplicate routes) with a provider that reads every handler span and writes valid deliverables: **100/100** evidenced dispositions, 8 with findings, 92 `reviewed_no_issue` | SC-004, FR-010..013 |
| 5 | Paired fixture reading only 8 spans: **8/100**, 92 gaps each with a reason; path mentions / out-of-span reads / prose claims / stale revision / malformed records never count; enforcement off keeps honest counts | SC-005, FR-014/015 |
| 6 | Silent provider (stops `complete`, writes nothing): one bounded re-run; success → valid file, else `failed` assignment with exact path + partial run; `produced:false` recorded; normal stop alone never passes | SC-006, FR-017 |
| 7 | Verification fixtures per class (repairable tool-envelope, persistent transport, invalid tool args, invalid submission, turn exhaustion): repairable recovers; others unresolved with class + contract reason; sessions checkpointed incl. on cancel; evidence checks unchanged | SC-007, FR-018/019 |
| 8 | Missing disposition / unregistered artifact block completion; orphan retained; repaired manifest keeps candidate id + `authored`/not-executed | SC-008, FR-020 |
| 9 | Sanitized replay of the audited run's failure categories: API, report (md/html), regenerated view show identical `outcome` counts and partial/degraded reasons; original evidence and human decisions unchanged | SC-009, FR-021..023 |
| 10 | Browser (operator-run, fresh binary): hundreds of apps → click/keyboard opens visible detail; deep link `#applications?app=…`; back; rapid switching no stale detail; error+retry; older SBOM/threat model shown with disclosure; root + `/app` | SC-010, FR-024..026 |
| 11 | Repeated `go test ./...` leaves real registry/reports/ledger/jobs/logs unchanged (regression asserts no write outside temp); cleanup preview lists only synthetic entries with reasons, preserves zero-scan real apps and all reports; apply requires explicit action and writes a backup first | SC-011, FR-027/028 |
| 12 | Fresh `CGO_ENABLED=0` binary serves embedded assets; `/api/config` build identity + tested URLs recorded in the validation report | SC-012 |

## Fixtures & doubles

- **Delayed provider**: writes deliverable, then sleeps before completing (live-visibility window).
- **Silent provider**: existing `silentProvider` (stops normally, writes nothing).
- **Reading provider**: issues `Read` tool calls over each assigned handler span (drives `ReadSpan`
  evidence), then writes a valid deliverable.
- **Failure-class providers**: tool-envelope parse error (repairable / persistent), transport error,
  invalid tool args, invalid evidence/decision submission, max_turns.
- **`testdata/coverage100`**: deterministic 100 entry points across Python, Go, JS/TS with sibling handlers
  and duplicate route names; **paired-8** variant metadata selects which spans the reading provider reads.
- **Sanitized replay**: recorded records (not prompts) reproducing the audited categories — 1 missing hunt
  file, N unresolved candidates by class, 1 missing repro disposition, 2 unregistered artifacts.

## Operator-owned (not in the offline gate)

Browser workflow tests against the freshly built binary (root, classic, legacy, `/app` after
`npm run build`), recorded with build identity and tested URLs; any live-model run is separately
authorized and never substitutes for these reproducible tests. This guide never launches a live scan.

### Validation report template (SC-012)

Record the build identity FIRST, from the binary under test — never from a source checkout:

```
$ CGO_ENABLED=0 go build -ldflags "-X vhlocal.Version=$(git describe --always --dirty) -X vhlocal.BuiltAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o vhlocal ./cmd/vhlocal
$ ./vhlocal server --port 8765 &
$ curl -s localhost:8765/api/config | jq .build
{ "version": "...", "embedded_assets_hash": "<sha256 over vhlocal/web, path+content>", "built_at": "...", "built_at_source": "ldflags" }
```

`built_at_source` is `ldflags` when stamped, `executable_mtime` as the honest fallback. A hash that
differs from the one recorded after `npm run build` means the embedded `/app` bundle is stale.

| Field | Value |
|---|---|
| version | `cc3c1f0-dirty` (recorded 2026-09-29 from the running server's `/api/config.build`) |
| embedded_assets_hash | `ecdfd971d51dc30b8fed16ac792cbc766683e3a4d46dcbecbaa99cce2c4692a0` |
| built_at / source | `2026-09-29T13:58:08Z` / `ldflags` |
| tested URLs | `/` `#applications` `#applications?app=<slug>` · `/classic` · `/legacy` · `/app/apps` `/app/apps?app=<slug>` — server `http://127.0.0.1:8421` |
| browsers | not recorded (operator-attested run) |

**Result (2026-09-29):** the operator ran the checklist below against this build and declared all nine items
complete. This is an operator attestation — the offline gate asserts only the shipped-source contract
(`TestShippedApplicationsContract`), not browser behavior. Note that the binary under test predates the
three live-run fixes recorded in `docs/engineering/2026-09-29-scan-reliability-handoff.md`
(`unresolved_verdict` class, `gaps:[]`, contract wording); none of them changes browser behavior.

Browser checklist (scenario 10; each row is pass/fail with the URL used):

1. Applications list with ≥ 150 entries renders 100 rows + "Show N more"; table sort and layout toggle still work; bulk select/delete still present.
2. Click a row/card → detail pane scrolls into view; URL becomes `#applications?app=<slug>` (`/app/apps?app=<slug>` in React).
3. Open that URL in a new tab → the same application is selected; Back returns to the list (`#applications`) with the detail cleared.
4. Tab to a row/card, press Enter and Space → detail opens.
5. Click three applications quickly → the pane shows the LAST one clicked only (no stale detail).
6. Stop the server, click an application → error with a Retry button (no indefinite "Loading…"); restart → Retry loads.
7. An application whose latest scan disabled the threat model but an older scan has one → Threat model tab shows the older material with "From scan … · revision …" and the "older than the latest scan" badge; SBOM tab explains absence when none is valid.
8. A report file made unreadable (`chmod 000`) → the tab shows an error (HTTP 500), not "absent".
9. `GET /api/applications/cleanup` lists only `/tmp/Test…/NNN` entries with zero history whose path is gone; `POST` without the token → 400 and nothing changes; with the token → `applications.json.bak-<ts>` exists and exactly those ids are gone; reports/ledgers unchanged. CLI parity: `vhlocal applications cleanup --preview` / `--apply --confirm <token>`.
