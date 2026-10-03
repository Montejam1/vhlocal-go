# Quickstart & Validation Guide: Go port of vhlocal

**Feature**: 002-golang-port | **Date**: 2026-09-14

Runnable scenarios that prove the port meets the spec's success criteria. Details of shapes/schemas live in [contracts/](./contracts/) and [data-model.md](./data-model.md); this guide is how to build, run, and validate. It does not contain implementation code.

## Prerequisites

- Go 1.23+ toolchain.
- Node/npm (build-time only) to build the React UI bundle into `vhlocal/web/app`.
- For live scans: a reachable inference endpoint (Ollama with a `tools`-capable model, or an OpenAI-compatible server, or OpenRouter with a key). **Not needed** for the offline test suite.
- The reference Python implementation available for differential comparison (already in-tree).

## Build

```bash
# 1. Build the browser UI (build-time dependency only)
cd web-react && npm ci && npm run build          # → vhlocal/web/app

# 2. Build the single self-contained binary (embeds skill/ + web/)
cd .. && go build -o vhlocal ./cmd/vhlocal

# 3. Cross-platform release binaries (SC-012)
make release        # linux/amd64, linux/arm64, darwin/amd64, darwin/arm64
```

Expected: one `vhlocal` binary that runs with no interpreter and no external asset directory (SC-011). `./vhlocal -h` lists subcommands; `./vhlocal run -h` lists the run flags (parity with cli.md).

## Scenario 1 — CLI scan artifact parity (P1 / SC-001, SC-004)

```bash
./vhlocal run --repo testdata/vulnapp --out /tmp/vh-go --host <endpoint>
ls /tmp/vh-go
```
**Expect** the same file set as the Python tool: `SCAN_REPORT.html`, `SCAN_REPORT.md`, `findings.json`, `findings.sarif`, `scan_meta.json`, `coverage_ledger.json`, `run_manifest.json`, `README.md`, the `phaseN_output.md` set, `results/`. Then differentially compare against a Python run on the same fixture/model:
- Same artifact filenames present (SC-001).
- `findings.json` carries `meta`, `attribution`, `run_status`, `coverage`, `counts`, `assessment`, `lifecycle`, `application_intelligence`, `findings` with the per-finding fields of data-model.md.
- `findings.sarif` validates as SARIF 2.1.0, driver `vhlocal`.
- Ignore timing/token/model-prose differences (assumptions); assert field presence, types, and deterministic labels.

## Scenario 2 — deterministic layers match Python exactly (SC-006 + honesty)

Run offline unit/differential tests over `testdata/`:
```bash
go test ./internal/consolidate/... ./internal/lifecycle/... ./internal/inventory/... ./internal/sbom/... ./internal/sarif/...
```
**Expect**: identical `normalized_cwe`/`cwe_family`/`normalized_severity` for a battery of CWE inputs (the `_FAMILIES` table + `_GATED` -1-tier rule); identical `root_cause_key` fingerprints; identical coverage dispositions and partition-fallback for the fixture's routes; identical lifecycle labels (new/persisting/regressed/fixed) for a two-run sequence; SBOM identical for a multi-ecosystem fixture. These are the honesty-critical tables (Principle I/II).

## Scenario 3 — scoring on the planted fixture (SC-006)

```bash
./vhlocal run --repo testdata/vulnapp --out /tmp/vh-score --host <endpoint>
go run ./testdata/score.go /tmp/vh-score      # ported scorer
```
**Expect**: recall on the five planted bugs within the same band as the Python tool on the same model; the negative control (`/api/users?email=` parameterized query) is **never** reported.

## Scenario 4 — HTTP engine + existing UI unchanged (P2 / SC-002)

```bash
./vhlocal server --host 127.0.0.1 --port 8420 --ollama-host <endpoint> &
```
- Open `http://127.0.0.1:8420/app` (React) and `/`, `/legacy`, `/classic` — all load from the embedded bundle.
- Exercise each screen (Dashboard, Applications, Scans, New Scan, Reports, Ledger, Activity, Docs, Settings). Every screen populates; every action succeeds with zero UI code changes (SC-002).
- Endpoint check (contracts/http-api.md): `curl -s localhost:8420/api/config`, `/api/scans`, `/api/reports`, `/api/stats`, `/api/profiles`, `/api/ledgers`, `/api/activity` return the same shapes.
- Submit a scan and stream events:
```bash
curl -X POST localhost:8420/api/scans -H 'Content-Type: application/json' -d '{"repo":"testdata/vulnapp"}'
curl -N localhost:8420/api/scans/<id>/events    # backlog replay then live SSE; keepalives
curl -X POST localhost:8420/api/scans/<id>/cancel   # stops within one model turn
```

## Scenario 5 — security posture (SC-009)

```bash
./vhlocal server --host 0.0.0.0                 # expect refusal without --unsafe-bind
./vhlocal server --host 0.0.0.0 --unsafe-bind   # expect it binds
curl 'localhost:8420/api/scans/<id>/file?path=../../etc/passwd'   # expect 403 path escape
curl -X POST localhost:8420/api/scans -d '{"repo":"/"}'          # expect 403 outside allow-roots
```
**Expect**: loopback-only by default; non-loopback needs `--unsafe-bind`; traversal and out-of-root targets refused (403). No artifact read escapes its owning results dir.

## Scenario 6 — resume & idempotency (SC-008)

```bash
./vhlocal run --repo testdata/vulnapp --out /tmp/vh-r --phases 1 --host <endpoint>
./vhlocal run --repo testdata/vulnapp --out /tmp/vh-r --resume --host <endpoint>
```
**Expect**: the second run skips phase 1 (valid deliverable present) and continues; re-running a completed scan produces no duplicated/double-counted findings or ledger entries. Kill mid-run and confirm a server job reloads as `interrupted`, never re-run.

## Scenario 7 — backward compatibility (FR-028 / SC-004)

Point the Go engine at a `--reports-dir` populated by the Python tool (existing `~/vulnhunter-reports`), plus an existing `~/.vhlocal/ledger` and `~/.vhlocal/jobs.json`.
**Expect**: every prior report lists and opens; ledgers and applications load; interrupted-on-reload semantics hold. Reports missing newer fields degrade to documented fallbacks, not dropped.

## Scenario 8 — offline test gate (SC-007)

```bash
go test ./...        # no network, no live model, no paid services
```
**Expect**: full suite passes offline using fake transports + fixtures, covering safety-boundary, status-honesty (three axes), provenance, explicit-failure (unreachable/malformed/budget-halt), and resume/idempotency, including degraded paths. This is the Go analog of `python3 -m unittest discover -s tests`.

## Scenario 9 — auxiliary tools (P3)

```bash
./vhlocal report /tmp/vh-go            # regenerate SCAN_REPORT.md/.html + findings.json (no model)
./vhlocal report --all                 # bulk regenerate under reports dir
./vhlocal logs <scan-tag>              # central-log slice for one scan
./vhlocal sbom testdata/vulnapp        # → ./sbom.cdx.json (CycloneDX)
./vhlocal report --delete /tmp/vh-go --yes   # guarded delete (refuses outside reports dir / active scan)
```
**Expect**: same outputs, exit behavior, and refusals as the Python entry points.

## Done criteria (maps to Success Criteria)

- [ ] SC-001 artifact filename set matches — Scenario 1
- [ ] SC-002 UI + every API endpoint unchanged — Scenario 4
- [ ] SC-003 all CLI flags accepted (migration note has zero undocumented deltas) — `-h` diff + cli.md
- [ ] SC-004 artifacts validate + old reports browsable — Scenarios 1, 7
- [ ] SC-005 three status axes on every surface — inspect report/API/SARIF/manifest
- [ ] SC-006 recall band + negative control — Scenarios 2, 3
- [ ] SC-007 offline suite green — Scenario 8
- [ ] SC-008 resume/idempotency — Scenario 6
- [ ] SC-009 security posture — Scenario 5
- [ ] SC-010 no egress beyond endpoints; report offline-clean — inspect network during scan / open HTML offline
- [ ] SC-011 single binary, no runtime prereq — Build
- [ ] SC-012 cross-platform binaries — Build (`make release`)
