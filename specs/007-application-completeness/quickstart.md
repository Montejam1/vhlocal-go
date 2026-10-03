# Quickstart & Validation Guide: Complete, usable scan-to-report workflows

Offline-first validation for feature 007. No Ollama, no Python, no live scan is required for the automated gate; browser acceptance runs against a live **local** Go server with **seeded on-disk** data. The reference in `../vhlocal` is consulted by reading it, never by executing it.

## Prerequisites

- Go toolchain: `export PATH=$PATH:/usr/local/go/bin` (Go 1.23+).
- Build: `go build -o bin/vhlocal ./cmd/vhlocal`.
- A scratch reports directory seeded with fixtures (below); point the server at it and bind loopback (default).

## Seed fixtures (offline)

Create seeded on-disk state that exercises the contracts without running a scan:

- **≥2 applications**, one scanned with **ledger disabled**, one with **multiple reports** including an **older/pre-fix** report shape.
- A **partial-run** report fixture mirroring the handoff run: `execution=partial`, `coverage=degraded`, phases `1,1t,2,3d,4` completed (2b, 3 incomplete), 140 candidates (10 supported / 7 rejected / 123 unresolved, 98 missing decisions), an existing `threat_model.md` and a 21-component `sbom.cdx.json`, and an `artifact_manifest.json` with the 6 invalid test bindings.
- **Material-state fixtures**: threat/SBOM in each `MaterialAvailability` state (not_requested / available / missing / malformed / generation_failed).
- **Recorded model transcripts** for a controlled verification recovery (one rejected-then-accepted submission; one exhausted-to-unresolved) and a reproduction per-candidate loop (one invalid-then-corrected; one deferral).

Fixtures live under the existing test trees and `tests/parity`; do not overwrite real reports.

## Automated offline checks (the gate)

```bash
export PATH=$PATH:/usr/local/go/bin
go build ./...
go test ./... -count=1        # backend, engine, verification, consolidate, report, parity
go vet ./...
gofmt -l internal tests web-react 2>/dev/null   # (Go dirs); frontend lint via its own toolchain
```

Map to contracts (see `contracts/api.md`, `contracts/behavior.md`):

| Area | Checks |
|---|---|
| Apps aggregation | CA-1, CA-2, CA-3 (discovery incl. ledger-disabled + report-only; detail history; forget preserves reports) |
| Scans/status | CA-4, CB-1..CB-5 (queue≠execution, no false all-complete, distinct dispositions, resume/regenerate integrity) |
| Error vs empty | CB-6, CB-7, CB-8 (no error-as-empty, legacy shapes, reconnect coherence) |
| Reports/files | CA-5 (mixed/legacy reports; path-escape rejection) |
| Material | CA-6, and material-state coverage |
| Verification recovery | CB-9, CB-10, CB-11 |
| Reproduction loop | CB-12, CB-13, CB-14 |
| Report content | CB-15, CB-16, CB-17, CB-18 |
| Options/limits | CB-19, CB-20 |
| Preservation/non-regression | CB-21, CB-22 (audit-protection suite stays green), CB-23 |

## Browser acceptance (live local server, seeded data)

```bash
bin/vhlocal serve --reports <seeded-dir>    # loopback default; confirm the served surface
```

1. Open the served operator surface (primary: legacy `/`; also `/legacy`, `/classic`; note `/app` currently 404s until the React build is embedded or explicitly scoped out) and confirm:
   - Scans list shows all seeded scans in correct states; forcing `/api/scans` to fail shows a distinguishable error, **not** "No scans yet" (CB-6).
   - Applications list shows all seeded apps (incl. ledger-disabled and report-only) with populated fields; detail shows scan history and threat/SBOM availability (CA-1/CA-2).
   - The partial-run scan never shows "All N steps complete"; unfinished phases show reasons (CB-2).
   - Threat model and SBOM open and download from scan/report/application views (CA-6).
2. Repeat after a **page refresh** and a **server restart** (history persists; dead in-flight jobs show `interrupted`).
3. Capture the first JS exception + failed request per surface as part of reproducing the original blank-view failure before/after the fix.

Record: the exact built frontend/backend provenance (commit + asset hashes) used for acceptance (SC-008).

## Representative supported finding (report usefulness)

From the seeded run's canonical evidence, open a representative **supported** finding in Markdown, HTML, and the machine-readable output and confirm all of CB-16's review elements are present (with explicit "unknown" where absent), unsupported candidates are in separate sections, the candidate total is not shown as a confirmed-vulnerability total, and the three renderings agree (CB-17/CB-18).

## Parity comparison (read-only)

Produce a behavior matrix vs. the reference (`../vhlocal`) for apps/report aggregation, status axes, material availability, and verdict/tiering — **matches / documented approximations / remaining gaps** — derived by reading the reference source (per `research.md`), not by running it. A passing Go suite or a Go-generated golden alone is insufficient (SC-008).

## Bounded live-model validation (operator-owned)

Define — do not auto-run — a bounded plan for the operator to run one live scan and confirm completion/yield/failure behavior, distinct from these integration contracts. Do not launch a multi-hour scan automatically and never execute generated exploit material (FR-039, constitution III).

## Success-criteria coverage

SC-001↔CB-6/CA-1; SC-002↔CA-4 + scripted workflow; SC-003↔CB-1/CB-2 partial-run fixture; SC-004↔CA-6/material states; SC-005↔CB-9..CB-14; SC-006↔CB-15..CB-18; SC-007↔CB-19/CB-20; SC-008↔parity matrix + browser provenance; SC-009↔CB-21 preservation check (before/after).
