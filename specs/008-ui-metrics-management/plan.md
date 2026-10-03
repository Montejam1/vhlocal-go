# Implementation Plan: Dashboard metrics & application/ledger management

**Branch**: `008-ui-metrics-management` | **Date**: 2026-09-22 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/008-ui-metrics-management/spec.md`

## Summary

Four operator-facing fixes on top of feature 007, all confirmed by code inspection:

1. **Dashboard metrics** — `handleStats` returns only `scans`, `findings`, `by_model`, and a float `avg_findings_per_scan`; it omits `total_tokens`, `avg_tokens_per_scan`, `total_seconds`, `avg_seconds_per_scan`, `with_usage`, and hardcodes per-model tokens to 0. The data exists in each run's `scan_meta.json` (`usage.prompt_tokens`/`completion_tokens`, `started_at`/`finished_at`) but `reports.Report` doesn't carry it. Fix: surface per-run tokens+duration in the report record and compute the full metric set; format the vulnerabilities average as an integer.
2. **Phantom applications** — `reports.Load` returns a `Report` for **any** directory (it only fails when the path isn't a dir); the reference's `is_report_dir` guard was dropped. Stray subdirectories under the reports dir become empty reports → empty applications that reappear every restart. Fix: gate `Load`/`Index` so a directory qualifies only if its name matches the results-dir pattern **or** it contains a recognized deliverable — restoring report-only discovery without phantoms.
3. **Applications list + delete** — the served UI needs a list layout and a confirmed delete; the delete capability (`DELETE /api/applications/{slug}` → `apps.Forget`, reports preserved) already exists.
4. **Ledger list + delete** — same, reusing `DELETE /api/ledgers/{slug}` → clear (reports preserved).

The served operator surface is the legacy self-contained `vhlocal/web/index.html` (the React `/app` bundle is not embedded — feature 007 R11/T048), so UI changes target it primarily; the `web-react` source is updated in parallel for when it is embedded. Backend changes (stats aggregation, report-dir guard) serve both.

## Technical Context

**Language/Version**: Go 1.23+ (`export PATH=$PATH:/usr/local/go/bin`). Frontend: legacy `vhlocal/web/index.html` (served) + `web-react` (build-time; not embedded here).

**Primary Dependencies**: standard library only; **no new runtime dependency** anticipated (stats aggregation, report parsing, and the apps/ledger handlers are all stdlib).

**Storage**: on-disk results dirs (`scan_meta.json`, `findings.json`), the applications registry (`applications.json`), and ledgers (`<slug>.json`). No database.

**Testing**: `go test ./...` offline for the stats aggregation, the `is_report_dir` guard, and preservation; browser confirmation of the list/delete UIs is operator-owned (consistent with feature 007).

**Target Platform**: loopback single-binary server + browser UI.

**Project Type**: web service (Go backend + served UI).

**Performance Goals**: not a throughput feature; stats read a handful of `scan_meta.json` files per Dashboard load — acceptable for the small report counts observed (≈8).

**Constraints**: metrics computed only from already-recorded data (no new measurement); deletes reuse existing forget/clear semantics and never remove report files; loading/empty/error states stay distinct; no scan-behavior change; static-only boundary untouched.

**Scale/Scope**: small — one metrics computation, one report-dir guard, two list+delete UI surfaces.

**Confirmed root causes (from code, this planning pass):**
- `internal/server/handlers.go` `handleStats` omits token/time aggregates + hardcodes `by_model` tokens 0 + float findings average.
- `internal/reports/reports.go` `Load` has no report-dir guard → phantom reports/apps.
- Delete endpoints already exist: `handleForgetApp` (`apps.Forget`, keeps reports), `handleClearLedger` (removes ledger json only).
- `scan_meta.json` carries `usage` + `started_at`/`finished_at` (per `internal/engine/record.go`).

No `NEEDS CLARIFICATION` items remain.

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after Phase 1. Constitution v1.1.0.*

- **I. Evidence Integrity (NON-NEGOTIABLE)** — ADVANCING. Metrics computed only from recorded data (FR-018); the current always-zero per-model tokens (a placeholder shown as real) is corrected; removing phantom applications makes the inventory truthful; deletes never fabricate or destroy scan evidence (FR-014/017/019). PASS.
- **II. Orthogonal Status Reporting** — not materially affected; Dashboard metrics are aggregates, not status axes. PASS.
- **III. Static-Only Safety Boundary (NON-NEGOTIABLE)** — no execution added; reads stay confined to the reports/results directories; deletes reuse existing confined operations. PASS.
- **IV. AI Result Provenance** — unaffected (no model calls). PASS.
- **V. Explicit AI Failure** — unaffected. PASS.
- **VI. Resumable, Idempotent Operations** — the report-dir guard makes discovery restart-stable (FR-009); deletes are explicit, confirmed, reversible-by-rescan for apps, and never touch reports (FR-014/017/019). PASS.
- **VII. Testable Acceptance & Regression Coverage** — offline tests for stats aggregation, the report-dir guard (phantom exclusion + report-only preserved), and preservation; degraded/empty paths tested (zero scans, partial-usage). Browser confirmation operator-owned. PASS.
- **Safety & Technical Constraints** — loopback default, no egress, self-contained UI, deterministic aggregation, runtime dependency budget unchanged. PASS.

**Gate result: PASS. No violations → Complexity Tracking omitted.** Re-evaluated after Phase 1: still PASS (no new runtime deps, no boundary/status/provenance impact).

## Project Structure

### Documentation (this feature)

```text
specs/008-ui-metrics-management/
├── plan.md          # this file
├── research.md      # Phase 0 output
├── data-model.md    # Phase 1 output
├── quickstart.md    # Phase 1 output
├── contracts/       # Phase 1 output (stats + apps/ledger list/delete contracts)
└── tasks.md         # /speckit-tasks (not created here)
```

### Source Code (repository root)

```text
internal/
├── reports/         # reports.go — add is_report_dir guard to Load/Index; add
│                    #   per-run tokens + duration to Report (from scan_meta)
├── server/          # handlers.go — rewrite handleStats to full metric set
│                    #   (tokens/time aggregates, integer findings avg, real by-model
│                    #   tokens); handleForgetApp / handleClearLedger already exist
└── (apps/, membank/ unchanged — list/delete semantics reused)

vhlocal/web/index.html   # served UI: Dashboard metric rendering (integer avg),
                         #   Applications list view + delete (confirm),
                         #   Ledger list view + delete (confirm)

web-react/src/
├── pages/Dashboard.tsx     # integer avg render (parallel; not embedded)
├── pages/Applications.tsx  # list layout + delete (parallel)
├── pages/Ledger.tsx        # list layout + delete (parallel)
└── lib/                    # types unchanged (Stats already declares the fields)

tests/  (internal/**/*_test.go)   # stats aggregation, report-dir guard, preservation
```

**Structure Decision**: existing web-service layout. Backend edits are the core (stats + report-dir guard), fully offline-testable; the served legacy UI is the primary UI target; `web-react` is updated in parallel. No new packages, no new runtime dependency.

## Complexity Tracking

No constitution violations — section intentionally omitted.
