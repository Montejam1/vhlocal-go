# Implementation Plan: Complete, usable scan-to-report workflows

**Branch**: `007-application-completeness` | **Date**: 2026-09-17 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/007-application-completeness/spec.md`; engineering evidence in `docs/engineering/2026-09-17-handoff.md` and `docs/engineering/2026-09-17-evidence.json`.

## Summary

The scanner-correctness protections from the prior audit are in place, but the surrounding application is unusable end-to-end: the operator's Scans and Apps views are blank despite 8 persisted scans/reports; a job shows `done` while its saved report is `partial`/`degraded`; generated threat-model/SBOM files exist on disk and return HTTP 200 but are unreachable in the workflow; verification left 123 of 140 candidates unresolved (98 missing decisions) and 6 reproduction artifacts failed structural validation with no repair; and the deterministic report is honest but too sparse to review.

Technical approach: close the **API↔UI contract gaps** so persisted scans and applications render truthfully and survive restart; **propagate engine-observed phase outcomes and the three status axes** through the queue/job to every surface so a partial run is never shown complete; make **existing on-disk threat/SBOM and generated material discoverable** with explicit availability states (no re-scan, no evidence rewrite); add **bounded, measured recovery** to verification and a **per-candidate corrective loop** to reproduction; and **enrich the deterministic report** from canonical evidence (review detail, supported-first, separated unsupported, navigation to intelligence). All work preserves existing history/reports/registry/tracking and the audit protections, is validated offline first, and is compared against the reference tool's behavior by reading it — never by executing Python.

The engine already computes truthful status (`consolidate.ComputeRunStatus` yields the three independent axes; `internal/report` already carries an honest incomplete-run banner). The dominant gaps are in the server aggregation/handlers, the job/queue success mapping, the browser surfaces, the reproduction repair loop, and report content — not in status derivation itself.

## Technical Context

**Language/Version**: Go 1.23+ (module `vhlocal`; toolchain Go 1.27.1 at `/usr/local/go/bin`, not on PATH). Frontend: the embedded self-contained root web UI (`vhlocal/web/index.html`) and the `web-react` browser app bundle.

**Primary Dependencies**: Standard library first per the constitution's runtime dependency budget; **no new runtime Go dependency is anticipated** for this feature (server, jobs, apps, report, engine are stdlib-based). Any addition must be justified and listed here before use. Frontend uses the existing React/TypeScript toolchain (build-time only; not part of the runtime budget).

**Storage**: On-disk results directories under the reports root (default `~/vulnhunter-reports/...`); per-scan `scan_meta.json`, `findings.json`, `verification_*.json`, `artifact_manifest.json`, `SCAN_REPORT.{md,html}`, `threat_model.md`, `sbom.cdx.json`, `hunt_execution.json`; the application registry and (optional) tracking ledger. No database.

**Testing**: `go test ./...` (offline, no model/network) for backend and engine; existing `tests/parity` offline fixtures and independent reference-contract checks; browser acceptance on the shipped surfaces against a real Go server with seeded on-disk fixtures (evidence supplied per FR-039/SC-008). Model/transport behavior exercised via fakes/recorded transcripts.

**Target Platform**: Linux loopback-bound single-binary server + browser UIs.

**Project Type**: Web service (Go backend + embedded/browser frontends) with a long-running scan engine.

**Performance Goals**: Not a throughput feature. Constraint of note: a scan must not silently expand into hours of unbounded retries (FR-036); recovery budgets are bounded and measured. API/list responses render without blocking the UI on large histories.

**Constraints**: Static-only safety boundary (no target execution, no exploit runs); loopback bind by default; no network egress beyond the inference endpoint; artifact reads confined to the owning results directory with symlink-escape rejection (already added); deterministic status/report/aggregation; preserve existing on-disk evidence and uncommitted work; **no Python executed at runtime or in the acceptance gate** — the reference is a read-only semantics oracle.

**Scale/Scope**: Handoff snapshot — 8 scans/reports, 1 registered application (under-aggregated), a 140-candidate partial run, 612 report files, 24 partitions/217 phase-2 agents. The feature must handle mixed/legacy persisted shapes and pre-fix reports.

**Open investigations (resolved in Phase 0 research, not blocking):**
1. Exact reference aggregation field set + join semantics for apps list/detail (from `../vhlocal` server/apps — read-only).
2. Full inventory of supported operator UI surfaces (root UI, `/app`, and any `/legacy`/`/classic`) and each one's data contract.
3. The intended threat-analysis ↔ SBOM (dependency inventory) relationship per the reference.
4. Whether `max_partitions` is a hard cap or a coverage-driven starting point (explain the requested-8 → actual-24 behavior).
5. Categorization of the 72 tool_repair / 26 max_turns verification exits from saved traces to choose a measured recovery strategy (not blind retry increases).

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after Phase 1. Constitution v1.1.0.*

- **I. Evidence Integrity (NON-NEGOTIABLE)** — CENTRAL AND ADVANCING. This feature exists to stop dishonest surfaces: `done` masking `partial`, candidate totals read as confirmed vulnerabilities, authored artifacts implied as executed, invisible degraded material. Every requirement pushes toward truthful, source-grounded reporting; nothing here fabricates or upgrades evidence. PASS.
- **II. Orthogonal Status Reporting** — CENTRAL. FR-012/013/014 require queue/execution/coverage/validation to stay independent across the API and both UIs, and per-phase progress to come from validated outcomes. The engine already derives the axes; the fix propagates them faithfully. PASS.
- **III. Static-Only Safety Boundary (NON-NEGOTIABLE)** — RESPECTED. No target execution or exploit runs are added (FR-027/FR-039); artifact discovery reads only within owning results directories (containment already enforced); reproduction remains authored-only. PASS.
- **IV. AI Result Provenance** — RESPECTED/ADVANCING. Verification/reproduction attempts, retry counts, and outcomes are recorded (FR-023); effective configuration is persisted (FR-034). No provenance reconstructed from prose. PASS.
- **V. Explicit AI Failure, No Silent Fallback** — RESPECTED/ADVANCING. Bounded same-endpoint corrective retries only (FR-022/FR-026), counts recorded; exhausted recovery becomes an explicit unresolved outcome (FR-023). No provider/model fallback. PASS.
- **VI. Resumable, Idempotent Operations** — RESPECTED. Restart/resume/regeneration preserve status distinctions and invalidate stale downstream results (FR-016); existing evidence is never overwritten (FR-020/FR-037); atomic writes retained. PASS.
- **VII. Testable Acceptance & Regression Coverage** — SATISFIED BY DESIGN. Measurable SC-001..009; offline-first tests plus browser acceptance evidence; audit-protection regressions retained (FR-038). Degraded paths are explicitly tested. PASS.
- **Safety & Technical Constraints** — Loopback default, no egress, embedded self-contained UI, deterministic aggregation/report, runtime dependency budget unchanged (no new runtime dep planned). PASS.

**Gate result: PASS. No violations to justify → Complexity Tracking omitted.** Re-evaluated after Phase 1 (see end of research.md / this file's re-check note).

## Project Structure

### Documentation (this feature)

```text
specs/007-application-completeness/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output (API + UI-facing contracts, reproduction/verify loop contracts)
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created here)
```

### Source Code (repository root)

```text
internal/
├── server/          # handlers.go (apps/scans/reports/files/threat/sbom), server.go (runScan success mapping, routes)
├── jobs/            # jobs.go (job states, done-mapping, persistence across restart)
├── apps/            # registry + aggregation (join reports/ledger; discovery independent of ledger)
├── engine/          # engine.go (apps.Register call site/guard, finalize/status), verify.go (bounded recovery),
│                    #   reproduction.go (per-candidate corrective loop), regenerate.go (resume/regeneration validity)
├── consolidate/     # status.go (axes — already correct), corroborate.go (authz/logic acceptance vs syntactic sink)
├── verification/    # verification.go, artifacts.go (validation feedback surfaced)
└── report/          # report.go (enriched deterministic Markdown/HTML from canonical evidence)

web-react/src/
├── pages/           # Scans.tsx, Applications.tsx (+ detail views): render truthful states, no silent empty-success
├── components/      # StepTracker.tsx (validated phase outcomes, not done→all-complete)
├── lib/             # types.ts (AppSummary/AppDetail/Scan/Report shapes), usePoll (surface errors)
└── ...

vhlocal/web/index.html   # root self-contained UI: same truthful contracts

tests/
├── (internal/**/*_test.go)          # backend/engine unit + audit regressions (offline)
└── tests/parity/                    # offline fixtures + independent reference contracts (retained/extended)
```

**Structure Decision**: Existing web-service layout (Go `internal/*` backend + `web-react` and embedded root UI). This feature edits existing packages and the two browser surfaces; it introduces no new top-level module and (planned) no new runtime dependency. New test fixtures for seeded history, partial-run status, artifact/material states, and verification/reproduction recovery are added under the existing test trees and `tests/parity`.

## Complexity Tracking

No constitution violations — section intentionally omitted.
