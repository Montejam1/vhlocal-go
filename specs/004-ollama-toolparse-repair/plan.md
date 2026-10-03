# Implementation Plan: Recover from provider tool-call-parse failures without aborting the scan

**Branch**: `004-ollama-toolparse-repair` | **Date**: 2026-09-15 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/004-ollama-toolparse-repair/spec.md`

## Summary

A live scan aborted at phase 2b on an Ollama **HTTP 500 "error parsing tool call"** — the model interleaved reasoning prose with tool-call JSON in one message, the provider's parser rejected the whole blob, and the harness treated that 500 as a fatal transport failure: it retried the identical request (which reproduces the blob), then aborted the entire run, discarding phases 1–2's work. The model's intended action (a `Glob` with a `pattern`) was present verbatim in the error body and was recoverable.

Fix, entirely within the existing Go engine/client (no interface, artifact, or schema change), reusing feature 003's repair machinery:

1. **Classify** the provider tool-call-parse failure distinctly from a generic transport failure, and extract the model's intended action (`raw='…'`) from the error body (`internal/client`).
2. **Route it into the existing fresh-context repair** from the agent's transport-error path (not just the client-side dispatch path), on the same endpoint, without naive replay (`internal/agent`).
3. **Degrade per phase, not the whole scan**: an unrecoverable endpoint failure in one phase records that phase as failed and continues to the remaining phases; the artifact set is always finalized; status is honestly partial/degraded; a total outage is still reported as failed (`internal/engine`).
4. **Deliverable-aware completion**: an agent that ends or times out without writing its declared deliverable is nudged once more; a phase counts as produced only if the deliverable exists (closes the recon-no-map gap) (`internal/agent`, `internal/engine`).

## Technical Context

**Language/Version**: Go 1.23+ (existing module `vhlocal`).

**Primary Dependencies**: Standard library only (no new deps). Touches `internal/client` (provider error type + Ollama/OpenAI 500 classification), `internal/agent` (transport-error → repair, completion nudge), `internal/engine` (per-phase degrade-not-abort), and their tests. Repair reuses the `client.Provider` interface and the existing `repairToolCall` in `internal/agent`.

**Storage**: Filesystem artifacts unchanged (names/schemas identical). Field *content* changes: `run_status.coverage_degraded_reasons` (adds per-phase endpoint-failure reasons), `scan_meta.aborted` (used only for systemic/cancel, not a single phase), `usage.repairs`/per-agent repair counts (already present, now also incremented by provider-parse repairs).

**Testing**: `go test ./...`, fully offline. New fakes return the exact tool-call-parse HTTP 500 (body carrying a recoverable `raw='…{"pattern":"…"}'`), an unrecoverable per-phase endpoint failure, and an agent that stops without its deliverable. Regression tests fail before each fix (Principle VII). **No live model — per operator instruction, live validation is the operator's.**

**Target Platform**: unchanged (Linux/macOS single binary).

**Performance Goals**: parity; recovery adds at most a bounded number of small fresh-context repair calls per affected agent (same budget as feature 003).

**Constraints**: preserve static-only boundary, sandbox confinement, loopback/allow-root posture, and no silent provider/model fallback; repair contacts only the operator-configured endpoint. No artifact/API/status-field-name changes.

**Scale/Scope**: small bug-fix across 3 packages + tests; grounded in run `…_2026-09-15-163205`; reproduced offline with fakes.

## Constitution Check

*GATE: Must pass before Phase 0. Re-check after Phase 1.*

Corrective feature — strengthens compliance; no gate fails.

| Principle | Effect |
|---|---|
| I. Evidence Integrity | **Preserved/strengthened.** Recovered work is real (repaired call actually dispatched); a phase counts produced only if its deliverable exists; no fabricated success. |
| II. Orthogonal Status | **Strengthened.** Per-phase endpoint failure becomes an explicit coverage-degradation reason; partial runs stay distinct from clean; a total outage is reported as failed. FR-006/008/009/011. |
| III. Static-Only Boundary (NON-NEGOTIABLE) | **Preserved.** Repair adds only a fresh-context `Chat` to the same endpoint; the recovered action runs through the existing sandbox confinement. FR-012. |
| IV. AI Result Provenance | **Preserved.** Repair attempts/successes/give-ups recorded, incl. those from provider-parse failures. FR-005. |
| V. Explicit AI Failure, No Silent Fallback (NON-NEGOTIABLE) | **Directly served.** A provider parse failure is recovered by bounded same-endpoint repair (permitted), never naive replay or a different provider/model; unrecoverable failures end the agent gracefully and are surfaced. FR-002/003/004/009. |
| VI. Resumable, Idempotent | **Strengthened.** One phase's failure no longer discards the whole run; the artifact set is always finalized; resume semantics unchanged. FR-006/007. |
| VII. Testable Coverage | **Served.** Every behavior has an offline regression test that fails pre-fix, using fakes (no live endpoint). FR-013; SC-007. |

**Safety & Technical Constraints**: Go runtime (constitution v1.1.0), stdlib-only, offline tests — satisfied. **Gate outcome: PASS**, no deviations, no Complexity Tracking.

### Post-Design Re-Check (after Phase 1)

Re-evaluated after research.md, data-model.md, contracts/behavior.md, quickstart.md: **still PASS.** No new dependency, no artifact/API/schema surface change (data-model confirms field-content-only changes: a new provider-error classification is internal; `TransportError` gains fields but is not serialized). Repair stays same-endpoint and bounded (III/V); per-phase degrade preserves completed work (VI) and honest status (II); all contracts (C-*) are offline-testable with fakes (VII). No Complexity Tracking needed. Ready for `/speckit-tasks`.

## Project Structure

### Documentation (this feature)

```text
specs/004-ollama-toolparse-repair/
├── plan.md              # This file
├── research.md          # Phase 0 — classification, repair-from-raw, degrade-vs-abort, nudge decisions
├── data-model.md        # Phase 1 — provider error classification, phase-outcome, extended repair path
├── quickstart.md        # Phase 1 — offline reproduction + validation (no live model)
├── contracts/
│   └── behavior.md      # Phase 1 — behavioral contracts for the changed paths
└── tasks.md             # /speckit-tasks (not created here)
```

### Source Code (files this feature changes)

```text
internal/client/provider.go     # TransportError gains Kind (Generic|ToolParse) + Raw (model's intended output)
internal/client/ollama.go       # classify the "error parsing tool call" 500: set Kind=ToolParse, extract raw='…',
                                #   mark NOT replay-retryable (replay reproduces it)
internal/client/openai.go       # same classification for the OpenAI-compatible backend's equivalent error
internal/agent/agent.go         # on a ToolParse transport error → fresh-context repair from te.Raw (reuse
                                #   repairToolCall machinery), continue on success, graceful tool_repair on budget;
                                #   completion nudge: model stops without deliverable → nudge once more
internal/engine/engine.go       # phase loop: per-phase endpoint failure degrades (record reason, continue),
                                #   not whole-run abort+break; keep finalize (already after the loop)
internal/engine/helpers.go      # runFanOut: same per-partition degrade-not-abort
internal/consolidate/status.go  # (if needed) surface phase-endpoint-failure reasons in coverage_degraded_reasons
internal/agent/agent_test.go    # + regression tests (C-A*, C-N*, C-X2)
internal/client/client_test.go  # + classification tests (C-P*)
internal/engine/*_test.go       # + per-phase-degrade + systemic-outage tests (C-E*)
```

**Structure Decision**: No new packages. The one new concept is a small **provider-error classification** (`TransportError.Kind` + `Raw`) threaded from the client into the agent's recovery path; everything else reuses feature-003 machinery (fresh-context repair, honest degraded status, per-phase outcomes).

## Complexity Tracking

No constitution violations; no entries required.
