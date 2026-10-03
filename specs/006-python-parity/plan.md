# Implementation Plan: Meet semantic parity with the Python reference (vhlocal)

**Branch**: `006-python-parity` | **Date**: 2026-09-16 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/006-python-parity/spec.md`

## Summary

Close the remaining behavioral divergences between the Go scanner and the authoritative Python reference (`../vhlocal/vhlocal/`), and build a **Go-only parity-behavior gate** that pins the Go engine's semantic output on a shared fixture to a committed expected projection authored from the reference code — no Python is executed (the operator judges final parity by recognition from their own Python runs). Priority order matches live-behavior impact: (US1) hunt over the model's partition plan; (US2) the parity-behavior gate; (US3) verification/publication fidelity; (US4) coverage/artifact/orchestration parity.

Technical approach (from research):
- **Partitions (US1)**: port `resolve_partitions` — parse the Phase-1 Subgraph-Partitions table → one corrective strict-JSON repartition (a bounded same-endpoint fresh-context call) → deterministic subsystem fallback; then coverage + threat-model augmentation; record source/fallback/collapsed/parse_error/uncovered. Wire the resolved partitions into `runHunt`.
- **Parity behavior gate (US2, Go-only)**: a **semantic response transcript** (rules keyed by phase + hunt partition/class + verify candidate-identity) replayed by a Go `transcriptProvider`. A Go **projector** reduces the run to a normalized semantic JSON (dispatch scope, candidate set by normalized identity, dispositions, tiers, coverage dispositions, handoffs/artifacts presence, run-status axes); a Go **comparator** asserts it equals a committed EXPECTED projection that encodes the reference methodology (authored from reading `../vhlocal/vhlocal/`, **not** a Python run). **No Python is executed** — per the operator, who judges final parity by recognition from their own Python runs. The reference code is read for behavior, never run.
- **Verification/publication fidelity (US3)**: enforce the complete containing-function evidence requirement, the authz route-guard entry-point match on a supported verdict, and extend the quality battery (SSTI-constant, access-control, class-primary evidence) + the distinct `reviewed` tier.
- **Coverage/artifacts (US4)**: resolve router/blueprint prefixes, websocket, and method defaults in the denominator; validate artifact manifests against supported candidates + on-disk files; port the hunt canary + budget cap.

## Technical Context

**Language/Version**: Go 1.23+ (module `vhlocal`). **No Python** — the reference repo `../vhlocal/vhlocal/` is READ for behavior, never executed (per operator; they judge parity by recognition).

**Primary Dependencies**: Standard library only for runtime (zero new runtime deps). No test-time Python dependency.

**Storage**: Filesystem artifacts. Additive-only schema (already declared in feature 005's `RunRecord`): populate `partition_source`, `partition_fallback`, `partition_parse_error`, `coverage_partitions_added`, `coverage_files_added`, `coverage_uncovered_remaining`, `threat_model_partitions`, `partition_collapsed`. No key removed/renamed.

**Testing**: `go test ./...`, hermetic and Go-only. The differential is a **Go parity-behavior test**: it drives the Go engine on a recorded transcript over `testdata/vulnapp` and asserts its semantic projection equals a committed EXPECTED projection authored from the reference code (documented as reference-derived, not a measured Python diff). **No live model, no Python — live validation is the operator's, by recognition.**

**Target Platform**: unchanged (Linux/macOS single binary).

**Performance Goals**: parity of behavior/evidence; the corrective repartition adds at most one bounded model call.

**Constraints**: preserve the static-only boundary, configured-endpoint routing, loopback/allow-root posture, three status axes, and feature-005 behaviors/tests; zero new runtime deps; the default gate stays hermetic (no Python required).

**Scale/Scope**: touches `internal/phases` (+ new `partition.go`), `internal/engine` (hunt wiring, verification fidelity, coverage), `internal/inventory` (denominator, deterministic partitions), `internal/consolidate` (quality battery, reviewed tier), `internal/verification` (function context, authz, artifact validation), and a new Go-only `tests/parity/` gate (transcript, Go provider, projector, comparator, expected golden authored from the reference code).

## Constitution Check

*GATE: Must pass before Phase 0. Re-check after Phase 1.*

Parity/verification feature — strengthens compliance; no gate fails.

| Principle | Effect |
|---|---|
| I. Evidence Integrity | **Strengthened.** Verdicts/tiers become reference-equal and *proven* by the harness; no fabricated parity claims. |
| II. Orthogonal Status | **Preserved/strengthened.** Partition source/fallback/uncovered recorded; coverage denominator faithful; status axes compared in the gate. |
| III. Static-Only Boundary (NON-NEGOTIABLE) | **Preserved.** No new tools; the corrective repartition is one fresh-context Chat to the same endpoint; the parity gate is Go-only/test-only. |
| IV. Provenance | **Preserved.** Partition-resolution provenance recorded. |
| V. Explicit AI Failure, No Silent Fallback (NON-NEGOTIABLE) | **Preserved/strengthened.** One bounded corrective repartition on the same endpoint, then a *recorded* deterministic fallback — never a silent narrowing. |
| VI. Resumable, Idempotent | **Preserved.** Deterministic projector; regeneration unaffected. |
| VII. Testable Coverage | **Directly served.** The Go-only parity-behavior gate makes reference-alignment testable offline; every divergence closed ships a failing-before test; default gate hermetic. |

**Safety & Technical Constraints**: Go runtime, zero new runtime deps, offline default gate — satisfied.

### Justified deviations (Complexity Tracking)

1. **Reference-derived expected golden (not a measured Python diff).** Per the operator, no Python is executed; the expected semantic projection is authored from reading the reference code and committed. Honest limit (documented in the golden's provenance + `tests/parity/README.md`): it encodes our faithful *reading* of the reference, so a mistaken reading would pass the Go gate but be caught by the operator's recognition on a live run — the operator is the final parity judge. Mitigation: the gate still pins behavior and prevents regressions; the golden is never presented as a live cross-check. Simpler alternative (run Python to measure the golden) rejected per the operator's explicit constraint.
2. **Semantic (not byte/ID-identical) comparison.** Candidate identity is a Go heuristic vs the reference AST digest; a strict ID diff would fail on a documented, intentional deviation. Mitigation: compare by normalized identity (location + CWE + normalized statement) and by disposition/tier/coverage semantics.
3. **Transcript keyed by semantic situation, not turn index.** So the same transcript exercises the intended dispatch/verdicts regardless of exact prompt wording.

### Post-Design Re-Check (after Phase 1)

Re-evaluated after research/data-model/contracts/quickstart: **still PASS.** No new runtime dependency; no Python executed anywhere (reference read only); additive-only schema (populating already-declared fields); the corrective repartition stays same-endpoint and bounded (III/V); the parity-behavior gate is offline and Go-only (VII). The three deviations above are the only ones and are mitigated. Ready for `/speckit-tasks`.

## Project Structure

### Documentation (this feature)

```text
specs/006-python-parity/
├── plan.md              # This file
├── research.md          # Phase 0 — R1..R7 decisions
├── data-model.md        # Phase 1 — entities + transcript + projection + schema
├── quickstart.md        # Phase 1 — offline validation incl. the differential command
├── contracts/
│   └── behavior.md      # Phase 1 — behavioral contracts C-* per story
└── tasks.md             # /speckit-tasks (not created here)
```

### Source Code (files this feature changes; grouped by story)

```text
# US1 — partition parity
internal/phases/partition.go       # new: parse table, parse_partition_json, resolve_partitions,
                                   #   augment_for_coverage, augment_from_threat_model, PartitionResolution
internal/inventory/inventory.go    # deterministic_partitions (subsystem partitions w/ routes), collapsed check
internal/engine/hunt.go            # dispatch over resolved partitions (not the deterministic-only list)
internal/engine/engine.go          # resolve partitions from phase1_output before phase 2; record source/flags;
                                   #   corrective repartition = one fresh-context Chat (like repairFromRaw)

# US2 — parity behavior gate (Go-only; no Python)
tests/parity/transcript/           # new: response-rule transcripts (JSON)
tests/parity/transcript_provider.go# new: Go provider replaying rules by (phase, partition/class, candidate-id)
tests/parity/project.go            # new: normalize a results dir → semantic projection JSON
tests/parity/compare.go            # new: normalize + diff two projections, name divergences
tests/parity/parity_behavior_test.go # new: run Go engine on the transcript; assert projection == expected golden
tests/parity/golden/               # new: committed EXPECTED projection, authored from the reference CODE
tests/parity/projctl/main.go       # new: Go helper to print a results dir's projection (authoring aid)

# US3 — verification & publication fidelity
internal/verification/verification.go # require complete containing-function evidence coverage
internal/verification/authz.go        # new (or reuse internal/authz): route-guard entry-point match
internal/consolidate/corroborate.go   # SSTI-constant + access-control + class-primary evidence
internal/consolidate/consolidate.go   # distinct `reviewed` tier from a validated review record

# US4 — coverage, artifacts, orchestration
internal/inventory/inventory.go    # router/blueprint prefixes, websocket, ROUTE-vs-GET method default
internal/verification/artifacts.go # new: validate_artifacts (entry↔supported candidate↔on-disk file)
internal/engine/hunt.go            # canary preflight + budget cap (where configured)
internal/engine/engine.go          # readHuntOutput corpus reconciliation (or record the justified divergence)
```

**Structure Decision**: No new runtime packages. The one substantial addition is the Go-only `tests/parity/` gate (Go provider + projector + comparator + a committed expected projection authored from the reference code). Partition logic lands in a new `internal/phases/partition.go`; the rest extends existing packages.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| Reference-derived expected golden (no Python) | Operator forbids running Python; the golden encodes a faithful reading of the reference | Running Python to measure the golden is rejected per operator; the operator is the final parity judge on a live run |
| Semantic (not raw-ID) comparison | Candidate identity is a Go heuristic vs reference AST — a documented deviation | A raw-ID diff is unachievable without an in-tree AST and would fail on intentional deviation |
| Transcript keyed by semantic situation | The two engines issue different prompt sequences | Turn-indexed / exact-prompt replay diverges across engines |
