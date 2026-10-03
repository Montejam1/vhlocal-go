# Implementation Plan: Scan-run reliability & honesty remediations

**Branch**: `003-scan-run-remediations` | **Date**: 2026-09-15 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/003-scan-run-remediations/spec.md`

## Summary

Fix the ported Go scan pipeline so a live scan against a degrading `gpt-oss`-class model actually completes its phases and produces findings, and — when it genuinely cannot — reports the failure truthfully instead of emitting misleading "clean"/"all fixed" output. The work is entirely within the existing Go engine; no interface, artifact schema, or API shape changes. Two behavior clusters:

1. **Agent resilience** (`internal/agent`, `internal/tools`): replace the stub "give up after 2 malformed tool calls" with a real bounded tool-call repair in a minimal fresh context; classify tool problems as recoverable (corrective tool result, agent continues) vs. unrecoverable-parse (repair, then bounded give-up); add context pruning so long sessions stay within the window; nudge a fan-out agent to write before `max_turns` and salvage partial output; broaden tool-name/arg matching.
2. **Honest degraded-run reporting** (`internal/engine`, `internal/consolidate`, `internal/inventory`, `internal/lifecycle`, `internal/report`): compute per-agent failure signals and surface them as coverage-degradation reasons; suppress cross-run lifecycle reconciliation on unreliable runs (no false "fixed" dump); only mark an entry point `reviewed_no_issue` when it was actually hunted; fix `usage.calls` to count model turns; add a per-phase outcome summary to the report.

Grounded in a real failed run (`..._2026-09-15-113555`): recon/verify/report died at `tool_repair` (2 turns), the hunt hit `max_turns` writing nothing (4,037,367 prompt tokens), `phases_completed=["1t"]`, lifecycle emitted a ~56 KB false-"fixed" list, coverage marked 61/100 routes reviewed with no hunt output, and `usage.calls=7` for ~296 real turns.

## Technical Context

**Language/Version**: Go 1.23+ (existing module `vhlocal`).

**Primary Dependencies**: Standard library only (no new deps). Changes touch `internal/agent`, `internal/tools`, `internal/engine`, `internal/consolidate`, `internal/inventory`, `internal/lifecycle`, `internal/report`, and their tests. Repair reuses the existing `client.Provider` interface (a minimal extra `Chat` call in a fresh context — same endpoint, never a different one).

**Storage**: Filesystem artifacts unchanged (same names/schemas). Content of existing fields changes: `scan_meta.usage.calls`, `run_status.coverage_degraded_reasons`, `coverage_ledger` dispositions, the `lifecycle` block (suppressed form), and the report body (new per-phase summary + broken-run banner).

**Testing**: `go test ./...`, fully offline. New fakes drive the failure modes: a provider that injects malformed tool-call JSON then valid turns; one that never writes; one that emits long transcripts; a two-run sequence for the lifecycle-suppression case. Regression tests fail before each fix, pass after (Principle VII).

**Target Platform**: unchanged (Linux/macOS single binary).

**Performance Goals**: bound per-turn prompt growth — total prompt tokens grow sub-linearly with turn count (the observed 4M-token blow-up must not recur). No wall-clock target beyond "hunt completes and writes."

**Constraints**: preserve the static-only boundary (repair/pruning add no new tool and touch only the configured endpoint), no silent provider/model fallback, loopback/allow-root posture, and offline testability. No change to artifact filenames, API paths/shapes, or the three status axes.

**Scale/Scope**: focused bug-fix across ~7 internal packages; ~16 functional requirements; the target repo (a real FastAPI app, ~100 entry points) is the live validation case, reproduced offline with fakes.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

This feature is **corrective toward the constitution** — it fixes violations the failed run exposed. All principles are strengthened; no gate fails.

| Principle | Effect |
|---|---|
| I. Evidence Integrity (NON-NEGOTIABLE) | **Strengthened.** Stops the pipeline from emitting a false "all prior findings fixed" list and from counting un-hunted routes as reviewed; a zero-finding broken run is no longer presentable as clean. FR-007–FR-010, FR-012. |
| II. Orthogonal Status Reporting | **Strengthened.** Agent failures (tool_repair/max_turns/no-deliverable, recon-no-map) become explicit coverage-degradation reasons on every surface; execution/coverage/validation axes stay independent. FR-009, FR-010, FR-013. |
| III. Static-Only Safety Boundary (NON-NEGOTIABLE) | **Preserved.** No new tool; repair adds only a fresh-context `Chat` to the same endpoint; pruning is local. FR-015. |
| IV. AI Result Provenance | **Strengthened.** `usage.calls` becomes the true model-turn count; repair calls and counts are recorded. FR-011, FR-014. |
| V. Explicit AI Failure, No Silent Fallback | **Strengthened.** Bounded same-endpoint repair (permitted) replaces a silent premature give-up; give-ups and repairs are recorded and surfaced; no alternate provider/model. FR-001–FR-003, FR-014. |
| VI. Resumable, Idempotent Operations | **Preserved.** Deliverable-validity still gates `phases_completed`; salvaged partial output must still be valid to count. FR-005. |
| VII. Testable Acceptance & Regression Coverage | **Directly served.** Every remediation ships an offline regression test that fails before the fix (FR-016; SC-008). |

**Safety & Technical Constraints**: Go runtime (constitution v1.1.0), stdlib-only, offline tests — all satisfied. **Gate outcome: PASS**, no deviations, no Complexity Tracking needed.

### Post-Design Re-Check (after Phase 1)

Re-evaluated after research.md, data-model.md, contracts/behavior.md, and quickstart.md: **still PASS.** The design adds no dependency and no new artifact/API surface (data-model confirms only content/computation changes to existing fields). Repair is a bounded same-endpoint `Chat` (Principle V-compliant, III-safe); pruning is local; lifecycle suppression and coverage-gating remove false claims (Principle I/II); `usage.calls` correction restores provenance accuracy (IV); every contract (C-A*, C-U*, C-C*, C-S*, C-L*, C-R*) is offline-testable with fakes (VII). No principle is weakened; no Complexity Tracking required.

**Remediations folded in (from `/speckit-analyze`):**
- **G1** — FR-011 clause (b) "token usage attributable per phase/agent" is now designed: `AgentRecord` gains `prompt_tokens`/`completion_tokens` (data-model §"RunRecord additions"); `recordAgent` populates them. This makes the design satisfy the *existing* FR-011 (no spec change needed).
- **G2** — the repair-stays-on-same-endpoint safety contract (C-A6, Principle III/V) is called out for explicit testing in `agent_test.go`.
- **T1** — lifecycle suppression is gated on the strict **`Reliable`** predicate, explicitly NOT on `coverage_status=="degraded"` (data-model §"Run reliability" clarifies the two are distinct thresholds).
- **I1** — the tool-alias change is correctly located in `internal/agent/agent.go` (no `internal/tools` change), per the corrected file map above.

Ready for `/speckit-tasks` (re-run to regenerate `tasks.md` with the G1/G2/T1 task-level edits).

## Project Structure

### Documentation (this feature)

```text
specs/003-scan-run-remediations/
├── plan.md              # This file
├── research.md          # Phase 0 — repair/pruning/coverage/lifecycle/usage decisions
├── data-model.md        # Phase 1 — behavioral entities (agent outcome, degraded reasons, tool-dispatch result)
├── quickstart.md        # Phase 1 — offline reproduction + validation scenarios
├── contracts/
│   └── behavior.md      # Phase 1 — behavioral contracts for the changed fields/report section
└── tasks.md             # /speckit-tasks (not created here)
```

### Source Code (files this feature changes)

```text
internal/agent/agent.go            # real repair loop; recoverable vs unrecoverable dispatch;
                                   #   context pruning; write-before-max_turns nudge; repair/give-up counts;
                                   #   broaden tool-name/argument-key aliases (canonicalTool/firstStr live HERE,
                                   #   not in internal/tools) — [I1]
internal/agent/agent_test.go       # + regression tests for each failure mode, incl. C-A6 repair-on-same-endpoint
internal/engine/helpers.go         # usage.calls counts turns(+repairs); recordAgent records per-agent
                                   #   prompt/completion tokens + repair counts; agent-failure signals — [G1]
internal/engine/engine.go          # finalize: compute degraded reasons (failed agents, recon-no-map),
                                   #   gate lifecycle on the strict Reliable predicate (NOT coverage_status) — [T1],
                                   #   pass hunted-file set to coverage
internal/inventory/inventory.go    # disposition: reviewed_no_issue only when actually hunted
internal/consolidate/status.go     # accept/propagate agent-failure degradation reasons
internal/lifecycle/lifecycle.go    # Suppressed() block for unreliable runs
internal/report/report.go          # per-phase outcome summary + broken-run banner
internal/engine/record.go          # RunRecord: run-level repair/give-up counts AND per-agent
                                   #   prompt_tokens/completion_tokens on AgentRecord (satisfies FR-011 clause b) — [G1]
tests/parity/…                     # extend the standing artifact/honesty guard if needed
```

**Structure Decision**: No new packages. Changes are surgical edits to the existing engine/agent/consolidation layers plus their tests, keeping the one-engine-shared-by-CLI-and-server invariant. The only cross-cutting new concept is a small **agent-outcome / degraded-reason vocabulary** threaded from the agent loop through the run record into status, coverage, lifecycle, and the report.

## Complexity Tracking

No constitution violations; no entries required.
