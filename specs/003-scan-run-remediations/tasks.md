---

description: "Task list for scan-run reliability & honesty remediations"
---

# Tasks: Scan-run reliability & honesty remediations

**Input**: Design documents from `/specs/003-scan-run-remediations/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/behavior.md, quickstart.md

**Tests**: REQUIRED — constitution Principle VII + spec FR-016 + SC-008 + contracts/behavior.md. Each fix ships a regression test that fails on the pre-fix code and passes after (TDD-first within each story).

**Organization**: By user story — US1 agent resilience (P1), US2 honest degraded reporting (P2), US3 diagnosability (P3). Grounded in the failed run `..._2026-09-15-113555`. No artifact/API/schema changes — engine *behavior* and field *content* only. Incorporates `/speckit-analyze` remediations G1 (per-agent tokens), G2 (repair-on-endpoint test), T1 (strict `Reliable` gating), I1 (alias file location).

## Format: `[ID] [P?] [Story] Description`
- **[P]** = different file, no dependency on an incomplete task.
- Most US1 work is in `internal/agent/agent.go` (+ `agent_test.go`) so those steps are sequential, not `[P]`.

---

## Phase 1: Setup (shared test infrastructure)

- [X] T001 [P] Extend the offline fake-provider support in `internal/client/testsupport/fake.go` with helpers to script: (a) a malformed tool-call payload on chosen turns, (b) a valid fresh-context repair response, (c) never-writes-deliverable behavior, (d) large tool-triggering transcripts, and (e) **an endpoint-recording provider that captures the endpoint of every `Chat` call** (for the C-A6 repair-on-endpoint test). No network, no live model (Principle VII).

---

## Phase 2: Foundational (shared vocabulary — blocks US1 impl and US2/US3 reads)

- [X] T002 Extend `agent.Result` with `RepairAttempts`, `RepairSuccesses`, and `Produced` fields, and add the tool-dispatch tri-state type `dispatchResult{Kind: ok|recoverable|unrecoverable, Content string}` in `internal/agent/agent.go` (data-model §"Tool-dispatch result" / §"Agent Result"). Keep `StoppedReason` values unchanged (`complete|max_turns|tool_repair|cancelled`).
- [X] T003 [P] In `internal/engine/record.go`: add run-level `repair_attempts`/`giveups` counters to the run record AND add per-agent `prompt_tokens` (int) + `completion_tokens` (int) fields to `AgentRecord` — additive, no existing field renamed/removed (FR-011 clause b [G1], FR-014; data-model §"RunRecord additions").

**Checkpoint**: shared outcome vocabulary exists — stories can proceed.

---

## Phase 3: User Story 1 — Scan survives a degrading model and produces output (P1) 🎯 MVP

**Goal**: recon/hunt/verify/report actually complete and write deliverables against a model that emits malformed tool calls and long transcripts.

**Independent Test**: offline fakes (T004); live re-run (T018) shows non-empty `phase1_output.md` and `results/` output.

- [X] T004 [US1] Write US1 regression tests in `internal/agent/agent_test.go` (fail pre-fix): C-A1 malformed-then-valid → `complete` with `RepairSuccesses>=1` (not `tool_repair`); C-A2 recoverable (missing/renamed arg, alias tool name) → continues, no give-up; C-A3 persistent unrecoverable → `tool_repair` only after the repair budget (not 2 turns); C-A4 long transcript → per-turn message size stays bounded; C-A5 write-nudge near `MaxTurns` → non-empty deliverable produced; **C-A6 [G2] the repair `Chat` targets the SAME provider/endpoint as the agent — using the endpoint-recording fake (T001e), assert no other endpoint is contacted (Principle III/V).**
- [X] T005 [US1] Make `dispatch` return the tri-state (T002) in `internal/agent/agent.go`: unparseable-JSON args → `unrecoverable`; missing/renamed arg or unknown-but-aliasable tool → `recoverable` (corrective tool result, agent continues); broaden case-insensitive tool names + argument-key synonyms in `canonicalTool`/`firstStr` **here in `agent.go` (not `internal/tools`) [I1]** (FR-002/006, C-A2).
- [X] T006 [US1] Implement bounded fresh-context tool-call repair on `unrecoverable` in `internal/agent/agent.go`: a minimal `Chat` (tool schema + parser error + the model's malformed output + writable-root grounding hint) **on the SAME provider/endpoint the agent already uses** (never another — C-A6); on success dispatch the repaired call and continue; end (`tool_repair`) only after the repair budget of consecutive failures; a success resets the counter; record `RepairAttempts`/`RepairSuccesses` (FR-001/003, C-A1/A3/A6). Recoverable results never count toward give-up.
- [X] T007 [US1] Add context pruning before each `Chat` in `internal/agent/agent.go`: when the estimated message-list size (byte-based) exceeds a budget derived from `NumCtx`, prune oldest/largest tool-result messages (never the system prompt or original task), leaving an elision marker (FR-004, C-A4).
- [X] T008 [US1] Add the write-before-`max_turns` nudge and partial-output salvage for fan-out hunt agents in `internal/agent/agent.go` (nudge injection) and `internal/engine/helpers.go` `runFanOut` (ensure a non-empty hunt file counts as produced) (FR-005, C-A5).

**Checkpoint**: agents complete and write output under a degrading model; US1 tests green.

---

## Phase 4: User Story 2 — A failed/degraded run reports honestly (P2)

**Goal**: a broken run is never presentable as clean or as "all prior findings fixed"; coverage and usage are truthful.

**Independent Test**: force no-deliverable runs offline (T009) and assert the honesty contracts.

- [X] T009 [US2] Write US2 regression tests (fail pre-fix): `internal/engine/engine_test.go` — usage.calls == sum(turns)+repairs (C-U1) AND each `agents[]` entry carries non-zero `prompt_tokens`/`completion_tokens` summing to the run totals (C-U3 [G1]); empty-hunt run → 0 `reviewed_no_issue`, all `not_reviewed` (C-C1); recon-no-map + failed agents → `coverage_degraded_reasons` populated and clean-vs-broken distinct (C-S1/2/3); `internal/lifecycle/lifecycle_test.go` — two-run sequence, broken second run → suppressed block, no `fixed` dump (C-L1), reliable run unchanged (C-L2), **and a reliable-but-coverage-degraded run STILL reconciles (not suppressed) [T1]**.
- [X] T010 [US2] Fix usage accounting in `internal/engine/helpers.go`: `recordAgent`/`addUsage` add the agent's `Turns` (+ repair calls) to `usage.calls` (not `+1` per agent), and record that agent's `RepairAttempts`/`RepairSuccesses` and its `prompt_tokens`/`completion_tokens` onto its `AgentRecord`; run-level token totals unchanged and equal to the sum of per-agent totals (FR-011, C-U1/C-U3 [G1]).
- [X] T011 [US2] Gate coverage `reviewed_no_issue` on actual hunting: build the hunted-file/partition set from `results/*.md` output in `internal/engine/engine.go` `finalize`, and change `internal/inventory/inventory.go` `BuildLedger`/`disposition` to require membership in that set (not any-corpus name match); empty hunt → all `not_reviewed` (FR-008, C-C1/2).
- [X] T012 [US2] Compute the degraded-reason taxonomy + run-reliability predicate in `internal/engine/engine.go` `finalize` and thread reasons through `internal/consolidate/status.go` `ComputeRunStatus`: recon-no-map, per-agent `tool_repair`/`max_turns`/no-output, empty-hunt (data-model §"RunStatus degraded reasons"); define `Reliable = execution complete AND hunt produced output AND recon produced a map` (FR-009/010/012, C-S1/2/3).
- [X] T013 [US2] Add `lifecycle.Suppressed(reason)` in `internal/lifecycle/lifecycle.go` (block with `comparison_status:"suppressed_unreliable_run"`, all counts 0, empty lists) and gate reconciliation in `internal/engine/engine.go` `reconcileLifecycle` on the **strict `Reliable` predicate from T012 — NOT on `coverage_status=="degraded"` [T1]** (a reliable run with degraded coverage MUST still reconcile normally). No `fixed`/`not_observed` list on unreliable runs (FR-007, C-L1/L2, SC-005; data-model §"Run reliability").

**Checkpoint**: broken runs report truthfully; US2 tests green; `tests/parity` still passes.

---

## Phase 5: User Story 3 — Diagnose why a run under-delivered (P3)

**Goal**: the report makes each phase's outcome and the run's brokenness obvious.

**Independent Test**: report tests (T014) assert the table + banner presence/absence.

- [X] T014 [US3] Write report regression tests in `internal/report/report_test.go` (fail pre-fix): per-phase outcome table present with per-agent tokens (C-R1); broken-run banner + reasons shown on an unreliable run and ABSENT on a clean run (C-R2).
- [X] T015 [US3] Render a "Per-phase outcome" section (phase key, agent label, turns, stop reason, produced?, and per-agent prompt/completion tokens [G1]) in `internal/report/report.go` from `scan_meta.agents` — Markdown and self-contained HTML (FR-013, C-R1).
- [X] T016 [US3] Render the broken-run banner near the top in `internal/report/report.go` when the run is unreliable — "N of M phases produced output; 0 findings reflects an incomplete scan, not a clean target," listing degradation reasons; surface repair/give-up counts; absent on a clean run (FR-012/014, C-R2).

**Checkpoint**: a failed run is self-diagnosing from its artifacts alone.

---

## Phase 6: Polish & cross-cutting

- [X] T017 [P] Run the full offline gate `go test ./...` (incl. `tests/parity/`) — all green; confirm no regression in the standing artifact/honesty guard.
- [X] T018 Live re-run validation per `quickstart.md`: `./bin/vhlocal run --repo ~/Research/vc-claude-code-seeded-v2-logistics-dispatch-fastapi` against the real `gpt-oss:120b`; confirm SC-001..SC-007 (recon+hunt produce output; `usage.calls` ≈ turns; per-agent tokens present; broken runs self-report). Record outcomes.
- [X] T019 [P] Add a CHANGELOG.md entry summarizing the reliability + honesty remediations.
- [X] T020 Confirm no artifact-filename / API-path / status-axis-field-name change (C-P1) — assert via `tests/parity/` and a diff of `findings.json`/`scan_meta.json` top-level keys against a pre-fix run (per-agent token fields are additive to `agents[]`).

---

## Dependencies & Execution Order

- **Setup (T001)** → **Foundational (T002, T003)** → stories.
- **US1 (T004–T008)**: T004 (tests) first; then T005→T006→T007→T008 sequential (all in `agent.go`; T008 also touches `engine/helpers.go`). US1 is the MVP.
- **US2 (T009–T013)**: T009 (tests) first; T010 (helpers), T011 (engine+inventory), T012 (engine+status), T013 (lifecycle+engine). T011/T012/T013 all edit `engine/engine.go` → keep sequential; T013 depends on T012's `Reliable` predicate. T010 is independent (`helpers.go`) but consumes the T003 `AgentRecord` token fields. US2 can be validated with fakes before US1 is finished.
- **US3 (T014–T016)**: T014 (tests) first; T015→T016 sequential (`report.go`). Reads `scan_meta.agents` (now incl. per-agent tokens) + reliability signal from US2 (T012); land after T012.
- **Polish (T017–T020)** after the targeted stories.

### Parallel opportunities
- T001 and T003 are `[P]` (different files) alongside early work.
- Across stories once Foundational is done: US1 (`agent.go`), US2's T010 (`helpers.go`), and US3 test-writing touch mostly different files and can overlap; the `engine/engine.go` edits (T008 salvage, T011, T012, T013) must serialize.
- T017 and T019 are `[P]` in polish.

---

## Implementation Strategy

**MVP = US1** (T001–T008): the scan actually produces output against a live degrading model — the core failure. Validate offline (T004) then live (T018).

**Then US2** (honesty) — arguably ship alongside US1 since misreporting is a Principle-I violation; it's independently testable with fakes even before US1 lands.

**Then US3** (diagnosability) — builds on US2's reliability signal.

**Governance**: no constitution deviation (the feature is corrective); no amendment needed. Every task carries or is covered by an offline regression test that fails pre-fix (SC-008).

## Notes
- The failed run `~/vulnhunter-reports/vc-...fastapi_..._2026-09-15-113555/` is the reference oracle for pre-fix behavior.
- Honesty-critical changes (T011, T012, T013, T016) must not fabricate — they remove false claims and surface real ones (Principle I/II).
- **[T1] critical distinction**: `Reliable` (lifecycle-suppression trigger) is stricter than `coverage_status=="degraded"`. A reliable run may have degraded coverage and MUST still reconcile lifecycle. Gate suppression on `Reliable` only.
- Keep `[P]` honest: same-file edits serialize; verify tests fail before implementing each fix.
