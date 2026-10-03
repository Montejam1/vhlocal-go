---

description: "Task list for provider tool-call-parse recovery (no whole-run abort)"
---

# Tasks: Recover from provider tool-call-parse failures without aborting the scan

**Input**: Design documents from `/specs/004-ollama-toolparse-repair/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/behavior.md, quickstart.md

**Tests**: REQUIRED — constitution Principle VII + spec FR-013 + SC-007 + contracts/behavior.md. Each fix ships a regression test that fails on the pre-fix code and passes after (TDD-first within each story). **All validation is offline (fakes); no live model — live testing is the operator's.**

**Organization**: By user story — US1 provider tool-parse recovery (P1), US2 per-phase degrade-not-abort (P2), US3 deliverable-aware completion (P3). Grounded in the aborted run `…_2026-09-15-163205` (HTTP 500 "error parsing tool call" at phase 2b). Builds on feature 003's repair machinery. No artifact/API/schema changes.

## Format: `[ID] [P?] [Story] Description`
- **[P]** = different file, no dependency on an incomplete task.
- `internal/agent/agent.go` steps (T007, T013) are sequential (same file).

---

## Phase 1: Setup (shared test infrastructure)

- [X] T001 [P] Add offline fakes in `internal/client/testsupport/fake.go` and/or test helpers to reproduce: (a) an `httptest` server returning the exact Ollama tool-parse 500 body `{"error":"error parsing tool call: raw='…{\"pattern\":\"…\"}', err=…"}`; (b) a scripted provider that returns a `*client.TransportError{Kind:ToolParse, Raw:…}` on a chosen turn then valid turns; (c) an endpoint-recording provider (for C-A2). No network, no live model.

---

## Phase 2: Foundational (shared type — blocks US1)

- [X] T002 Extend `client.TransportError` in `internal/client/provider.go` with `Kind` (values `Generic` default | `ToolParse`) and `Raw string` (the model's intended output carried in the error). Not serialized; existing fields (`Backend,Endpoint,Status,Msg,Retryable`) unchanged (data-model §"Provider error classification").

**Checkpoint**: the classification type exists.

---

## Phase 3: User Story 1 — Scan survives a provider tool-call-parse error (P1) 🎯 MVP

**Goal**: an Ollama (or OpenAI-compatible) tool-call-parse rejection is recovered via fresh-context repair on the same endpoint instead of aborting.

**Independent Test**: offline fakes (T003, T006); the pre-fix code aborts, the fixed code repairs-and-continues.

- [X] T003 [US1] Write client classification tests in `internal/client/client_test.go` (fail pre-fix): C-P1 the `error parsing tool call` 500 → `TransportError{Kind:ToolParse}` with `Raw` from `raw='…'`; C-P2 ToolParse is `Retryable=false`, generic 5xx/429 stay `Retryable=true`; C-P3 connection-refused/401 → `Kind:Generic`; C-P4 OpenAI-compatible equivalent → `Kind:ToolParse`.
- [X] T004 [US1] In `internal/client/ollama.go` `doWithRetry`/response handling: when an HTTP 500 body contains `error parsing tool call`, return `TransportError{Kind:ToolParse, Raw:<extracted raw='…'>, Retryable:false}`; otherwise unchanged. Extract the single-quoted `raw='…'` payload (empty if absent) (FR-001, C-P1/P2).
- [X] T005 [P] [US1] In `internal/client/openai.go`: classify the OpenAI-compatible backend's tool/function-call parse error (4xx/5xx whose error indicates a tool-call parse failure) as `Kind:ToolParse` (best-effort `Raw`) (FR-001, C-P4).
- [X] T006 [US1] Write agent recovery tests in `internal/agent/agent_test.go` (fail pre-fix): C-A1 one ToolParse error (with recoverable `Raw`) then valid → repairs from `Raw`, continues, completes (`RepairSuccesses>=1`), no error returned; C-A2 repair `Chat` on the same endpoint (endpoint-recording fake); C-A3 persistent ToolParse → `tool_repair` after budget, returns nil error, AND the give-up is recorded on the result (`RepairAttempts` incremented, `RepairSuccesses` not; recorded give-up count reflects it) (FR-005); C-A4 a `Kind:Generic` transport error still propagates as an error.
- [X] T007 [US1] In `internal/agent/agent.go` `Run`: when `p.Chat` returns `*client.TransportError{Kind:ToolParse}`, invoke the existing fresh-context repair seeded from `te.Raw` (add a `repairFromRaw` wrapper around the current `repairToolCall` logic) on the same provider; on success dispatch the recovered call and continue; count under the same bounded repair budget; on budget exhaustion end `tool_repair` returning nil error (engine degrades the phase). A `Kind:Generic` error still returns as an error (FR-002/003/004/005, C-A1/A2/A3/A4).

**Checkpoint**: a tool-parse 500 mid-agent is recovered or degrades that agent gracefully; US1 tests green.

---

## Phase 4: User Story 2 — A per-phase endpoint failure degrades, not aborts (P2)

**Goal**: one phase's unrecoverable endpoint failure degrades that phase; the scan runs remaining phases and always finalizes artifacts.

**Independent Test**: offline (T008) with a generic-error fake; can be validated independently of US1.

- [X] T008 [US2] Write engine tests in `internal/engine/*_test.go` (fail pre-fix): C-E1 one phase's agent fails at the endpoint → engine records it degraded, runs remaining requested phases, finalizes the full artifact set; C-E2 failed phase appears in `coverage_degraded_reasons`, `execution_status` partial, distinct from clean; C-E3 a single-phase failure does NOT set `scan_meta.aborted`; C-E4 all phases fail → run reported failed/incomplete with endpoint error surfaced, lifecycle suppressed, not clean.
- [X] T009 [US2] In `internal/engine/engine.go` phase loop: on a per-phase agent error, record the phase as failed (do not add to `phases_completed`) and `continue` to the next requested phase instead of `rec.Aborted=…; break`; reserve `rec.Aborted` for cancellation and caller-level fatal only — never a single phase's endpoint failure (FR-006, C-E1/E3).
- [X] T010 [US2] In `internal/engine/helpers.go` `runFanOut`: apply the same per-partition degrade-not-abort — a partition's endpoint failure degrades that unit and the fan-out continues (FR-006).
- [X] T011 [US2] In `internal/engine/engine.go` `finalize` (+ `internal/consolidate/status.go` if needed): add `"phase <k> endpoint failure: <reason>"` to `coverage_degraded_reasons`, ensure `execution_status` reflects a partial/incomplete run, and confirm the all-phases-fail case is reported failed (not clean) with lifecycle suppressed (FR-008/009, C-E2/E4).

**Checkpoint**: broken-at-one-phase runs still deliver artifacts + honest status; US2 tests green; `tests/parity` passes.

---

## Phase 5: User Story 3 — Deliverable-aware completion (P3)

**Goal**: an agent that stops or times out without writing its declared deliverable is nudged; a phase counts produced only if the deliverable exists.

**Independent Test**: offline (T012).

- [X] T012 [US3] Write agent tests in `internal/agent/agent_test.go` (fail pre-fix): C-N1 an agent that would end `complete` with `DeliverablePath` set but no deliverable → one final write nudge → writes → `Produced` true; C-N2 the completion nudge fires at most once (no loop) and, if still no deliverable, the agent ends and the phase is reported not-produced.
- [X] T013 [US3] In `internal/agent/agent.go` `Run`: when the model stops calling tools (would end `complete`) but `DeliverablePath` is set and `Produced` is false, inject one final write nudge and continue the loop instead of returning; guard with a one-shot flag; complements the existing near-`MaxTurns` nudge (FR-010/011, C-N1/N2).

**Checkpoint**: recon/verify/report are more likely to write their deliverable; a phase is produced only when its file exists.

---

## Phase 6: Polish & cross-cutting

- [X] T014 [P] Run the full offline gate `go test ./...` (incl. `tests/parity/`) — all green; `go vet ./...` + `gofmt -l .` clean.
- [X] T015 [P] Add a CHANGELOG.md entry summarizing provider tool-parse recovery + per-phase degrade-not-abort + completion nudge.
- [X] T016 Confirm no artifact-filename / API-path / status-axis-field-name change (C-X1) via `tests/parity/` and a top-level-key diff of `findings.json`/`scan_meta.json` (`TransportError` is not serialized).
- [X] T016a [P] Preserved-invariant test (C-X2) in `internal/agent/agent_test.go`: a repair triggered by a ToolParse error issues only a `Chat` to the **same** provider/endpoint (endpoint-recording fake), invokes no shell/exec tool, and the recovered call resolves only within the sandbox roots — asserting Principles III/V hold on the new path (FR-012).
- [ ] T017 Operator-owned live validation (NOT executed by the harness): the operator re-runs the failed target/model to confirm SC-001..SC-006 on a live endpoint. Leave unchecked until the operator reports results.

---

## Dependencies & Execution Order

- **Setup (T001)** → **Foundational (T002)** → stories.
- **US1 (T003–T007)**: T003/T006 (tests) first; T004 (ollama), T005 (openai, `[P]`), then T007 (agent.go). MVP.
- **US2 (T008–T011)**: T008 (tests) first; T009→T011 sequential (`engine.go`), T010 (`helpers.go`) independent. Validatable with a generic-error fake independently of US1.
- **US3 (T012–T013)**: T012 (tests) first; T013 (`agent.go`) — sequential after T007 (same file).
- **Polish (T014–T017)** after the stories; T017 is operator-owned.

### Parallel opportunities
- T001 `[P]` at setup; T005 `[P]` vs T004 (different client files); T010 (`helpers.go`) can overlap US2's `engine.go` edits; T014/T015/T016a `[P]` in polish (T016a's `agent_test.go` is free once T007/T013 land). All `agent.go` edits (T007, T013) and all `engine.go` edits (T009, T011) serialize.

---

## Implementation Strategy

**MVP = US1** (T001–T007): the tool-parse 500 that aborted the run is recovered/degraded gracefully. **Then US2** (one phase failing no longer discards the whole scan) — independently testable. **Then US3** (deliverable nudge).

**Governance**: no constitution deviation (corrective; strengthens Principle V/II/VI). Every task carries or is covered by an offline regression test that fails pre-fix (SC-007). **The harness performs no live-endpoint calls; T017 live validation is the operator's.**

## Notes
- Reference oracle for pre-fix behavior: `~/vulnhunter-reports/vc-…fastapi_…_2026-09-15-163205/` (aborted at 2b).
- Reuse feature 003's `repairToolCall` — do not add a second repair mechanism (research R3).
- Honesty-critical (T009/T011): degrade and surface real endpoint failures; never hide a total outage as clean (Principle I/II).
