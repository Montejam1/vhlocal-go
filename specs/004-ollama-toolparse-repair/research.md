# Phase 0 Research: Recover from provider tool-call-parse failures

**Feature**: 004-ollama-toolparse-repair | **Date**: 2026-09-15

Decisions resolving the plan's choices. Each: **Decision / Rationale / Alternatives**. Grounded in the aborted run `…_2026-09-15-163205` and the current code.

---

## R1. Classify the provider tool-call-parse failure

- **Decision**: Add `Kind` to `client.TransportError` with values `Generic` (default) and `ToolParse`, plus a `Raw string` field for the model's intended output. In `internal/client/ollama.go`, when an HTTP 500 body matches the provider's tool-call-parse signature (contains `error parsing tool call`), set `Kind=ToolParse` and populate `Raw` from the `raw='…'` segment. Do the same in `internal/client/openai.go` for the OpenAI-compatible backend's equivalent (a 400/500 whose error indicates a tool-call/function-call parse failure).
- **Rationale**: The failure is semantically a malformed tool call the *provider* rejected, not an outage — but it currently surfaces as an opaque transport error and bypasses repair. A typed classification lets the agent route it to repair while leaving genuine outages fatal.
- **Alternatives**: String-match the error at the agent layer (leaks provider quirks into the agent; the client already owns transport semantics). Rejected. A brand-new error type (more churn than extending `TransportError`). Rejected.
- **Extraction**: parse the `raw='…'` (single-quoted) payload out of the Ollama body; if absent, `Raw` stays empty and repair proceeds with the phase context only, degrading gracefully if it cannot recover.

## R2. Do not naive-retry a tool-parse failure

- **Decision**: A `ToolParse` error is marked NOT replay-retryable (the current `doWithRetry` retries 5xx twice; replaying the identical request regenerates the same prose+JSON blob and the same 500). Generic 5xx/429 keep their bounded same-endpoint retry.
- **Rationale**: Observed: the abort came after the retry already failed for exactly this reason. Repair (fresh context) is the correct recovery, not replay (Principle V permits bounded same-endpoint repair, not a doomed replay loop).
- **Alternatives**: Keep retrying (wastes turns, still fails). Rejected.

## R3. Route ToolParse errors into the existing fresh-context repair

- **Decision**: In `internal/agent/agent.go`, when `p.Chat` returns a `*TransportError{Kind:ToolParse}`, invoke the existing repair mechanism seeded with `te.Raw` as the model's malformed output (a `repairFromRaw` entry point wrapping the current `repairToolCall` logic): a minimal fresh-context `Chat` (schema + "your previous tool call was rejected as unparseable" + the raw + writable-root hint) on the **same** provider. On success, dispatch the repaired call and continue the agent loop; count it under the same bounded repair budget as feature 003. On budget exhaustion, end the agent gracefully (`tool_repair`) — returning nil error so the engine degrades the phase, not aborts the run.
- **Rationale**: This is precisely the R14 mechanism; it already exists for client-side unparseable args. Widening its trigger to the provider-error path is the minimal, consistent fix and reuses tested code.
- **Alternatives**: A separate provider-parse recovery path (duplicates logic, diverges). Rejected.

## R4. Degrade per phase instead of aborting the whole scan

- **Decision**: In the engine phase loop (`engine.go`) and `runFanOut` (`helpers.go`), an unrecoverable endpoint failure from an agent records that phase as failed (a coverage-degradation reason + the agent's stop reason) and **continues to the next requested phase** instead of setting a whole-run `aborted` and breaking. `finalize` already runs after the loop, so the artifact set is always produced. `scan_meta.aborted` is reserved for cancellation and is no longer set by a single phase's endpoint failure.
- **Rationale**: The aborted run had completed recon-adjacent phases and a hunt; aborting at 2b discarded the chance to consolidate/report. Per-phase degradation preserves work and honesty (Principles II, VI). Later phases that depend on the failed one will simply find its deliverable missing and degrade in turn — reported, not hidden.
- **Alternatives**: Keep whole-run abort (loses work, the current bug). Fail-fast only on systemic outage (harder to define mid-run; the degrade-per-phase model naturally yields an incomplete/failed run when everything fails). Rejected the abort; the systemic case falls out of per-phase degradation (FR-009) via execution status.
- **Systemic outage**: when every model phase fails at the endpoint, execution status is `incomplete` and every phase carries an endpoint-failure reason → reported as a failed run (SC-006), not clean.

## R5. Deliverable-aware completion nudge

- **Decision**: In `agent.go`, when the model stops calling tools (would end `complete`) but `DeliverablePath` is set and the deliverable was not produced, inject one final "write your deliverable to <path> now" nudge and continue the loop instead of returning; guard with a one-shot flag so it cannot loop. This complements the existing near-max_turns nudge (feature 003) by also covering *premature* completion.
- **Rationale**: In the failed run recon hit max_turns without writing its map; in the prior run recon ended "complete" at turn 27 without writing. Both leave the hunt blind. A completion-time nudge closes the premature-stop case; the phase still counts produced only if the file lands (FR-011).
- **Alternatives**: Auto-synthesize the deliverable (fabrication — violates Principle I). Rejected. Make recon failure fatal (contradicts the continue-and-flag policy). Rejected.

## R6. Testing (offline, no live model)

- **Decision**: Fakes drive every path:
  - a provider returning the exact `error parsing tool call: raw='…{"pattern":"…"}'` HTTP 500 once, then valid → agent repairs from raw and continues (C-P*/C-A*);
  - a provider whose tool-parse 500 recurs unrecoverably → agent ends `tool_repair`, phase degraded, run still finalizes (C-A*/C-E*);
  - a per-phase generic transport failure → that phase degrades, later phases run, artifacts finalized (C-E*);
  - all-phases-fail → run reported failed/incomplete, not clean (C-E*);
  - an agent that stops without its deliverable → completion nudge → deliverable written / else reported not-produced (C-N*).
- **Rationale**: Principle VII / FR-013 / SC-007; and the operator has asked that live testing be theirs.

---

## Resolved unknowns

All Technical Context items resolved; no `NEEDS CLARIFICATION` remains. No new dependencies; no constitution deviation.
