# Phase 0 Research: Scan-run reliability & honesty remediations

**Feature**: 003-scan-run-remediations | **Date**: 2026-09-15

Decisions that resolve the plan's open choices. Each: **Decision / Rationale / Alternatives**. All grounded in the failed run and the current code.

---

## R1. Tool-dispatch result classification

- **Decision**: Change `dispatch` (in `internal/agent`) to return a tri-state instead of a bool: `ok` (tool ran), `recoverable` (a corrective tool result the model can act on — missing/renamed arg, unknown-but-aliasable tool, tool error), or `unrecoverable` (the arguments could not be parsed as JSON at all). Only `unrecoverable` feeds the repair/give-up path; `recoverable` returns an error tool-result and the agent continues.
- **Rationale**: The root cause of recon/verify dying at 2 turns is that `dispatch` returns "malformed=true" for *both* unparseable JSON and ordinary recoverable problems, and two of those in a row kills the agent. A missing arg or an odd tool name is normal model behavior and must not end the run.
- **Alternatives**: Keep a bool but only set it for parse failures — works but loses the ability to record recoverable-error counts; the tri-state is clearer and testable.

## R2. Real tool-call repair (fresh context)

- **Decision**: On an `unrecoverable` tool call, perform a bounded repair: issue a **separate `Chat` in a minimal fresh context** containing only (a) the tool schema, (b) the parser error, and (c) the model's own malformed output (which carries the intended path/content), plus a grounding hint (the writable results root). If the repair returns a well-formed tool call, dispatch it and continue the main agent. Do NOT resend the large main transcript (replaying it reproduces the garbage). Repair uses the same provider/endpoint (Principle V permits bounded same-endpoint repair).
- **Rationale**: This is the R14 mechanism the port under-implemented. `gpt-oss` degrades by emitting invalid tool JSON deep in a session; repairing in a small context recovers the intended action (especially a Write whose path/content are in the malformed blob) without re-triggering the failure.
- **Alternatives**: Re-prompt in the full context (reproduces the failure); skip the turn (loses the intended write); a JSON-repair library (adds a dependency and can't recover a truncated path the way a grounded model re-emit can). Rejected.

## R3. Give-up threshold and counting

- **Decision**: The agent ends early only after the repair mechanism has failed on `attemptsAllowed` consecutive unrecoverable calls (default small, e.g. 2 *repair* failures — not 2 malformed turns). A successful repair resets the counter. Recoverable errors never increment it. Record `RepairAttempts` and `Giveups` on the agent result.
- **Rationale**: The observed failure was "2 malformed turns → dead." The fix makes the budget about *failed repairs*, so a single malformed turn that repairs successfully costs nothing, and a productive agent survives normal model noise.
- **Alternatives**: Unbounded repair (risks infinite loops / cost); a per-run global budget (harder to reason about per-agent). Bounded-per-agent chosen.

## R4. Context pruning

- **Decision**: Before each `Chat`, if the estimated token size of the message list exceeds a budget derived from `num_ctx` (e.g. keep prompts under a safe fraction of the window), prune the oldest/largest *tool-result* messages (never the system prompt or the original task), replacing pruned content with a short elision marker. Keep the most recent turns intact.
- **Rationale**: The hunt ran 80 turns and accumulated 4,037,367 prompt tokens because every turn resends the full growing transcript; past ~`num_ctx` the model silently truncates and degrades, which is why it never wrote output. Bounding the context keeps the model coherent and lets it reach a Write.
- **Alternatives**: Summarize old turns via the model (extra calls, cost, non-determinism); hard message-count cap (crude but simple — acceptable fallback). Token-estimate pruning of tool results is the primary approach; a message-count cap is the simple floor.
- **Estimation**: token count is approximated from byte length (no tokenizer dependency); the goal is bounding, not exactness.

## R5. Write-before-max_turns nudge + partial salvage

- **Decision**: When a fan-out (hunt) agent reaches a high fraction of `MaxTurns` without having produced its deliverable, inject a user message instructing it to write its findings to the exact output path now. Independently, the engine already gates `phases_completed` on a valid non-empty deliverable, so any well-formed partial output that lands under `results/` is naturally captured; ensure the deliverable-validity check treats a non-empty hunt file as produced.
- **Rationale**: The hunt hit `max_turns` writing nothing. A late nudge converts exploration into at least one written artifact; salvage ensures partial work isn't discarded.
- **Alternatives**: Auto-write a synthesized file on the agent's behalf (fabricates content — violates Principle I); rejected. The nudge asks the *model* to write what it found.

## R6. usage.calls counts model turns

- **Decision**: `addUsage`/`recordAgent` MUST add the agent's turn count (plus any repair calls) to `usage.calls`, not `+1` per agent. `calls` then equals total model calls across the run.
- **Rationale**: Observed `calls=7` for 7 agents while ~296 turns ran — a provenance error (Principle IV). Token totals were already correct (accumulated per turn in the agent); only the call counter was wrong.
- **Alternatives**: none; this is a straight correctness fix.

## R7. Coverage "reviewed_no_issue" criterion

- **Decision**: An entry point is `reviewed_no_issue` only when the file/partition it belongs to was actually **hunted** — i.e. it appears in the set of files a hunt agent produced output about (the `results/*.md` corpus specifically), not merely mentioned in any results-dir text (which includes `threat_model.md`, `phase1_output.md`, etc.). Pass the engine a hunted-file/partition set built from actual hunt outputs; if the hunt produced nothing, no route is `reviewed_no_issue`.
- **Rationale**: The run marked 61/100 routes `reviewed_no_issue` though `results/` was empty — because the disposition heuristic scans the whole corpus for a name match. That massively overstates coverage on a broken run.
- **Alternatives**: Require a per-route explicit disposition from the hunt (ideal but depends on the model emitting one reliably); as an interim, gating on real hunt output is a strict improvement and deterministic.

## R8. Lifecycle suppression on unreliable runs

- **Decision**: The engine computes a `reliable` predicate for the run — true only when execution status is `complete` AND the hunt produced output AND recon produced a map. When not reliable, the engine does NOT call `lifecycle.Reconcile`; instead it emits a `lifecycle.Suppressed(reason)` block: `{has_prior, comparison_status:"suppressed_unreliable_run", reason, new:0, persisting:0, not_observed:0, ...empty lists, fixed_keys:[]}`. No "fixed"/"not_observed" list is produced.
- **Rationale**: The broken run compared its 0 findings against a prior report and declared essentially everything "fixed" (~56 KB). A run that found nothing because it broke has no basis to claim anything was fixed (Principle I).
- **Alternatives**: Still reconcile but flag it (a reader may still be misled and the huge list persists); suppress only the list but keep counts (counts would still imply "all fixed"). Full suppression with a clear reason chosen.

## R9. Degraded-reason taxonomy

- **Decision**: `finalize` derives coverage-degradation reasons from engine facts and feeds them to `ComputeRunStatus`:
  - recon produced no `phase1_output.md` → `"recon produced no attack-surface map"`.
  - any required-deliverable agent ended on `tool_repair` → `"phase <k> agent gave up on tool-call errors"`.
  - any hit `max_turns` without a deliverable → `"phase <k> agent hit max_turns without output"`.
  - hunt produced no `results/` output → `"hunt produced no candidates (pipeline incomplete, not a clean result)"`.
  These join the existing shallow-run signals; all appear in `run_status.coverage_degraded_reasons`, SARIF invocation notifications, and the report.
- **Rationale**: FR-009/010/012 — make a broken run legible on every surface and distinct from a clean one.
- **Alternatives**: a single generic "degraded" flag (less actionable). Reason strings chosen for diagnosability.

## R10. Report per-phase summary + broken-run banner

- **Decision**: Add a "Per-phase outcome" section to `SCAN_REPORT.md/.html` rendered from `scan_meta.agents` (phase, label, turns, stop reason, produced?). When the run is unreliable, add a prominent banner near the top: "⚠ Incomplete run — N of M phases produced output; 0 findings here reflects an incomplete scan, not a clean target," listing the degradation reasons.
- **Rationale**: FR-013 + FR-012; the empty report currently looks like a clean pass.
- **Alternatives**: only JSON (operators read the HTML/MD first). Both surfaces get it; the summary derives from engine facts (Principle I).

## R11. Recon-failure policy (resolved default)

- **Decision**: Continue the run after recon failure (do not fail-fast), but mark it severely coverage-degraded (R9) and flag that the hunt's fallback partitioning ran without a recon map. This matches the spec's Assumptions and the resumable/graceful posture.
- **Rationale**: Fail-fast would discard the threat-model and any later value and complicate resume; loud degradation preserves honesty without throwing away partial work.
- **Alternatives**: fail-fast on recon (simpler signal, but less resumable and discards work) — deferred as a possible future opt-in.

## R12. Testing approach

- **Decision**: Offline fakes in the agent and engine tests reproduce each failure mode:
  - malformed-then-valid provider → agent completes (no premature give-up); repair path exercised.
  - persistently-unrecoverable provider → agent ends only after the repair budget, with recorded counts.
  - long-transcript provider → pruning keeps prompt size bounded (assert on message list / estimated size).
  - never-writes provider over phases → engine marks failed agents, suppresses lifecycle, no false coverage, banner present.
  - two-run sequence with a prior report but a broken second run → lifecycle suppressed, no "fixed" dump.
  - `usage.calls == sum(turns)` asserted.
- **Rationale**: Principle VII / FR-016 / SC-008 — every fix has a regression test that fails before it.

---

## Resolved unknowns

All Technical Context items resolved; no `NEEDS CLARIFICATION` remains. No new dependencies, no constitution deviations.
