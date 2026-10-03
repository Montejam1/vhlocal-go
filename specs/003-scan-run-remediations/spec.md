# Feature Specification: Scan-run reliability & honesty remediations

**Feature Branch**: `003-scan-run-remediations`

**Created**: 2026-09-15

**Input**: User description: "a test run has completed, the run failed, please review the report, determine the issues and create a list of remediations to be implemented in the code"

## Overview

A live scan of a real FastAPI target (`vc-claude-code-seeded-v2-logistics-dispatch-fastapi`) against `gpt-oss:120b` on a remote Ollama host completed but **produced zero findings and no usable deliverables** — a failed run. Reviewing the run's own records (`scan_meta.json`, `findings.json`, `SCAN_REPORT.md`) shows the failure is in the ported scan pipeline's resilience and in the honesty layers that report on it, not in the target:

- **Every model-facing agent that had to write a deliverable failed.** Recon (Phase 1) ended after **2 turns** with `stopped_reason: tool_repair`; Verify (2b) ended after **2 turns** `tool_repair`; Report (Phase 4) ended `tool_repair`; the Hunt agent ran to `max_turns` (80 turns) and wrote **nothing** to `results/`; Phases 3 and 3d also hit `max_turns`. Only the threat-model phase (1t) completed.
- **Consequence:** `phases_completed` = `["1t"]` only; `results/` is empty; there is no `phase1_output.md`, `phase2b_output.md`, `phase3_output.md`, `phase3d_output.md`, or `README.md`; the findings array is empty.
- **The honesty/reporting layers then misreported the broken run:**
  - `lifecycle` ballooned to ~56 KB by declaring essentially all of a prior run's findings **not_observed / "fixed"** — a broken run that finds nothing looks like it fixed everything.
  - `coverage_ledger` marked **61 of 100** entry points `reviewed_no_issue` even though the hunt produced no output — routes were counted as "reviewed" merely because their names appeared in text, overstating coverage.
  - `usage.calls` = **7** (one per agent) while ~296 model turns actually ran and consumed **4,037,367 prompt tokens** — the call count is wrong and the enormous prompt growth signals unbounded context.
  - The consolidated report shows "0 findings" with no prominent explanation that the pipeline failed, so a clean run and a broken run look nearly identical.

This feature specifies the remediations so that (a) a scan against a degrading local model actually completes its phases and produces findings, and (b) when it genuinely cannot, the run reports the failure loudly and truthfully rather than emitting misleading "clean"/"all fixed" output. It directly serves constitution Principles I (Evidence Integrity), II (Orthogonal/honest status), V (Explicit AI failure), VI (Resumable/idempotent), and VII (Testable).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A scan survives a degrading local model and produces output (Priority: P1)

An operator runs a full scan of a real repository against a local `gpt-oss`-class model. The model intermittently emits malformed tool-call JSON and drifts over long sessions (well-documented behavior). The operator expects the harness to recover from those hiccups — repair a malformed tool call, tolerate a recoverable tool error, and keep the agent working within a bounded context — so that recon, hunt, verify, reproduce, sweep, and report each run to completion and write their deliverables, yielding a real findings set.

**Why this priority**: This is the core failure. Without it, a live scan yields nothing — the tool does not do its one job. Every other remediation is about reporting on a run that this story makes succeed.

**Independent Test**: Re-run the same target/model. Recon writes `phase1_output.md`; the hunt writes per-agent output under `results/`; verify/report write their deliverables; `phases_completed` reflects the phases that actually produced valid output; the findings array is non-empty when candidates exist. Deterministic parts are exercised offline with a fake model that injects malformed tool calls and long transcripts.

**Acceptance Scenarios**:

1. **Given** a model that returns a malformed tool-call payload on a turn, **When** the agent processes it, **Then** the harness attempts a bounded, real repair of that tool call (in a minimal fresh context) and, on success, continues the agent rather than ending it.
2. **Given** a tool call with a recoverable problem (missing/renamed argument, unknown-but-aliasable tool name), **When** the agent dispatches it, **Then** the harness returns a corrective tool result and the agent continues on the next turn — this does NOT count toward ending the agent.
3. **Given** an agent runs many turns on a large repository, **When** its transcript would exceed the context budget, **Then** older/large tool outputs are pruned so prompts stay bounded and the model does not degrade from context overflow.
4. **Given** a hunt agent approaches its turn limit without having written its deliverable, **When** it nears `max_turns`, **Then** it is prompted to write its output, and any partial results it produced are captured rather than discarded.
5. **Given** recon, hunt, verify, reproduce, sweep, and report all run against a reachable model, **When** the scan finishes, **Then** each phase that produced a valid, non-empty deliverable is listed in `phases_completed`, and a findings set is produced when the hunt surfaced candidates.

---

### User Story 2 - A failed or degraded run reports the failure honestly (Priority: P2)

When a run genuinely under-delivers (agents fail, hunt produces nothing), the operator must be able to tell at a glance that the run is broken — not mistake an empty result for a clean codebase, and not be told that prior findings were "fixed" when this run simply found nothing.

**Why this priority**: Misreporting a broken run is a direct violation of the project's core honesty principles and is arguably worse than the failure itself. It must be fixed regardless of whether US1 fully lands.

**Independent Test**: Force a run in which recon and hunt produce no deliverables (fake model that never writes). The lifecycle block does NOT mark prior findings as fixed/not-observed; coverage does NOT count un-hunted routes as reviewed; the report prominently states the run under-delivered and which agents failed; `usage.calls` equals the real model-turn count.

**Acceptance Scenarios**:

1. **Given** a run whose execution status is `partial`/`incomplete` or whose hunt produced no output, **When** lifecycle reconciliation runs, **Then** it does NOT declare prior findings "fixed"/"not_observed"; instead it records that comparison was suppressed because the current run was unreliable, and the run does not emit a large false "fixed" list.
2. **Given** the hunt produced no per-agent output for a partition, **When** coverage dispositions are computed, **Then** its entry points are NOT marked `reviewed_no_issue` on the basis of a name appearing in unrelated text; an un-hunted route is `not_reviewed`.
3. **Given** a run in which one or more required-deliverable agents ended on `tool_repair`, `max_turns`, or wrote no output, **When** the report and `findings.json` status are produced, **Then** they prominently list those agent failures as coverage-degraded reasons and state that a zero-finding result reflects an incomplete run, not a clean target.
4. **Given** any run, **When** usage is recorded, **Then** `usage.calls` equals the number of model calls (turns) actually made, and token totals are attributable per phase/agent.
5. **Given** recon produced no `phase1_output.md`, **When** status is computed, **Then** "recon produced no attack-surface map" is recorded as a coverage-degradation reason and the run is not presented as having meaningfully covered the target.

---

### User Story 3 - The operator can diagnose why a run under-delivered (Priority: P3)

An operator looking at a failed run can quickly see, from the report and artifacts, which agents failed and why, so they can decide whether to re-run, switch models, raise limits, or resume.

**Why this priority**: Diagnosability turns an honest failure into an actionable one. It builds on US2's honest signals.

**Independent Test**: From a failed run's artifacts alone, a reader can enumerate each phase's outcome (completed / ended on tool_repair / hit max_turns / wrote nothing) and the run's three status axes, without reading source.

**Acceptance Scenarios**:

1. **Given** a completed run, **When** the operator opens the report, **Then** a per-phase outcome summary (phase, agent, turns, stop reason, produced-deliverable?) is visible.
2. **Given** repeated tool-call repairs or a circuit-breaker-style condition occurred, **When** the operator reads the run record, **Then** the counts of repairs/failures are recorded and surfaced.

---

### Edge Cases

- **Model emits malformed tool-call JSON repeatedly**: bounded real repair attempts; only after those genuinely fail does the agent end gracefully, and the ending is recorded as a degradation — not silently.
- **Model calls a tool with an unrecognized argument name or a known-alias tool name**: treated as recoverable (corrective tool result), not as a fatal parse failure.
- **Hunt agent hits `max_turns`**: it is nudged to write, partial output is salvaged, and the max_turns outcome is recorded and surfaced.
- **Recon fails entirely (no `phase1_output.md`)**: the run continues but is marked severely coverage-degraded; the hunt's fallback partitioning is flagged as operating without a recon map.
- **Prior report exists but the current run is partial/empty**: lifecycle comparison is suppressed (no false "fixed" list); the report says why.
- **Large repository, long transcripts**: context stays bounded via pruning; prompt-token growth per turn does not scale unboundedly with turn count.
- **A run that legitimately finds nothing on a clean target** (all phases completed, coverage complete): correctly reported as clean — distinct from a broken run.

## Requirements *(mandatory)*

### Functional Requirements

#### Agent resilience (US1)

- **FR-001**: On a malformed tool-call payload from the model, the system MUST attempt a bounded repair of that specific tool call in a minimal fresh context (tool schema + the parser error + the model's intended action), and on success continue the agent, rather than immediately ending it.
- **FR-002**: A recoverable tool problem (unparseable-but-repairable arguments after repair fails, a missing or renamed argument, or an unknown tool name that maps to a known tool) MUST be returned to the model as a corrective tool result so it can retry on the next turn, and MUST NOT by itself count toward ending the agent.
- **FR-003**: The agent MUST end early ("give up") only after the bounded repair mechanism has genuinely failed the allowed number of times on unrecoverable tool-call parse failures; the give-up threshold MUST be high enough that a single malformed turn does not kill an otherwise-productive agent (the observed 2-turn death of recon and verify MUST NOT recur under equivalent conditions).
- **FR-004**: The agent MUST keep its working context within a bounded budget across long sessions by pruning older or oversized tool outputs, so that per-turn prompt size does not grow unboundedly with turn count.
- **FR-005**: A fan-out (hunt) agent that approaches its turn limit without having written its deliverable MUST be prompted to write its output before the limit, and any partial well-formed output it produced MUST be captured rather than discarded.
- **FR-006**: The tool-name and tool-argument matching MUST accept the range of shapes a `gpt-oss`-class model produces (case-insensitive names, common aliases, and common argument-key synonyms) so that ordinary model variation is not treated as failure.

#### Honest reporting of degraded runs (US2)

- **FR-007**: Cross-run lifecycle reconciliation MUST be suppressed (and MUST NOT emit a "fixed"/"not_observed" list) when the current run is unreliable — i.e. execution status is not `complete`, or the hunt produced no output, or recon produced no map. In that case the lifecycle block MUST record that comparison was skipped and why.
- **FR-008**: Coverage dispositions MUST NOT mark an entry point `reviewed_no_issue` unless it was actually covered by a hunt unit that produced output; a name merely appearing in unrelated text MUST NOT count as "reviewed." Un-hunted entry points MUST be `not_reviewed`.
- **FR-009**: The consolidated report and `findings.json` run status MUST prominently surface, as coverage-degradation reasons, every required-deliverable agent that ended on `tool_repair`/`max_turns` or wrote no output, and MUST make clear that a zero-finding result from such a run reflects an incomplete scan, not a clean target.
- **FR-010**: When recon produced no attack-surface map (`phase1_output.md` absent), the run status MUST record that as a coverage-degradation reason and MUST NOT present the target as meaningfully covered.
- **FR-011**: The engine-recorded `usage.calls` MUST equal the number of model calls (turns) actually made across all agents, and token usage MUST remain attributable per phase/agent (Principle IV).
- **FR-012**: The distinction between a clean run (all requested phases complete, coverage complete, zero findings) and a broken run (phases failed / coverage degraded, zero findings) MUST be unambiguous on every status-bearing surface.

#### Diagnosability (US3)

- **FR-013**: The report MUST include a per-phase outcome summary (phase key, agent label, turns, stop reason, whether a valid deliverable was produced), derived from engine-recorded facts.
- **FR-014**: The system MUST record counts of tool-call repairs and agent give-ups per run, and surface them in the run record so an operator can gauge model instability.

#### Constraints preserved

- **FR-015**: All remediations MUST preserve the static-only safety boundary, no-silent-fallback behavior, loopback/allow-root posture, and offline-testability guarantees already in force; repair and pruning MUST NOT send data to any endpoint other than the operator-configured one.
- **FR-016**: Every remediation MUST be covered by an automated, offline test using a fake model/transport that reproduces the failure mode (malformed tool calls, long transcripts, no-write agents, partial runs), and each fix MUST add a regression test that fails without it (Principle VII).

### Key Entities

- **Agent run outcome**: per-agent record of phase, label, turns, stop reason, deliverable-produced, and repair/failure counts — the basis for honest status and the report's per-phase summary.
- **Tool-call repair attempt**: a bounded recovery of a malformed model tool call, recorded with its outcome.
- **Run status (three axes)**: execution / coverage / validation-mode — the surfaces that must distinguish clean from broken and carry degradation reasons.
- **Lifecycle reconciliation**: cross-run comparison that must be suppressed on unreliable runs.
- **Coverage ledger disposition**: per-entry-point review state that must reflect actual hunting, not textual mention.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On a re-run of the same target and model, recon produces a non-empty `phase1_output.md` and the hunt produces at least one non-empty file under `results/` — i.e. the two agents that died at 2 turns / wrote nothing now complete. (Verified live; the failure modes are reproduced offline with fakes.)
- **SC-002**: In the offline test suite, an agent given a single malformed tool call followed by valid turns runs to completion (does not end on repair), and an agent given persistent unrecoverable malformed calls ends gracefully only after the full bounded repair budget is exhausted.
- **SC-003**: Per-turn prompt size for a long agent session stays within a bounded budget — total prompt tokens grow sub-linearly with turn count rather than resending the full transcript every turn.
- **SC-004**: A run whose hunt produced no output reports zero entry points as falsely `reviewed_no_issue`; every un-hunted route is `not_reviewed`.
- **SC-005**: A partial/broken run emits no false "fixed"/"not_observed" lifecycle list; the lifecycle block instead states comparison was suppressed, and its size is bounded (no ~56 KB false-fixed dump).
- **SC-006**: `usage.calls` equals the summed model turns of all agents (not the agent count) for 100% of runs.
- **SC-007**: The report of a broken run visibly names every failed agent and states the run was incomplete; a reader can distinguish it from a clean zero-finding run without reading source or JSON.
- **SC-008**: 100% of the remediations ship with offline regression tests that fail before the fix and pass after.

## Assumptions

- **The recorded run is representative** of the ported engine's behavior against a live `gpt-oss:120b`; the fixes target the failure modes it exhibited (tool-call repair, context pruning, hunt output capture, honest degraded-run reporting), which correspond to known-hard local-model behaviors already anticipated in the port's research notes.
- **Recon failure does not abort the run.** The default remains to continue and report severe degradation (consistent with resumable/graceful operation), rather than fail-fast — but the degradation is made loud. (If fail-fast on recon is later preferred, that is a separate, explicit change.)
- **Bounded repair and context budgets reuse the values the methodology already assumes** (e.g. the existing per-tool output caps and phase turn limits); exact thresholds are implementation details chosen to keep prompts within the configured context window.
- **The target itself is out of scope**: this feature does not judge whether the FastAPI app is vulnerable; it ensures the harness can scan it and report truthfully.
- **No change to the interface contract**: artifact names, API shapes, and the three status axes are unchanged; this feature changes engine *behavior* and the *content/honesty* of existing fields, not their schema.
- **The prior `2026-09-14` run of the same target** is available as the lifecycle "prior report," which is why the broken run produced a large false "fixed" list; the fix must handle exactly this case.
