# Feature Specification: Recover from provider tool-call-parse failures without aborting the scan

**Feature Branch**: `004-ollama-toolparse-repair`

**Created**: 2026-09-15

**Input**: User description: "The last run ended in an endpoint failure, please investigate the error and provide a plan for resolution" → turn the investigation into a spec.

## Overview

A live scan aborted mid-run on a provider-side error. From the run record (`…_2026-09-15-163205/scan_meta.json`), the endpoint was reachable and phases 1, 1t, and 2 ran; the run then **aborted in phase 2b** with:

```
HTTP 500: {"error":"error parsing tool call:
  raw='We need to locate candidate findings output file(s). … Let's list the tree
       of that directory.{"pattern":"/home/.../**"}',
  err=invalid character 'W' looking for beginning of value"}
```

Root cause: the model (a `gpt-oss`-class model) emitted **reasoning prose immediately followed by tool-call JSON in one message**. The **provider's own** tool-call parser tried to parse the whole blob and returned **HTTP 500**. The harness currently treats that HTTP 500 as a fatal transport failure: it retries the *identical* request (which reproduces the same 500 because the same context regenerates the same blob), then aborts the **entire** run — even though phases 1–2 had already produced work and the model's intended action (a `Glob` with a `pattern`) is recoverable and is present verbatim inside the error body.

This is the exact case the harness's fresh-context tool-call repair exists for, but the current implementation wires repair only to the *client-side* path (when the harness itself receives a tool call whose arguments won't parse). A **provider-side** tool-parse HTTP 500 surfaces as a transport error and bypasses repair entirely.

This feature makes a provider tool-call-parse failure recoverable: route it through the existing fresh-context repair (using the model's intended action carried in the error), and — when a phase's endpoint interaction still cannot be salvaged — degrade that phase's coverage rather than aborting the whole scan, so later phases and the report still run and the outcome is reported honestly. It also closes a contributing reliability gap the same run showed: recon (phase 1) hit its turn limit without writing its deliverable.

This serves constitution Principles V (explicit AI failure, bounded same-endpoint recovery, no silent fallback), II (honest, orthogonal status), VI (resumable/graceful), and VII (testable, offline).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A scan survives a provider tool-call-parse error (Priority: P1)

An operator runs a scan against a local `gpt-oss`-class model that intermittently interleaves prose with tool-call JSON, causing the provider to reject the response with a tool-call-parse HTTP 500. The operator expects the harness to recover the model's intended action and continue the phase, not to abort the whole run.

**Why this priority**: This is the failure that aborted the run. Without it, one provider-side parse hiccup — a routine behavior of these models — throws away all prior phase work and yields nothing.

**Independent Test**: Offline, a fake provider returns the exact tool-call-parse HTTP 500 (body carrying the model's intended `Glob` action) on one turn, then valid turns. The agent repairs the intended call in a fresh context, dispatches it, and continues to completion; the run is not aborted.

**Acceptance Scenarios**:

1. **Given** the provider returns a tool-call-parse error (an HTTP 500 whose body indicates a tool-call parse failure and carries the model's raw intended output), **When** the agent processes it, **Then** the harness attempts a bounded fresh-context repair using the intended action extracted from the error, and on success dispatches the repaired call and continues the agent.
2. **Given** such an error, **When** the harness recovers, **Then** it does NOT naive-retry the identical request (which would reproduce the failure) and does NOT switch provider, endpoint, or model.
3. **Given** the repair budget is exhausted by repeated unrecoverable tool-call-parse errors, **When** the agent gives up, **Then** it ends gracefully (recorded as `tool_repair`) as degraded coverage — it does not crash or silently succeed.
4. **Given** a recovered run, **When** it finishes, **Then** the repair attempts and successes are recorded in the run record.

---

### User Story 2 - A per-phase endpoint failure degrades coverage but does not abort the whole scan (Priority: P2)

When one phase's interaction with the endpoint cannot be salvaged, the operator still wants the phases that already ran, the consolidated artifacts, and an honest report — not an all-or-nothing abort that discards completed work.

**Why this priority**: The aborted run had completed recon-adjacent phases and a hunt; aborting at 2b threw away the chance to consolidate and report what did run. Graceful degradation preserves value and honesty (Principles II, VI).

**Independent Test**: Offline, a phase's agent returns an unrecoverable endpoint failure; the engine records that phase as failed/degraded, then still runs the remaining requested phases it can, finalizes the artifact set, and marks the run degraded with the reason — rather than setting a whole-run `aborted` that stops everything.

**Acceptance Scenarios**:

1. **Given** a phase agent ends on an unrecoverable endpoint failure, **When** the scan continues, **Then** the engine records that phase as failed and proceeds to the remaining requested phases that can still run, and always finalizes the artifact set (findings.json, report, etc.).
2. **Given** such a run, **When** status is computed, **Then** the failed phase appears as a coverage-degradation reason, execution status reflects a partial run, and the run is not presented as clean.
3. **Given** a systemic endpoint outage (every phase fails at the endpoint), **When** the scan ends, **Then** the run is clearly reported as failed/degraded with the endpoint error surfaced, and no misleading "clean"/"all fixed" output is produced.

---

### User Story 3 - An agent that ends without its deliverable is prompted to produce it (Priority: P3)

An operator expects recon (and any phase with a required output) to actually write its deliverable. In the failed run, recon hit its turn limit without writing its attack-surface map, leaving the hunt to run blind.

**Why this priority**: Missing recon output degrades every later phase. It is a contributing reliability gap seen across recent runs, distinct from the endpoint error but worth closing together.

**Independent Test**: Offline, an agent that would otherwise end (by completing early or by hitting its turn limit) without having written its declared deliverable is prompted to write it; if it then writes a non-empty deliverable, the phase counts as produced; if not, the phase is honestly reported as not produced.

**Acceptance Scenarios**:

1. **Given** an agent nears its turn limit without having produced its declared deliverable, **When** it approaches the limit, **Then** it is prompted to write the deliverable to the exact path.
2. **Given** an agent ends its own turn (stops calling tools) without having produced its declared deliverable, **When** it signals completion, **Then** it is prompted once more to write the deliverable before the phase is finalized.
3. **Given** the agent still produces no deliverable, **When** status is computed, **Then** the phase is recorded as not produced and surfaced as a degradation reason (it is never marked produced on the basis of the agent merely stopping).

---

### Edge Cases

- **Provider returns a tool-call-parse error whose body does not carry a recoverable intended action**: repair is attempted with what is available; if it cannot recover, the agent ends gracefully as degraded, and the phase (not the whole run) is affected.
- **Repeated tool-call-parse errors within one agent**: bounded repair budget applies; then graceful per-agent end.
- **Genuine transport failure** (endpoint unreachable, auth error, connection refused): remains an explicit failure, recorded and surfaced; this feature does not silently swallow real outages — but a single phase's failure still degrades that phase rather than aborting the whole scan where later phases can still run.
- **The intended action in the error targets a path inside the sandbox** (e.g. listing the results directory): honored within the existing read/write confinement; nothing about repair widens the sandbox.
- **A tool-call-parse error on a paid/cloud backend**: repair is still bounded and same-endpoint; the budget/cost caps already in force still apply.
- **Recon that legitimately finds no attack surface**: distinct from recon that failed to write — the former is reported honestly (empty but produced), the latter as not produced.

## Requirements *(mandatory)*

### Functional Requirements

#### Recover from provider tool-call-parse failures (US1)

- **FR-001**: The system MUST distinguish a provider **tool-call-parse failure** (a response the provider rejected because it could not parse the model's tool call — e.g. an HTTP 500 whose body indicates a tool-call parse error) from a generic transport failure (unreachable, auth, timeout).
- **FR-002**: On a provider tool-call-parse failure, the system MUST extract the model's intended action carried in the error (the raw malformed output) and attempt a **bounded fresh-context repair** using it — the same repair mechanism used for client-side unparseable tool calls — rather than treating it as a fatal error.
- **FR-003**: The system MUST NOT recover from a tool-call-parse failure by naive-retrying the identical request (replaying the context reproduces the failure), and MUST NOT switch provider, endpoint, or model (Principle V). Bounded repair on the same endpoint is permitted.
- **FR-004**: A tool-call-parse failure that repair recovers MUST let the agent continue; one that repair cannot recover after the bounded budget MUST end the agent gracefully (recorded as a repair give-up) and count as degraded coverage — never a crash and never a silent success.
- **FR-005**: Repair attempts, successes, and give-ups arising from provider tool-call-parse failures MUST be recorded in the run record (Principle IV/diagnosability), consistent with existing repair accounting.

#### Per-phase failure degrades, not aborts (US2)

- **FR-006**: An unrecoverable endpoint failure in one phase MUST degrade that phase (recorded as failed, surfaced as a coverage-degradation reason) and MUST NOT, by itself, abort the entire scan when later requested phases can still run.
- **FR-007**: The system MUST always finalize the artifact set (consolidated findings, report, status, manifests) even when one or more phases failed at the endpoint, so completed work is preserved and the outcome is reported.
- **FR-008**: A run in which a phase failed at the endpoint MUST report a partial/degraded status with the endpoint failure named, and MUST remain clearly distinct from a clean run (no misleading clean/all-fixed output) — consistent with the existing honest-degraded-run behavior.
- **FR-009**: A genuine systemic endpoint outage (all phases fail) MUST still be reported as a failed run with the endpoint error surfaced; graceful per-phase degradation MUST NOT mask a total outage as a normal result.

#### Deliverable-aware agent completion (US3)

- **FR-010**: An agent with a declared required deliverable that ends — whether by reaching its turn limit or by stopping tool use — without having produced that deliverable MUST be prompted at least once to write it before the phase is finalized.
- **FR-011**: A phase MUST be counted as produced only when its deliverable actually exists and is non-empty (never on the basis of the agent merely stopping); when it does not exist, the phase MUST be reported as not produced and surfaced as a degradation reason.

#### Constraints preserved

- **FR-012**: All recovery MUST preserve the static-only safety boundary, the sandbox read/write confinement, the loopback/allow-root posture, and the no-silent-fallback rule; repair MUST contact only the operator-configured endpoint.
- **FR-013**: Every behavior above MUST be covered by an automated, offline test using a fake provider/transport that reproduces the failure mode (a tool-call-parse HTTP 500 carrying a recoverable intended action; an unrecoverable endpoint failure in one phase; an agent that stops without its deliverable), and each fix MUST add a regression test that fails without it (Principle VII). No live model is required.
- **FR-014**: No artifact filename, API path/shape, or status-axis field name changes; this feature changes engine/client *behavior* and the *content* of existing fields only.

### Key Entities

- **Provider error classification**: distinguishes tool-call-parse failures (repairable) from generic transport failures (real outages), carrying the model's intended action when present.
- **Tool-call repair attempt**: the existing bounded fresh-context recovery, now reachable from the provider-error path as well as the client-side dispatch path.
- **Phase outcome**: per-phase record (completed / failed-at-endpoint / repair-gave-up / produced-deliverable?) driving honest status and the report — extended so a per-phase endpoint failure is degradation, not whole-run abort.
- **Run status (three axes)**: execution / coverage / validation-mode, carrying the endpoint-failure degradation reasons.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In the offline suite, an agent given one tool-call-parse HTTP 500 (carrying a recoverable intended action) followed by valid turns runs to completion via repair; the run is not aborted.
- **SC-002**: A scan in which exactly one phase fails unrecoverably at the endpoint still finalizes the full artifact set and completes the other requested phases it can, rather than aborting at the failing phase.
- **SC-003**: A run with an endpoint-failed phase reports partial/degraded status with the endpoint failure named, and is distinguishable from a clean run on every status-bearing surface.
- **SC-004**: The identical request that produced a tool-call-parse failure is not blindly re-sent as the recovery path (verified by asserting the recovery is a fresh-context repair, not a replay).
- **SC-005**: A recon phase that hits its turn limit or stops without writing its deliverable is prompted to write it; if it still does not, the phase is reported as not produced (never as produced).
- **SC-006**: A systemic endpoint outage (all phases fail) is reported as a failed run with the endpoint error surfaced — never as clean or all-fixed.
- **SC-007**: 100% of the above ship with offline regression tests that fail before the fix and pass after; no live endpoint is used to validate.

## Assumptions

- **The recorded run (`…_2026-09-15-163205`) is representative**: the abort came from a provider-side tool-call-parse HTTP 500 whose body carried the model's intended action, on a reachable endpoint. The fix targets that class of failure.
- **The provider's tool-call-parse error is identifiable from the response** (status plus an error body indicating a tool-call parse problem, including the raw model output). If a given provider does not carry the raw intended action, repair proceeds with whatever the error provides and degrades gracefully if it cannot recover.
- **Reusing the existing repair mechanism** (feature 003) is preferred over a new one; this feature widens where that mechanism is triggered (the provider-error path) and how a phase failure is scoped (degrade, not abort).
- **Recon-failure policy remains continue-and-flag** (not fail-fast), consistent with prior features; US3 improves the odds recon produces its deliverable but does not make recon failure fatal.
- **Out of scope**: changing the models, prompts, or methodology; eliminating the model's prose-plus-JSON behavior at the source; per-agent parallelism. This is about surviving and honestly reporting the failure, not preventing the model from emitting it.
