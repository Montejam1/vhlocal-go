# Data Model: Recover from provider tool-call-parse failures

**Feature**: 004-ollama-toolparse-repair | **Date**: 2026-09-15

No new artifacts and no artifact-schema change. New internal types + changed field *content* only. `TransportError` is an in-memory error, not serialized.

## Provider error classification (internal, `internal/client`)

`TransportError` gains:
- **Kind**: `Generic` (default — unreachable, auth, timeout, other non-parse failures) | `ToolParse` (the provider rejected the model's tool call as unparseable, e.g. Ollama HTTP 500 `error parsing tool call`).
- **Raw** string: the model's intended output carried in the error (Ollama's `raw='…'`); empty when the provider does not supply it.
- Existing fields unchanged: `Backend, Endpoint, Status, Msg, Retryable`.
- **Retryable semantics**: a `ToolParse` error is `Retryable=false` (replay reproduces it); generic 5xx/429 remain `Retryable=true` for the existing bounded same-endpoint retry.

## Extended repair trigger (internal, `internal/agent`)

- The existing bounded fresh-context repair (feature 003, `repairToolCall`) is reachable from **two** triggers now:
  1. client-side: a received tool call whose arguments are unparseable JSON (`kindUnrecoverable` dispatch) — unchanged;
  2. **provider-side (new)**: `p.Chat` returns `*TransportError{Kind:ToolParse}` → repair is seeded from `TransportError.Raw`.
- Both share one repair budget per agent; `Result.RepairAttempts`/`RepairSuccesses` count both. Give-up ends the agent `tool_repair` (graceful; nil error to the engine).
- Repair always targets the same provider/endpoint (Principle III/V).

## Phase outcome & run scoping (internal, `internal/engine`)

- **Per-phase endpoint failure** = an agent returning a non-recovered error (generic transport, or a `ToolParse` that exhausted repair → surfaced as `tool_repair`). It records:
  - the phase as **not completed** (absent from `phases_completed`),
  - a **coverage-degradation reason** naming the phase and the endpoint failure,
  - and the loop **continues** to the next requested phase (no whole-run abort/break).
- **`scan_meta.aborted`**: now set only for cancellation (and, optionally, a caller-level fatal); a single phase's endpoint failure does NOT set it.
- **finalize always runs** after the phase loop (already true) → the artifact set is always produced.
- **Systemic outage** (all model phases fail): falls out of per-phase degradation — `execution_status` becomes `incomplete`, every phase carries an endpoint-failure reason → reported as a failed run (never clean).

## RunStatus degraded reasons (expanded content)

Same field (`run_status.coverage_degraded_reasons: []string`); new reason strings:
- `"phase <k> endpoint failure: <short reason>"` (per phase whose agent failed unrecoverably at the endpoint),
plus the existing feature-003 reasons (recon-no-map, tool_repair/max_turns, empty-hunt, shallow-run). Execution status set by existing logic; these strings make the endpoint cause explicit.

## Deliverable-aware completion (internal, `internal/agent`)

- **Config.DeliverablePath** (existing) now drives two nudges: the near-`MaxTurns` nudge (feature 003) AND a **completion nudge** — when the model would end `complete` but the deliverable was not produced, inject one final write instruction and continue; one-shot guarded so it cannot loop.
- **Produced** remains: a phase is produced only when its deliverable file exists and is non-empty (report/`phases_completed` already derive from this — feature 003); never from the agent merely stopping.

## Preserved (unchanged schemas)

Artifact filenames, API paths/shapes, the three status-axis field names, and `agents[]` fields are unchanged. This feature changes engine/client behavior and the *content* of existing fields only.
