# Contract: Behavioral contracts for the remediations

No API path, artifact filename, or field-schema changes. These are the observable behavior contracts the remediations must satisfy — each is asserted by an offline test (Principle VII).

## Agent loop (`internal/agent`)

- **C-A1 (repair, not premature death)**: Given a provider that returns one malformed tool-call payload followed by valid turns, `Run` completes with `StoppedReason == complete` and `RepairAttempts >= 1`, `RepairSuccesses >= 1`. It MUST NOT end on `tool_repair`.
- **C-A2 (recoverable ≠ giveup)**: Given tool calls with a missing/renamed argument or an aliasable tool name, the agent receives a corrective tool result and continues; such turns never move the agent toward `tool_repair`.
- **C-A3 (bounded giveup)**: Given a provider that emits unrecoverable malformed tool JSON every turn and whose repairs also fail, `Run` ends `tool_repair` only after the repair budget is exhausted (not after 2 turns), with `RepairAttempts == budget`.
- **C-A4 (context bound)**: Given a long-running agent on large tool outputs, the estimated size of the message list sent each turn stays under the derived budget; total prompt bytes/tokens grow sub-linearly with turn count (no full-transcript resend every turn).
- **C-A5 (write nudge)**: Given a fan-out agent nearing `MaxTurns` without a deliverable, a write instruction is injected; if the model then writes a non-empty file, the deliverable exists and the phase counts as produced.
- **C-A6 (repair stays on-endpoint)**: The repair `Chat` uses the same provider/endpoint as the agent; no other endpoint is contacted (Principle III/V).

## Usage / provenance (`scan_meta.json`)

- **C-U1**: `usage.calls == sum(agent.turns) + repair_calls` for the run (SC-006). Never the agent count.
- **C-U2**: `usage.prompt_tokens` / `completion_tokens` remain the true per-turn accumulated totals (unchanged meaning).
- **C-U3 [G1]**: each `scan_meta.agents[]` entry carries its own `prompt_tokens`/`completion_tokens`, and their sum across agents equals the run-level totals — usage is attributable per phase/agent (FR-011 clause b).

## Coverage (`coverage_ledger.json`)

- **C-C1**: With an empty hunt (no `results/*.md`), zero routes are `reviewed_no_issue`; all enumerated routes are `not_reviewed`; `complete == false`.
- **C-C2**: A route is `reviewed_no_issue` only if its file/partition is in the hunted set (from actual hunt output). `finding_emitted` still wins for a route with a finding at its file.

## Run status (`findings.json.run_status`, SARIF, report)

- **C-S1**: If recon produced no `phase1_output.md`, `coverage_degraded_reasons` contains a recon-no-map reason and `coverage_status == degraded`.
- **C-S2**: Each required-deliverable agent that ended on `tool_repair`/`max_turns` or wrote nothing appears as a distinct degradation reason.
- **C-S3**: A broken zero-finding run and a clean zero-finding run are distinguishable on every status-bearing surface (execution status + reasons + report banner).

## Lifecycle (`findings.json.lifecycle`)

- **C-L1 (suppression)**: On an unreliable run (execution not complete, or empty hunt, or no recon map), the lifecycle block has `comparison_status == "suppressed_unreliable_run"`, all counts 0, all lists empty, and no `fixed`/`not_observed` entries — even when a prior report exists. Block size is bounded (SC-005).
- **C-L2 (reliable unchanged)**: On a reliable run, lifecycle reconciliation behaves exactly as today (new/persisting/regressed/not_observed).

## Report (`SCAN_REPORT.md/.html`)

- **C-R1**: A per-phase outcome table (phase, agent, turns, stop reason, produced?) is present, derived from `scan_meta.agents`.
- **C-R2**: On an unreliable run, a prominent banner states the run was incomplete, lists reasons, and clarifies that 0 findings ≠ clean target. Absent on a clean run.

## Preserved invariants

- **C-P1**: Artifact filenames, API paths/shapes, and the three status-axis field names are unchanged.
- **C-P2**: Static-only boundary, no silent provider/model fallback, loopback/allow-root posture, and `go test ./...` offline all still hold.

## Acceptance
The existing `tests/parity/` guard still passes (artifact set + findings.json blocks unchanged in shape), and the new regression tests (C-A*, C-U1, C-C1, C-L1, C-S*, C-R*) pass after the fixes and fail before them.
