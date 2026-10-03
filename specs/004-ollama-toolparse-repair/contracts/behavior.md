# Contract: Behavioral contracts for provider tool-call-parse recovery

No API path, artifact filename, or field-schema change. Observable behavior contracts, each asserted by an offline test with a fake provider (Principle VII). **No live model.**

## Provider error classification (`internal/client`)

- **C-P1**: An Ollama HTTP 500 whose body contains `error parsing tool call` is returned as `*TransportError{Kind: ToolParse}` with `Raw` populated from the `raw='…'` segment. A 500 without that signature stays `Kind: Generic`.
- **C-P2**: A `ToolParse` error is `Retryable=false` (not blindly replayed); generic 5xx/429 remain retried by the existing bounded same-endpoint retry.
- **C-P3**: A genuine transport failure (connection refused, 401/403, timeout) is `Kind: Generic` and is NOT misclassified as `ToolParse`.
- **C-P4**: The OpenAI-compatible backend classifies its equivalent tool/function-call parse error as `ToolParse` too (best-effort; `Raw` may be empty).

## Agent recovery (`internal/agent`)

- **C-A1**: Given `Chat` returns `*TransportError{Kind:ToolParse, Raw:"…{\"pattern\":\"…\"}"}` once, then valid turns, the agent performs a fresh-context repair seeded from `Raw`, dispatches the recovered call, and continues to completion (`RepairAttempts>=1`, `RepairSuccesses>=1`); it does NOT return an error.
- **C-A2**: The repair `Chat` targets the same provider/endpoint as the agent (Principle III/V) — asserted with an endpoint-recording fake.
- **C-A3**: Given a `ToolParse` error that recurs unrecoverably, the agent ends `tool_repair` after the bounded repair budget and returns **nil error** (so the engine degrades the phase, not aborts the run).
- **C-A4**: A `Kind:Generic` transport error is returned as an error (real outage), not silently swallowed.

## Engine per-phase degradation (`internal/engine`)

- **C-E1**: When one phase's agent fails unrecoverably at the endpoint, the engine records that phase failed, **continues to the remaining requested phases**, and finalizes the full artifact set (findings.json, SCAN_REPORT.*, sarif, manifests).
- **C-E2**: The failed phase appears as a `coverage_degraded_reasons` entry naming the phase + endpoint failure; `execution_status` is partial/incomplete; the run is distinct from a clean run.
- **C-E3**: A single phase's endpoint failure does NOT set `scan_meta.aborted` (reserved for cancellation).
- **C-E4**: When ALL model phases fail at the endpoint, the run is reported failed/incomplete with the endpoint error surfaced — never clean/all-fixed (SC-006); lifecycle is suppressed (unreliable run, per feature 003).

## Deliverable-aware completion (`internal/agent`)

- **C-N1**: An agent that would end `complete` with `DeliverablePath` set but the deliverable not produced receives one final write nudge and continues; if it then writes a non-empty file, `Produced` is true.
- **C-N2**: The completion nudge fires at most once (no loop); if the deliverable is still not produced, the agent ends and the phase is reported not-produced (never produced on the basis of stopping).

## Preserved invariants

- **C-X1**: Artifact filenames, API paths/shapes, and status-axis field names unchanged; `TransportError` is not serialized.
- **C-X2**: Static-only boundary, sandbox confinement, loopback/allow-root posture, and no silent provider/model fallback all still hold; repair contacts only the configured endpoint.

## Acceptance
The existing `tests/parity/` guard and the full offline suite pass; the new contracts (C-P*, C-A*, C-E*, C-N*) pass after the fixes and fail before them. The reference oracle for pre-fix behavior is run `…_2026-09-15-163205` (aborted at 2b).
