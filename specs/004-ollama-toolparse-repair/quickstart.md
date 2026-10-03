# Quickstart & Validation: Provider tool-call-parse recovery

**Feature**: 004-ollama-toolparse-repair | **Date**: 2026-09-15

Reproduce the abort, then validate the fix — **entirely offline**. Contracts: [contracts/behavior.md](./contracts/behavior.md); entities: [data-model.md](./data-model.md).

> Live validation is the operator's. These scenarios use fakes and never contact an inference endpoint.

## Prerequisites
- Go 1.23+ (`export PATH=$PATH:/usr/local/go/bin`).
- Reference oracle for pre-fix behavior: `~/vulnhunter-reports/vc-…-fastapi_VULNHUNT_RESULTS_gptoss120b_2026-09-15-163205/` (aborted at 2b).

## The bug, from the aborted run's record
```bash
D=~/vulnhunter-reports/vc-…-fastapi_VULNHUNT_RESULTS_gptoss120b_2026-09-15-163205
python3 -c "import json;print(json.load(open('$D/scan_meta.json'))['aborted'])"
# endpoint failure: ... HTTP 500: {"error":"error parsing tool call: raw='We need to ... {\"pattern\":\"...\"}', err=invalid character 'W' ...}
python3 -c "import json;d=json.load(open('$D/scan_meta.json'));print('phases_completed:',d['phases_completed'])"
# ['2']  — aborted at 2b; phases 3/3d/4 never ran; whole run discarded
```

## Offline validation (the gate — no model, no network)

```bash
go test ./...
```

Targeted scenarios (each maps to a contract):

1. **Classification (C-P1/P2/P3)** — `internal/client/client_test.go`: an httptest server returns the exact `error parsing tool call: raw='…{"pattern":"…"}'` 500 → client returns `TransportError{Kind:ToolParse, Raw:…, Retryable:false}`; a plain 500 → `Kind:Generic, Retryable:true`; connection-refused/401 → `Kind:Generic`.
2. **Agent recovery (C-A1/A2/A3/A4)** — `internal/agent/agent_test.go`: one ToolParse error then valid → repairs from `Raw`, continues, completes; repair on the same endpoint; persistent ToolParse → `tool_repair`, nil error; generic transport error → propagates.
3. **Per-phase degrade (C-E1/E2/E3)** — `internal/engine/*_test.go`: one phase's agent fails at the endpoint → engine records it degraded, runs remaining phases, finalizes artifacts; no `scan_meta.aborted`; status partial + reason present.
4. **Systemic outage (C-E4)** — every phase fails → run reported failed/incomplete, endpoint error surfaced, lifecycle suppressed, not clean.
5. **Completion nudge (C-N1/N2)** — an agent that stops without its deliverable is nudged once; writes → produced; still doesn't → reported not-produced.

Expected: all pass after the fixes; each fails on the pre-fix code (SC-007). `tests/parity/` still passes (no schema change).

## Live validation (operator-run, later)
When you choose to test live, re-run the same target/model and confirm SC-001..SC-006: a tool-call-parse 500 mid-run is recovered (or degrades that phase) instead of aborting the whole scan; completed phases + report are always produced; a total outage is reported as failed. The harness does not initiate this — you do.

## Done criteria (→ Success Criteria)
- [ ] SC-001 one ToolParse 500 (recoverable) → repaired, run not aborted
- [ ] SC-002 one phase fails → full artifact set + other phases still run
- [ ] SC-003 endpoint-failed phase → partial/degraded, distinct from clean
- [ ] SC-004 recovery is fresh-context repair, not identical-request replay
- [ ] SC-005 recon that stops/times-out without deliverable → nudged; else reported not-produced
- [ ] SC-006 all-phases outage → reported failed, error surfaced
- [ ] SC-007 every fix has an offline regression test that failed pre-fix
