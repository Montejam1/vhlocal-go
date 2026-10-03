# Quickstart & Validation: Scan-run reliability & honesty remediations

**Feature**: 003-scan-run-remediations | **Date**: 2026-09-15

How to reproduce the failure, then validate the fixes. Offline scenarios are the gate; the live scenario confirms against the real model. Shapes/contracts: [contracts/behavior.md](./contracts/behavior.md); entities: [data-model.md](./data-model.md).

## Prerequisites
- Go 1.23+ (`export PATH=$PATH:/usr/local/go/bin`).
- The failed run for reference: `~/vulnhunter-reports/vc-claude-code-seeded-v2-logistics-dispatch-fastapi_VULNHUNT_RESULTS_gptoss120b_2026-09-15-113555/`.
- For the live check only: the same target repo + a reachable `gpt-oss:120b` (e.g. `VHLOCAL_OLLAMA_HOST=http://192.168.6.214:11434`).

## The bug, from the failed run's own records (baseline)
```bash
D=~/vulnhunter-reports/vc-...-fastapi_VULNHUNT_RESULTS_gptoss120b_2026-09-15-113555
python3 -c "import json;d=json.load(open('$D/scan_meta.json'));[print(a['label'],a['turns'],a['stopped_reason']) for a in d['agents']]"
#   1 2 tool_repair   | 1t 56 complete | hunt:backend 80 max_turns | 2b 2 tool_repair | 3 80 max_turns | 3d 60 max_turns | 4 16 tool_repair
python3 -c "import json;d=json.load(open('$D/scan_meta.json'));print('calls',d['usage']['calls'],'prompt_tokens',d['usage']['prompt_tokens'])"   # 7 / 4,037,367
python3 -c "import json;d=json.load(open('$D/findings.json'));print('findings',len(d['findings']),'lifecycle_bytes',len(json.dumps(d['lifecycle'])))"  # 0 / ~56000
python3 -c "import json;d=json.load(open('$D/coverage_ledger.json'));print(d['counts'])"  # reviewed_no_issue:61 with empty results/
```

## Offline validation (the gate — no model, no network)

Run the whole suite:
```bash
go test ./...
```

Targeted scenarios (each maps to a contract in behavior.md):

1. **Repair, not premature death (C-A1)** — fake provider: malformed tool call, then valid turns → `Run` returns `complete`, `RepairSuccesses>=1`, not `tool_repair`. `internal/agent/agent_test.go`.
2. **Recoverable ≠ giveup (C-A2)** — missing-arg / aliased-tool calls → corrective tool result, agent continues.
3. **Bounded giveup (C-A3)** — persistently unrecoverable → ends `tool_repair` only after the repair budget (not 2 turns).
4. **Context bound (C-A4)** — long transcript → per-turn message size stays under budget (assert estimated size / that old tool results were pruned).
5. **Write nudge (C-A5)** — hunt fake that only writes when nudged → deliverable exists; phase counts as produced.
6. **usage.calls (C-U1)** — after a multi-turn run, `usage.calls == sum(turns)+repairs`.
7. **Coverage honesty (C-C1/2)** — engine run with empty hunt → 0 `reviewed_no_issue`, all `not_reviewed`. `internal/inventory` / engine test.
8. **Lifecycle suppression (C-L1)** — two-run sequence: reliable run writes findings; a second, broken run (empty hunt) with the prior present → lifecycle `comparison_status=suppressed_unreliable_run`, no `fixed` list, small block. `internal/lifecycle` + engine test.
9. **Degraded reasons + banner (C-S1/2/3, C-R1/2)** — engine run where recon/hunt produce nothing → `coverage_degraded_reasons` names recon-no-map + failed agents; report has the per-phase table and the broken-run banner; a clean run has neither. `internal/engine` + `internal/report` tests.

Expected: all pass after the fixes; each fails on the pre-fix code (SC-008). The standing `tests/parity/` guard still passes (no schema change).

## Live validation (confirms against the real model)
```bash
export PATH=$PATH:/usr/local/go/bin VHLOCAL_OLLAMA_HOST=http://192.168.6.214:11434
make build
./bin/vhlocal run --repo ~/Research/vc-claude-code-seeded-v2-logistics-dispatch-fastapi
```
Expect (SC-001..SC-007): `phase1_output.md` non-empty; ≥1 non-empty file under `results/`; `phases_completed` reflects phases that produced output; `usage.calls` ≈ total turns (not 7); if findings exist they populate `findings.json`/report; if the run still under-delivers, the report **says so** (banner + per-phase table) and lifecycle is suppressed rather than emitting a false "fixed" list.

## Done criteria (→ Success Criteria)
- [ ] SC-001 recon + hunt produce output on the live re-run
- [ ] SC-002 repair survives one malformed call; bounded giveup on persistent failure
- [ ] SC-003 per-turn prompt size bounded (sub-linear growth)
- [ ] SC-004 no false `reviewed_no_issue` when hunt is empty
- [ ] SC-005 no false "fixed" lifecycle dump; suppressed block is small
- [ ] SC-006 `usage.calls == sum(turns)`
- [ ] SC-007 broken run visibly distinct from clean run
- [ ] SC-008 every fix has a regression test that failed pre-fix
