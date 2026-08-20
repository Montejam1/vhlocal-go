# Controlled A/B: does the partition fallback explain the coverage gap?

The post-run audit of the gpt-oss:120b scan traced most of the missed cross-file
findings to one mechanism: Phase 1's partition table was unparseable, so the
harness silently collapsed to a **single whole-repo partition** and Phase 2 ran
only `3×1 + 1 = 4` agents. The patched harness (P1-E) replaces that silent
collapse with a structured-contract → corrective-retry → deterministic
subsystem fallback, and records exactly which path was taken.

**This is a hypothesis, not a settled cause.** A subsystem partitioner that fans
Phase 2 across auth / authz / file-handling / config / ops is *expected* to lift
recall on cross-file authorization and configuration findings — but it will not
recover findings the hunt model cannot reason about regardless of scoping. The
only way to separate "the harness never let it look" from "the model can't see
it" is a controlled rerun.

## Design

Hold everything fixed except the harness version.

| Variable | Setting |
|---|---|
| Target repo | `vc-claude-code-seeded-v2-logistics-dispatch-fastapi` |
| Commit | `047e3a2471ed7c14793c19798c460882cb1d1de1` (pinned, clean tree) |
| Hunt model | `gpt-oss:120b` (same digest/quant) |
| Falsification model | `qwen3.5:122b-a10b` (same digest/quant) |
| `--num-ctx`, `--max-partitions`, temperature, seed | identical across arms |
| Trials per arm | ≥ 3 (open-weight agentic runs are non-deterministic) |

**Arm A (baseline):** harness at the pre-P1-E commit (silent single-partition
fallback).
**Arm B (patched):** current harness. Record `partition_source`,
`partition_fallback`, `partition_collapsed` from `scan_meta.json` for every run —
Arm B is only a valid test of the hypothesis on runs where Arm A actually
collapsed and Arm B actually fanned out. Discard pairs where Arm A's table
parsed cleanly (the mechanism never engaged).

## What to measure (per run, from the machine artifacts)

The patched harness now emits everything needed without hand-scoring:

- `findings.json` → `run_status` (execution/coverage/validation), `attribution`,
  `coverage` summary, per-finding `root_cause_key` + validation state.
- `coverage_ledger.json` → enumerated entry points and per-route disposition.

Primary endpoints:

1. **Unique seeded recall** (semantic) — the audit's most diagnostic number.
2. **Enriched-finding recall**, especially the authorization/config/storage
   findings that were 0/14 in the audited run.
3. **Entry-point coverage** — `reviewed / total` from the ledger, and the
   `not_reviewed` set. This is the direct mechanistic readout: if Arm B reviews
   the auth/config routes Arm A never reached, the causal path is confirmed
   regardless of whether recall moves.
4. **Partition count and `partition_source`** — confirms the arms actually
   differ.

Secondary: headline-duplicate count (should be 0 with P0-B), false verdict count
(0 with P0-A), tokens, duration, phase-failure rate.

## Reading the result

- **Coverage up *and* enriched recall up** → the fallback was a real cause; the
  fix helps. Quantify how much of the gap it closes (it will not be 100%).
- **Coverage up but enriched recall flat** → the harness now *reaches* those
  routes but the model still can't reason about the authorization invariants.
  That isolates the remaining gap as a model-capability problem (→ P1-F's
  authorization-invariant pass, F in the original plan), not orchestration.
- **No coverage change** → the arms didn't actually diverge (check
  `partition_source`); the hypothesis is untested, not disproved.

Report mean ± sd across trials, plus union/intersection recall across the three
runs per arm — a single run undersells a non-deterministic pipeline.

## Note

Arm B runs must **not** be aggregated with Arm A into a single model-ranking
number: they are different orchestrators. Per audit 7.4 and P0-D, the artifacts
label hunt vs. falsification vs. orchestrator separately so the comparison stays
honest.
