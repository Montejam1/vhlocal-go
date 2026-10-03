# Data Model: Scan-run reliability & honesty remediations

**Feature**: 003-scan-run-remediations | **Date**: 2026-09-15

This feature adds no new artifacts and changes no artifact schema. It introduces a small internal vocabulary and changes the *content/computation* of existing fields. Entities below are behavioral (in-memory) except where they surface in existing artifacts.

## Tool-dispatch result (internal, `internal/agent`)

Replaces the current `(string, bool)` return of `dispatch`.

- **Kind**: `ok` | `recoverable` | `unrecoverable`
  - `ok`: tool executed; content is the tool output.
  - `recoverable`: content is a corrective message for the model (missing/renamed arg, unknown-but-aliasable tool, tool error). Agent continues; does **not** count toward give-up.
  - `unrecoverable`: arguments were not parseable JSON. Triggers bounded repair (R2); only repeated repair failures end the agent.
- **Content**: string returned to the model as the tool result.

## Agent Result (extended, `internal/agent`)

Existing: `Turns`, `StoppedReason`, `FinalContent`, `Usage`, `Provenance`. Add:
- **RepairAttempts** int — count of fresh-context repairs attempted.
- **RepairSuccesses** int — repairs that yielded a well-formed tool call.
- **Produced** bool (optional) — whether the agent wrote its expected deliverable (engine already checks the file; may be mirrored here for the record).

`StoppedReason` values unchanged: `complete` | `max_turns` | `tool_repair` (now meaning "repair budget exhausted", not "2 malformed turns") | `cancelled`.

## Usage (corrected, `scan_meta.usage`)

Existing keys unchanged; **`calls` now equals total model turns across all agents plus repair calls** (was: agent count). Run-level `prompt_tokens`/`completion_tokens` unchanged in meaning (already per-turn accumulated); **per-agent token totals now also live on each `agents[]` entry** (see RunRecord additions) so usage is attributable per phase/agent (FR-011). Optionally add `repairs` (total repair attempts) for provenance (FR-014).

## RunRecord (`scan_meta.json`) additions

- **agents[]** gains two per-agent token fields — `prompt_tokens` (int) and `completion_tokens` (int) — alongside the existing `label, phase, model, turns, stopped_reason`. This makes token usage **attributable per phase/agent** and satisfies FR-011 clause (b) [G1]. The report's per-phase summary derives from this record. (Additive; no existing field removed/renamed.)
- Run-level counters: `repair_attempts`, `giveups` (under `usage` or as fields) — surfaced for diagnosability (FR-014).

## Coverage disposition (changed computation, `coverage_ledger.json`)

Dispositions and schema unchanged (`finding_emitted | reviewed_no_issue | covered_by_parent_analysis | excluded_with_reason | not_reviewed`). **Rule change (FR-008):**
- `reviewed_no_issue` requires the route's file/partition to be in the **hunted set** — the set of files a hunt agent actually produced output about (from `results/*.md`), not any results-dir text.
- If the hunt produced no output, the hunted set is empty → no route is `reviewed_no_issue`; un-hunted routes are `not_reviewed`.
- `finding_emitted` (a finding at the file) still takes precedence.

## RunStatus degraded reasons (expanded content, `run_status.coverage_degraded_reasons`)

Same field (`[]string`); new reason strings the engine may add (FR-009/010):
- `"recon produced no attack-surface map"`
- `"phase <k> agent gave up on tool-call errors"` (per failed required-deliverable agent)
- `"phase <k> agent hit max_turns without output"`
- `"hunt produced no candidates (pipeline incomplete, not a clean result)"`
Plus the existing shallow-run signals. Execution status (`partial`/`incomplete`) is set by the existing logic; these strings make *why* explicit.

## Run reliability (internal predicate, `internal/engine`)

- **Reliable** bool = `execution_status == complete` AND hunt produced output AND recon produced a map.
- Gates lifecycle reconciliation (R8) and the report's broken-run banner (R10). Not persisted as a field; derived at finalize and reflected via status reasons + report.
- **[T1] `Reliable` is distinct from and STRICTER than `coverage_status == "degraded"`.** A run may be reliable yet report degraded coverage (e.g. some `not_reviewed` routes) — such a run MUST still reconcile lifecycle normally. Only an *unreliable* run suppresses lifecycle. Implementers MUST gate suppression on `Reliable`, never on `coverage_status`. Do not conflate the two.

## Lifecycle block (suppressed form, `findings.json.lifecycle`)

Same block key; when the run is not reliable it takes the **suppressed shape**:
- `has_prior` (bool), `comparison_status: "suppressed_unreliable_run"`, `reason` (string), `new: 0`, `persisting: 0`, `not_observed: 0`, `not_observed_findings: []`, `reappeared: 0`, `regressed: 0`, `fixed: 0`, `fixed_findings: []`, `fixed_keys: []`.
- No large "fixed"/"not_observed" list is emitted; block size stays small (SC-005).
- On a reliable run, the existing reconcile shape is unchanged.

## Report additions (`SCAN_REPORT.md/.html`)

- **Per-phase outcome** section: rows of (phase key, agent label, turns, stop reason, produced-deliverable?) from `scan_meta.agents`.
- **Broken-run banner**: shown when not Reliable; states N-of-M phases produced output, lists degradation reasons, and that 0 findings reflect an incomplete run. Distinct from a clean zero-finding run.

## Context budget (internal, `internal/agent`)

- **Budget**: derived from `num_ctx` (a safe fraction). Pruning removes oldest/largest tool-result messages when the estimated message-list size exceeds it; system prompt and original task are never pruned. Token size approximated from byte length (no tokenizer dependency).
