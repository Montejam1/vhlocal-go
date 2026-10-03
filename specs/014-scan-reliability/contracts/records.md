# Contract — Persisted evidence records

All additive; older records read gracefully. Concurrent writers append whole lines/documents under a mutex.

## `prompts.jsonl` (FR-005/007)
One `PromptRecord` per line (see data-model). Invariants: `seq` strictly increasing per scan; every `Chat`
call of every role/kind recorded at call time (never reconstructed); `system`/`task` are the actual sent
content after `redact` + host-credential stripping, clamped with `truncated:true`; no API key or
`Authorization` value ever appears (test asserts against fixtures containing planted secrets).
`scan_meta.prompt_capture_version` present iff records were captured by this version.
**As built**: the 8 KB clamp is applied at write time, so the full text of a truncated record is NOT stored
and there is no "fetch the full record by seq" — the evidence-api Bounds row describing that expand path is
aspirational and is superseded by this note. A live full scan wrote 4,784 records (≈63 MB), 99% truncated:
prompts are large because they embed the phase methodology; the clamp keeps the file bounded per record.

## Scan-tagged log lines (FR-006/007)
`<ts> <level> [<scan_tag>] [<label>] <event>: <detail>`; events as enumerated in data-model; detail clamped
and redacted; readable by tag via the existing `logsetup.ReadLog` filter. Concurrent lines never interleave
mid-line (`-race` + interleave test).

## `review_units.json` (FR-010..016)
`assignments[]`, `units[]`, `gaps[]` as in data-model. Invariants:
- **C-R1**: every supported inventory route appears exactly once in `assignments` (with `unit_id` or a reason).
- **C-R2**: `reviewed_no_issue` only when deliverable `valid` ∧ handler span intersected by a unit `ReadSpan`
  ∧ route in unit scope ∧ revision current. Path mentions, out-of-span reads, prose, `produced:false` → never.
- **C-R3**: sibling handlers / duplicate route names have distinct route ids and spans; a finding in one never
  marks another reviewed.
- **C-R4**: with enforcement off, `gaps[]` is still populated; with it on, each gap has ≤1 bounded follow-up
  attempt recorded before a `retry_exhausted`/limiting reason.
- **C-R5**: `BuildLedger` consumes this file; `coverage_ledger.json` dispositions derive from it plus the
  unchanged in-span-finding rule; regeneration of an older scan without this file produces no `reviewed_no_issue`.

## `hunt_execution.json` (FR-017)
**As built**: the legacy `files[]` (planned relative paths) is kept for resume; the additive `detail[]`
carries `{path, status, unit_id, attempts}` with `status ∈ valid|missing|empty|malformed|misplaced|duplicate`
(`misplaced` = an unplanned `results/*.md`, reported and never deleted; follow-up deliverables
`*_followup.md` are not misplaced). `complete` true only if every planned file is `valid`.
`AgentRecord.produced` recorded; `stopped_reason:"complete"` with `produced:false` is a failure, never a pass;
exactly one bounded re-run (`<label>.retry1`, `attempts:2`) per unit/sink/IaC pass whose deliverable is
invalid after a normal stop, under ctx/budget/breaker.

## `review_units.json` — as-built shape
`{revision, assignments[], units[], dispositions[{route_id, disposition, rationale, unit_label, evidence[]}],
gaps[{route_id, reason}], follow_up_ran, counts{total, assigned, attempted, reviewed_with_findings,
reviewed_no_issue, partial, failed, skipped, unsupported, not_reviewed}}`. Go registration-style routes resolve
their span to the handler function (`Route.Handler` / `HandlerDeclLine`), not the registration line.

## `verification_sessions.json` (FR-018/019)
`failures_by_class{transport,tool_envelope,invalid_tool_args,invalid_submission,turn_exhaustion}`,
`last_operation`, `last_contract_violation`; written after every session and on cancellation (a context
cancel records `stop_reason:"cancelled"`, not `endpoint_failure`); reconciliation `unresolved` reasons cite the
dominant class ("; dominant failure: <class> at <op> — <violation>"), preserved by finalize's re-render;
evidence validation rules unchanged; the repair budget still counts only envelope + submission failures.

## `artifact_manifest.json` (FR-020) — unchanged
Missing disposition / unregistered artifact errors persist in `artifact_errors`; orphans never deleted;
`status:"authored"`; not-executed label on every surface.

## `findings.json` → `run_status.outcome` (FR-021..023)
`OutcomeSummary` as in data-model; identical values rendered in report Markdown/HTML and regenerated views;
SARIF semantics unchanged; regeneration reads persisted records only and alters no evidence or human decision.
**As built**: the same block is also `scan_meta.json.outcome`; it is assembled by `engine.buildOutcome` from
`review_units.json` (units), `verification_reconciliation.json` + `verification_sessions.json` (candidates,
`failed_candidates[].class` = `unresolved_verdict` when the verifier submitted an `unresolved` decision
(the model's rationale is the reason; never a failure class — live-run fix 2026-09-29), else the session's
dominant failure class, `cancelled`, or `not_attempted`),
`hunt_execution.json.detail` (`failed_assignments`), `artifact_errors` (`missing_artifacts`) and
`phases_skipped` (`"1t (threat_model=false)"`), with deterministic `recovery_steps`. The report renders it as
`## Completion` (each group linked to its record file) and lists `gaps[]` as `## Review coverage`. A recovered
silent unit (follow-up ran) keeps its failed assignments listed — recovery never hides the failure.
`testdata/replay-audit/` (scenario + README) drives the consistency/immutability tests.

## `applications.json` cleanup (FR-028)
Apply only after preview; backup `applications.json.bak-<ts>` written first; removes exactly previewed ids;
synthetic iff `^/tmp/Test[A-Za-z0-9_]+\d+/\d{3}$` ∧ zero history ∧ path gone.
