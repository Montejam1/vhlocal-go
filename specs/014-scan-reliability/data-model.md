# Phase 1 Data Model: Reliable scan evidence and review completion

All persisted changes are **additive** (no schema-version field; graceful read of older records). Existing
types are extended, not replaced. Every record that can be written concurrently (013 concurrency) is
written as a whole line/document under a mutex.

## Job (`internal/jobs`, `jobs.json`) — additive

| Field | Type | Rule |
|---|---|---|
| `results_dir` | string | **Bound at `scan_start`** (not at run end); must be confined to allowed roots and owned by this job; persisted immediately. |
| `started` | bool/timestamp | Set when the engine announced start; distinguishes `not_started` from `running_no_files`. |
| `evidence_state` (derived) | enum | `unknown` · `not_started` · `running_no_files` · `ready` · `empty` · `unavailable` — computed by one resolver used by every evidence endpoint. |

## PromptRecord (`prompts.jsonl`, one JSON object per line, append-only)

| Field | Type | Notes |
|---|---|---|
| `seq` | int | per-scan monotonic call order |
| `ts` | RFC3339 | call time |
| `scan_tag` | string | |
| `phase` | string | `1`,`1t`,`2`,`2b`,`3`,… |
| `label` | string | agent/assignment label (e.g. `hunt:sg-3:inj.s2`, `verify:CAND-…`) |
| `role` | enum | `hunt|recon|verify|reproduce` |
| `model` | string | requested model |
| `kind` | enum | `main|repair|canary|repartition` |
| `system` | string | actual system content sent (redacted, clamped with `truncated:true`) |
| `task` | string | actual task / last user content sent (redacted, clamped) |
| `messages_count` | int | |
| `tool_calls` | []{name} | summary of assistant tool calls in the response |
| `response_stop` | string | |
| `redactions` | []string | what was masked (never the values) |

`scan_meta.json` gains `prompt_capture_version` (int). Absent → "not recorded by this version".
Invariant: **no** `Authorization`/API key/credentialed host ever appears (providers hold keys outside
`ChatRequest`; hosts pass through `redactURL`).

## ScanLogRecord (central log, scan-tagged lines via `logsetup`)

Line = `<ts> <level> [<scan_tag>] [<label>] <event>: <bounded, redacted detail>`. Events: `phase_start|
phase_skip|phase_done|agent_start|agent_stop(<reason>)|tool_failure(<class>)|validation_failure|retry(<n>)|
output_written(<path>)|budget|breaker|cancel|resume_invalidated|terminal(<outcome>)`. Detail is clamped
(e.g. 2 KB) and passed through `redact`. Read via `tail`/`follow` window; empty → explicit `no_lines`.

## ReadSpan (`agent.Result.Reads`)

`{File string (repo-relative, confined), Start, End int}` recorded from successful `Read`/`Grep` tool
dispatches. Factual tool evidence; feeds review dispositions.

## ReviewAssignment & ReviewUnit (`review_units.json`)

```
assignments: [{ route_id, file, line, language, unit_id | null, reason (when null) }]
units: [{
  unit_id, phase, partition, class, sample, label, attempts,
  revision,                       # git commit of the scanned repo
  deliverable: { path, status: valid|missing|empty|malformed|misplaced|duplicate },
  agent: { stopped_reason, produced },
  reads: [ReadSpan],
  dispositions: [{ route_id, disposition, rationale, evidence: { prompt_seq[], log_refs[] } }]
}]
gaps: [{ route_id, reason: unsupported_scope|assignment_failure|cancelled|budget|model_tool_failure|
         retry_exhausted|not_attempted }]
```

**Disposition values** (per assigned route): `reviewed_with_findings` · `reviewed_no_issue` · `partial` ·
`failed` · `skipped` · `unsupported` · `not_reviewed`.

**Validation rules** (FR-012/014): `reviewed_no_issue` requires ALL of — unit deliverable `valid`; route's
handler span (from `recognize.EnclosingScope`) intersected by a `ReadSpan` of that unit; route within the
unit's assigned scope; `revision` equals the current repo revision. Otherwise at most `partial`. A path
mention, a read outside the span, a prose claim, or `stopped_reason: complete` with `produced:false` never
yields a reviewed disposition. Sibling handlers in one file are distinct routes/spans.

## Coverage ledger (`inventory.LedgerEntry`, `coverage_ledger.json`) — additive

`disposition` now also produced as `reviewed_no_issue` and `excluded_with_reason` (from
`review_units.json` evidence); `finding_emitted` rule unchanged; new fields `unit_id`, `reason`,
`evidence_ref`.

**Naming mapping (one concept, two records):** a review-unit disposition of `reviewed_with_findings`
corresponds exactly to the ledger disposition `finding_emitted`. The ledger keeps `finding_emitted` for
feature-012 / dashboard compatibility; `review_units.json` uses the disposition vocabulary of FR-012.
`BuildLedger` (T036) and the outcome counts (T049) MUST treat them as the same state — never count a
route under both, and never let the two names drift into different rules. Measures (separate): `discovered`, `supported`, `assigned`, `attempted`, `completed`,
`findings`, plus the verification axis kept apart.

## HuntExecution (`hunt_execution.json`) — additive

`files: [{ path, status: valid|missing|empty|malformed|misplaced|duplicate, unit_id, attempts }]`
alongside the existing `complete`. `AgentRecord` gains `produced bool`.

## VerificationSessionOutcome (`verification_sessions.json`) — additive

`{ candidate_id, stop_reason, turns, failures, failures_by_class: { transport, tool_envelope,
invalid_tool_args, invalid_submission, turn_exhaustion }, last_operation, last_contract_violation }`.
Checkpointed after **every** session and on cancellation. Reconciliation reasons cite the dominant class.

## ReproductionDisposition (unchanged contract)

Candidate-bound entry with `status: authored` only; manifest harness-written; orphans reported in
`artifact_errors`, never deleted. Fixture-tested.

## OutcomeSummary (`findings.json` → `run_status.outcome`, additive; mirrored in report)

```
units: { total, assigned, attempted, reviewed_with_findings, reviewed_no_issue, partial, failed,
         skipped, unsupported, not_reviewed }
candidates: { supported, rejected, unresolved }
failed_assignments: [{ unit_id, path, reason }]
failed_candidates:  [{ candidate_id, class, reason }]
missing_artifacts:  [string]
disabled_optional_phases: [string]      # e.g. "1t (threat_model=false)"
recovery_steps: [string]                 # deterministic, actionable
```
Axes stay distinct: job termination (jobs), execution, coverage, verification, artifacts, validation mode.

## ApplicationArtifactSelection (API `/api/applications/{slug}`)

Per kind (`threat_model`, `sbom`): `{ scan_id, created, revision, path, valid: bool, older_than_latest:
bool, reason (when absent/invalid) }` — newest **valid** from that application's own history; never another
application's; `threat_model=false` on the latest → explained absence.

## RegistryCleanupPreview (`internal/apps/cleanup.go`)

`{ candidates: [{ slug, repo, reason }], preserved_count, backup_path (on apply) }`. Synthetic iff path
matches `^/tmp/Test[A-Za-z0-9_]+\d+/\d{3}$` **and** zero scan history **and** path no longer exists. Apply
writes `applications.json.bak-<ts>` first, removes exactly the previewed ids, touches no reports/ledgers.

## BuildIdentity (`/api/config`, validation evidence)

`{ version, embedded_assets_hash, built_at }` + tested URLs recorded by the browser validation run.

## Relationships

Job ⟶ results dir (bound at start) ⟶ {prompts.jsonl, scan log lines, review_units.json,
hunt_execution.json, verification_sessions.json, artifact_manifest.json, scan_meta.json}. Review units
reference inventory route ids (012) and prompt `seq`/log refs; `BuildLedger` consumes unit dispositions;
`finalize` folds ledger + reconciliation + manifest into `OutcomeSummary`; report/API/regeneration render
that summary from persisted records only. Applications select artifacts from their own report history.
