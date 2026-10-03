# Data Model: Restore functional scanner parity and trustworthy evidence

**Feature**: 005-scanner-parity-evidence | **Date**: 2026-09-15

Entities, additive schema changes, and new artifacts. **Schema changes are additive** (FR-043): existing artifact filenames, API paths, and existing JSON keys are retained; new keys/files are added so honest evidence is represented rather than dropped. This supersedes feature-004's C-X1 "no serialized schema change" guard, which is replaced by the new differential-parity semantic diff (US6). All values are engine-observed fact (Principle I).

## Internal entities (in-memory)

### Partition / hunt unit (`internal/phases`, `internal/engine/hunt.go`)
- **Partition**: `{ ident, description (with concrete `method path (file:line)` routes), source ∈ model_table|model_retry|deterministic|single_fallback|coverage|threat_model, fallback bool, collapsed bool }`.
- **Uncovered scope**: route files beyond the cap → `coverage_uncovered_remaining` (recorded, never dropped).
- **Hunt unit** = `(partition × class ∈ {COMBINED} | {INJ,NAV,LOG}) × sample 1..N`; plus the sink-driven unit and the conditional IaC unit.
- **Validation**: `n_samples` clamped to 1..5; a partition with no routes is still valid (subsystem-level); cap = `max_partitions + len(subsystems)`.

### Candidate (`internal/verification/manifest.go`)
- **Identity** (line-shift/prose-insensitive): `hash(normalized_function_owner + whitespace/comment-stripped cited-statement + normalized_CWE + normalized_path)`. Heuristic (not AST — see plan Complexity).
- **Fields**: `{ id, identity, cwe, location (file:line), entry_point, provenance (units+votes), revision }`.
- **Built before verification**; consumed by the session and reconciliation.

### Evidence record (`internal/verification/evidence.go`)
- `{ ev_id = EV-<sha256>, file, line_range, quote (byte-exact from live source), revision }` — **immutable** once captured; must cover the candidate's cited primary location.

### Verification decision / disposition (`internal/verification/reconcile.go`)
- `{ candidate_id, verdict ∈ supported|rejected|unresolved, rationale, entry_point, attacker_control, preconditions, defenses_reviewed[], security_impact, evidence_ids[], unresolved_questions[], error? }`.
- **State transitions**: candidate → (session submits) → reconcile → `supported` (all checks pass) | `rejected` (cited evidence for non-exploitability) | `unresolved` (no/invalid/duplicate decision, failed evidence match, missing function context, revision mismatch, or quality-battery block). Reconcile iterates **all** candidates; `complete=false` if any error.

### Finding classification / assessment / state (`internal/consolidate`)
- **Classification**: `reviewed > statically_supported > hypothesis`.
- **Assessment**: `supported | unresolved`; totals: `candidates, supported, unresolved, statically_supported, reviewed, hypotheses, reproduced`.
- **finding_state**: `statically_supported | dynamically_confirmed | unresolved`.
- **Rules**: `statically_supported` requires a `supported` verification decision OR source-corroboration (cited file contains a matching CWE-family sink) AND passing per-class veto; logic/authorization CWEs require a validated review record and never reach supported on prose; missing source/checker → retain uncertainty (`unavailable`/hypothesis); `dynamically_confirmed`/reproduced require executor evidence (none in the default harness → never set).

### Coverage entry (`internal/inventory`)
- `{ entry_point (method + path + file:line), disposition ∈ finding_emitted|reviewed_no_issue|not_reviewed|covered_by_parent|excluded_with_reason, evidence }`.
- **Denominator fidelity**: resolve router/blueprint prefixes; method defaults → `ROUTE` (not `GET`); include websocket; **exclude test files** (`test_*`, `*_test.*`, `conftest.*`, `tests/`); dedup by stable key; security-relevant subsystem rules. **Corpus scope** includes phase1/2b/3/3d/README (not only `results/*.md`) or records the divergence.

### Agent result / record (`internal/agent`, `internal/engine/record.go`)
- `Result` gains `WroteFiles []string`, `Error string`, `ErrorKind string` (+ existing `Produced` now keyed to the declared deliverable & non-empty).
- Cancellation: agent returns stop reason `cancelled` (not an endpoint error).

## Additive schema changes (persisted)

### `scan_meta.json` → `agents[]` (AgentRecord)
- **Add**: `expected_deliverable`, `wrote_files[]`, `produced` bool, `error`, `error_kind`, `partition`, `vuln_class`. Existing fields unchanged.

### `scan_meta.json` → RunRecord
- **Add serialized**: `backend` (real provider backend — enables deterministic regeneration without fabricating `ollama`); `endpoint_failures[]` (was feature-004 `json:"-"` — now serialized so reasons survive regeneration).
- **Populate (already declared, currently always empty)**: `partition_fallback`, `partition_parse_error`, `coverage_partitions_added`, `coverage_files_added`, `coverage_uncovered_remaining`, `threat_model_partitions`, `hunt_halted_reason`, `budget_*` (where a paid backend is configured).
- `aborted` is reserved for a **systemic / caller-level fatal only**; **cancellation never sets `aborted`**. A cancelled run sets `cancelled=true` and leaves `aborted` empty, so `ComputeRunStatus` (which checks `aborted` before `cancelled`) yields `execution_status=cancelled`. (This corrects feature-004's behavior of setting `aborted="cancelled"`.)

### `run_manifest.json`
- `phase2_mode` = the **executed** mode (not hardcoded `"split"`); `transport.backend` = the real backend (from RunRecord.Backend); hunt-halt/budget reasons surfaced.

## New artifacts (files)
- `candidate_manifest.json` — now built **before** 2b with strong identity (was a finalize-time placeholder).
- `verification_decisions.json` — per-candidate decisions (harness-written from the session).
- `verification_metrics.json` — counts + per-candidate reconcile outcomes.
- `verification_reconciliation.json` — reconciliation summary (also produced on report regeneration from existing decisions).
- `artifact_manifest.json` — validated against candidate identity + on-disk artifacts; **never clobbered** with `[]` on finalize/regeneration (empty only on legitimate zero-verified skip).
- `hunt_votes.json` — sample-merge vote provenance.
- `phase2b_handoff.md` — supported-only handoff consumed by phase 3 (currently read but never written).
- `results/<slug>_{code}[.sN].md`, `results/sink_driven.md`, `results/iac.md`, per-unit placeholders for failed/empty units.

## Preserved (unchanged)
- Existing artifact filenames and API paths; the three status-axis field names; feature-004's `TransportError.Kind/Raw`, same-endpoint repair, per-phase degrade, completion nudge, and their tests.
- Static-only boundary; loopback/allow-root posture; configured-endpoint routing.

## Migration / compatibility note
The additive keys mean older readers see extra fields (ignored) and the feature-004 parity test's exact-key-set assertion is updated to allow the additions. No key is removed or renamed; no artifact is dropped.
