# Feature Specification: Restore functional scanner parity and trustworthy evidence in vhlocal-go

**Feature Branch**: `005-scanner-parity-evidence`

**Created**: 2026-09-15

**Status**: Draft

**Input**: User description: "Restore functional scanner parity and trustworthy evidence in vhlocal-go following the feature-004 reliability sprint. Use ../vhlocal as the authoritative Python behavioral reference. Audit the current Go implementation before specifying requirements; distinguish implemented behavior from declarations in tasks.md and comments. … Produce measurable acceptance criteria and identify every remaining scanner simplification."

## Overview

Features 002–004 delivered a Go port that **builds, runs, and emits the reference artifact set with matching filenames and JSON keys**, and (feature 004) recovers from provider tool-call-parse failures and degrades per phase. A pre-spec audit of the actual Go implementation against the authoritative Python reference (`../vhlocal/vhlocal/*.py`) found that, beneath the matching surface, the Go scanner **reproduces the reference's vocabulary but not its evidence discipline**: it grounds "statically supported" on surface signals, runs a single generic agent per route-partition instead of the reference methodology, ports essentially none of the adversarial-verification machinery, and carries several flags/records/manifests that describe behavior it does not perform. Some paths are not merely simplified — they are **honest-reporting defects** that can present unsupported or rejected findings as confirmed, or destroy real evidence on report regeneration.

This feature restores functional parity with the reference methodology and makes the scanner's evidence trustworthy: it must accurately distinguish **statically-supported findings, unresolved candidates, rejected candidates, incomplete scans, and legitimate clean scans**. Producing matching filenames or non-empty placeholder files is explicitly insufficient.

Feature 004's behaviors (provider tool-call-parse classification, same-endpoint fresh-context repair, per-phase failure continuation, completion nudge) and their regression tests are **preserved**; this feature corrects the honesty regressions those behaviors sit on top of and completes the methodology and evidence layers around them.

### Audit basis (implemented vs declared)

The requirements below are grounded in a six-area audit comparing Go `internal/` against Python `../vhlocal/vhlocal/`. The audit distinguished real Go behavior from comments and prior task-list claims. The **remaining scanner simplifications** it found are enumerated in their own section near the end of this spec, and the "prior completion claims to correct" are listed under Assumptions. Constitution alignment: this feature directly serves Principle I (Evidence Integrity), II (Orthogonal Status), IV (Provenance), VI (Resumable/Idempotent), and VII (Testable, offline).

## User Scenarios & Testing *(mandatory)*

The six user stories map to the six dependency-ordered outcomes in the request. They are ordered so each unblocks the next; **US1 is the foundation** (nothing above it can produce trustworthy evidence without usable tools and grounding). Several stories also contain **correctness-critical honesty defects** (called out under Requirements) that should be pulled forward regardless of sequencing.

### User Story 1 - Grounded assignments and usable file tools (Priority: P1)

Every agent receives everything it needs to do real work — the absolute target repository path, its writable results directory, its assigned scope with concrete routes, prior-phase inputs, and an exact deliverable contract — and the file tools it is told to use actually behave the way the methodology assumes. An operator running any phase gets file:line-citable reads, recursive globs that match the documented patterns, and returned paths that feed directly back into a read; a missing methodology file fails loudly instead of running an agent on a placeholder.

**Why this priority**: The whole methodology depends on file:line citation and on globs/reads that round-trip. Today Go `Read` emits no line numbers and cannot page; `Glob` uses non-recursive matching and returns relative paths that don't resolve back through `Read`; agents never receive the absolute repo path or their concrete scope; and a missing prompt runs a full agent on `"(phase prompt unavailable…)"`. Until this is fixed, every downstream evidence claim rests on tools that cannot support it. This story is an independently valuable and independently testable MVP.

**Independent Test**: Offline, against the shared `testdata/vulnapp` fixture, drive the tools directly and via a scripted agent: assert `Read` paging + line-numbered output and a continuation past the first page; assert recursive-glob semantics matching the reference and that every returned path is directly readable; assert an agent task contains the absolute repo path, results dir, assigned scope, and exact deliverable; assert a missing prompt/methodology file produces an explicit configuration failure rather than a placeholder run.

**Acceptance Scenarios**:

1. **Given** a large source file, **When** an agent reads past the first page, **Then** `Read` accepts an offset/limit, returns line-numbered content and a continuation indication, and a citation to a line beyond the first page resolves to the correct source line.
2. **Given** a recursive glob pattern (e.g. `**/*.py`) over the target repo, **When** the tool runs, **Then** it matches nested files per the reference glob semantics (not Go `filepath.Match`), and every returned path can be passed straight to `Read` and to `Grep` scoping without modification.
3. **Given** any phase agent, **When** its task is built, **Then** the task states the absolute target repository (read-only), the results directory (its only writable location), the assigned scope/partition with concrete routes where available, the prior-phase inputs to read first, and the exact deliverable path/contract.
4. **Given** writes routed through a symlinked parent directory into the results dir, **When** the agent writes, **Then** the path resolves and the write is confined to the results dir; a write targeting a harness-owned artifact (e.g. `scan_meta.json`, `candidate_manifest.json`) is refused.
5. **Given** a missing or unreadable required methodology/prompt file, **When** the phase would run, **Then** the run raises an explicit configuration failure (surfaced and recorded) and does not fabricate a placeholder agent run.

---

### User Story 2 - Harness-controlled hunt orchestration (Priority: P2)

The hunt runs the reference methodology, not a single generic agent per directory. It uses the model's recon partitions when valid, deterministically augments/falls back for omitted routes, adds threat-model partitions, dispatches the class split (INJ/NAV/LOG) with the shared and per-class prompts plus the sink-driven pass and conditional IaC analysis, runs repeated samples and merges them with provenance, and — critically — **names uncovered scope instead of silently dropping it**. Exposed options actually change execution, and the run manifest describes the mode that was actually executed.

**Why this priority**: The hunt is where candidates are found; a generic single-pass hunt finds a narrower, different set than the reference, and today's partition cap silently discards scope (the exact failure the reference's "uncovered_remaining" exists to prevent). Options (`split`, `hunt_samples`, `iac_lens`, `max_partitions`) are advertised in the CLI/manifest but are no-ops or silently truncate, so the manifest misreports what ran.

**Independent Test**: Offline with scripted providers over `testdata/vulnapp`: assert the model's recon partition plan is consumed (with corrective retry on malformed plans), coverage/threat-model augmentation appends omitted routes, the cap records uncovered scope rather than dropping it, split mode dispatches per (partition × class) with the shared+class prompts, `hunt_samples=N` produces N passes merged with vote provenance, `iac_lens` runs only when IaC is present, and the manifest's recorded mode equals the executed mode.

**Acceptance Scenarios**:

1. **Given** a valid Phase-1 partition plan, **When** the hunt starts, **Then** it uses those partitions; **Given** a malformed plan, **Then** it performs one corrective repartition before falling back to deterministic partitions, recording the partition source.
2. **Given** routes omitted from the plan and more partitions than the cap, **When** partitions are finalized, **Then** omitted routes are added as coverage partitions and any scope beyond the cap is recorded as uncovered-remaining (never silently dropped).
3. **Given** split mode, **When** the hunt dispatches, **Then** it runs the INJ/NAV/LOG class split with the shared + per-class prompts (and the sink-driven pass), and combined mode concatenates class references into one agent; the manifest records the mode actually executed.
4. **Given** `hunt_samples=N (>1)`, **When** a unit runs, **Then** it executes N independent samples and merges candidates by stable identity with vote provenance recorded; **Given** `iac_lens` and IaC present, **Then** the IaC pass runs; with no IaC, it does not.
5. **Given** budget/breaker/cancellation conditions where applicable, **When** they trigger, **Then** the hunt halts with a recorded reason and the run remains honestly incomplete.

---

### User Story 3 - Structured adversarial verification and phase handoffs (Priority: P3, contains correctness-critical fixes)

Phase 2b is a candidate-bound, fail-closed verifier, not a generic summarizer. A candidate manifest is built before verification; each candidate receives a supported / rejected / unresolved disposition backed by captured, quote-matched, immutable source evidence with revision/identity checks and required function/defense context; results are reconciled with metrics; and the downstream handoffs are generated. A valid zero-survivor verification must not resurrect raw hunt findings, and unsupported or malformed verification output must never imply confirmation.

**Why this priority**: This is the core of "trustworthy evidence" and contains the two most dangerous defects found: (a) a valid all-rejected 2b result silently falls back to raw hunt findings and can even promote rejected candidates to "supported"; (b) any parseable 2b output is unconditionally promoted to statically-supported with no evidence validation. Both are Evidence-Integrity (Principle I) violations. Full parity depends on US1's file tools (evidence capture needs paging + line numbers), but the fail-closed fixes (a)/(b) should be pulled forward.

**Independent Test**: Offline with scripted verification providers: assert the candidate manifest is built before 2b and consumed; assert every candidate ends supported/rejected/unresolved with quote-matched evidence and function context; assert a zero-survivor result yields zero supported findings (no raw-hunt fallback, no resurrected rejections); assert malformed/unsupported verification output yields unresolved/rejected, never supported; assert `phase2b_handoff.md` (supported-only) and phase-3 assignments are generated and consumed.

**Acceptance Scenarios**:

1. **Given** hunt candidates, **When** verification begins, **Then** a candidate manifest keyed by stable candidate identity (function-owner + statement + CWE + location, line-shift/prose-insensitive) exists and drives verification.
2. **Given** a supported submission, **When** reconciled, **Then** it is accepted only if its evidence quotes byte-match live source, cover the cited location, include the containing function/defenses, and pass the quality battery at the required revision; otherwise it becomes unresolved with a reason.
3. **Given** a verification pass where every candidate is rejected, **When** findings are consolidated, **Then** zero findings are published as supported, no raw hunt findings are resurrected, and rejected candidates are recorded as rejected (never supported).
4. **Given** malformed, empty, or schema-invalid verification output, **When** consolidated, **Then** no candidate is treated as confirmed; affected candidates remain explicitly unresolved.
5. **Given** verification completes, **When** downstream phases run, **Then** `phase2b_handoff.md` (supported-only) and the phase-3 assignment inputs are generated, and phase 3 consumes them (no dangling read of a non-existent handoff).

---

### User Story 4 - Source-grounded publication and artifact validation (Priority: P4, contains a correctness-critical fix)

A finding is published as statically-supported only through a structured verification decision or a source-corroborated quality result — never from a text field, a prose data-flow arrow, model confidence, or sample agreement alone. Missing source and unsupported checker families retain explicit uncertainty. Reproduction/artifact manifests are validated against candidate identities and the actual artifacts on disk, a legitimate artifact manifest is never overwritten with empty arrays during finalization or regeneration, and runtime reproduction is never claimed from static analysis.

**Why this priority**: Publication is where evidence reaches the operator. Today support is derived from surface signals; the tier taxonomy is collapsed (no `reviewed`, `rejected`, or `dynamically_confirmed`); artifact manifests are placeholders; and — correctness-critical — `finalize`/regeneration overwrite a real `artifact_manifest.json` with `[]`, so `vhlocal report` destroys authored PoC/test records. Depends on US3's decisions for full fidelity, but the artifact-manifest-clobber fix is standalone and should be pulled forward.

**Independent Test**: Offline: assert a finding with a location string + prose arrow but no source corroboration is NOT statically-supported; assert logic/uncovered-class candidates retain uncertainty; assert the publication tiers (reviewed / statically-supported / unresolved / rejected / hypothesis; incomplete; clean) are all reachable and distinct; assert artifact-manifest validation against candidate identity + on-disk files; assert regeneration preserves an existing non-empty artifact manifest; assert no static path sets a dynamic/reproduced validation state.

**Acceptance Scenarios**:

1. **Given** a candidate whose cited source does not contain a matching sink and has no validated review record, **When** published, **Then** it is a hypothesis/unresolved, not statically-supported — regardless of text fields, arrows, confidence, or sample agreement.
2. **Given** a class with no checker rule or an unreadable checkout, **When** assessed, **Then** the finding retains explicit uncertainty (hypothesis/unavailable) and cannot reach statically-supported on prose.
3. **Given** an authored reproduction/artifact manifest, **When** validated, **Then** each entry references a known supported candidate and an existing on-disk artifact carrying the candidate ID and location; unregistered on-disk artifacts and orphaned entries are flagged.
4. **Given** a results directory with a real `artifact_manifest.json`, **When** `finalize` or report regeneration runs, **Then** the existing manifest is preserved (not overwritten with `[]`).
5. **Given** static-only analysis, **When** status is computed, **Then** validation mode is static and no finding is marked dynamically-confirmed/reproduced without executor evidence.

---

### User Story 5 - Truthful completion, coverage, resume, and regeneration (Priority: P5, contains correctness-critical fixes)

Completion, coverage, resume, cancellation, and regeneration tell the truth. Each agent/unit's expected deliverable, actual valid output, stop reason, and error are tracked; a write to an unrelated or empty file neither suppresses the completion nudge nor counts as produced; valid partial hunt evidence is preserved without marking the whole hunt complete on one unit's output; coverage identifies the specific entry point, disposition, and review evidence; resume validates saved outputs and identities and counts valid resumed work; cancellation retains cancellation status even in the final phase; and deterministic regeneration preserves status, provenance, evidence decisions, and artifact manifests without fabricated attribution or lost failure reasons.

**Why this priority**: These are the honesty seams that make a run's status believable across resume and regeneration. Correctness-critical defects here: an empty/misplaced write sets `Produced=true` and suppresses the recovery nudge; cancellation reports `execution_status=aborted` (and mislabels the cancelled agent as `endpoint_failure` with a bogus degraded reason); regeneration fabricates an `ollama` backend and drops endpoint-failure degradation reasons (non-deterministic status/provenance).

**Independent Test**: Offline: assert a write to a wrong/empty path does not set produced and does not suppress the nudge; assert one hunt unit's output does not mark the whole hunt complete and per-unit attribution is recorded; assert coverage names the specific reviewed entry point + disposition + evidence and that a bare file mention does not mark every route in that file reviewed; assert resume validates saved outputs/identities and counts valid resumed work (a fully-resumed run is not `incomplete`); assert a mid-run cancellation yields `execution_status=cancelled` (not aborted, not endpoint_failure) with artifacts finalized; assert regeneration after an endpoint failure preserves the real backend and the endpoint-failure reasons.

**Acceptance Scenarios**:

1. **Given** an agent that writes an empty file or an unrelated path, **When** it would complete, **Then** it is still nudged to write the declared deliverable, and the phase/unit is marked produced only when that deliverable exists and is non-empty.
2. **Given** a hunt where some units produce output and others fail, **When** completion is computed, **Then** valid partial evidence is preserved, per-unit attribution (partition/class, stop reason, error) is recorded, and the hunt is not marked complete solely because one unit wrote output.
3. **Given** coverage computation, **When** a route is dispositioned, **Then** the specific entry point, its disposition, and the supporting review evidence are recorded; a file/route mention does not mark every route in that file reviewed; an explicit clean review (zero candidates) remains valid.
4. **Given** a prior run's saved outputs, **When** resumed, **Then** saved deliverables are validated for identity/validity, invalid units are rerun, and valid resumed work is included in effective completion.
5. **Given** a scan cancelled mid-run (including during the final phase), **When** it ends, **Then** `execution_status=cancelled` is retained, the cancelled agent is not labeled an endpoint failure, and artifacts are finalized.
6. **Given** an original run on a specific backend/model that hit an endpoint failure, **When** the report is regenerated deterministically, **Then** status, provenance (real backend/model), evidence decisions, artifact manifests, and endpoint-failure degradation reasons are preserved — no fabricated `ollama` attribution, no lost reasons.

---

### User Story 6 - Genuine differential parity and regression coverage (Priority: P6)

Parity is proven by executing both implementations offline against shared source fixtures and equivalent scripted model/tool interactions, then comparing normalized semantic outputs — dispatch scope, candidate identities and provenance, verification dispositions, publication tiers, coverage, handoffs, artifacts, and run status — normalizing only incidental timestamps, temp roots, and ordering. Filename/key checks remain smoke tests and are not labeled parity. A required set of regression scenarios is covered.

**Why this priority**: Parity claims must be enforced by tests, not asserted in prose. Today `tests/parity/` is a Go-only smoke test whose golden values are authored to match its own fake provider; the Python reference is never executed or compared. This story locks in every prior story and prevents regressions. It depends on the earlier stories producing the semantics worth comparing.

**Independent Test**: Offline, the differential harness runs both implementations on `testdata/vulnapp` with equivalent scripted providers and asserts normalized-semantic equality across the enumerated dimensions; the required regression scenarios each have a failing-before/passing-after test; the filename/key smoke test remains but is labeled as such.

**Acceptance Scenarios**:

1. **Given** the shared source fixture and equivalent scripted model/tool scripts, **When** both implementations run offline, **Then** their normalized semantic outputs (dispatch scope, candidate identities/provenance, verification dispositions, publication tiers, coverage, handoffs, artifacts, run status) are compared and must match, with only timestamps/temp roots/ordering normalized.
2. **Given** the differential harness, **When** a semantic divergence exists, **Then** the test fails and names the diverging dimension (it does not pass on filename/key existence).
3. **Given** the regression suite, **When** run offline, **Then** it covers: wrong-path/empty writes, a missing prompt, results-directory discovery, citations beyond the first Read page, failed hunt units, all-candidates-rejected, absent/contradictory source evidence, malformed verification decisions, preserved artifact manifests, resume, cancellation, regeneration after an endpoint failure, and split/samples/IaC option behavior.

---

### Edge Cases

- **Zero-survivor verification** (all candidates rejected): the run publishes zero supported findings, does not resurrect raw hunt findings, and is a legitimate outcome distinct from a clean scan and from an incomplete scan.
- **Legitimate clean scan** (routes reviewed, no candidates): remains valid and distinct from a broken/empty run.
- **Malformed / empty / schema-invalid verification output**: fail-closed to unresolved; never confirmation.
- **Missing methodology/prompt/SKILL file**: explicit configuration failure, never a placeholder agent run.
- **Recursive globs and off-CWD paths**: returned paths round-trip to `Read`/`Grep` regardless of process CWD.
- **Symlinked parent into results dir**: resolves and is confined; harness-owned artifacts are not overwritable by the model.
- **Partition cap exceeded**: excess scope is recorded as uncovered-remaining, not dropped.
- **Options set but inapplicable** (e.g. `iac_lens` with no IaC in repo): the option no-ops *honestly* — the manifest reflects that it did not run, rather than claiming it did.
- **Cancellation during the final phase**: cancellation status is retained; artifacts still finalize.
- **Regeneration of a partial/degraded/endpoint-failed run**: preserves status, provenance, decisions, artifact manifests, and degradation reasons deterministically.
- **Additive schema needs**: where evidence cannot be represented in the current key set, an additive schema change is introduced and documented rather than dropping the evidence.

## Requirements *(mandatory)*

### Correctness-critical defects (Evidence Integrity — pull forward regardless of story sequencing)

- **FR-C1**: A valid zero-survivor verification MUST NOT fall back to raw hunt findings, and rejected candidates MUST NOT be published as supported (fixes the `collectFindings` raw-results fallback). *(US3)*
- **FR-C2**: Malformed, empty, or schema-invalid verification output MUST NOT imply confirmation; affected candidates remain explicitly unresolved. *(US3)*
- **FR-C3**: `finalize` and report regeneration MUST NOT overwrite an existing, non-empty artifact manifest with empty arrays. *(US4)*
- **FR-C4**: A write to an empty or unrelated file MUST NOT set the produced state nor suppress the deliverable nudge. *(US5)*
- **FR-C5**: A cancelled run MUST report `execution_status=cancelled` (not `aborted`), and a cancelled in-flight agent MUST NOT be labeled an endpoint failure or generate an endpoint-failure degradation reason. *(US5)*
- **FR-C6**: Deterministic regeneration MUST NOT fabricate provider attribution (e.g. hardcoded `ollama`) and MUST NOT lose endpoint-failure degradation reasons; the real backend/model and the failure reasons must survive re-render. *(US5)*

### US1 — Grounded assignments and file tools

- **FR-001**: Every agent task MUST state the absolute target repository (read-only), the results directory (its only writable location), the assigned scope/partition (with concrete routes where available), the prior-phase inputs to read first, and the exact deliverable path/contract, adapted to the agent's actual tool capabilities.
- **FR-002**: Reference prompt variables and orchestrator instructions MUST be adapted to the Go agent's real capabilities (no instructions the tools cannot honor; no omitted grounding the methodology relies on, including threat-model/SBOM/seed-route context where the reference injects it).
- **FR-003**: `Read` MUST support paging with an offset and limit and MUST emit line-numbered output with a continuation indication, so citations beyond the first page are possible and verifiable (reference-compatible).
- **FR-004**: `Grep` MUST be scoped to permitted roots, support the reference's scoping/options where the methodology uses them, exclude skip-dirs consistently across ripgrep and fallback paths, and bound its output.
- **FR-005**: `Glob` semantics MUST match the reference (including `**` recursion), not Go `filepath.Match`; glob semantics MUST be defined from the reference, not assumed equivalent.
- **FR-006**: Paths returned by `Glob`/`Grep` MUST be directly usable as `Read` inputs regardless of process working directory (round-trip guaranteed).
- **FR-007**: Reads MUST be confined to the repository/skill/results roots and writes to the results dir, with paths resolved (including symlinked parent directories) before containment checks; the model MUST NOT be able to overwrite harness-owned artifacts.
- **FR-008**: Tool outputs MUST remain bounded (existing caps preserved).
- **FR-009**: A missing or unreadable required methodology/prompt/SKILL file MUST produce an explicit configuration failure (surfaced and recorded), never a placeholder agent run or silently dropped preamble.

### US2 — Hunt orchestration

- **FR-010**: The hunt MUST use the model's recon (Phase-1) partition plan when valid, perform one corrective repartition on a malformed plan, and fall back to deterministic partitions otherwise, recording the partition source.
- **FR-011**: The hunt MUST deterministically augment partitions for routes omitted from the plan and MUST add additive threat-model partitions, recording what was added.
- **FR-012**: A partition cap MUST record uncovered scope explicitly (uncovered-remaining) and MUST NOT silently drop it.
- **FR-013**: The hunt MUST implement the class split (INJ/NAV/LOG) with the shared and per-class prompts in split mode, and concatenated class references in combined mode, plus the sink-driven pass.
- **FR-014**: Conditional IaC analysis MUST run only when IaC is present and the option is enabled, and MUST NOT be claimed when it did not run.
- **FR-015**: Repeated-sample execution MUST actually run N samples and merge candidates by stable identity with vote provenance; a recorded sample count MUST equal the executed count.
- **FR-016**: Cancellation, budget caps, and breaker behavior MUST be honored where applicable, recording halt reasons; the run remains honestly incomplete when halted.
- **FR-017**: Exposed options (split/phase2-mode, samples, IaC, max_partitions) MUST affect execution, and the run manifest MUST describe the mode actually executed (no hardcoded or requested-but-not-executed mode).

### US3 — Structured adversarial verification and handoffs

- **FR-018**: A candidate manifest MUST be built before verification and consumed by it, keyed by a stable candidate identity that is line-shift/prose-insensitive (function-owner + statement + CWE + location).
- **FR-019**: Verification MUST capture candidate-bound, immutable source evidence whose quotes byte-match live source and cover the cited primary location, at a checked revision/identity.
- **FR-020**: Each candidate MUST receive an explicit supported / rejected / unresolved disposition; a candidate with no valid decision remains unresolved with a reason.
- **FR-021**: A supported disposition MUST require the containing function/defense context and pass the required quality battery; the outcome is harness-owned and MUST NOT be ingested from model-authored files as-is.
- **FR-022**: Verification metrics and reconciliation MUST be recorded.
- **FR-023**: The downstream handoffs MUST be generated (supported-only `phase2b_handoff.md` and the phase-3 assignment inputs) and consumed by downstream phases; no phase may depend on a handoff that is never written.

### US4 — Source-grounded publication and artifact validation

- **FR-024**: A finding MUST be classified statically-supported only via a structured verification decision or a source-corroborated quality result (the cited source actually contains a matching sink / a validated review record), never from a text field, prose data-flow arrow, model confidence, or sample agreement alone.
- **FR-025**: Missing source and unsupported/uncovered checker families MUST retain explicit uncertainty (hypothesis/unavailable) and MUST NOT reach statically-supported on prose; class-specific vetoes MUST be enforced.
- **FR-026**: The publication taxonomy MUST distinguish, and be able to reach, all reference tiers/dispositions: reviewed, statically-supported, unresolved candidate, rejected candidate, incomplete scan, and legitimate clean scan (no collapsed or dead tiers presented as complete).
- **FR-027**: Reproduction/artifact manifests MUST be validated against candidate identities and the actual on-disk artifacts (entry references a known supported candidate; artifact exists and carries the candidate ID + location); unregistered artifacts and orphaned entries MUST be flagged.
- **FR-028**: Runtime reproduction / dynamic confirmation MUST NOT be claimed from static analysis; a positive fail-closed guard MUST require executor evidence before any dynamically-confirmed/reproduced state, independent of a hardcoded flag.

### US5 — Truthful completion, coverage, resume, regeneration

- **FR-029**: Each agent/unit MUST track its expected deliverable, actual valid output, stop reason, and error; the completion nudge MUST be keyed to the specific expected deliverable.
- **FR-030**: Valid partial hunt evidence MUST be preserved with per-unit attribution (partition/class, stop reason, error); the hunt MUST NOT be marked complete solely because one unit wrote output.
- **FR-031**: Coverage MUST identify the specific reviewed entry point, its disposition, and supporting review evidence; a bare file/route mention MUST NOT mark every route in that file reviewed; the enumeration denominator MUST match the reference (router prefixes, method defaults, websocket, test-file exclusion, dedup, subsystem rules); the review corpus scope MUST match the reference or its divergence be justified and recorded.
- **FR-032**: Explicit clean reviews (zero candidates) MUST remain valid and distinct from broken/empty runs.
- **FR-033**: Resume MUST validate saved outputs and identities (not merely file non-emptiness), rerun missing/invalid units, and include valid resumed work in effective completion.
- **FR-034**: Cancellation status MUST be retained across all phases including the final phase, distinct from abort and from endpoint failure.
- **FR-035**: Failure diagnostics and the actual provider/model/settings MUST be persisted so deterministic regeneration preserves status, provenance, evidence decisions, and artifact manifests; endpoint-failure reasons MUST survive regeneration and provider attribution MUST NOT be fabricated.

### US6 — Differential parity and regression coverage

- **FR-036**: A differential parity test MUST execute both implementations offline against shared source fixtures and equivalent scripted model/tool interactions.
- **FR-037**: It MUST compare normalized semantic outputs — dispatch scope, candidate identities and provenance, verification dispositions, publication tiers, coverage, handoffs, artifacts, and run status — normalizing only incidental timestamps, temporary roots, and ordering.
- **FR-038**: Filename/key existence checks MUST remain smoke tests and MUST NOT be labeled differential parity.
- **FR-039**: Regression scenarios MUST exist for: wrong-path/empty writes, a missing prompt, results-directory discovery, citations beyond the first Read page, failed hunt units, all-candidates-rejected, absent/contradictory source evidence, malformed verification decisions, preserved artifact manifests, resume, cancellation, regeneration after an endpoint failure, and split/samples/IaC option behavior. Each bug fix ships a regression test that fails before the fix.

### Cross-cutting constraints (preserved)

- **FR-040**: The static-only safety boundary, configured-endpoint routing (no silent provider/model fallback), loopback/allow-root server posture, and the three independent status axes MUST be preserved.
- **FR-041**: Implementation MUST remain in Go; Python is a test/reference dependency only.
- **FR-042**: Feature-004 behaviors (provider tool-call-parse classification, same-endpoint fresh-context repair, per-phase failure continuation, completion nudge) and their regression tests MUST be preserved.
- **FR-043**: Necessary additive schema changes MUST be documented rather than sacrificing evidence to preserve the current key set; existing artifact filenames and API paths MUST NOT be broken.
- **FR-044**: This feature is bounded to scanner execution, evidence, artifacts, and parity validation; unrelated UI redesign and auxiliary-command expansion are out of scope.
- **FR-045**: All validation is offline; live validation is operator-owned and MUST remain explicitly pending until the operator reports it; the harness MUST NOT initiate live scans.

### Key Entities

- **Agent assignment/task**: absolute repo path, results dir, assigned scope (partition + concrete routes), prior inputs, exact deliverable contract, adapted tool capabilities.
- **Partition/unit**: a scope of the target (from model plan, deterministic augmentation, or threat-model), with source provenance and coverage/uncovered accounting; a hunt unit is (partition × class × sample).
- **Candidate**: a hunt-proposed finding with a stable identity (function-owner + statement + CWE + location), provenance (which units/votes proposed it).
- **Evidence record**: immutable, candidate-bound, quote-matched source citation at a checked revision.
- **Verification decision / disposition**: supported / rejected / unresolved, with rationale, entry point, defenses, evidence IDs, and reconciliation status.
- **Publication tier / finding state**: reviewed / statically-supported / hypothesis; unresolved / rejected; incomplete / clean.
- **Coverage entry**: entry point + disposition + review evidence, against a faithful enumeration denominator.
- **Handoff**: supported-only phase-2b handoff and phase-3 assignment inputs consumed downstream.
- **Artifact manifest entry**: reproduction/PoC artifact bound to a supported candidate and an on-disk file.
- **Run status (three axes)**: execution / coverage / validation-mode, plus honest degradation reasons and persisted provenance for deterministic regeneration.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In the offline differential harness, the Go and Python implementations produce matching normalized semantic outputs across all enumerated dimensions (dispatch scope, candidate identities/provenance, verification dispositions, publication tiers, coverage, handoffs, artifacts, run status) on the shared fixture with equivalent scripted interactions.
- **SC-002**: The scanner distinguishes, on demonstrable offline cases, all five outcome classes — statically-supported findings, unresolved candidates, rejected candidates, incomplete scans, and legitimate clean scans — each reachable and each distinct on every status-bearing surface.
- **SC-003**: A zero-survivor verification yields zero supported findings with no raw-hunt resurrection and no promoted rejections (FR-C1); malformed/unsupported verification never yields confirmation (FR-C2).
- **SC-004**: `Read` supports paged, line-numbered reads and a citation beyond the first page resolves correctly; recursive globs match the reference and every returned path round-trips to `Read` regardless of CWD.
- **SC-005**: A finding backed only by a prose arrow / text field / confidence / sample agreement is never statically-supported; logic/uncovered classes retain explicit uncertainty.
- **SC-006**: Report regeneration preserves an existing non-empty artifact manifest (FR-C3) and preserves status, provenance (real backend/model), evidence decisions, and endpoint-failure reasons deterministically (FR-C6); no fabricated provider attribution appears.
- **SC-007**: A write to an empty/unrelated file neither marks produced nor suppresses the nudge (FR-C4); one hunt unit's output does not mark the whole hunt complete; per-unit attribution is recorded.
- **SC-008**: Coverage names the specific reviewed entry point, disposition, and evidence; a bare file mention does not mark all routes in that file reviewed; the enumeration denominator matches the reference on the shared fixture.
- **SC-009**: A fully-resumed run counts valid resumed work (not `incomplete`), reruns invalid units, and validates saved-output identity; a mid-run and final-phase cancellation reports `execution_status=cancelled` with artifacts finalized (FR-C5).
- **SC-010**: Exposed options change execution and the manifest reflects the executed mode: `hunt_samples=N` runs N merged samples, split mode dispatches the class split, IaC runs only when applicable, and a partition cap records uncovered scope rather than dropping it.
- **SC-011**: Every required regression scenario (FR-039) has an offline test that fails before the corresponding fix and passes after; feature-004 regression tests continue to pass.
- **SC-012**: All acceptance is offline; live validation remains explicitly pending until operator-reported. (Live parity does not require an exact Python finding count from stochastic scans.)
- **SC-013**: The spec's "remaining scanner simplifications" list is resolved or explicitly re-declared as deferred with justification; prior completion claims (in features 002–004 task-lists/comments) are corrected to match the resulting implementation.

## Remaining Scanner Simplifications (audit findings to resolve or explicitly defer)

Enumerated from the pre-spec audit; each is a place where Go currently diverges from the authoritative reference. This is the checklist FR-039/SC-013 track.

> **Resolution status (implementation, 2026-09-16).** RESOLVED: 1 (Read paging/line-numbers), 2 (glob fnmatch + absolute round-trip; Grep options + skip-dir), 3 (agent grounding), 4 (config-failure), 6 (class split + sink pass), 9 (verification manifest/session/reconcile/metrics), 10 (handoffs written + consumed), 11 (zero-survivor + malformed → fail-closed), 12 (source-grounded support + logic exclusion + XSS/CORS/weak-random veto; `reviewed` tier still folded into supported), 13 (artifact-manifest clobber fixed; full artifact *validation* pending), 14 (produced keyed to deliverable; AgentRecord attribution added), 15 (denominator: test-file exclusion + dedup; router-prefix/websocket/method-default and corpus-scope divergence documented), 16 (resume counts valid work), 17 (cancellation distinct), 18 (regeneration preserves backend + reasons), 7-partial (samples/votes + IaC gating + phase2_mode/manifest done; model partition-table parse deferred), 8-partial (breaker done; canary/budget deferred). DEFERRED (documented): 5 (model partition-table parse + augmentation), 19 (genuine Go-vs-Python differential harness — US6), plus artifact-manifest validation, the `reviewed` tier, and a positive dynamic-reproduction guard.

1. `Read`: no offset/limit paging, no line numbers, no binary/dir handling. *(US1)*
2. `Glob`: `filepath.Match` (no `**`), returns relative paths; `Grep`: only `pattern`, relative paths, ripgrep path omits skip-dir excludes. Round-trip to `Read` broken off-CWD; repo path never grounded. *(US1)*
3. Agent grounding: no absolute repo path, no "only writable location," no assignment header, no threat-model/SBOM/seed-route injection; scope is a bare subsystem string. *(US1/US2)*
4. Missing prompt/SKILL → placeholder agent run / dropped preamble, not a config failure. *(US1)*
5. Model partition plan never parsed; no corrective repartition; no coverage or threat-model augmentation; cap silently truncates (`subs[:max]`) with no uncovered-remaining. *(US2)*
6. No INJ/NAV/LOG class split (single generic agent per partition); `ClassGroups` dead; no sink-driven pass. *(US2)*
7. `iac_lens` carried but never runs; `hunt_samples` carried but single-pass (no merge/votes); `phase2_mode` has no flag/field, manifest hardcodes `"split"`, profile override discarded. *(US2)*
8. Budget cap, canary, and circuit breaker absent (record fields dead); serial only. *(US2)*
9. Candidate manifest built post-hoc (finalize), weak identity, never consumed; no evidence capture/submit, no reconciliation, no function context, no metrics; `VerificationStatus` never set. *(US3)*
10. No handoffs written (`phase2b_handoff.md` read by phase 3 but never produced). *(US3)*
11. Zero-survivor resurrection + malformed→confirmed promotion (`collectFindings` fallback; unconditional `StaticallySupported`). *(US3 — FR-C1/C2)*
12. Static support from surface signals; no source corroboration/class veto/logic-CWE exclusion/review records; tiers collapsed to {statically-supported, hypothesis} (`reviewed`, `rejected`, `dynamically_confirmed`/`reproduced` absent/dead). *(US4)*
13. Artifact/candidate manifests are placeholders (`artifact_manifest.json` always `[]`); no validation; finalize/regeneration clobber a real manifest with `[]`. *(US4 — FR-C3)*
14. `isSuccessfulWrite` ignores deliverable path/content; `AgentRecord` lacks expected/actual/error/provenance. *(US5 — FR-C4)*
15. Coverage: file-mention marks all routes in a file reviewed (shared with reference), but Go corpus scope narrower and enumeration denominator less faithful (no router prefixes/websocket, GET default vs ROUTE, no test-file exclusion, no dedup, coarse subsystem). *(US5)*
16. Resume validates only file non-emptiness; resumed phases not counted in completion → fully-resumed run computes `incomplete`. *(US5)*
17. Cancellation sets `aborted` (→ `execution_status=aborted`) and mislabels the in-flight cancelled agent as `endpoint_failure` with a spurious degraded reason. *(US5 — FR-C5)*
18. Regeneration fabricates `ollama` backend (no backend persisted) and loses endpoint-failure reasons (`EndpointFailures` is `json:"-"`; finalize doesn't convert `StopEndpointFailure`); served-model provenance dropped. *(US5 — FR-C6)*
19. `tests/parity/` is a Go-only filename/key smoke test with fake-tuned golden values; no Python execution/recorded fixtures; `internal/verification` has zero tests. *(US6)*

## Assumptions

- **Authoritative reference**: `../vhlocal/vhlocal/*.py` (sibling repo) is the behavioral oracle. The in-repo `vhlocal-go/vhlocal/*.py` copy is not authoritative.
- **Shared fixtures**: `testdata/vulnapp` and `testdata/ground_truth` are byte-identical across both repos and are the shared differential substrate.
- **Offline only**: all validation uses scripted providers/fakes; no live model, network, or paid service. Live validation is operator-owned and remains explicitly pending until reported (consistent with the standing operator constraint).
- **Python is a test/reference dependency only**; the delivered product remains the Go binary.
- **Additive schema is permitted**: where the current artifact key set cannot represent required evidence (e.g. per-unit attribution, verification decisions/metrics, persisted backend), additive fields/files are introduced and documented; existing filenames/API paths are not broken.
- **Feature-004 is preserved** and this spec builds on it.
- **Prior completion claims to correct**: features 002–004 task-lists and several Go source comments assert parity the implementation does not have (e.g. "parity with the Python quality battery," `ClassGroups` "mirrors … dispatch," `Phase2Mode: "split"`, `Regenerate` "deterministically … preserves," `isSuccessfulWrite` "produced the agent's deliverable"). These will be corrected to match the resulting implementation as part of SC-013.
- **Not required**: an exact Python finding count from stochastic live scans; per-agent parallelism is optional (concurrency is a performance, not evidence, concern) and may be deferred with justification.
- **Out of scope**: UI redesign and auxiliary-command (batch/bench/etc.) expansion beyond what evidence/parity requires.
