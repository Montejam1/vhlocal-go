---

description: "Task list for scanner parity and trustworthy evidence"
---

# Tasks: Restore functional scanner parity and trustworthy evidence

**Input**: Design documents from `/specs/005-scanner-parity-evidence/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/behavior.md, quickstart.md

**Tests**: REQUIRED — constitution Principle VII + spec FR-013/FR-036..039 + SC-011 + contracts/behavior.md. Each story leads with contract/regression tests that FAIL on the pre-fix code and pass after (TDD-first). **All validation is offline (scripted providers + fakes over `testdata/vulnapp`); no live model — live testing is the operator's.**

**Organization**: By user story in priority order — US1 grounding+tools (P1), US2 hunt orchestration (P2), US3 verification+handoffs (P3), US4 publication+artifacts (P4), US5 truthful completion/coverage/resume/regen (P5), US6 differential parity (P6). The six **correctness-critical Evidence-Integrity fixes** (FR-C1..C6) live inside US3/US4/US5 but each has a minimal, standalone task that can be **fast-tracked** ahead of the full story work (see Implementation Strategy). Grounded in the six-area audit. Schema changes are additive (FR-043); feature-004 behaviors/tests are preserved.

## Format: `[ID] [P?] [Story] Description`
- **[P]** = different file, no dependency on an incomplete task.
- Same-file tasks serialize. Heavy shared files: `internal/tools/tools.go`, `internal/engine/engine.go`, `internal/engine/helpers.go`, `internal/consolidate/consolidate.go`.

---

## Phase 1: Setup (shared test infrastructure)

- [ ] T001 [P] Define the shared interaction-transcript schema + loader in `tests/parity/transcript/` (JSON: list of `{when:{phase,turn,contains?}, assistant:{content?,tool_calls?[]}}`; tool *results* come from the real sandbox tools over `testdata/vulnapp`, not scripted) (research R1/R2).
- [ ] T002 [P] Add a Go `transcriptProvider` implementing `client.Provider` in `tests/parity/transcript_provider.go` that replays a transcript and records the requests it saw.
- [ ] T003 [P] Add normalization helpers in `tests/parity/normalize.go` (strip timestamps, temp roots, and absolute-path prefixes → `<REPO>`/`<RESULTS>`; stable list ordering) (C-6a).
- [ ] T004 [P] Scaffold the opt-in reference generator in `tests/parity/genref/` (Python `TranscriptClient` + a `main` that subprocesses `../vhlocal` on a transcript and emits normalized semantic golden JSON to `tests/parity/golden/`); NOT run by `go test ./...` (research R1).
- [ ] T005 [P] Add a `Makefile` target `goldens` that runs the genref generator, and confirm `testdata/vulnapp` is the shared fixture (byte-identical to the reference copy).

---

## Phase 2: Foundational (blocking prerequisites — block the user stories)

- [X] T006 [P] In-repo fnmatch→regexp glob translator in `internal/tools/glob.go` (stdlib only: `*`→`.*` spanning `/`, `?`→`.`, `[...]` classes, else escaped, anchored full-match) (research R3; blocks US1).
- [X] T007 Additive schema in `internal/engine/record.go`: `AgentRecord` gains `expected_deliverable`, `wrote_files[]`, `produced`, `error`, `error_kind`, `partition`, `vuln_class`; `RunRecord` gains serialized `backend` and serialized `endpoint_failures` (replace feature-004 `json:"-"`); keep all existing keys (data-model §Additive schema; blocks US5).
- [ ] T008 `agent.Result` gains `WroteFiles[]`, `Error`, `ErrorKind`; `agent.Config` carries the absolute repo root + assigned scope; provider provenance is retained (not discarded) through `recordAgent` in `internal/agent/agent.go` + `internal/engine/helpers.go` (blocks US1/US5).
- [X] T009 Verification tool-envelope scaffolding in `internal/agent/agent.go`: a SEPARATE read-only envelope adding `capture_evidence` + `submit_verification` tool schemas (hunt envelope unchanged; no shell/exec) (blocks US3; C-X3).

**Checkpoint**: shared harness + additive types + glob + verification envelope exist; user stories can begin.

---

## Phase 3: User Story 1 — Grounded assignments and usable file tools (P1) 🎯 MVP

**Goal**: agents get full grounding and file tools that support file:line citation, recursive globs, and round-tripping paths; missing methodology fails loudly.

**Independent Test**: offline, drive the tools + a scripted agent over `testdata/vulnapp` (contracts C-1a..f).

- [X] T010 [P] [US1] Read paging + line-number tests (C-1a) in `internal/tools/tools_test.go`: offset/limit, `%6d\t` line numbers, continuation hint, a citation past the first page resolves; also assert the existing Read output cap (`MaxReadLines`) still holds after the rewrite (FR-008 preserve).
- [X] T011 [P] [US1] Glob recursion + absolute round-trip tests (C-1b) in `internal/tools/tools_test.go`: `**/*.py` matches nested files; every returned path is absolute and readable from any CWD.
- [X] T012 [P] [US1] Grep options + skip-dir + absolute-path tests (C-1c) in `internal/tools/tools_test.go`: path/glob/ignore_case/files_with_matches; skip-dirs excluded on both rg and fallback; also assert the existing Grep output caps (`MaxGrepMatches` + per-file cap) still hold after the rewrite (FR-008 preserve).
- [X] T013 [P] [US1] `buildTask` grounding test (C-1d) in `internal/engine/helpers_test.go`: task contains absolute repo path, results dir, scope+routes, inputs, exact deliverable.
- [X] T014 [P] [US1] Sandbox tests (C-1e) in `internal/tools/tools_test.go`: write via a symlinked results parent is confined; write to a harness-owned artifact is refused.
- [X] T015 [P] [US1] Missing prompt/SKILL config-failure test (C-1f) in `internal/engine/engine_test.go`: no placeholder run; explicit surfaced+recorded failure.
- [X] T016 [US1] Implement Read offset/limit + line-numbered output + continuation + binary/dir handling in `internal/tools/tools.go` (FR-003).
- [X] T017 [US1] Glob uses `glob.go`, returns absolute paths, resolves relatives against `read_roots[0]` (repo root) in `internal/tools/tools.go` (FR-005/006).
- [X] T018 [US1] Grep gains path/glob/ignore_case/files_with_matches, skip-dir excludes on rg AND fallback, absolute paths in `internal/tools/tools.go` (FR-004/006).
- [X] T019 [US1] `resolveWrite` symlink-parent resolution + harness-owned-artifact write guard in `internal/tools/tools.go` (FR-007).
- [X] T020 [US1] Read tool schema gains `offset`/`limit` in `internal/agent/agent.go` (FR-003).
- [X] T021 [US1] `buildTask` emits absolute repo path + writable-location + scope/routes + framed inputs + deliverable contract in `internal/engine/helpers.go` (FR-001/002).
- [X] T022 [US1] Missing/unreadable prompt or SKILL → explicit configuration failure (no placeholder, no silently-dropped preamble) in `internal/engine/engine.go` + `internal/engine/skill.go` (FR-009).

**Checkpoint**: tools support the methodology's citation/glob/round-trip assumptions; US1 tests green.

---

## Phase 4: User Story 2 — Harness-controlled hunt orchestration (P2)

**Goal**: run the reference hunt methodology (model partitions + augmentation + uncovered accounting; class split + sink + IaC; samples/votes; canary/breaker) with options that actually execute and a truthful manifest.

**Independent Test**: offline scripted providers (contracts C-2a..f).

- [ ] T023 [P] [US2] Partition resolution tests (C-2a) in `internal/phases/partition_test.go`: model-table used; malformed → one repartition → deterministic fallback; `partition_source` recorded.
- [X] T024 [P] [US2] Augmentation + cap tests (C-2b) in `internal/phases/partition_test.go` + `internal/inventory/inventory_test.go`: omitted routes appended; over-cap scope in `coverage_uncovered_remaining` (never dropped).
- [X] T025 [P] [US2] Class-split + sink + executed-mode tests (C-2c) in `internal/engine/hunt_test.go`: split dispatches (partition × INJ/NAV/LOG) with shared+class prompts + sink pass; manifest `phase2_mode` == executed mode.
- [X] T026 [P] [US2] Sample merge + votes tests (C-2d) in `internal/engine/votes_test.go`: N samples merged by block identity; `hunt_votes.json` provenance; recorded count == executed.
- [X] T027 [P] [US2] IaC gating tests (C-2e) in `internal/engine/hunt_test.go`: IaC runs only when IaC present; not claimed otherwise.
- [ ] T028 [P] [US2] Canary/breaker/budget tests (C-2f) in `internal/engine/hunt_test.go`: halt records reason; run honestly incomplete; cancellation excluded from breaker.
- [ ] T029 [US2] `internal/phases/partition.go`: parse model partition table + one corrective repartition + deterministic fallback; record `partition_source`/`partition_fallback`/`partition_parse_error` (FR-010).
- [ ] T030 [US2] Coverage + threat-model augmentation in `internal/phases/partition.go`; populate `coverage_partitions_added`/`coverage_files_added`/`threat_model_partitions` (FR-011).
- [X] T031 [US2] `internal/inventory/inventory.go`: cap records `coverage_uncovered_remaining` (remove silent `subs[:max]`); denominator fidelity — router/blueprint prefixes, method defaults→`ROUTE`, websocket, test-file exclusion, dedup, security subsystem rules (FR-012, FR-031 denominator).
- [X] T032 [US2] `internal/engine/hunt.go` (extract from `helpers.runFanOut`): class split (shared+per-class) + combined mode + sink-driven pass (FR-013).
- [X] T033 [US2] `internal/engine/votes.go`: N-sample loop + merge by block identity + `hunt_votes.json` (FR-015).
- [X] T034 [US2] IaC gating (`_has_iac`) + IaC pass in `internal/engine/hunt.go` (FR-014).
- [ ] T035 [US2] Canary preflight + circuit breaker + budget cap; record `hunt_halted_reason`/`budget_*` in `internal/engine/hunt.go` (FR-016).
- [X] T036 [US2] `ScanSpec.Phase2Mode` + `--phase2-mode` flag + profile override handler (`internal/cli/run.go`); manifest `phase2_mode` = executed mode + real backend (`internal/manifest/manifest.go`, `internal/engine/engine.go`) (FR-017).

**Checkpoint**: hunt runs the methodology; options affect execution; manifest is truthful; US2 tests green.

---

## Phase 5: User Story 3 — Structured adversarial verification and handoffs (P3) — contains FR-C1/C2

**Goal**: a candidate-bound, fail-closed verifier with dispositions, evidence, metrics, and handoffs; no resurrection, no malformed→confirmed.

**Independent Test**: offline scripted verification providers (contracts C-3a..e, C-C1, C-C2).

- [X] T037 [P] [US3] Candidate-manifest-before-2b + identity tests (C-3a) in `internal/verification/manifest_test.go`.
- [X] T038 [P] [US3] `capture_evidence` quote-match/immutability tests (C-3b) in `internal/verification/evidence_test.go`.
- [X] T039 [P] [US3] Reconcile disposition-completeness + function-context + revision tests (C-3c) in `internal/verification/reconcile_test.go`.
- [X] T040 [P] [US3] Decisions/metrics/reconciliation written + harness-owned tests (C-3d) in `internal/verification/reconcile_test.go`.
- [X] T041 [P] [US3] Handoffs written + consumed tests (C-3e) in `internal/verification/handoff_test.go` + `internal/engine/engine_test.go`.
- [X] T042 [P] [US3] Zero-survivor no-resurrection (C-C1) + malformed→unresolved (C-C2) tests in `internal/engine/verify_flow_test.go` (must FAIL pre-fix).
- [X] T043 [US3] **[FR-C1/C2 fast-track]** `collectFindings` consumes verification decisions, NEVER falls back to raw `results/*.md`, and treats absent/malformed/empty decisions as zero-supported (no promotion) in `internal/engine/helpers.go` + `internal/engine/engine.go`.
- [X] T044 [US3] `internal/verification/manifest.go`: build candidate manifest BEFORE 2b with the line-shift/prose-insensitive identity (normalized function-owner + statement digest + CWE + path) (FR-018).
- [X] T045 [US3] `internal/verification/session.go`: per-candidate fresh session; `capture_evidence` + `submit_verification`; one candidate/session, `max_failures=3` (FR-019/020).
- [X] T046 [US3] `internal/verification/evidence.go`: quote byte-match live source, cover cited location, revision/identity check; immutable `EV-<sha>` (FR-019).
- [X] T047 [US3] `internal/verification/reconcile.go`: iterate all candidates → supported/rejected/unresolved with function/defense context + quality battery; write `verification_decisions.json`/`verification_metrics.json`/`verification_reconciliation.json`; harness-owned outcome (FR-020/021/022).
- [X] T048 [US3] `internal/verification/handoff.go`: `phase2b_output.md` (dispositions + "does not imply confirmation" note) + `phase2b_handoff.md` (supported-only) + phase-3 assignments + zero-verified sentinel (FR-023).
- [X] T049 [US3] Engine wires 2b to the verification session and feeds phase 3 the handoff in `internal/engine/engine.go` (FR-023).

**Checkpoint**: every candidate has an evidence-backed disposition; handoffs flow; no resurrection/confirmation defects; US3 tests green.

---

## Phase 6: User Story 4 — Source-grounded publication and artifact validation (P4) — contains FR-C3

**Goal**: static support requires real source corroboration or a supported decision; full tier taxonomy; validated, non-clobbered artifact manifests; no static dynamic-claims.

**Independent Test**: offline (contracts C-4a..e, C-C3).

- [X] T050 [P] [US4] Source-corroboration/class-veto/logic-CWE tests (C-4a/b) in `internal/consolidate/quality_test.go`.
- [X] T051 [P] [US4] Tier-taxonomy reachability tests (C-4c) in `internal/consolidate/consolidate_test.go`.
- [ ] T052 [P] [US4] `validate_artifacts` tests (C-4d) in `internal/verification/artifacts_test.go`.
- [X] T053 [P] [US4] Artifact-manifest preservation on finalize+regenerate tests (C-C3) in `internal/engine/regenerate_test.go` (must FAIL pre-fix).
- [ ] T054 [P] [US4] Dynamic-state fail-closed test (C-4e) in `internal/consolidate/status_test.go`.
- [X] T055 [US4] **[FR-C3 fast-track]** `finalize`/`Regenerate` never overwrite an existing non-empty `artifact_manifest.json` (write `[]` only on legitimate zero-verified skip) in `internal/engine/engine.go` + `internal/engine/regenerate.go`.
- [X] T056 [US4] `internal/consolidate/quality.go`: source-corroboration (open cited file, match CWE-family sink) + per-class veto + logic-CWE exclusion + retain uncertainty for uncovered/unavailable (FR-024/025).
- [ ] T057 [US4] `internal/consolidate/consolidate.go`: full tier taxonomy (reviewed/statically_supported/hypothesis; rejected; states) driven by verification decisions/review records, not surface signals (FR-026).
- [ ] T058 [US4] `internal/verification/artifacts.go`: `validate_artifacts` against candidate identity + on-disk files; flag unregistered/orphaned (FR-027).
- [ ] T059 [US4] `internal/consolidate/status.go`: `apply_validation` requires executor evidence for dynamic/reproduced (positive fail-closed guard) (FR-028).

**Checkpoint**: publication is source-grounded; manifests validated + preserved; US4 tests green.

---

## Phase 7: User Story 5 — Truthful completion, coverage, resume, regeneration (P5) — contains FR-C4/C5/C6

**Goal**: produced/coverage/resume/cancellation/regeneration all tell the truth.

**Independent Test**: offline (contracts C-5a..d, C-C4, C-C5, C-C6).

- [ ] T060 [P] [US5] Produced-keyed-to-deliverable + nudge tests (C-C4/C-5a) in `internal/agent/agent_test.go` (must FAIL pre-fix).
- [ ] T061 [P] [US5] Per-unit attribution + partial-hunt tests (C-5b) in `internal/engine/hunt_test.go`.
- [X] T062 [P] [US5] Coverage entry-point/evidence + denominator tests (C-5c) in `internal/inventory/inventory_test.go`.
- [X] T063 [P] [US5] Resume validates identity + counts resumed work tests (C-5d) in `internal/engine/engine_test.go`.
- [X] T064 [P] [US5] Cancellation-stays-cancelled tests (C-C5) in `internal/engine/engine_test.go` (must FAIL pre-fix).
- [X] T065 [P] [US5] Regeneration preserves backend + endpoint reasons tests (C-C6) in `internal/engine/regenerate_test.go` (must FAIL pre-fix).
- [X] T066 [US5] **[FR-C4 fast-track]** `isSuccessfulWrite` keyed to `DeliverablePath` + non-empty; nudges key off the specific missing deliverable in `internal/agent/agent.go`.
- [X] T067 [US5] **[FR-C5 fast-track]** Cancellation: don't set `rec.Aborted`; a cancelled in-flight agent returns a `cancelled` stop reason and is not marked `endpoint_failure` / no endpoint degradation reason (`internal/engine/engine.go`, `internal/engine/helpers.go`, `internal/agent/agent.go`).
- [X] T068 [US5] **[FR-C6 fast-track]** Regeneration: persist+restore real `backend`/served model/provenance; serialized `endpoint_failures`; convert persisted `endpoint_failure` stop reasons → degradation reasons at finalize (`internal/engine/regenerate.go`, `internal/engine/engine.go`, `internal/engine/helpers.go`).
- [X] T069 [US5] `recordAgent` persists per-unit attribution (partition/vuln_class/expected/wrote/error/provenance); failed hunt units get placeholders in `internal/engine/helpers.go` + `internal/engine/hunt.go` (FR-029/030).
- [X] T070 [US5] Coverage names the specific entry point + disposition + evidence; corpus scope matches the reference (include phase1/2b/3/3d/README) or records the divergence in `internal/inventory/inventory.go` + `internal/engine/helpers.go` (readHuntOutput) (FR-031/032).
- [X] T071 [US5] Resume validates saved-output identity + verification/artifact contract, reruns invalid units, counts valid resumed work in effective completion in `internal/engine/engine.go` + `internal/consolidate/status.go` (FR-033).

**Checkpoint**: status is believable across resume/regeneration; US5 tests green.

---

## Phase 8: User Story 6 — Differential parity and regression coverage (P6)

**Goal**: parity proven by semantic differential, not filename smoke; full regression scenario set.

**Independent Test**: the differential test + the FR-039 scenarios (contracts C-6a/b/c).

- [ ] T072 [P] [US6] Relabel the filename/JSON-key checks as a smoke test in `tests/parity/parity_test.go` (FR-038).
- [ ] T073 [US6] Differential test in `tests/parity/differential_test.go`: run the Go engine on the shared transcript and compare normalized semantics (dispatch scope, candidate identities/provenance, dispositions, tiers, coverage, handoffs, artifacts, run status) to committed goldens (FR-036/037, C-6a).
- [ ] T074 [P] [US6] Seeded-divergence test that fails and names the diverging dimension in `tests/parity/differential_test.go` (C-6b).
- [ ] T075 [US6] Generate + commit goldens via `make goldens` (genref); document regeneration in `tests/parity/README.md` (C-6a).
- [ ] T076 [P] [US6] Opt-in `-tags pythonref` live Go-vs-Python variant in `tests/parity/pythonref_test.go` (C-6c).
- [ ] T077 [P] [US6] Regression sweep: ensure every FR-039 scenario has a failing-before test (fill gaps not already covered by US1–US5: results-dir discovery, citations-beyond-first-page, contradictory source evidence) across the touched `internal/*_test.go` (FR-039).

**Checkpoint**: differential parity is the gate; every required scenario covered.

---

## Phase 9: Polish & cross-cutting

- [ ] T078 [P] Run the full offline gate `go test ./...` (incl. `tests/parity/`) — all green; `go vet ./...` + `gofmt -l .` clean.
- [ ] T079 [P] Update the feature-004 parity/key-set guard to allow the additive keys; confirm the feature-004 suite stays green (C-X1/C-X2) in `tests/parity/` + `internal/engine/*_test.go`.
- [ ] T080 [P] Correct prior completion claims (SC-013): fix over-stated Go source comments (e.g. `tools.go` "parity", `phases.go` ClassGroups "mirrors dispatch", `regenerate.go` "preserves", `agent.go` `isSuccessfulWrite`) and update `CHANGELOG.md` + `README.md`/`RUNBOOK.md`.
- [ ] T081 Resolve or explicitly defer each of the 19 remaining simplifications in `spec.md` (SC-013): mark resolved or deferred-with-justification.
- [X] T083 [P] Preserve-invariant regression (FR-040, C-X3) in `internal/server/*_test.go` + `internal/consolidate/status_test.go`: assert loopback-default bind with non-loopback requiring the explicit unsafe opt-in, scan-root allow-listing / results-dir read confinement, configured-endpoint-only routing (no provider/model fallback), and that all three status axes are present and independent on every status-bearing surface.
- [ ] T082 Operator-owned live validation (NOT executed by the harness): the operator confirms SC-002/SC-012 on a live endpoint. Leave unchecked until the operator reports results.

---

## Dependencies & Execution Order

- **Setup (T001–T005)** → **Foundational (T006–T009)** → stories.
- **US1 (T010–T022)**: tests (T010–T015) first; T016–T020 are `internal/tools/tools.go`/`agent.go` (T016–T019 serialize on `tools.go`); T021 (`helpers.go`), T022 (`engine.go`/`skill.go`). MVP.
- **US2 (T023–T036)**: tests first; T029/T030 (`partition.go`) serialize; T031 (`inventory.go`); T032/T034/T035 (`hunt.go`) serialize; T033 (`votes.go`); T036 (`cli`/`manifest`/`engine`). Needs US1 grounding (T021) for scope-in-task.
- **US3 (T037–T049)**: tests first; T043 (fast-track) standalone; T044–T048 new `internal/verification/*` files (mostly `[P]`); T049 (`engine.go`). Full fidelity needs US1 tools (evidence paging) and US2 candidates.
- **US4 (T050–T059)**: tests first; T055 (fast-track) standalone; consumes US3 decisions for full fidelity.
- **US5 (T060–T071)**: tests first; T066/T067/T068 (fast-track) standalone; T069–T071 use US2 attribution + US3/US4 contracts.
- **US6 (T072–T077)**: after the stories produce comparable semantics; T073/T075 serialize (goldens before diff).
- **Polish (T078–T082)** last; T082 operator-owned.

### Parallel opportunities
- All of Phase 1 (`[P]`) and T006/T009 in Phase 2. All test tasks within a story (`[P]`). Across stories after Foundational, US1 and US2 can proceed together; `internal/verification/*` new files (T044–T048) parallelize. Same-file edits serialize (`tools.go`, `engine.go`, `helpers.go`, `consolidate.go`, `hunt.go`, `partition.go`).

---

## Implementation Strategy

### Correctness-critical fast-track (Evidence Integrity — ship first)
The six FR-C fixes are the highest-value, lowest-cost slice and each has a **standalone** task with minimal dependencies:
- **T042 → T043** (FR-C1/C2): stop raw-hunt resurrection + malformed→confirmed — needs only "treat absent/malformed decisions as zero-supported."
- **T053 → T055** (FR-C3): stop artifact-manifest clobber.
- **T060 → T066** (FR-C4): produced keyed to the declared deliverable.
- **T064 → T067** (FR-C5): cancellation stays `cancelled`.
- **T065 → T068** (FR-C6): regeneration preserves backend + endpoint reasons (depends on the T007 serialized fields).
Deliver this slice (tests-first) immediately after Phase 2 as a hardening increment, then proceed with the full stories.

### MVP and incremental delivery
1. Setup + Foundational.
2. **Fast-track FR-C1..C6** (hardening MVP — stops the active honesty defects).
3. **US1** (grounding + tools) — the functional MVP everything else depends on.
4. US2 → US3 → US4 → US5 in priority order, each independently testable.
5. **US6** locks parity + regression; then Polish.

### Governance
No constitution deviation beyond the three tracked in plan.md (Python test-dep, heuristic identity, deferred concurrency). Every fix ships a failing-before offline test (SC-011). The harness performs no live-endpoint calls; T082 live validation is the operator's.

## Notes
- Reference: authoritative Python `../vhlocal/vhlocal/`; shared fixture `testdata/vulnapp` (byte-identical across repos).
- Reuse feature-004's same-endpoint repair; do not add a second repair mechanism.
- Honesty-critical throughout (Principle I/II): never publish unsupported/rejected as confirmed; never fabricate provenance; never drop uncovered scope.
