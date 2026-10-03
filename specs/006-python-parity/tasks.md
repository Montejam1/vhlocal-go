---

description: "Task list for meeting semantic parity with the Python reference (Go-only)"
---

# Tasks: Meet semantic parity with the Python reference (vhlocal)

**Input**: Design documents from `/specs/006-python-parity/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/behavior.md, quickstart.md

**Tests**: REQUIRED — constitution Principle VII + FR-015 + SC-006. Each divergence ships a Go regression test that FAILS on the pre-fix code. **No Python is used anywhere** (per operator: they have run the Python reference many times and judge parity by recognition). Parity behavior is pinned by Go tests that encode the reference methodology on the shared `testdata/vulnapp` fixture; the operator validates final parity by running the Go app. All validation is offline; no live model.

**Organization**: By user story in priority order — US1 partition parity (P1), US2 parity behavior tests (P1, the Go-only regression gate), US3 verification/publication fidelity (P2), US4 coverage/artifacts/orchestration (P3). Parity = SEMANTIC equivalence with the reference behavior (compared by normalized identity), judged finally by the operator. Additive-only schema; feature-005 behaviors/tests preserved.

## Format: `[ID] [P?] [Story] Description`
- **[P]** = different file, no dependency on an incomplete task.
- Heavy shared files serialize: `internal/engine/engine.go`, `internal/engine/hunt.go`, `internal/inventory/inventory.go`, `internal/consolidate/corroborate.go`, `internal/phases/partition.go`, `tests/parity/*`.

---

## Phase 1: Setup (Go-only parity-test infrastructure)

- [X] T001 [P] Define the response-rule transcript schema + loader in `tests/parity/transcript/` (JSON: rules `{match:{phase,partition?,class?,candidate_id?}, response:{content?,writes?[],tool_calls?[]}}`) per data-model §Transcript. Go-only.
- [X] T002 [P] Add the Go `transcriptProvider` in `tests/parity/transcript_provider.go` implementing `client.Provider`: extract `(phase, partition, class, candidate norm_id)` from the grounded request and return the matched rule's response; advance sub-steps (capture→submit) by per-session call count; an unmatched request errors loudly.
- [X] T003 [P] Add the semantic **projector** in `tests/parity/project.go`: reduce a results dir to canonical JSON (dispatch, candidates by `norm_id`, dispositions, tiers, coverage, handoffs/artifacts presence, run_status) per data-model §Semantic projection; `norm_id = sha1(normPath+":"+lineBucket+":"+CWE)`.
- [X] T004 [P] Add normalization + comparator in `tests/parity/compare.go`: strip timestamps/temp-abs-paths/ordering/raw `CAND-` ids; diff two projections and return the diverging dimensions/candidates.
- [X] T005 [P] Add a small Go helper `tests/parity/projctl/main.go` that prints a results dir's projection JSON (to author/review expected goldens) and confirm `testdata/vulnapp` is the shared fixture.

---

## Phase 2: Foundational (blocking prerequisites)

- [X] T006 [P] Partition types in `internal/phases/partition.go`: `Partition`, `PartitionResolution{partitions,source,fallback,parse_error,collapsed}`, `CoverageAugmentation{partitions,added,added_files,uncovered_remaining}` (data-model §Partition entities; blocks US1).

**Checkpoint**: Go-only transcript/provider/projector/comparator + partition types exist; user stories can begin.

---

## Phase 3: User Story 1 — Partition parity (P1) 🎯 MVP

**Goal**: the hunt fans out over the model's Phase-1 partition plan (with corrective retry, augmentation, uncovered accounting), not one collapsed partition.

**Independent Test**: offline, feed a recon output with/without a partition table (contracts C-1a..d).

- [X] T007 [P] [US1] Partition-parse tests in `internal/phases/partition_test.go` (fail pre-fix): C-1a valid table → partitions + `source=model_table`; C-1b malformed → one repartition (>1 ⇒ `model_retry`) else `deterministic`/`single_fallback` with `parse_error`/`collapsed`; C-1c omitted routes augmented + over-cap → `uncovered_remaining`.
- [X] T008 [US1] `internal/phases/partition.go`: `parsePartitionTable` (tolerant heading+`|`-rows+`SG-N`), `parsePartitionJSON`, `resolvePartitions` (table → corrective retry → deterministic → single), recording source/fallback/collapsed/parse_error (FR-001/002).
- [X] T009 [US1] `internal/phases/partition.go`: `augmentForCoverage` (append coverage partitions for omitted route files; cap → uncovered) + `augmentFromThreatModel` (additive PASTA partitions) (FR-003).
- [X] T010 [US1] `internal/inventory/inventory.go`: `DeterministicPartitions` (subsystem partitions carrying their concrete routes) + a `collapsed`/whole-repo check, for the fallback path (FR-002).
- [X] T011 [US1] `internal/engine/engine.go`: resolve partitions from `phase1_output.md` before Phase 2 (replacing the pre-hunt `FallbackPartitions` call); the corrective repartition is one fresh-context Chat (reuse the `repairFromRaw`-style same-endpoint call); populate `partition_source`/`partition_fallback`/`partition_parse_error`/`partition_collapsed`/`coverage_*`/`threat_model_partitions` (FR-001/002/003).
- [X] T012 [US1] `internal/engine/hunt.go`: dispatch over the resolved partitions (each × class split) and put each partition's concrete routes into the hunt task's assigned scope (FR-001, C-1d).

**Checkpoint**: the hunt covers the model's plan; US1 tests green.

---

## Phase 4: User Story 2 — Parity behavior tests (P1, Go-only regression gate)

**Goal**: Go tests pin the semantic behavior to the reference methodology on the shared fixture, so divergences are caught mechanically and regressions prevented — the operator is the final parity judge (no Python).

**Independent Test**: the parity-behavior test on `testdata/vulnapp` (contracts C-D1..D5, Go-only).

- [X] T013 [US2] Author the shared transcript for `testdata/vulnapp` in `tests/parity/transcript/vulnapp.json`: a recon partition table (exercises US1), per (partition×class) hunt candidates, and per-candidate verify evidence+verdicts — enough to drive the engine through all phases.
- [X] T014 [US2] Author the committed EXPECTED semantic projection `tests/parity/golden/vulnapp.json` encoding the reference's expected dispatch / candidates (norm_id) / dispositions / tiers / coverage / run-status on the fixture — **derived from the reference CODE (`../vhlocal/vhlocal/`), not a Python run**; document its provenance in `tests/parity/README.md` (FR-004/005).
- [X] T015 [US2] Parity-behavior test in `tests/parity/parity_behavior_test.go` (`TestParityBehavior`): run the Go engine on the transcript over `testdata/vulnapp`, project it, and assert it equals the expected projection across every dimension (C-D1).
- [X] T016 [P] [US2] Seeded-divergence test in `tests/parity/parity_behavior_test.go`: a variant transcript that flips a verdict / drops a candidate / changes a tier makes the projection differ from expected, and the comparator names the diverging dimension+candidate (FR-007, C-D2).
- [X] T017 [P] [US2] Comparator-normalization test in `tests/parity/compare_test.go`: incidental differences (timestamps/temp paths/ordering/raw ids) do NOT fail; a semantic difference does (FR-006, C-D3).
- [X] T018 [P] [US2] Transcript-completeness test in `tests/parity/parity_behavior_test.go`: the provider errors loudly on a request it has no rule for, so the fixture can't silently under-exercise a phase (C-D5).

**Checkpoint**: the parity-behavior gate passes on the shared fixture and catches seeded divergences. Remaining stories close whatever it (or the operator's recognition) flags.

---

## Phase 5: User Story 3 — Verification & publication fidelity (P2)

**Goal**: Go verdicts and tiers equal the reference's on identical evidence.

**Independent Test**: offline per-class evidence (contracts C-3a..d).

- [X] T019 [P] [US3] Function-context + authz tests in `internal/verification/verification_test.go` (fail pre-fix): C-3a supported needs evidence covering the complete containing function; C-3b supported access-control needs entry_point == resolved route guard.
- [X] T020 [P] [US3] Battery-tier parity tests in `internal/consolidate/corroborate_test.go`: C-3c each class (SQLi, XSS HTML-vs-JSON, CORS, weak-random, SSTI-constant, access-control) reaches the reference tier; C-3d a review record → `reviewed`.
- [X] T021 [US3] `internal/verification/verification.go`: compute the enclosing function span (bracket/indentation scan) and require the evidence line-ranges to cover it for a supported verdict (FR-009).
- [X] T022 [US3] Authz entry-point match on a supported access-control verdict (reuse `internal/authz` route-guard resolution) in `internal/verification/verification.go` (+ `internal/verification/authz.go` if a thin adapter is needed) (FR-010).
- [X] T023 [US3] `internal/consolidate/corroborate.go`: add SSTI constant-template refutation + access-control NA handling + class-primary evidence per the reference; wire into the veto/gate (FR-011).
- [X] T024 [US3] `internal/consolidate/consolidate.go`: the distinct `reviewed` tier from a validated review record (above `statically_supported`) (FR-011).

**Checkpoint**: verdicts/tiers are reference-equal; US3 tests green; the parity-behavior gate still passes.

---

## Phase 6: User Story 4 — Coverage, artifacts, orchestration (P3)

**Goal**: coverage denominator, artifact validation, and hunt safety controls match the reference.

**Independent Test**: offline (contracts C-4a..c).

- [X] T025 [P] [US4] Denominator test in `internal/inventory/inventory_test.go` (fail pre-fix): router/blueprint prefixes applied, websocket routes included, method-less `route`/`api_route` → `ROUTE` (C-4a).
- [X] T026 [P] [US4] Artifact-validation test in `internal/verification/artifacts_test.go`: entry↔supported-candidate↔on-disk-file binding; unregistered/orphaned flagged; real manifest never clobbered (C-4b).
- [X] T027 [P] [US4] Canary/budget test in `internal/engine/hunt_test.go`: a canary failure / budget trip halts with a recorded reason (C-4c).
- [X] T028 [US4] `internal/inventory/inventory.go`: resolve `APIRouter(prefix=…)`/`Blueprint` prefixes, add websocket routes, default method-less routes to `ROUTE` (FR-012).
- [X] T029 [US4] `internal/verification/artifacts.go`: `ValidateArtifacts` (bind to supported candidates + on-disk files; flag unregistered/orphaned); wire into finalize/load without clobbering (FR-013).
- [X] T030 [US4] `internal/engine/hunt.go`: hunt canary preflight (a cheap same-endpoint Chat before fan-out) + budget cap where configured, recording `hunt_halted_reason`/`budget_*` (FR-014).
- [X] T031 [US4] Reconcile the review corpus to the reference in `internal/engine/helpers.go` (readHuntOutput) ONLY if a coverage disposition on the fixture differs from the reference; otherwise record the justified divergence (FR-012). **Recorded divergence (no change made):** the coverage denominator now matches the reference route enumeration after T028 (router/blueprint prefixes, websocket routes, method-less `route`/`api_route` → `ROUTE`); with the standing no-Python constraint there is no measured coverage-disposition difference on `testdata/vulnapp` to reconcile, so `readHuntOutput` is left unchanged. The operator (T034) is the final coverage-parity judge.

---

## Phase 7: Polish & cross-cutting

- [X] T032 [P] Run the full offline gate `go test ./...` (incl. `tests/parity/`) — all green; `go vet ./...` + `gofmt -l .` clean; feature-005 suite green (C-X2).
- [X] T033 [P] Confirm additive-only schema (no key removed/renamed; populate declared partition fields) via a scan_meta top-level-key check (C-X1); CHANGELOG.md entry.
- [ ] T034 Operator-owned live validation (NOT executed by the harness): the operator runs the live Go scan and recognizes whether dispatch/dispositions/coverage track the Python reference they know (SC-007). Leave unchecked until the operator reports results.

---

## Dependencies & Execution Order

- **Setup (T001–T005)** → **Foundational (T006)** → stories.
- **US1 (T007–T012)**: T007 (tests) first; T008/T009 (`partition.go`) serialize; T010 (`inventory.go`); T011/T012 (`engine.go`/`hunt.go`). MVP.
- **US2 (T013–T018)**: needs US1 (partition table in the transcript) + Setup provider/projector/comparator. T013→T014→T015 (transcript→golden→test) serialize; T016–T018 `[P]`. Go-only regression gate.
- **US3 (T019–T024)**: tests first; `verification.go` (T021/T022) serialize; `corroborate.go`/`consolidate.go` for the battery. Verified by the parity-behavior gate.
- **US4 (T025–T031)**: tests first; `inventory.go` (T028), `artifacts.go` (T029), `hunt.go` (T030) mostly independent; T031 conditional.
- **Polish (T032–T034)** last; T034 operator-owned.

### Parallel opportunities
- All of Phase 1 (`[P]`) + T006. Within each story, test tasks `[P]`. `internal/verification/*` (T021/T022/T029), `internal/inventory/*` (T028), `internal/consolidate/*` (T023/T024) parallelize across files. Same-file edits serialize.

---

## Implementation Strategy

**MVP = US1 + US2** (T001–T018): the hunt covers the model's plan, and the Go-only parity-behavior gate pins it to the reference methodology. Build it incrementally: dispatch + candidates first, then dispositions + tiers, then coverage + artifacts (each dimension added to the projection + expected golden as its story lands). Then **US3** (verdict/tier fidelity) and **US4** (coverage/artifacts/orchestration) close whatever the gate or the operator flags. Polish + operator live validation last.

**Governance**: two tracked deviations (plan.md Complexity, minus the dropped Python one): semantic (norm_id) comparison, and a semantic-keyed transcript. **No Python is used** — the expected golden is authored from the reference code and documented as such; the operator is the final parity judge. Every closed divergence ships a failing-before offline test (SC-006); the harness performs no live-endpoint calls; T034 live validation is the operator's.

## Notes
- Reference: authoritative Python `../vhlocal/vhlocal/` (read for behavior, never executed); shared fixture `testdata/vulnapp` (byte-identical).
- Reuse feature-005 machinery (verification session, veto battery, tools, coverage); do not fork it.
- Honesty-critical (Principle I/II): a recorded partition fallback, never a silent narrowing; the expected golden is explicitly "reference-derived, not a measured Python diff," so it is never presented as a live cross-check.
