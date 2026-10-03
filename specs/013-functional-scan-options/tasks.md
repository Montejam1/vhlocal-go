---

description: "Task list for feature 013: Functional scan options"
---

# Tasks: Functional scan options

**Input**: Design documents from `/specs/013-functional-scan-options/`

**Prerequisites**: plan.md, spec.md, research.md (R0–R11), data-model.md, contracts/options-matrix.md, contracts/api.md, quickstart.md

**Tests**: INCLUDED — the specification explicitly requires them (FR-030, SC-004/005/006/011; recording/barrier providers; the `seed_routes=true` regression). Test tasks are written before their implementation tasks within each story.

**Organization**: Grouped by user story. All five stories are P1; ordered by dependency (US1 contract first, then the plan's staged sequence US2 → US3 → US4 → US5).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: US1–US5 (Setup/Foundational/Polish carry no story label)
- Exact file paths included.

## Path Conventions

Single Go module `vhlocal` at repo root. Build: `export PATH=$PATH:/usr/local/go/bin`; `CGO_ENABLED=0 go build -o bin/vhlocal ./cmd/vhlocal`. Offline gate: `gofmt -l . && go vet ./... && go build ./... && go test ./...` plus `go test -race ./internal/engine/... ./internal/server/...`.

**Standing constraints (every task):** static-only (never execute target code); offline only (fake/recording/barrier providers — never a live model, never Ollama); `../vhlocal` read-only reference; stdlib concurrency only (no `golang.org/x/sync`); persisted changes additive; preserve features 008–012 + data + dashboards; `false`/`0`/omitted/`null` distinct — never coerce `false`→default or round fractional `concurrency`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create the empty homes for the new code so later tasks only fill them.

- [X] T001 Create `internal/config/scanopts.go` with the `ScanOptionDef` type (`{ID, Type (bool|int|float|enum|string), Default, Min/Max or Enum, Deps, ApplicablePhases, ApplicableProviders, OmittedNullHandling, Precedence, Effect}`) and an empty `Registry` map — the single source of truth consulted by validator, buildScan, CLI, and profiles (research R1, data-model "ScanOptionDef"). No option entries yet.
- [X] T002 [P] Create `internal/pricing/pricing.go` with a reviewed per-backend/model price table (local backends = $0) and `Lookup(backend, model) (price Price, known bool)` (research R6, data-model "Pricing"). Table is data, not a dependency.
- [X] T003 [P] Create `internal/engine/seed.go` and `internal/engine/budget.go` as empty stubs with package clause + doc comment only (filled in US2 and US4).
- [X] T004 [P] Create `internal/server/effective_config.go` as an empty stub with package clause + doc comment only (filled in US1).
- [X] T005 Run `gofmt -w` on new files and confirm `go build ./...` compiles the empty scaffolding.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Types and test doubles every user story depends on. NO story can start until this phase is done.

**⚠️ CRITICAL**: Blocks all user stories.

- [X] T006 Add new fields to `ScanSpec` in `internal/engine/engine.go`, quoting data-model defaults verbatim: `SeedRoutes bool` (default false), `SeedPrior bool` (default false), `EnforceCoverage bool` (**default true**), `Concurrency int` (**default 1**; valid range 1–8), and per-role `VerifyBackend/VerifyHost/ReconBackend/ReconHost/ReproduceBackend/ReproduceHost string` (default `""`, blank inherits Hunt). Ensure `Temperature *float64` (distinct from unset; `0` is real) and `Phase2Mode` are present for later population. Keep zero-values backward-compatible with existing callers.
- [X] T007 Define the `EffectiveConfig` type — `{Requested map[string]any, Applied map[string]any, NotApplicable []{Option string, Reason string}}` with **secrets removed** — in `internal/server/effective_config.go` (data-model "EffectiveConfig"). Include a `Redact` helper that strips API keys and credential-bearing endpoints.
- [X] T008 Extend `RunRecord`/`scan_meta.json` in `internal/engine/record.go` **additively** (no schema-version field; graceful read of old records) with: `effective_config`; seeding provenance (`seed_routes {requested, applied, source, version, scope_count, truncated, unavailable_reason}`, `seed_prior {requested, applied, report_id, revision, supplied, reason}`, `seeded_or_correlated` flag); `concurrency {requested, effective, max_active_observed}`; `budget {cap_usd, spent_usd, priced, unpriced_calls, enforced, disclosure}` (data-model "RunRecord additions").
- [X] T009 [P] Add a **recording provider** to `internal/client/testsupport/fake.go` (or a sibling file in the package): captures per-call role, model, backend, host, and inference params (temperature/reasoning/ctx/output) for effective-config assertions. Offline only.
- [X] T010 [P] Add a **barrier-controlled provider** to `internal/client/testsupport`: gates N concurrent in-flight calls so tests can observe max-active vs the concurrency limit and prove serial-at-1. Offline only, `-race`-safe.
- [X] T011 [P] Add a **fake-usage provider** to `internal/client/testsupport`: emits deterministic `client.Usage` (known + unknown pricing) to drive budget accounting tests.
- [X] T012 Populate `internal/config/scanopts.go` `Registry` with every option row from `contracts/options-matrix.md` (~28 options + cross-cutting rules): id, type, default, range/enum, deps (e.g. per-role host requires per-role backend; `seed_*` require phase 1), applicable phases/providers, omitted/null handling, precedence (builtin < profile < explicit). This is the authoritative contract for FR-001.
- [X] T013 Add shared validation/coercion helpers in `internal/config/scanopts.go` that read the `Registry`: `Validate(raw map[string]any) []FieldError` (type/range/enum + cross-field, **deterministic order**, distinct `false`/`0`/omitted/`null`, never round fractional int) and `Coerce(raw) (values, notApplicable)`. Used by validator, buildScan, CLI, profiles so surfaces cannot diverge (research R1, FR-002).

**Checkpoint**: Shared contract, spec fields, persistence, and test doubles exist — stories can begin.

---

## Phase 3: User Story 1 - One explicit, enforced scan-option contract (Priority: P1) 🎯 MVP

**Goal**: Every surface resolves options through one contract; invalid input fails pre-queue with field-specific deterministic errors; effective config (requested vs applied, secrets removed) is persisted and exposed.

**Independent Test**: Submit each option via UI/API/CLI/profile → identical effective resolution; `false`/`0`/omitted/`null` distinct; invalid types/combos rejected pre-queue with field-specific errors and no model work started; run metadata records requested vs applied with secrets removed.

### Tests for User Story 1 ⚠️ (write first, ensure they FAIL)

- [X] T014 [P] [US1] Contract test in `internal/config/scanopts_test.go`: `Validate` returns deterministic, field-specific errors for invalid types/ranges/enums and cross-field violations; `false`/`0`/omitted/`null` are distinct; fractional `concurrency` (`1.5`) is rejected, never rounded (FR-003/004).
- [X] T015 [P] [US1] Cross-surface equivalence test in `internal/server/options_test.go`: the same option set via API request and via an applied profile resolves to the same `ScanSpec` + `Providers` + `EffectiveConfig` (FR-002); assert against recording provider where inference params matter.
- [X] T016 [P] [US1] Effective-config test in `internal/server/effective_config_test.go`: a launched scan persists `effective_config` with requested vs applied and explained `not_applicable`, **secrets removed** (no API keys / credentialed endpoints) (FR-005, SC-010).
- [X] T017 [P] [US1] Pre-queue rejection test in `internal/server/scan_launch_test.go`: invalid requests return 4xx **before** any provider call is recorded (no model work) (FR-004, SC-008).

### Implementation for User Story 1

- [X] T018 [US1] Rewrite the validator in `internal/server/handlers.go` (currently the compat patch at ~212-272) to call `config.Validate`/`Coerce`: add `seed_routes`/`seed_prior`/`enforce_coverage`/`concurrency` to the allowlist, accept implemented values, keep field-specific/deterministic pre-queue rejection of genuinely invalid input, remove the fixed `is not implemented` rejections as their behavior lands (contracts/api.md C-V1..C-V5).
- [X] T019 [US1] Update `buildScan` in `internal/server/server.go` to resolve the request through `config.Coerce` and map **every** accepted option to its `ScanSpec` field or record it not-applicable — no silent drops (contracts/api.md C-B1). (Per-role providers land in US4 T041; here wire the scalar/bool/int fields + `Temperature`/`Phase2Mode` population hook.)
- [X] T020 [US1] Implement effective-config assembly in `internal/server/effective_config.go`: build `EffectiveConfig{requested, applied, not_applicable}` from the coerced values + engine outcome, redact secrets, and hand it to `RunRecord` (FR-005). A provider limitation appears as not-applicable/disclosed, never honored.
- [X] T021 [US1] Expose effective config on the existing scan-detail/report surface (additive, no redesign) so the operator can see requested vs applied — server handler + the served detail view fields (FR-005).
- [X] T022 [US1] Ensure UI defaults do not overwrite saved values / explicit overrides without explanation — verify the resolution precedence (builtin < profile < explicit) in `config.Coerce` and the form-value merge (FR-006).

**Checkpoint**: One contract enforced end to end; effective config honest and persisted. MVP.

---

## Phase 4: User Story 2 - Route and prior-report seeding actually seed (Priority: P1)

**Goal**: `seed_routes`/`seed_prior` supply real, bounded, source-grounded context to Phase-1 recon; prior findings are independently re-verified; provenance recorded.

**Independent Test**: With seeding on, recorded Phase-1 request contains expected seeded inventory / prior leads + provenance; off omits them; exercise Python/Go/mixed scope, no-prior, malformed, wrong-repo, changed-source, phase-omitted; HTTP 201 alone insufficient.

### Tests for User Story 2 ⚠️ (write first, ensure they FAIL)

- [X] T023 [P] [US2] Route-seed test in `internal/engine/seed_test.go`: with `SeedRoutes=true` + phase 1, recon task input carries the feature-012 multi-language inventory for Python, Go, and mixed fixtures; `false` omits it; empty/partial inventory is explained, not presented as complete; provenance (source/version/scope_count/truncated) recorded (FR-008/009, SC-001).
- [X] T024 [P] [US2] Not-applicable test in `internal/engine/seed_test.go`: `SeedRoutes=true` with recon/phase 1 not selected is recorded not-applicable and does **not** silently launch an extra phase (FR-009).
- [X] T025 [P] [US2] Prior-seed selection test in `internal/engine/seed_test.go`: `SeedPrior=true` deterministically selects an eligible prior report for the **same** repo/app, injects findings as leads with report identity/revision/supplied; `false` injects none; no-prior/malformed/wrong-repo/changed-source each run explicitly unseeded (never a fake seed, never another repo's report) (FR-010, SC-002).
- [X] T026 [P] [US2] Re-verification test in `internal/engine/seed_test.go`: seeded prior findings are re-verified against current source (no copied support/severity/execution/human decisions) and the run is marked `seeded_or_correlated` so it is not treated as an independent benchmark sample (FR-011, SC-002).

### Implementation for User Story 2

- [X] T027 [US2] Implement route seeding in `internal/engine/seed.go`: when `SeedRoutes` && phase 1 selected, build a bounded, source-grounded recon seed from `internal/inventory.EnumerateRoutes` (feature 012 recognize/inventory) and inject into the phase-1 recon task input; record requested/applied, source, version, scope_count, truncation, unavailable_reason (FR-008/009). Controls recon context only — does not change coverage measurement or eligibility.
- [X] T028 [US2] Implement prior-report seeding in `internal/engine/seed.go`: deterministic eligible-report selection for the same repo/app slug (e.g. most-recent complete report), read findings, inject as recon **leads** with recorded identity/revision/supplied; handle no-prior/malformed/wrong-repo/changed-source as explained-unseeded (FR-010).
- [X] T029 [US2] Ensure prior-seed leads pass through the **existing** per-candidate verification unchanged (evidence re-derived independently); set the `seeded_or_correlated` provenance flag in `RunRecord` (FR-011).
- [X] T030 [US2] Call the seeding hooks from the engine phase-1 path in `internal/engine/engine.go`/`hunt.go` and thread `SeedRoutes`/`SeedPrior` from `buildScan` (server.go) — recon input assembly only, no new phase (FR-008).

**Checkpoint**: Seeding real and provenance-honest across all fixtures; independent re-verification preserved.

---

## Phase 5: User Story 3 - Coverage enforcement and bounded parallelism are functional (Priority: P1)

**Goal**: `enforce_coverage` toggles augmentation while keeping coverage truthful; `concurrency` gives real bounded overlap (never exceeding the limit) with safe aggregation and cancellation.

**Independent Test**: Incomplete partition plan → augmentation on / explicit unassigned-unreviewed off (truthful both ways); barrier provider shows >1 overlap at concurrency>1 never exceeding limit, serial at 1, `-race` clean, cancel/fail/sampling exercised.

### Tests for User Story 3 ⚠️ (write first, ensure they FAIL)

- [X] T031 [P] [US3] Coverage-enforcement test in `internal/engine/hunt_test.go`: incomplete partition plan with `EnforceCoverage=true` adds the documented augmentation; with `false`, augmentation is skipped but inventory + coverage measurement + unassigned/unreviewed disclosure remain; neither manufactures complete coverage (FR-012, SC-003).
- [X] T032 [P] [US3] Bounded-overlap test in `internal/engine/hunt_concurrency_test.go` using the barrier provider: `Concurrency>1` produces overlapping hunt units never exceeding the limit; `Concurrency==1` strictly serial; run with `-race` (FR-013/014, SC-004).
- [X] T033 [P] [US3] Safety test in `internal/engine/hunt_concurrency_test.go`: parallel runs don't mix outputs, corrupt counters, duplicate candidates, lose work, or publish stale results; aggregation deterministic by unit id (FR-014).
- [X] T034 [P] [US3] Cancellation test in `internal/engine/hunt_concurrency_test.go`: on cancel/stop, no new work scheduled, completed artifacts preserved, unfinished assignments accounted explicitly (FR-015).

### Implementation for User Story 3

- [X] T035 [US3] Gate `phases.AugmentForCoverage` (in `resolveHuntPartitions`, `internal/engine/hunt.go`) on `EnforceCoverage`: true → augment as today; false → skip augmentation but still enumerate, measure coverage, and disclose unassigned/unreviewed scope. Keep its relationship to threat-model augmentation, deterministic fallback planning, and partition limits distinct (not one conflated toggle) (FR-012).
- [X] T036 [US3] Replace the serial partition×class×sample loop in `internal/engine/hunt.go` with a **stdlib** bounded worker pool: buffered-channel semaphore sized to `Concurrency` + `sync.WaitGroup`; per-unit goroutines; `context` cancellation stops new scheduling and preserves completed artifacts (research R4, FR-013/015). No `golang.org/x/sync`.
- [X] T037 [US3] Guard all shared state in `internal/engine/hunt.go` (counters, candidate collection, circuit breaker, budget hooks) with `sync.Mutex`/atomics; aggregate results deterministically by unit id where order is not semantically meaningful (FR-014). Must be `-race` clean.
- [X] T038 [US3] Validate `Concurrency` range in the contract (`internal/config/scanopts.go`) — integer within 1–8, define "active agent", and document interactions with sampling/provider capacity/cancellation/retries/circuit breaker/budget in `contracts/options-matrix.md` cross-reference (FR-013).

**Checkpoint**: Coverage truthful both ways; bounded concurrency real, safe, cancellable, race-clean.

---

## Phase 6: User Story 4 - Accepted settings are honored throughout the engine (Priority: P1)

**Goal**: Every accepted option reaches its actual effect — split/combined, samples, per-role providers, temperature/reasoning/ctx/output (incl. repair/reproduce), threat-model/SBOM, toggles, budget enforcement, resume.

**Independent Test**: Recording providers confirm effective per-role model/host/backend + inference params reaching applicable calls; split/combined + sample counts match; threat-model-off with phases=all not falsely incomplete; each toggle changes documented behavior; positive budget cap stops new work at boundary; resume validates deliverables.

### Tests for User Story 4 ⚠️ (write first, ensure they FAIL)

- [X] T039 [P] [US4] Per-role + inference test in `internal/server/options_test.go` (recording provider): effective model/host/backend per role reach their calls; blank inherits Hunt (documented); no silent provider switch; temperature (incl. `0`), reasoning, ctx, output reach applicable calls **including verify/repair/reproduce** (FR-017/018, SC-005).
- [X] T040 [P] [US4] Dispatch test in `internal/engine/hunt_test.go` (recording provider): split vs combined changes actual dispatch; hunt samples change repeated assignments with union semantics + sample provenance; counts match a deterministic seed manifest (FR-016, SC-005).
- [X] T041 [P] [US4] Budget test in `internal/engine/budget_test.go` (fake-usage provider): positive cap stops new work at the boundary, accounts in-flight, preserves partial results; missing pricing disclosed (`priced=false`) not zero-cost; zero/no cap, retries, local & mixed providers covered (FR-021, SC-006).
- [X] T042 [P] [US4] Toggle/phase test in `internal/engine/engine_test.go`: `phases=all` with threat-model off is not falsely incomplete (defined resolution or pre-launch error); IaC/ledger/remediation/redaction each change documented work/output; output-redaction ≠ input-redaction (FR-019/020).
- [X] T043 [P] [US4] Resume test in `internal/engine/reproduction_loop_test.go` (or a resume test file): resume uses a compatible effective config and validates deliverables; incompatible changes trigger explicit invalidation/replan or an actionable error (FR-022).

### Implementation for User Story 4

- [X] T044 [US4] Populate `Temperature` and `Phase2Mode` from the request in `buildScan` (`internal/server/server.go`) and build per-role providers — construct `engine.Providers{Hunt, Verify, Recon, Reproduce}` from per-role backend/host/model; blank inherits Hunt (documented); only operator-configured endpoints; no silent switch (contracts/api.md C-B2, FR-017).
- [X] T045 [US4] Carry `Temperature`/`ReasoningEffort` on the `repairChat` retry path in `internal/engine/agent.go` (~310-319) — currently dropped (research R5, FR-018).
- [X] T046 [US4] Implement budget accounting in `internal/engine/budget.go`: thread-safe `BudgetAccount` accumulating `spent_usd` from `client.Usage` via `internal/pricing`; `Allow()` checks `cap>0 && spent<cap` before scheduling a unit (wire into the T036 scheduler + retries); unknown pricing not counted toward a monetary cap and **disclosed** (`priced=false`), never zero-cost; stop new work at the boundary preserving in-flight/partial results (FR-021).
- [X] T047 [US4] Resolve the threat-model/SBOM phase-conflict in `internal/engine/engine.go`: `phases=all` + threat-model off must not read as incomplete — define explicit conflict resolution or a pre-launch error (FR-019).
- [X] T048 [US4] Verify/adjust IaC/ledger/remediation/redaction toggle handling in the engine so each changes documented work/output and output-redaction does not imply input redaction; report artifact failures preserving original evidence (FR-020).
- [X] T049 [US4] Extend resume in the engine to validate saved deliverables against the effective config and trigger explicit invalidation/replan or an actionable incompatibility error on invalidating changes (FR-022).

**Checkpoint**: Every accepted option traced to a real effect; budget enforced with disclosure; resume validated.

---

## Phase 7: User Story 5 - Working UI controls and profile behavior (Priority: P1)

**Goal**: Re-enable seeding/coverage/concurrency controls (now that behavior exists) across all four forms + React; CLI parity; profiles apply only structural settings and preserve overrides; `sweep_mode` resolved; build identity recorded.

**Independent Test**: Launch through main/React/classic/legacy + profiles without unsupported-option failures for valid choices (actual submit + persisted job config); `seed_routes=true` passes only after real behavior; applying/changing/reloading/resuming doesn't reset `false`/`0`; build identity in evidence.

### Tests for User Story 5 ⚠️ (write first, ensure they FAIL)

- [X] T050 [P] [US5] Flip `TestScanLaunchRejectsUnimplementedBehavior` and `TestShippedScanFormOptionContract` in `internal/server/scan_launch_test.go` to assert **implemented effects** and re-enabled controls, while retaining rejection of genuinely invalid inputs (`concurrency` 0/1.5/"1"/non-int, non-bool seeds); include the `seed_routes=true` regression that passes only after real behavior (FR-030, SC-008).
- [X] T051 [P] [US5] Per-form launch test in `internal/server/scan_launch_test.go`: launching via main/classic/legacy submit paths + an applied profile queues valid advertised choices without unsupported-option failures, verified by the **persisted job config** (not a copied payload) (FR-024, SC-008).
- [X] T052 [P] [US5] Profile test in `internal/profiles/profiles_test.go`: a profile (incl. benchmark seeding-off) applies only documented structural settings, preserves explicit overrides and inference connections, and applying/changing-one-field/reloading/resuming does not reset `false`/`0` or reintroduce stale options; `sweep_mode` is resolved (no silent accept) (FR-026).
- [X] T053 [P] [US5] Build-identity test in `internal/server/scan_launch_test.go`: validation evidence records build identity distinguishing source/embedded/running/older-page/profile/alternate-client (FR-025, SC-011).

### Implementation for User Story 5

- [X] T054 [P] [US5] Re-enable and wire the seeding/coverage/concurrency controls in `vhlocal/web/index.html` (remove `disabled`/payload-strip; show effective state + concise help; submit keys) (FR-023).
- [X] T055 [P] [US5] Re-enable and wire the same controls in `vhlocal/web/index.classic.html` (FR-023).
- [X] T056 [P] [US5] Re-enable and wire the same controls in `vhlocal/web/index.legacy.html` (FR-023).
- [X] T057 [P] [US5] Add seeding/coverage/concurrency (+ any missing) controls to `web-react/src/pages/NewScan.tsx` with effective-state display + help (FR-023). (Operator runs `npm run build`; not embedded/committed.)
- [X] T058 [US5] Add the missing CLI flags in `internal/cli/run.go`: `--concurrency`, `--seed-routes`, `--seed-prior`, `--enforce-coverage`, `--temperature`, `--max-budget-usd`, `--app-name`, and per-role `--verify-backend/--verify-host/--recon-backend/--recon-host/--reproduce-backend/--reproduce-host`; build per-role providers on the CLI path; resolve through `config.Coerce` so CLI == API == UI (FR-002, research R10).
- [X] T059 [US5] Wire `concurrency`/`seed_routes`/`seed_prior`/`enforce_coverage`/`max_budget_usd` into profile setters (CLI + web) in `internal/profiles/profiles.go`; **resolve `sweep_mode`** (implement or remove from `allowed`/reject — no silent accept); preserve precedence (builtin < profile < explicit) and never reset `false`/`0` on apply/reload/resume (FR-026, research R9).
- [X] T060 [US5] Record build identity in validation evidence (source vs embedded vs running vs older page vs profile vs alternate client) so a green source test is not mistaken for a fixed running app (FR-025).

**Checkpoint**: Controls live across all surfaces; CLI/profile parity; build identity honest.

---

## Phase 8: Polish & Cross-Cutting Concerns

- [X] T061 [P] Update `contracts/options-matrix.md` status column from the as-built code (drop/inert/compat → ok) so the matrix reflects reality; note any documented intentional differences vs `../vhlocal` (FR-029).
- [X] T062 [P] Run the full offline gate: `gofmt -l .` (empty), `go vet ./...`, `go build ./...`, `CGO_ENABLED=0 go build -o bin/vhlocal ./cmd/vhlocal`, `go test ./...`, `go test -race ./internal/engine/... ./internal/server/...` — all green (SC-011).
- [X] T063 [P] Run feature-012 parity + regression suites (`tests/parity/...`) and confirm no regression to default requests, dashboards, history, multi-language scope, or analyst/ledger data (FR-027, SC-009).
- [X] T064 Execute `quickstart.md` scenarios 1–10 end to end offline and record actual checks/results/limitations (SC-011); no live model, no target execution.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies.
- **Foundational (Phase 2)**: after Setup — **blocks all stories** (ScanSpec fields T006, EffectiveConfig T007, RunRecord T008, test doubles T009–T011, contract T012–T013).
- **US1 (Phase 3)**: after Foundational. The MVP and the contract every other story consumes.
- **US2 (Phase 4)**: after US1 (uses the contract + effective config + seeding provenance fields).
- **US3 (Phase 5)**: after US1 (independent of US2; coverage/concurrency in the engine).
- **US4 (Phase 6)**: after US1; T046 (budget) integrates with US3's scheduler (T036) — sequence US3 before US4's T046, or land the budget hook points in T036.
- **US5 (Phase 7)**: after the behavior it exposes exists (re-enable controls only once US1–US4 land, per FR-023).
- **Polish (Phase 8)**: after all desired stories.

### Within Each Story

- Tests (T014–T017, T023–T026, T031–T034, T039–T043, T050–T053) written first and failing before implementation.
- ScanSpec/contract before engine consumption; engine behavior before UI re-enable.

### Parallel Opportunities

- Setup: T002, T003, T004 in parallel (different files).
- Foundational: T009, T010, T011 (test doubles) in parallel.
- Each story's test tasks marked [P] run together (distinct files).
- US5 form tasks T054–T057 in parallel (four different files); T061–T063 in parallel.
- Cross-story: US2 and US3 can proceed in parallel once US1 lands (different engine areas: seed.go vs hunt.go).

---

## Parallel Example: User Story 1 tests

```bash
# Launch US1 test tasks together (different files):
Task: "Contract test in internal/config/scanopts_test.go (T014)"
Task: "Cross-surface equivalence test in internal/server/options_test.go (T015)"
Task: "Effective-config test in internal/server/effective_config_test.go (T016)"
Task: "Pre-queue rejection test in internal/server/scan_launch_test.go (T017)"
```

---

## Implementation Strategy

### MVP First (US1)

1. Phase 1 Setup → Phase 2 Foundational (CRITICAL — blocks all).
2. Phase 3 US1 → **STOP and VALIDATE**: one contract enforced, effective config honest and persisted.

### Incremental Delivery (per the plan's staged sequence)

1. Foundation → US1 (contract) — MVP.
2. US2 (seeding + launch integration) — the operator's first-hit failure fixed; validate on Python/Go/mixed.
3. US3 (coverage enforcement + bounded concurrency) — validate with barrier provider + `-race`.
4. US4 (remaining option matrix: drop-field wiring, per-role providers, budget, resume).
5. US5 (re-enable controls, CLI/profile parity, build identity) — ties functional options back to the surfaces.
6. Polish: matrix status refresh, full offline gate, 012 parity, quickstart.

An early seeding fix is **not** feature completion — the full option matrix (US4) and cross-surface regressions (US5) remain in scope (spec Assumptions "Sequencing").

---

## Notes

- [P] = different files, no incomplete-task dependency.
- Every accepted option must be traced to a real effect (FR-007) — an allowlist entry is not implementation.
- Offline only: fake/recording/barrier providers, `-race`; no live model, no Ollama, no target execution, `../vhlocal` read-only.
- Persisted changes additive; preserve features 008–012 + data + dashboards.
- Commit after each task or logical group; keep partially completed tasks unchecked.
