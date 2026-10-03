# Phase 0 Research: Functional scan options

Grounded in a verified current-state inventory (validator, `buildScan`, `ScanSpec` consumption, CLI,
profiles, forms, tests). Each decision cites what exists so the fix is real behavior, not more validation.

## R0 — Current state (the gap map)

- **Validator** `internal/server/handlers.go:212-272`: allowlist `supportedScanOptions`; compatibility
  patch rejects `seed_routes`/`seed_prior=true`, `enforce_coverage=false`, `concurrency!=1` pre-queue.
- **Builder** `internal/server/server.go:129-187`: **drops** `temperature`, `phase2_mode`, per-role
  `*_backend`/`*_host`; builds only `Providers{Hunt: prov}` (per-role models change the string via
  `roleModel`, same backend/host; Verify/Recon/Reproduce providers nil → fall back to Hunt).
- **Engine** `internal/engine/*`: consumes Temperature/ReasoningEffort/NumCtx/MaxOutputTokens/HuntSamples/
  Phase2Mode/QualityStrictness/toggles on the main path; **Temperature/ReasoningEffort dropped on
  `repairChat`** (`agent.go:310-319`); **`MaxBudgetUSD` inert** (`BudgetSpentUSD` never incremented, cap
  never trips — `hunt.go:115-134`); hunt **serial** (no goroutines); **no** SeedRoutes/SeedPrior/
  EnforceCoverage/Concurrency field; no SBOM toggle field.
- **CLI** `internal/cli/run.go`: per-role **models only**; no concurrency/seeding/budget/temperature/
  app_name flags; single Hunt provider; Temperature/MaxBudgetUSD/AppName never set.
- **Profiles** `internal/profiles/profiles.go`: `allowed` includes concurrency/seed_routes/seed_prior/
  enforce_coverage/sweep_mode/max_budget_usd; several **silently accepted, unused**; `sweep_mode`
  **orphaned** (no field/flag/allowlist key); `benchmark` sets seeding off; explicit values win.
- **Forms**: HTML forms disable+strip seed/enforce/concurrency; React `NewScan.tsx` omits them entirely;
  no temperature control anywhere.
- **Tests to flip**: `TestScanLaunchRejectsUnimplementedBehavior`, `TestShippedScanFormOptionContract`.

## R1 — One authoritative option contract (single source of truth)

**Decision**: Define one option registry (id, type, default, range/enum, deps, applicable phases/
providers, omitted/null handling, precedence, effect) that the validator, `buildScan`, CLI, and profile
application all consult, so surfaces cannot diverge. Represent it as the `contracts/options-matrix.md`
mapping realized in code by shared validation/coercion helpers (not four copies).

**Rationale**: FR-001/002/007; today the validator, buildScan, CLI, and profiles each encode option
knowledge independently (drift already exists — buildScan drops keys the validator accepts).

**Alternatives**: keep per-surface logic — rejected (that is the current drift/silent-drop bug).

## R2 — Route & prior-report seeding (US2, first increment)

**Decision**: Add `SeedRoutes`/`SeedPrior` to `ScanSpec`. In a new `internal/engine/seed.go`, when
`SeedRoutes` and phase 1 is selected, build a bounded, source-grounded recon seed from the **feature-012
multi-language inventory** (`internal/inventory.EnumerateRoutes` → recognize) and inject it into the
phase-1 recon task input; record requested/applied, seed source/version, scope/count, truncation. When
`SeedPrior`, deterministically select an eligible prior report for the **same** repo/app slug (e.g. most
recent complete report for that slug), read its findings, inject as recon **leads**, and record report
identity/revision/supplied. Prior findings enter as leads only — the existing per-candidate verification
re-derives evidence independently (never copy support/severity/execution/human decisions); mark the run
seeded/correlated.

**Rationale**: FR-008..011, SC-001/002; reuses 012's inventory (no competing Python-only one) and the
existing independent verification. Seeding controls recon *context* only — coverage/eligibility unchanged.

**Alternatives**: a separate seed inventory — rejected (competes with 012, FR-008). Copying prior verdicts
— rejected (evidence integrity, FR-011).

## R3 — Coverage enforcement toggle (US3)

**Decision**: Add `EnforceCoverage bool` (default true). Gate `phases.AugmentForCoverage` (invoked in
`hunt.go` `resolveHuntPartitions`) on it: true → augment as today; false → skip augmentation but still
enumerate, measure coverage, and disclose unassigned/unreviewed scope. Specify its relationship to
threat-model augmentation, deterministic fallback planning, and partition limits (distinct mechanisms,
not one toggle).

**Rationale**: FR-012, SC-003; today augmentation always runs and the validator forbids disabling.

## R4 — Bounded concurrency (US3), stdlib only

**Decision**: Add `Concurrency int` (default 1; validated range, e.g. 1–8). Replace the serial
partition×class×sample loop in `hunt.go` with a **stdlib** bounded worker pool: a buffered-channel
semaphore of size `Concurrency` + `sync.WaitGroup`; per-unit work runs in goroutines; shared state
(counters, candidate collection, circuit breaker, budget) guarded by `sync.Mutex`/atomics; `context`
cancellation stops scheduling new units and preserves completed artifacts; results aggregated
deterministically (sort by unit id) where order is not semantically meaningful. `Concurrency==1` keeps
strictly serial behavior. **No `golang.org/x/sync/errgroup`** — stay within the zero-baseline runtime
dependency budget (constitution Runtime clause).

**Rationale**: FR-013/014/015, SC-004; today there are no goroutines. Stdlib meets the need without a new
dependency. `-race` is required in tests.

**Alternatives**: `errgroup` — cleaner API but a new runtime dependency; rejected under the budget.

## R5 — Honor the dropped/inert fields (US4)

**Decision**:
- `buildScan` (and CLI) **populate** `Temperature` and `Phase2Mode` from the request/flags.
- Add per-role backend/host to `ScanSpec` (`VerifyBackend/VerifyHost/ReconBackend/ReconHost/
  ReproduceBackend/ReproduceHost`) and **build per-role providers** in `engine.Providers`
  (`Verify`/`Recon`/`Reproduce`) from them (falling back to Hunt when blank, with documented inherited
  semantics); `forPhase` already routes per role. No silent switch; only operator-configured endpoints.
- Carry `Temperature`/`ReasoningEffort` on the `repairChat` retry path (`agent.go:310-319`).
- Threat-model/SBOM: `phases=all` with threat-model off must not read as incomplete; define explicit
  phase/toggle conflict resolution or a pre-launch error.
- Redaction: output redaction is not input redaction — keep that distinction explicit.

**Rationale**: FR-016..020; these are the concrete accepted-but-ignored gaps confirmed in R0.

## R6 — Budget accounting + enforcement (US4)

**Decision**: Add `internal/pricing` — a small, **reviewed** per-backend/model price table (data). In
`internal/engine/budget.go`, increment `BudgetSpentUSD` from `client.Usage` (thread-safe) after each
call; before scheduling a hunt unit (and in retries), check the cap and stop new work at the boundary,
accounting for in-flight calls and preserving partial results. Where pricing is unavailable (e.g. local
Ollama = $0, or an unknown model) **disclose** it before/at launch — a best-effort bound with disclosure,
never a false monetary ceiling and never zero-cost-for-missing-usage.

**Rationale**: FR-021, SC-006; today `BudgetSpentUSD` is never written (cap inert). Pricing is data, not a
dependency (budget-compliant).

**Alternatives**: promise a strict ceiling — rejected (undefinable without reliable pricing/usage).

## R7 — Effective-configuration persistence & exposure (US1)

**Decision**: Assemble an `effective_config` block (requested values, applied values, explained
non-applicability) with **secrets removed**, persist it additively in `RunRecord`/`scan_meta.json`, and
expose it via the existing scan-detail/report surfaces (additive; no redesign). Distinguish requested vs
applied so an accepted-but-inapplicable option reads as such, not as honored.

**Rationale**: FR-005/010, SC-010; additive-only + graceful read, consistent with prior features.

## R8 — Validator becomes a real contract (US1/US5)

**Decision**: Add `seed_routes`/`seed_prior`/`enforce_coverage`/`concurrency` to the allowlist and
**remove the compatibility rejections** as each behavior lands; validate types/ranges/enums and
cross-field prerequisites (e.g. seed requires phase 1; per-role host requires per-role backend) with
**field-specific, deterministic** errors (stable order when multiple invalid), **before queuing**; keep
rejecting genuinely invalid values (`concurrency` 0/1.5/non-int, non-bool seeds, out-of-range). `false`/
`0`/omitted/`null` are distinct.

**Rationale**: FR-003/004; converts the compatibility-only validator into the real contract.

## R9 — UI controls & profiles (US5)

**Decision**: Re-enable the seeding/coverage/concurrency controls in the three HTML forms and **add** them
to React `NewScan.tsx` (which lacks them), each showing effective state + concise help, submitting the
keys only when implemented. Profiles: wire `concurrency`/`seed_routes`/`seed_prior`/`enforce_coverage`/
`max_budget_usd` into CLI + web setters; **resolve `sweep_mode`** — implement it or remove it from
`allowed`/reject it (no silent accept, FR-026). Preserve explicit operator overrides and inference
connections; applying/reloading/resuming must not reset `false`/`0`. Record build identity in validation
evidence (distinguish source/embedded/running/older-pages/profiles/clients).

**Rationale**: FR-023..026, SC-007/008; a disabled control or silently-accepted profile field is not a fix.

## R10 — CLI parity (US1)

**Decision**: Add CLI flags for the currently missing options: `--concurrency`, `--seed-routes`,
`--seed-prior`, `--enforce-coverage`, `--temperature`, `--max-budget-usd`, `--app-name`, and per-role
`--verify-backend/--verify-host/--recon-backend/--recon-host/--reproduce-backend/--reproduce-host`; build
per-role providers on the CLI path too; extend `applyProfile` setters to the new knobs. Equivalent
UI/API/CLI/profile inputs resolve identically (FR-002).

**Rationale**: FR-002; CLI currently omits these, so surfaces are not equivalent.

## R11 — Tests & validation posture (offline)

**Decision**: Flip `TestScanLaunchRejectsUnimplementedBehavior` and `TestShippedScanFormOptionContract`
to assert **implemented effects** (and re-enabled controls), while **retaining** rejection of genuinely
invalid inputs (`concurrency` 0/1.5/"1"/non-int, non-bool seeds). Add: recording providers asserting
effective per-role model/host/backend + inference params (temperature/reasoning/ctx/output) reaching
calls; a barrier-controlled provider proving bounded overlap at `concurrency>1` and serial at 1, `-race`
clean, with cancellation/failure/sampling; budget tests (missing pricing, retries, zero/no cap, local &
mixed providers); an effective-config test (requested vs applied, secrets removed); per-form launch tests
using actual submit + persisted job config, including the `seed_routes=true` regression and build
identity. Full existing Go suite stays green; React typecheck/build + shipped-build browser check are
operator-owned. No live model; no target execution; `../vhlocal` read-only.

**Rationale**: FR-030, SC-004/005/006/008/009/011.

## Post-design constitution re-check

The design adds struct fields, per-role providers, a **stdlib** bounded worker pool, budget accounting
from a small reviewed pricing table, and additive effective-config metadata — no new runtime dependency,
no egress beyond configured endpoints, no silent provider switch, evidence integrity preserved
(prior-seed reverification, honest budget/effective-config), static-only, offline-testable.
**Constitution Check remains PASS after design.**
