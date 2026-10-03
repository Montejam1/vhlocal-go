# Phase 1 Data Model: Functional scan options

All persisted changes are **additive** (no schema-version field; additive + graceful read + parity
contracts). Cited existing types are extended, not replaced.

## ScanSpec additions (`internal/engine/engine.go`)

New fields (option behavior that has no field today):

| Field | Type | Default | Rule |
|---|---|---|---|
| `SeedRoutes` | bool | false | true → seed recon with the multi-language inventory; not applicable if phase 1 not selected |
| `SeedPrior` | bool | false | true → seed recon with an eligible prior report's findings (as leads) |
| `EnforceCoverage` | bool | **true** | true → coverage-driven hunt-plan augmentation; false → skip augmentation, still measure + disclose |
| `Concurrency` | int | **1** | 1 = serial; >1 = bounded overlap within a validated range (e.g. 1–8) |
| `VerifyBackend`/`VerifyHost` | string | "" | per-role provider; blank inherits Hunt (documented) |
| `ReconBackend`/`ReconHost` | string | "" | per-role provider; blank inherits Hunt |
| `ReproduceBackend`/`ReproduceHost` | string | "" | per-role provider; blank inherits Hunt |

Existing fields to actually populate/honor: `Temperature *float64` (populate in buildScan/CLI; distinct
from unset; `0` is a real value, never replaced by a default), `Phase2Mode` (populate; split|combined),
`MaxBudgetUSD` (make enforcing — see BudgetAccount).

## engine.Providers (`internal/engine`)

`Providers{Hunt, Verify, Recon, Reproduce client.Provider}` — `buildScan` and the CLI MUST construct the
per-role providers from per-role backend/host/model (currently only `Hunt` is built). `forPhase` already
routes per role; a nil role provider inherits `Hunt` (documented inherited semantics). No provider may
target an endpoint the operator did not configure (no silent switch).

## ScanOptionDef & OptionMatrixEntry (contract, shared validation)

- **ScanOptionDef**: `{id, type (bool|int|float|enum|string), default, range/enum, deps, applicable
  phases/providers, omitted_null_handling, precedence, effect}` — one authoritative definition per option,
  consulted by the validator, buildScan, CLI, and profile application (no per-surface copies).
- **OptionMatrixEntry** (contracts/options-matrix.md): id → UI control(s) / API key / CLI flag / profile
  field → effective-config field → engine behavior → saved metadata → acceptance test.

## EffectiveConfig (new; persisted in RunRecord, exposed in results)

`{requested: map[option]value, applied: map[option]value, not_applicable: [{option, reason}]}` with
**secrets removed** (no API keys, credential-redacted endpoints). `requested` records what the operator
asked; `applied` records what the engine used; `not_applicable` explains accepted-but-inapplicable options
(e.g. `seed_routes` with phase 1 omitted, a budget cap unenforceable for a provider). Distinct from a
silently-honored claim — an unapplied provider limitation appears here, never as "honored".

## RunRecord additions (`internal/engine/record.go`, additive `scan_meta.json`)

- `effective_config` (the block above).
- **Seeding provenance**: `seed_routes {requested, applied, source, version, scope_count, truncated,
  unavailable_reason}`; `seed_prior {requested, applied, report_id, revision, supplied, reason}`; a
  `seeded_or_correlated` flag so seeded runs aren't treated as independent benchmark samples.
- **Concurrency provenance**: `concurrency {requested, effective, max_active_observed}`.
- **Budget provenance**: `budget {cap_usd, spent_usd, priced, unpriced_calls, enforced, disclosure}`.

## BudgetAccount (new; `internal/engine/budget.go` + `internal/pricing`)

- **Pricing** (`internal/pricing`): a small reviewed table mapping backend/model → price/1k prompt &
  completion tokens (local backends = $0); lookup returns `(price, known bool)`.
- **BudgetAccount**: thread-safe accumulation of `spent_usd` from `client.Usage` after each call;
  `Allow()` checks `cap>0 && spent < cap` before scheduling a unit; unknown pricing → not counted toward a
  monetary cap and **disclosed** (`priced=false`), never reported as zero cost; enforcement stops
  scheduling new work at the boundary while preserving in-flight/partial results.

## Concurrency scheduler (transient; `internal/engine/hunt.go`)

Bounded set of active hunt units (partition×class×sample) sized to `Concurrency` via a stdlib
semaphore + WaitGroup; shared counters/candidate collection/circuit-breaker/budget guarded by
mutex/atomics; `context` cancellation stops new scheduling and preserves completed artifacts; aggregation
deterministic by unit id. Never exceeds `Concurrency`; `1` is strictly serial.

## Profile (existing `internal/profiles`, semantics clarified)

`Overrides` keys become effective only when they map to an implemented setter/field. `concurrency`,
`seed_routes`, `seed_prior`, `enforce_coverage`, `max_budget_usd` are wired into CLI + web setters;
`sweep_mode` is resolved (implemented or removed from `allowed`/rejected — no silent accept). Precedence
unchanged (builtin < profile < explicit operator value); applying/reloading/resuming never resets
`false`/`0` or overwrites explicit overrides or inference connections.

## Validation rules (from requirements)

- `false` / `0` (where valid) / omitted / `null` are distinct; never coerce `false`→default or round
  fractional `concurrency` (FR-003).
- Type/range/enum + cross-field prerequisites checked **pre-queue**, field-specific, deterministic on
  multiple errors; invalid never starts model work (FR-004).
- `concurrency` ∈ integer within range; `hunt_samples` 1–5 (existing); `max_budget_usd` ≥ 0 (existing);
  per-role host requires per-role backend; `seed_routes`/`seed_prior` require phase 1 (else not_applicable,
  not error, per FR-009).

## Relationships

- A launch request (UI/API/CLI/profile) resolves — via one ScanOptionDef registry — to a `ScanSpec` +
  `Providers` + an `EffectiveConfig`; the engine consumes the spec, records provenance + effective config
  in `RunRecord`, and the results/report expose it. Profiles feed the same resolution (structural knobs
  only). Budget/concurrency/seeding each have provenance so requested-vs-applied stays honest.
