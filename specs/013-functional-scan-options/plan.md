# Implementation Plan: Functional scan options

**Branch**: `013-functional-scan-options` | **Date**: 2026-09-28 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/013-functional-scan-options/spec.md`

## Summary

Make every advertised scan option functional end to end — one authoritative option contract shared by
the UI, request validator, config builder, engine, profiles, persisted job, and results; each effective
option producing its documented scanner behavior (or a pre-launch, field-specific error); requested-vs-
applied effective config persisted (secrets removed); and the previously disabled controls re-enabled as
their behavior lands. Preserve feature 012 and all existing data/dashboards.

**Current state (verified this planning pass — the fix is real behavior, not more validation):**
- **Validator** (`internal/server/handlers.go:212-272`): `supportedScanOptions` allowlist + a
  compatibility patch that rejects `seed_routes`/`seed_prior=true`, `enforce_coverage=false`, and
  `concurrency!=1` with fixed error strings, all **before** queuing.
- **Builder** (`internal/server/server.go:129-187` `buildScan`): maps most keys to `ScanSpec` but
  **drops `temperature`, `phase2_mode`, and every per-role `*_backend`/`*_host`**, and builds **only one
  Hunt provider** (`Providers{Hunt: prov}`) — per-role models change the model *string* via `roleModel`
  but run on the same backend/host; `Verify`/`Recon`/`Reproduce` providers are nil (fall back to Hunt).
- **Engine** (`internal/engine/*`): `Temperature`/`ReasoningEffort`/`NumCtx`/`MaxOutputTokens`/`HuntSamples`/
  `Phase2Mode`/`QualityStrictness`/phase & feature toggles **are** consumed on the main agent path — but
  the server never populates `Temperature`/`Phase2Mode`; `Temperature`/`ReasoningEffort` are dropped on
  the `repairChat` retry (`agent.go:310-319`); **`MaxBudgetUSD` is inert** (`BudgetSpentUSD` is never
  incremented — the cap can never trip); hunt is **strictly serial** (no goroutines); there is **no**
  `SeedRoutes`/`SeedPrior`/`EnforceCoverage`/`Concurrency` field at all.
- **CLI** (`internal/cli/run.go`): per-role **models only**; **no** concurrency/seeding/budget/temperature/
  app_name flags; also builds only a Hunt provider. `Temperature`/`MaxBudgetUSD`/`AppName` never set.
- **Profiles** (`internal/profiles/profiles.go`): `allowed` includes `concurrency`, `seed_routes`,
  `seed_prior`, `enforce_coverage`, `sweep_mode`, `max_budget_usd` — several **silently accepted but
  unused**; `sweep_mode` is **fully orphaned** (no field/flag/allowlist key anywhere); built-in
  `benchmark` sets seeding off; profiles never pin model/host/backend; explicit operator values win.
- **Forms**: all three HTML forms (`index.html`/`index.classic.html`/`index.legacy.html`) hard-disable
  and strip the seed/enforce/concurrency controls; **React `NewScan.tsx` never renders them at all** and
  omits several options; **no temperature control exists anywhere**.
- **Tests to flip**: `internal/server/scan_launch_test.go::TestScanLaunchRejectsUnimplementedBehavior`
  (asserts `seed_routes`/`seed_prior=true` & `concurrency=2` → 400) and `TestShippedScanFormOptionContract`
  (asserts those controls carry `disabled`) — must be updated to test implemented effects while keeping
  genuine invalid-input rejection.

**Approach (staged, per the handoff):** (1) route/prior **seeding** + launch integration; (2) **coverage
enforcement + bounded concurrency**; (3) the **remaining option matrix** (drop-field wiring, per-role
providers, budget accounting, effective-config persistence) + cross-surface (UI/CLI/profiles/React) +
regressions. Every accepted option is traced to a real effect (contract `contracts/options-matrix.md`);
`../vhlocal` is a read-only reference; validation is offline (fake/recording providers, race detector).

## Technical Context

**Language/Version**: Go 1.23+ (module `vhlocal`), single static binary (`CGO_ENABLED=0`). Front-end:
served `vhlocal/web/*.html` (vanilla JS, embedded) + React `web-react/` (operator-built).

**Primary Dependencies**: standard library only. **Concurrency uses stdlib** (`sync`, buffered-channel
semaphore, `context`) — **not** `golang.org/x/sync/errgroup` (avoids a new runtime dependency; the
constitution's zero-baseline budget). No other new runtime dependency. A small **pricing table** for
budget accounting is data (config/table), not a dependency.

**Storage**: files. New state is **additive**: `ScanSpec` gains option fields; `RunRecord`
(`scan_meta.json`) gains an `effective_config` block (requested/applied/not-applicable, secrets removed)
+ seeding/concurrency/budget provenance; profiles unchanged in shape. No schema-version field — additive
+ graceful read + parity contracts (as in prior features).

**Testing**: offline Go suite (`go test ./...`, `-race` for concurrency), fake/**recording** providers
(assert effective per-role model/host/backend + inference params), a **barrier-controlled** provider for
concurrency, a deterministic **seed manifest**, and build-identity checks. React typecheck/build + a
browser check of the shipped build are operator-owned. No live model; no target execution; `../vhlocal`
read-only.

**Target Platform**: loopback single-binary server + CLI; browser UIs.

**Performance Goals**: bounded concurrency must give real overlap without exceeding the limit; no speedup
promise. Validation stays pre-queue and fast.

**Constraints**: false/0/omitted/null distinct (no silent coercion); invalid → pre-queue field-specific
errors; no silent provider switch or egress beyond operator-configured endpoints; output redaction ≠
input redaction; budget = best-effort bound + disclosure (no false monetary ceiling); resume validates
deliverables; static-only; preserve features 008–012 + data + dashboards; re-enable controls (no
redesign).

**Scale/Scope**: ~30 options across 5 surfaces; touches `server` (validator + buildScan + providers),
`engine` (seeding, coverage toggle, concurrency, budget, drop-field consumption, effective config),
`cli/run.go`, `profiles`, the four forms, and the option/launch tests.

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after Phase 1. Constitution v1.1.0.*

- **I. Evidence Integrity** — prior-report seeds are re-verified against current source, never copied as
  support/severity/decisions (FR-011); effective config is honest (requested vs applied; provider
  limitations disclosed, not recorded as honored — FR-005/018); budget missing-usage is disclosed, never
  reported as zero cost (FR-021). PASS.
- **II. Orthogonal Status** — coverage stays truthful with enforcement on or off; disabling never
  manufactures completeness; unassigned/unreviewed scope disclosed (FR-012). PASS.
- **III. Static-Only Safety** — no target execution to configure/launch a scan; seeding reads the
  existing static inventory/reports only (FR-028). PASS.
- **IV. Provenance / V. Explicit Failure & No Silent Fallback** — per-role providers reach only
  operator-configured endpoints; blank/inherited semantics documented; **no silent provider switch** and
  no egress beyond configuration (FR-017); budget/provider limits surfaced explicitly. PASS.
- **VI. Resumable/Idempotent** — resume uses a compatible effective config and validates deliverables;
  incompatible changes trigger explicit invalidation/replanning (FR-022); parallel aggregation is
  deterministic where order is not meaningful (FR-014). PASS.
- **VII. Testable offline** — fake/recording/barrier providers + `-race`; no live model; build provenance
  recorded (FR-025, SC-011). PASS.
- **Safety & Technical Constraints — Runtime / dependency budget** — concurrency is **stdlib-only** (no
  `x/sync`); no new runtime dependency; budget pricing is a small reviewed data table; UI stays
  self-contained/offline. **PASS.**

**Gate result: PASS.** No violations → Complexity Tracking omitted. Re-check after Phase 1: still PASS
(design adds struct fields, per-role providers, a stdlib worker pool, budget accounting, and additive
metadata — all within the boundaries).

## Project Structure

### Documentation (this feature)

```text
specs/013-functional-scan-options/
├── plan.md          # this file
├── research.md      # Phase 0 (R0 current state; R1–R11 decisions)
├── data-model.md    # Phase 1 (ScanSpec/Providers/RunRecord additions; EffectiveConfig; profile)
├── quickstart.md    # Phase 1 (offline gate + race + recording providers + per-form launch)
├── contracts/
│   ├── options-matrix.md  # option-by-option traceability (control/request→config→engine→metadata→test)
│   └── api.md             # validator + /api/scans request contract changes
└── tasks.md         # /speckit-tasks (not created here)
```

### Source Code (repository root)

```text
internal/engine/engine.go        # ScanSpec: +SeedRoutes,SeedPrior,EnforceCoverage,Concurrency,
                                 #   per-role Backend/Host; effective-config assembly in finalize/record
internal/engine/seed.go          # NEW: recon route-seed (reuse inventory/recognize) + prior-report seed
                                 #   selection/provenance; injected into phase-1 recon task inputs
internal/engine/hunt.go          # bounded-concurrency worker pool (stdlib); enforce_coverage gate on
                                 #   AugmentForCoverage; budget checks before scheduling; race-safe aggregation
internal/engine/budget.go        # NEW: BudgetSpentUSD accounting from client.Usage + pricing; cap + disclosure
internal/engine/record.go        # RunRecord: +effective_config, seeding/concurrency/budget provenance (additive)
internal/engine/agent.go         # carry Temperature/ReasoningEffort on the repairChat retry too
internal/server/server.go        # buildScan: populate Temperature/Phase2Mode/seed/enforce/concurrency;
                                 #   build per-role providers (Verify/Recon/Reproduce) from per-role backend/host
internal/server/handlers.go      # validator: accept implemented options; keep invalid rejection; field-
                                 #   specific + deterministic multi-error; allowlist +seed/enforce/concurrency
internal/server/effective_config.go # NEW/extend: assemble + expose effective config (requested/applied/na)
internal/cli/run.go              # add flags: --concurrency,--seed-routes,--seed-prior,--enforce-coverage,
                                 #   --temperature,--max-budget-usd,--app-name, per-role --*-backend/--*-host;
                                 #   build per-role providers; apply profile to new knobs
internal/profiles/profiles.go    # wire concurrency/seed/enforce/budget into setters; resolve sweep_mode
                                 #   (implement or reject — no silent accept)
internal/pricing/pricing.go      # NEW: small reviewed per-backend/model pricing table (data) + lookup
vhlocal/web/index.html, index.classic.html, index.legacy.html  # re-enable controls + submit keys + help
web-react/src/pages/NewScan.tsx  # add seed/enforce/concurrency (+missing) controls; effective-state display
internal/server/scan_launch_test.go, options_test.go, effective_config_test.go  # flip rejection tests to
                                 #   effect tests; keep invalid-input rejection; add build-identity + matrix cases
```

**Structure Decision**: extend the existing pipeline in place (no new packages except `internal/engine/
seed.go`, `internal/engine/budget.go`, `internal/pricing`). The single-provider bottleneck is fixed by
adding per-role providers to `engine.Providers` construction in both `buildScan` and the CLI; concurrency
is a stdlib worker pool inside the existing hunt fan-out; every change is additive to persisted data.

## Complexity Tracking

No constitution violations to justify. (Concurrency deliberately uses the standard library rather than
adding `golang.org/x/sync/errgroup`, keeping the runtime dependency budget at zero — recorded in
research R4, no Complexity row required.)
