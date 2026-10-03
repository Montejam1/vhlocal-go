# Feature Specification: Functional scan options

**Feature Branch**: `013-functional-scan-options`

**Created**: 2026-09-28

**Status**: Draft

**Input**: User description: "Functional scan options (from
`docs/engineering/2026-09-28-scan-options-speckit-specify.md`) — the operator must be able to configure
and launch a scan with the advertised options, and each effective option must produce its documented
scanner behavior. UI, request validator, configuration builder, engine, profiles, persisted job, and
results must agree on the meaning and value of each option. Hiding controls, forcing defaults, or
accepting ignored fields is NOT completion. Preserve feature 012 and existing data."

## Overview

Scan options are advertised across the shipped UIs (main `index.html`, React, classic, legacy), the
public scan API, the CLI, and profiles — but several are non-functional today: a compatibility patch
accepts only `seed_routes=false` / `seed_prior=false` / `enforce_coverage=true` / `concurrency=1`,
disables those controls, and strips them from payloads (fixing default-request compatibility, not the
missing behavior); the operator now sees `seed_routes is not implemented; set it to false or omit it`.
Beyond that, `server.buildScan` accepts but does not populate `Phase2Mode`/`Temperature`, per-role
backend/host keys are accepted but the builder returns only the default Hunt provider, and
`BudgetSpentUSD` is accepted with no charging integration.

This feature makes scan options **functional end to end**: one explicit option contract shared by every
surface, real scanner behavior for each effective option, honest disclosure of requested-vs-applied
values, and re-enabled UI controls whose switches actually do what they say. **Hiding a control,
forcing a default, accepting an ignored field, or a compatibility-only validator does not satisfy any
requirement here** — the option must produce its documented effect (or fail before launch with an
actionable, field-specific error).

Scope discipline: this is a focused configuration/functionality repair, not a redesign. Feature 012's
ongoing multi-language work, analyst workflows, saved results, application names, ledger/review data,
and all existing dashboard metrics/charts are preserved. `../vhlocal` (the Python implementation) is a
**read-only behavioral reference**; intentional differences are documented, and stronger current
evidence rules are preserved (never blindly ported). Validation is offline (fake/recording providers,
race detector); no unsolicited live paid scan and no execution of target code are required.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - One explicit, enforced scan-option contract (Priority: P1)

An operator (and every surface) shares one authoritative definition of each scan option: its type,
default, accepted range/enum, dependencies, applicable phases/providers, omitted/null handling,
precedence, and effective value. Equivalent inputs from the UI, API, CLI, or a profile resolve to
equivalent behavior. Invalid types, unsupported combinations, or missing prerequisites fail **before a
costly scan is queued**, with actionable field-specific errors (deterministic when several fields are
invalid). The effective configuration is shown to the operator and persisted in run metadata (secrets
removed), distinguishing requested values, applied values, and any explained non-applicability.

**Why this priority**: Every other option behavior depends on a single, honest contract; without it,
surfaces disagree and fields are silently ignored. Foundation of the feature.

**Independent Test**: Submit each option from UI, API, CLI, and a profile; confirm identical effective
resolution; confirm `false`, numeric `0` (where valid), omission, and `null` are treated distinctly
(never silently coerced); confirm invalid types/combos are rejected pre-queue with field-specific
errors and never start model work; confirm run metadata records requested vs applied effective config
with secrets removed.

**Acceptance Scenarios**:

1. **Given** the same option set expressed via UI, API, CLI, and a profile, **When** a scan is
   configured, **Then** all four resolve to the same effective configuration and observable behavior.
2. **Given** an option with a boolean or numeric value, **When** `false`, `0` (where valid), omission,
   or `null` is supplied, **Then** each is handled as its own distinct case — `false` is never converted
   to a true default and fractional concurrency is never silently rounded.
3. **Given** an invalid type, unsupported combination, or missing prerequisite (possibly several at
   once), **When** the request is validated, **Then** it fails **before queuing** with deterministic,
   field-specific, actionable errors and no model work begins.
4. **Given** a launched scan, **When** run metadata is written, **Then** it records the effective
   configuration with requested vs applied values (and explained non-applicability), secrets removed.
5. **Given** UI defaults, **When** a saved value or explicit operator override exists, **Then** defaults
   do not overwrite it without explanation.

---

### User Story 2 - Route and prior-report seeding actually seed (Priority: P1)

An operator can turn on route seeding and prior-report seeding and have them supply real context to
Phase 1 reconnaissance. `seed_routes=true` provides the current deterministic **multi-language**
entry-point inventory (feature 012's `internal/recognize`/`inventory`, not a competing Python-only
inventory) to recon as additional investigation context; `false` omits that optional seed. `seed_prior=
true` deterministically selects an eligible prior report for the **same** repository/application and
supplies its prior findings as recon leads; `false` injects nothing. Prior findings are independently
re-verified against current source — never copied as support/severity/execution/human decisions.

**Why this priority**: These are the options the operator hit first (`seed_routes` failure), and the
handoff sequences seeding + launch integration first. Delivering real seeding is the initial usable
increment.

**Independent Test**: With seeding on, the recorded Phase-1 request contains the expected seeded
inventory / prior leads and provenance; with it off, the optional seed/leads are absent; exercise
Python, Go, and mixed/unsupported scope, no-prior, malformed history, wrong-repository, changed source,
and explicit recon omission — capturing HTTP 201 alone is not sufficient.

**Acceptance Scenarios**:

1. **Given** `seed_routes=true`, **When** Phase 1 runs, **Then** the recon input contains the current
   deterministic multi-language inventory as bounded, source-grounded context, recording
   requested/applied, seed source/version, scope/count, and any truncation or unavailable inventory;
   `seed_routes=false` omits this seed. It controls recon context only — it does not change whether
   coverage is measured or which source is eligible for investigation, and does not erase mandatory
   scope/assignment facts.
2. **Given** recon is not selected, **When** `seed_routes=true`, **Then** the option is identified as
   not applicable without silently launching an extra phase.
3. **Given** an empty or partially supported inventory, **When** it is seeded, **Then** it is explained
   as such and never presented as a complete attack-surface list.
4. **Given** `seed_prior=true` and an eligible prior report for the same repository/application, **When**
   Phase 1 runs, **Then** prior findings are supplied as recon leads with recorded report identity,
   revision, and whether context was supplied; `seed_prior=false` injects none.
5. **Given** no eligible / missing / malformed / mismatched prior report, **When** `seed_prior=true`,
   **Then** the condition is visible and the scan runs explicitly unseeded — never a fake successful
   seed, and never another repository's report as a substitute.
6. **Given** prior findings are seeded, **When** the scan runs, **Then** they are independently
   re-verified against current source (no copied support/severity/execution claims or human decisions),
   and the run is identified as seeded/correlated so it is not treated as an independent benchmark
   sample.

---

### User Story 3 - Coverage enforcement and bounded parallelism are functional (Priority: P1)

An operator can toggle coverage enforcement and set concurrency and have both actually work.
`enforce_coverage=true` enables the documented coverage-driven augmentation of the hunt plan; `false`
disables that automatic augmentation — and **both** retain inventory, coverage measurement, and honest
disclosure of unassigned/unreviewed scope (disabling never manufactures complete coverage).
`concurrency=1` runs hunt assignments serially; supported values greater than one permit real bounded
overlap without mixing outputs, corrupting counters, duplicating candidates, losing work, or publishing
stale results.

**Why this priority**: The second sequenced increment; these are advertised controls the compatibility
patch pinned to a single value. Real behavior here is core to the fix.

**Independent Test**: A deliberately incomplete model partition plan yields coverage augmentation with
enforcement on and explicit unassigned/unreviewed scope with it off (coverage truthful in both); a
barrier-controlled fake provider shows more than one overlapping hunt assignment at concurrency > 1
(never exceeding the limit) and strictly serial at 1, with cancellation/failure/sampling exercised,
consistent artifact bindings/counters, and race-detector coverage.

**Acceptance Scenarios**:

1. **Given** an incomplete partition plan and `enforce_coverage=true`, **When** the hunt plan is built,
   **Then** coverage-driven augmentation adds the documented assignments; with `false`, augmentation is
   disabled and unassigned/unreviewed scope is disclosed explicitly. Neither state manufactures complete
   coverage, and the relationship to threat-model augmentation, deterministic fallback planning, and
   partition limits is specified (not one conflated toggle).
2. **Given** `concurrency=1`, **When** hunt runs, **Then** assignments execute serially; **Given** a
   supported `concurrency>1`, **When** hunt runs, **Then** bounded overlap occurs and never exceeds the
   limit (with a defined range, definition of an active agent, and interactions with sampling, provider
   capacity, cancellation, retries, circuit breakers, and budget).
3. **Given** parallel execution, **When** assignments run, **Then** outputs are not mixed, shared
   counters are not corrupted, candidates are not duplicated, completed work is not lost, and stale
   results are not published; aggregation is deterministic where order is not semantically meaningful.
4. **Given** cancellation or a stop condition, **When** it fires, **Then** no new work is scheduled,
   completed artifacts are preserved, and unfinished assignments are accounted for explicitly.

---

### User Story 4 - Accepted settings are honored throughout the engine (Priority: P1)

Every option the validator accepts reaches its actual effect (traced to behavior, not just added to an
allowlist): split-vs-combined hunt dispatch, hunt samples, per-role provider/backend/host/model,
temperature/reasoning-effort/context-limit/output-limit, threat-model/SBOM expectations, IaC/ledger/
remediation/redaction toggles, budget cap enforcement, and resume compatibility.

**Why this priority**: The heart of "make options functional" — the accepted-but-ignored fields
(`Phase2Mode`, `Temperature`, per-role providers, budget) are the concrete gaps.

**Independent Test**: Recording/fake providers confirm effective model/host/backend per role and actual
inference options (temperature/reasoning/context/output) reaching applicable calls; split/combined
assignment counts and sample counts match requested behavior; threat-model-off with `phases=all` does
not create a false incomplete run; each toggle changes its documented behavior; a positive budget cap
stops new work at the boundary and accounts for in-flight work; resume validates deliverables.

**Acceptance Scenarios**:

1. **Given** split vs combined mode and a hunt-sample count, **When** hunt dispatches, **Then** the
   actual dispatch and repeated assignments change accordingly, preserving union semantics and sample
   provenance, and are recorded correctly.
2. **Given** per-role provider/backend/host/model choices, **When** their phases call inference, **Then**
   the assigned calls use those choices; blank/inherited choices have documented semantics; there is no
   silent provider switch and no external traffic beyond explicit operator configuration.
3. **Given** temperature, reasoning effort, context limit, and output limit, **When** applicable calls
   are made (including verification/repair/reproduction where relevant), **Then** the values reach those
   calls; a provider limitation is disclosed rather than recording an unapplied setting as honored; zero
   temperature is not replaced by a default.
4. **Given** `phases=all` with the optional threat-model toggle off, **When** the run completes, **Then**
   it is not falsely marked incomplete merely because the optional phase was disabled; explicit
   phase/toggle conflicts have a defined resolution or a pre-launch error.
5. **Given** IaC, ledger, remediation, and redaction toggles, **When** set, **Then** each changes its
   documented work/output; output redaction does not imply input was redacted before inference; artifact
   failures are reported and original evidence preserved per existing contracts.
6. **Given** a positive budget cap, **When** the scan runs (including parallel work and retries),
   **Then** real accounting and scheduling enforcement stop new work at the documented boundary with
   defined treatment of in-flight calls, available pricing, and estimated-vs-reported cost; an
   unenforceable cap for a provider is explained before launch, never run silently uncapped and never
   reported as zero cost for missing usage.
7. **Given** a resume, **When** it starts, **Then** it uses a compatible effective configuration and
   validates saved deliverables; changed settings that invalidate earlier work trigger explicit
   invalidation/replanning or an actionable incompatibility error.

---

### User Story 5 - Working UI controls and profile behavior (Priority: P1)

The previously disabled seeding, coverage, and concurrency controls are re-enabled **once their behavior
is implemented**, showing their effective state and concise help. Profiles apply only their documented
structural settings, preserve explicit operator overrides, and leave selected inference connections
intact. The default launch path keeps working during incremental development, and compatible cached
clients are preserved without accepting unknown options or silently changing requested behavior.

**Why this priority**: The operator interacts through the forms and profiles; a disabled switch or a
compatibility-only validator is explicitly not a fix. Ties the functional options back to the surfaces.

**Independent Test**: Launch through main, React, classic, and legacy entrypoints and profiles without
unsupported-option failures for valid advertised choices (using actual submit behavior and persisted
job config, not a copied payload); the reported `seed_routes=true` failure passes only after real
behavior exists; applying a profile / changing one field / navigating/reloading / resuming does not
reintroduce stale options or reset `false`/`0` values; build identity is included in validation
evidence.

**Acceptance Scenarios**:

1. **Given** an implemented option, **When** its control is shown, **Then** it is re-enabled with its
   effective state and concise help; a disabled switch, removed payload field, forced default, or
   compatibility-only validator does not satisfy the requirement.
2. **Given** main, React, classic, and legacy entrypoints and profiles, **When** an operator launches a
   scan with valid advertised choices, **Then** it queues without unsupported-option failures, verified
   by actual submit behavior and the persisted job configuration.
3. **Given** the served and embedded assets, **When** validation evidence is recorded, **Then** it
   includes build identity so a passing source test is not mistaken for a fixed running application, and
   the reported `seed_routes=true` failure is covered as a regression that passes only after real
   behavior is implemented.
4. **Given** a profile (built-in or user, including benchmark profiles that turn seeding off), **When**
   it is applied, **Then** only its documented structural settings apply, explicit operator overrides
   and selected inference connections are preserved, and applying/changing-one-field/navigating/
   reloading/resuming does not reintroduce stale options or reset `false`/`0` values. A silently
   accepted profile field is not implemented support.

---

### Edge Cases

- `false`, numeric `0` (where valid), omission, and `null` are distinct for every option; none is
  silently coerced to a default or rounded.
- An option that is inapplicable to the selected phases/providers is reported as not-applicable, not
  silently applied or silently dropped.
- A `seed_prior=true` with no eligible prior report (or malformed / wrong-repo / changed-source) runs
  explicitly unseeded, never faking a seed or borrowing another repo's report.
- A provider that cannot honor an inference parameter (temperature/reasoning/context/output) or a budget
  cap has that limitation disclosed before/at launch, not recorded as honored.
- Cancellation or a stop condition during parallel hunting preserves completed artifacts and accounts
  for unfinished assignments; no stale/duplicated/lost results.
- An older cached page or alternate client submitting a now-unknown option is handled per the contract
  (compatible defaults accepted; genuinely unknown/invalid values rejected with actionable errors) —
  distinguishing source assets, embedded assets, the running executable, older open pages, profiles, and
  alternate clients.
- Resume with settings that invalidate prior deliverables triggers explicit invalidation/replanning or
  an actionable incompatibility error — never silent reuse of stale work as valid completion.

## Requirements *(mandatory)*

### Functional Requirements

**Option contract & validation (US1)**

- **FR-001**: The system MUST define one authoritative contract for every scan option covering at least:
  route seeding, prior-report seeding, coverage enforcement, concurrency, split/combined hunting, hunt
  samples, IaC lens, threat-model/SBOM behavior, ledger, redaction, remediation, quality strictness,
  phase selection, partition limits, context/output limits, reasoning effort, temperature, budget cap,
  model/provider/host and per-role overrides, resume, output location, application name, profile
  selection, and any sweep-mode settings profiles/parity contracts expose. Each entry documents type,
  default, accepted range/enum, dependencies, applicable phases/providers, omitted/null handling,
  precedence, effective value, and observable effect.
- **FR-002**: Equivalent option inputs from the UI, API, CLI, and profiles MUST resolve to equivalent
  effective configuration and behavior.
- **FR-003**: `false`, numeric `0` (where valid), omission, and `null` MUST be treated as distinct; the
  system MUST NOT convert `false` to a true default nor silently round fractional concurrency.
- **FR-004**: Invalid types, unsupported combinations, or missing prerequisites MUST fail **before a
  scan is queued**, with actionable field-specific errors, deterministic when multiple fields are
  invalid; invalid requests MUST NOT start model work.
- **FR-005**: The effective configuration MUST be exposed to the operator and persisted in run metadata
  with secrets removed, distinguishing requested values, applied values, and explained
  non-applicability.
- **FR-006**: UI defaults MUST NOT overwrite saved values or explicit operator overrides without
  explanation.
- **FR-007**: Each accepted option MUST be traced to its actual effect in the engine — adding a key to
  an allowlist (accepting an ignored field) MUST NOT be treated as implementing the option.

**Route & prior-report seeding (US2)**

- **FR-008**: `seed_routes=true` MUST provide the current deterministic **multi-language** entry-point
  inventory (feature 012's inventory/recognize, not a competing Python-only inventory) to Phase-1 recon
  as bounded, source-grounded additional context; `false` MUST omit this optional seed. It MUST control
  recon context only — not whether coverage is measured or which source is eligible — and MUST NOT erase
  mandatory scope/assignment facts.
- **FR-009**: The system MUST record whether route seeding was requested/applied, the seed
  source/version, scope/count, and any truncation or unavailable inventory; empty/partial inventories
  MUST be explained, never presented as a complete attack-surface list. If recon is not selected, the
  option MUST be reported not-applicable without silently launching an extra phase.
- **FR-010**: `seed_prior=true` MUST deterministically select an eligible prior report for the **same**
  repository/application and supply its prior findings as recon leads, recording report identity,
  revision, and whether context was supplied; `false` MUST inject none. Missing/malformed/mismatched/
  unavailable prior reports MUST be visible and yield an explained unseeded scan — never a fake seed and
  never another repository's report.
- **FR-011**: Prior findings used as seeds MUST be independently re-verified against current source; the
  system MUST NOT copy historical support, severity, execution claims, or human decisions into new
  evidence, and MUST identify runs using prior findings as seeded/correlated so they are not presented
  as independent benchmark samples.

**Coverage enforcement & concurrency (US3)**

- **FR-012**: `enforce_coverage=true` MUST enable the documented coverage-driven hunt-plan augmentation;
  `false` MUST disable that automatic augmentation. Both MUST retain inventory, coverage measurement,
  and honest disclosure of unassigned/unreviewed scope; disabling MUST NOT manufacture complete
  coverage. The relationship to threat-model augmentation, deterministic fallback planning, and
  partition limits MUST be specified rather than conflated into one toggle.
- **FR-013**: `concurrency=1` MUST run hunt assignments serially; supported values greater than one MUST
  permit real bounded overlap consistent with the Phase-2 semantics, with a defined allowed range, a
  definition of an active agent, and defined interactions with sampling, provider capacity,
  cancellation, retries, circuit breakers, and budget.
- **FR-014**: Parallel execution MUST NOT mix assignment outputs, corrupt shared counters, duplicate
  candidates, lose completed work, or publish stale results; aggregation MUST be deterministic where
  order is not semantically meaningful, and MUST be race-detector clean.
- **FR-015**: On cancellation or a stop condition, the system MUST stop scheduling new work, preserve
  completed artifacts, and account for unfinished assignments explicitly.

**Engine honoring of accepted settings (US4)**

- **FR-016**: Split vs combined mode MUST change actual hunt dispatch and be recorded correctly; hunt
  samples MUST change repeated assignments while preserving union semantics and sample provenance.
- **FR-017**: Per-role provider/backend/host/model choices MUST reach their assigned calls; blank/
  inherited choices MUST have documented semantics; there MUST be no silent provider switch and no
  external traffic beyond explicit operator configuration.
- **FR-018**: Temperature, reasoning effort, context limit, and output limit MUST reach applicable calls
  (including verification/repair/reproduction where relevant); zero temperature MUST NOT be replaced by
  a default; a provider limitation MUST be disclosed rather than recording an unapplied setting as
  honored.
- **FR-019**: Threat-model/SBOM expectations MUST be explicit: `phases=all` with the optional
  threat-model toggle off MUST NOT create a false incomplete run; explicit phase/toggle conflicts MUST
  have a defined resolution or a pre-launch error.
- **FR-020**: IaC, ledger, remediation, and redaction toggles MUST change their documented work/output;
  output redaction MUST NOT imply input was redacted before inference; artifact failures MUST be
  reported and original evidence preserved per existing contracts.
- **FR-021**: A positive budget cap MUST have real accounting and scheduling enforcement across relevant
  calls/providers (including parallel work and retries), with defined treatment of in-flight calls,
  available pricing, and estimated-vs-reported cost. The system MUST NOT promise a strict monetary
  ceiling without a defensible bound; an unenforceable cap MUST be explained before launch, never run
  silently uncapped, and missing usage MUST NOT be reported as zero cost.
- **FR-022**: Resume MUST use a compatible effective configuration and validate saved deliverables;
  changed settings that invalidate earlier work MUST trigger explicit invalidation/replanning or an
  actionable incompatibility error.

**UI controls & profiles (US5)**

- **FR-023**: Previously disabled seeding, coverage, and concurrency controls MUST be re-enabled once
  their behavior is implemented, showing effective state and concise help. A disabled switch, removed
  payload field, forced default, or compatibility-only validator MUST NOT be counted as satisfying the
  behavior requirements.
- **FR-024**: Scans MUST launch through the main, React, classic, and legacy supported entrypoints and
  profiles without unsupported-option failures for valid advertised choices, verified by actual submit
  behavior and the persisted job configuration (not a copied payload alone).
- **FR-025**: The default launch path MUST keep working during incremental development; compatible
  cached clients MUST be preserved without accepting unknown options or silently changing requested
  behavior; validation evidence MUST include build identity so a passing source test is not mistaken for
  a fixed running application, distinguishing source assets, embedded assets, the running executable,
  older open pages, profiles, and alternate clients.
- **FR-026**: Profiles (built-in and user, including benchmark profiles that turn seeding off) MUST
  apply only their documented structural settings, preserve explicit operator overrides, and leave
  selected inference connections intact; applying a profile, changing one field, navigating/reloading,
  or resuming MUST NOT reintroduce stale options or reset `false`/`0` values; a silently accepted
  profile field is not implemented support.

**Preservation & safety (cross-cutting)**

- **FR-027**: The feature MUST preserve feature 012's ongoing multi-language work, analyst workflows,
  saved results, application names, ledger/review data, and all existing dashboard metrics/charts, and
  MUST NOT regress existing default requests, history, multi-language scope, or scan safety.
- **FR-028**: The system MUST preserve existing scan safety defaults (static-only, path/secret handling,
  explicit inference destinations, no egress beyond operator-configured endpoints) and MUST NOT execute
  target code to configure or launch a scan.
- **FR-029**: `../vhlocal` MUST be used only as a read-only behavioral reference; intentional
  differences MUST be documented and stronger current evidence rules preserved (unsafe/inaccurate
  reference behavior MUST NOT be blindly ported).
- **FR-030**: Temporary tests that currently expect seeding/parallelism rejection MUST be updated to
  test their newly implemented effects; rejection tests for genuinely invalid inputs MUST be retained.

### Key Entities *(include if feature involves data)*

- **Scan option definition**: The authoritative description of one option — id, type, default, accepted
  range/enum, dependencies, applicable phases/providers, omitted/null handling, precedence, and
  observable effect.
- **Option matrix entry**: One option's mapping across surfaces — UI control(s), API key, CLI flag,
  profile field — to its effective configuration, engine behavior, saved metadata, and acceptance test.
- **Effective configuration**: The resolved per-run configuration distinguishing requested values,
  applied values, and explained non-applicability; persisted in run metadata with secrets removed.
- **Route seed context**: The bounded, source-grounded multi-language inventory supplied to recon when
  route seeding is applied, with source/version/scope/truncation provenance.
- **Prior-report seed context**: The deterministically selected eligible prior report (identity,
  revision) and its findings supplied as recon leads, marked seeded/correlated and independently
  re-verified.
- **Concurrency scheduler state**: The bounded set of active hunt assignments, respecting the limit,
  cancellation/stop conditions, and safe aggregation.
- **Budget accounting**: Per-run cost accounting (available pricing, estimated vs reported, in-flight
  treatment) enforcing a positive cap or disclosing non-enforceability.
- **Profile**: A named set of documented structural settings (built-in or user) applied without
  overriding explicit operator choices or inference connections.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001 (Route seeding effect)**: A browser launch using the actual served form with route seeding on
  queues successfully AND the recorded Phase-1 request contains the expected seeded inventory; with it
  off, the optional seed is absent — verified for supported Python and Go fixtures and mixed/unsupported
  scope (without pretending discovery is complete). HTTP 201 alone does not pass.
- **SC-002 (Prior seeding effect)**: Prior-report seeding on/off produces the expected recon context and
  recorded provenance across no-prior, malformed history, wrong-repository, changed-source, and explicit
  phase omission; seeded prior findings never bypass current verification.
- **SC-003 (Coverage enforcement)**: A deliberately incomplete model partition plan produces coverage
  augmentation with enforcement on and explicit unassigned/unreviewed scope with it off; coverage
  remains truthful in both cases.
- **SC-004 (Bounded concurrency)**: A barrier-controlled fake provider demonstrates more than one
  overlapping hunt assignment at concurrency > 1, never exceeding the limit; concurrency 1 stays serial;
  cancellation, failure, and sampling are exercised with consistent artifact bindings/counters and
  race-detector coverage.
- **SC-005 (Per-role providers & inference options)**: Recording providers verify the effective
  model/host/backend per role and the actual inference options (temperature/reasoning/context/output)
  reaching applicable calls; split/combined assignment counts and sample counts match requested behavior
  (bounded by a deterministic seed manifest).
- **SC-006 (Budget enforcement)**: Positive budget caps stop new work at the documented boundary,
  account for in-flight work, and preserve partial results across missing-pricing, retries, zero/no cap,
  and local and mixed-provider scenarios with controlled usage data.
- **SC-007 (Full option matrix)**: Every exposed toggle is exercised in both states and every
  numeric/enum control at valid and invalid boundaries, each recording an observable effect or explicit
  documented non-applicability, across UI, API, CLI, profiles, and applicable resume/repeat paths,
  including `false`/`0`/omitted/`null` semantics.
- **SC-008 (Cross-surface launch)**: Launch through main, React, classic, and legacy entrypoints and
  profiles succeeds without unsupported-option failures for valid advertised choices (verified by actual
  submit behavior and persisted job config); invalid requests never start model work; the reported
  `seed_routes=true` failure is a regression that passes only after real behavior is implemented.
- **SC-009 (No regression)**: Existing default requests, dashboard numbers, history, multi-language
  scope (feature 012), analyst review/ledger data, and scan safety are preserved; temporary
  seeding/parallelism-rejection tests are updated to test implemented effects while invalid-input
  rejection tests are retained.
- **SC-010 (Effective-config honesty)**: For every launch, the persisted run metadata exposes the
  effective configuration with requested vs applied values (and explained non-applicability), secrets
  removed; no accepted field is silently ignored and no provider limitation is recorded as honored.
- **SC-011 (Offline validation & provenance)**: All acceptance runs offline with fake/recording
  providers and the full existing Go suite, plus race checks for new concurrency and a browser check for
  the shipped build; actual checks, build provenance, limitations, and skipped validation are reported;
  no unsolicited live paid scan and no execution of target code are required.

## Assumptions

- **Read-only Python reference**: `../vhlocal` informs intended option semantics (recon seeds, parallel
  dispatch, role routing, budget accounting) but is a behavioral reference only; intentional differences
  are documented and stronger current evidence rules are preserved (FR-029).
- **Feature 012 is the inventory source**: route seeding reuses the evolving multi-language
  `internal/recognize`/`inventory` (feature 012), never a competing Python-only inventory; 012's
  in-progress work and data are preserved (FR-008/027).
- **Offline, deterministic validation**: fake/recording providers, barrier-controlled concurrency
  fixtures, a deterministic seed manifest, and the race detector validate behavior; per the standing
  project constraint no live model workloads are sent, no Python is executed, and no target code is run
  to configure/launch a scan (FR-028, SC-011).
- **Build-identity awareness**: because a compatibility patch already shipped, validation distinguishes
  source assets, embedded assets, the running executable, older open pages, profiles, and alternate
  clients, and records build identity so a green source test is not mistaken for a fixed running app
  (FR-025).
- **Sequencing** (delivery order, not scope reduction): (1) route/prior seeding + launch integration;
  (2) coverage enforcement + bounded concurrency; (3) the remaining option matrix + cross-surface
  regressions. An early seeding fix is not feature completion — the full matrix is tracked with a
  delivered/tested/remaining report and user documentation of effective settings and limitations.
- **No redesign**: this is a focused configuration/functionality repair; UI/API/CLI shapes and features
  008–012 behavior are preserved, with controls re-enabled (not redesigned) as behavior lands.
- **Budget bound is best-effort-with-disclosure**: a positive cap is enforced with real accounting and a
  defensible bound; where a provider cannot be capped or lacks pricing, that is disclosed before launch
  rather than promised as a strict monetary ceiling (FR-021).

### Explicit Exclusions / Non-Goals

- A UI/UX redesign, or new options beyond the advertised matrix.
- A strict, provider-guaranteed monetary ceiling where pricing/usage is unavailable (best-effort bound +
  disclosure instead).
- New dynamic execution of target code, live paid model runs, or requiring target-language toolchains to
  validate configuration behavior.
- Changing feature 008–012 behavior, dashboards, or persisted data semantics beyond the additive
  effective-configuration metadata this feature records.
- Completing feature 012's remaining language stages (tracked separately); this feature only ensures the
  seeding option consumes 012's current inventory without a competing one.
