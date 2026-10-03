# Claude handoff: Make scan options work end to end

Prepared: 2026-09-28

## Start in Claude

```text
/speckit-specify Read docs/engineering/2026-09-28-scan-options-speckit-specify.md and use its entire "Specification input" section as the feature description. Create a new feature specification and requirements checklist for functional scan options across the UI, API, CLI, profiles, and scanner. Implementing actual option behavior is the required outcome; hiding controls, accepting ignored fields, or forcing defaults is not a complete fix. Preserve feature 012's ongoing work and existing scan data. Stop after specification and checklist generation.
```

This is specification input for Claude. Preparing this document does not change
application code, create a feature branch, or change the active feature pointer.

## Observed starting point

- The operator first received `unsupported option: seed_routes` when launching
  a scan. The main, classic, and legacy forms submitted unsupported fields even
  at their default values.
- The preceding compatibility patch accepts only `seed_routes=false`,
  `seed_prior=false`, `enforce_coverage=true`, and `concurrency=1`. It disables
  those controls and removes them from the updated forms' payloads. This fixed
  default-request compatibility, not missing scanner functionality.
- The operator now receives `seed_routes is not implemented; set it to false
  or omit it`. The current validator emits that error for true or a non-boolean
  value. Capture the actual request and served build to determine its origin;
  do not assume that the operator merely failed to refresh the browser. The
  updated source forms omit the field, so distinguish source assets, embedded
  assets, running executable, older open pages, profiles, and alternate clients.
- Current `server.buildScan` does not populate `Phase2Mode` or `Temperature`
  despite accepting their request keys. Per-role backend/host keys are accepted,
  but the builder returns only the default Hunt provider. These are additional
  configuration-path gaps, not proof that every related CLI path is broken.
- `BudgetSpentUSD` has no charging integration in the hunt budget check; simply
  accepting a positive cap does not demonstrate enforcement.

Recheck these observations against the current code before implementing. The
Python application in `../vhlocal` is a read-only behavioral reference.

## Specification input

Create a feature named "Functional scan options" for vhlocal-go. The operator
must be able to configure and launch a scan with the advertised options, and
each effective option must produce its documented scanner behavior. The UI,
request validator, configuration builder, engine, profiles, persisted job, and
results must agree on the meaning and value of those options.

Read the constitution and existing scan-option/parity contracts first. Preserve
ongoing feature 012 multi-language work, analyst workflows, saved results,
application names, ledger/review data, and all existing dashboard metrics and
charts. This is a focused configuration/functionality repair, not a redesign.

### P1: Establish one explicit scan-option contract

Inventory every option exposed by the shipped main UI, React UI, classic and
legacy entrypoints, public scan API, CLI, and built-in/user profiles. Include
resume and repeat-scan paths where they exist. For each option document its
type, default, accepted range/enum, dependencies, applicable phases/providers,
omitted/null handling, precedence, effective value, and observable effect.

The matrix must cover at least route seeding, prior-report seeding, coverage
enforcement, concurrency, split/combined hunting, hunt samples, IaC lens, threat
model/SBOM behavior, ledger, redaction, remediation, quality strictness, phase
selection, partition limits, context/output limits, reasoning effort,
temperature, budget cap, model/provider/host and role overrides, resume, output
location, application name, and profile selection. Assess sweep-mode settings
where profiles or parity contracts expose them; a silently accepted profile
field is not implemented support.

Explicit false, numeric zero where valid, omission, and null are distinct.
Never convert false to a true default or fractional concurrency to an integer
silently. Invalid types, unsupported combinations, or missing prerequisites
must fail with actionable field-specific errors before queuing a costly scan.
Return deterministic errors when multiple fields are invalid.

Expose the effective configuration to the operator and persist it in run
metadata with secrets removed. Distinguish requested values, applied values,
and any explained non-applicability. Equivalent UI/API/CLI/profile inputs must
resolve to equivalent behavior. UI defaults must not overwrite saved values
or explicit operator overrides without explanation.

### P1: Implement route and prior-report seeding

**Route seeding:** `seed_routes=true` must provide the current deterministic
entry-point inventory to Phase 1 reconnaissance as additional investigation
context. False must omit this optional seed. Reuse the evolving multi-language
inventory from feature 012; do not introduce a competing Python-only inventory.
This option controls recon context, not whether coverage is measured or source
is eligible for investigation. Do not erase mandatory scope/assignment facts
merely to distinguish the off state.

Record whether seeding was requested/applied, seed source/version, scope/count,
and any truncation or unavailable inventory. Empty or partially supported
inventories must be explained, not called a complete attack-surface list. If
recon is not selected, identify the option as not applicable without silently
launching an extra phase. Keep seed content bounded and source-grounded.

**Prior-report seeding:** `seed_prior=true` must select an eligible prior report
for the same repository/application and provide prior findings as investigation
leads to recon. Define selection deterministically and record report identity,
revision, and whether context was supplied. False must not inject those leads.
Missing, malformed, mismatched, or unavailable prior reports must be visible;
no eligible report may produce an explained unseeded scan rather than a fake
successful seed. Never read another repository's report as a substitute.

Prior findings must be independently reverified against current source. Do not
copy historical support, severity, execution claims, or human decisions into
new evidence. Identify runs using prior findings as seeded/correlated so they
are not presented as independent benchmark samples. Use the Python reference
for intended semantics while preserving stronger current evidence rules.

### P1: Make coverage enforcement and parallelism functional

`enforce_coverage=true` enables the documented coverage-driven augmentation of
the hunt plan; false disables that automatic augmentation. Both settings retain
inventory, coverage measurement, and honest disclosure of unassigned or
unreviewed scope. Disabling enforcement must never manufacture complete
coverage. Specify the relationship to threat-model augmentation, deterministic
fallback planning, and partition limits instead of treating all of these as
one toggle.

`concurrency=1` runs hunt assignments serially. Supported values greater than
one must permit actual bounded overlap, consistent with the Python option's
Phase 2 semantics. Define the allowed range, what counts as an active agent,
and interactions with sampling, provider capacity, cancellation, retries,
circuit breakers, and budget enforcement. Do not imply every scanner phase
becomes parallel or promise a particular speedup.

Parallel execution must not mix assignment outputs, corrupt shared counters,
duplicate candidates, lose completed work, or publish stale results. Stop
scheduling new work after cancellation or a relevant stop condition, preserve
completed artifacts, and account for unfinished assignments explicitly.
Aggregate results deterministically where order is not semantically meaningful.

### P1: Honor accepted settings throughout the engine

Trace each matrix option to its effect rather than adding keys to an allowlist.
In particular:

- Split versus combined mode must change actual hunt dispatch and be recorded
  correctly. Hunt samples must change repeated assignments and preserve union
  semantics and sample provenance.
- Per-role provider/backend/host/model choices must reach their assigned calls.
  Blank/inherited choices have documented semantics. No silent provider switch
  or external traffic beyond explicit operator configuration is allowed.
- Temperature, reasoning effort, context limits, and output limits must reach
  applicable calls, including verification/repair/reproduction where relevant.
  Disclose provider limitations rather than recording an unapplied setting as
  honored. Zero temperature must not be replaced by a default.
- Threat-model and SBOM expectations must be explicit. `phases=all` with the
  optional threat-model toggle off must not create a false incomplete run
  merely because the optional phase was disabled. Explicit phase/toggle
  conflicts need defined resolution or a pre-launch error.
- IaC, ledger, remediation, and redaction toggles must change their documented
  work/output behavior. Redaction of output does not imply input was redacted
  before inference. Report artifact failures and preserve original evidence
  according to existing contracts.
- A positive budget cap must have real accounting and scheduling enforcement
  across relevant calls/providers, including parallel work and retries. Define
  treatment of in-flight calls, available pricing, and estimated versus reported
  cost. Do not promise a strict monetary ceiling without a defensible bound.
  If a requested cap cannot be enforced for a provider, explain that before
  launch; do not silently run uncapped or claim zero cost for missing usage.
- Resume must use a compatible effective configuration and validate saved
  deliverables. Changed settings that invalidate earlier work must trigger
  explicit invalidation/replanning or an actionable incompatibility error.

### P1: Restore working UI controls and profile behavior

Re-enable the previously disabled seeding, coverage, and concurrency controls
when their behavior is implemented. Show their effective state and concise
help text. A disabled switch, removed payload field, forced default, or
compatibility-only validator does not satisfy the core requirements above.

Keep the existing default launch path working during incremental development.
Preserve compatible cached clients without accepting unknown options or
silently changing requested behavior. Check the actual served and embedded
assets. Include build identity in validation evidence so a successful source
test is not mistaken for a fixed running application.

Profiles must apply only their documented structural settings, preserve explicit
operator overrides, and leave selected inference connections intact. Support
built-in and user profiles, including benchmark profiles that explicitly turn
seeding off. Applying a profile, changing one field, navigating/reloading, or
resuming must not reintroduce stale options or reset false/zero values.

### Acceptance and validation

Convert these outcomes into requirements and Given/When/Then acceptance cases:

1. A browser launch using the actual served form with route seeding on queues
   successfully and the recorded Phase 1 request contains the expected seeded
   inventory. With it off, the optional seed is absent. Test supported Python
   and Go fixtures and mixed/unsupported scope without pretending discovery is
   complete. Capturing HTTP 201 alone is not sufficient.
2. Prior-report seeding on/off produces the expected recon context and recorded
   provenance. Cover no prior report, malformed history, wrong repository,
   changed source, and explicit phase omission. Old findings never bypass
   current verification.
3. A deliberately incomplete model partition plan produces coverage augmentation
   with enforcement on and unassigned/unreviewed scope with it off. Coverage
   remains truthful in both cases.
4. A barrier-controlled fake provider demonstrates more than one overlapping
   hunt assignment at concurrency greater than one, never exceeding the limit;
   concurrency one stays serial. Exercise cancellation, failure, and sampling,
   with consistent artifact bindings/counters and race-detector coverage.
5. Recording providers verify effective model/host/backend per role and actual
   inference options. Split/combined assignment counts and sample counts match
   requested behavior. Use a deterministic seed manifest to bound these tests.
6. Positive budget caps stop new work at the documented boundary, account for
   in-flight work, and preserve partial results. Test missing pricing, retries,
   zero/no cap, local and mixed-provider scenarios with controlled usage data.
7. Exercise every exposed toggle in both states and every numeric/enum control
   at valid and invalid boundaries. Record an observable effect or explicit
   documented non-applicability. The matrix covers UI, API, CLI, profiles, and
   applicable resume/repeat paths, including false/zero/omitted/null semantics.
8. Launch through main, React, classic, and legacy supported entrypoints and
   profiles without unsupported-option failures for valid advertised choices.
   Use actual submit behavior and persisted job configuration, not a copied
   payload alone. Invalid requests never start model work. Include the reported
   `seed_routes=true` failure as a regression that passes only after real
   behavior is implemented.
9. Regression tests preserve existing default requests, dashboard numbers,
   history, multi-language scope, and scan safety. Update the temporary tests
   that currently expect seeding/parallelism rejection to test their newly
   implemented effects; retain rejection tests for genuinely invalid inputs.
10. Run offline tests with recording/fake providers and the full existing Go
    suite; run race checks for new concurrency and browser checks for the shipped
    build. Report actual checks, build provenance, limitations, and skipped
    validation. No unsolicited live paid scan or execution of target code is
    required to validate configuration behavior.

### Deliverables and sequencing

Produce a specification and separate quality checklist. The subsequent plan
must include an option-by-option traceability matrix from control/request to
effective configuration, engine behavior, saved metadata, and acceptance test.
Use `../vhlocal` as a read-only behavior reference and document intentional
differences; do not blindly port unsafe or inaccurate behavior.

Deliver route/prior seeding and launch integration first, then coverage and
bounded concurrency, then complete the remaining option matrix and cross-surface
regressions. Keep the entire scope tracked: an early seeding fix is not feature
completion. Produce a delivered/tested/remaining matrix and user documentation
for effective settings and limitations. Do not spend another sprint solely on
specification, UI wiring, or validators while leaving the engine unimplemented.

## Source pointers for planning

- `internal/server/handlers.go`: option validation and launch submission.
- `internal/server/server.go`: effective scan configuration and provider routing.
- `internal/cli/run.go`, `internal/profiles/profiles.go`: flags and profile handling.
- `internal/engine/engine.go`, `hunt.go`, `verify.go`, `reproduction.go`,
  `record.go`, `regenerate.go`: phase behavior, calls, persistence, and resume.
- `internal/inventory/`, `internal/recognize/`, `internal/phases/partition.go`:
  current multi-language scope and coverage augmentation.
- `internal/client/`: provider-specific inference parameters and usage.
- `vhlocal/web/index.html`, `index.classic.html`, `index.legacy.html`,
  `web-react/src/pages/NewScan.tsx`: launch forms, profiles, payload construction.
- `internal/server/scan_launch_test.go`, `options_test.go`,
  `effective_config_test.go`: existing launch/option regression checks.
- `../vhlocal/vhlocal/engine.py`, `server.py`, profiles/client/CLI modules:
  reference option semantics, recon seeds, parallel dispatch, role routing,
  and budget accounting.
