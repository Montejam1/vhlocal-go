# Contract — Option-by-option traceability matrix

The authoritative mapping (the handoff's required deliverable): each option's control/request → effective
configuration → engine behavior → saved metadata → acceptance test. Columns:

- **Key/flag**: API key · CLI flag · profile key (where each exists).
- **ScanSpec**: field it resolves to (★ = new/needs population this feature).
- **Effect**: the documented engine behavior.
- **Status**: `ok` (works today) · `drop` (accepted, dropped in buildScan) · `inert` (accepted, no effect)
  · `compat` (compatibility-only rejection) · `none` (no field) · `missing-cli`/`missing-react`.

> **As-built status (updated 2026-09-28):** every option below now reports `ok` — the drop/inert/compat/
> missing gaps identified during planning are implemented and offline-tested (`sweep_mode` was resolved by
> removal from the profile allowed set, per FR-026). The `Status today` column reflects the shipped code.
- **Test**: the acceptance check that proves the effect (offline).

| Option | Key / flag / profile | ScanSpec | Effect | Status today | Acceptance test |
|---|---|---|---|---|---|
| Route seeding | `seed_routes` · `--seed-routes` · `seed_routes` | `SeedRoutes` ★ | seed recon with 012 multi-language inventory; off omits; N/A if no phase 1 | ok | recon input contains seeded inventory on / absent off (Py+Go+mixed); 201-only insufficient (SC-001) |
| Prior-report seeding | `seed_prior` · `--seed-prior` · `seed_prior` | `SeedPrior` ★ | seed recon leads from eligible prior report; reverified; provenance | ok | on/off recon context + provenance across no-prior/malformed/wrong-repo/changed-source/phase-omitted; no bypass of verification (SC-002) |
| Coverage enforcement | `enforce_coverage` · `--enforce-coverage` · `enforce_coverage` | `EnforceCoverage` ★ (default true) | true→augment plan; false→skip augmentation, still measure+disclose | ok | incomplete plan → augmentation on / unassigned-unreviewed off; truthful both (SC-003) |
| Concurrency | `concurrency` · `--concurrency` · `concurrency` | `Concurrency` ★ (default 1) | 1 serial; >1 bounded overlap ≤ limit | ok | barrier provider: >1 overlap never exceeding limit; 1 serial; -race; cancel/fail/sampling (SC-004) |
| Split/combined hunt | `phase2_mode` · `--phase2-mode` · `phase2_mode` | `Phase2Mode` | change hunt dispatch; recorded | ok | recording provider: dispatch/counts match; recorded (SC-005) |
| Hunt samples | `hunt_samples` · `--hunt-samples` · `hunt_samples` | `HuntSamples` | repeated assignments, union semantics + provenance | ok | sample count matches; provenance (SC-005) |
| IaC lens | `iac_lens` · `--iac-lens` · `iac_lens` | `IaCLens` (default true) | gates IaC hunt task/file | ok | toggle changes IaC work (SC-007) |
| Threat model / SBOM | `threat_model` · `--threat-model` | `ThreatModel` + `Phases` (1t) | gates phase 1t + threat_model.md; `phases=all` + off ≠ incomplete | ok | phases=all + off not false-incomplete; conflict resolved/erid (FR-019, SC-007) |
| Ledger | `ledger` · `--ledger` · `ledger` | `Ledger` | ledger emission | ok | toggle changes ledger output (SC-007) |
| Redaction | `redact` · `--redact` · `redact` | `Redact` | output redaction (not input) | ok | output redacted; input-redaction distinction explicit (FR-020) |
| Remediation | `remediate` · `--remediate` · `remediate` | `Remediate` | remediation emission | ok | toggle changes remediation output (SC-007) |
| Quality strictness | `quality_strictness` · `--quality-strictness` · `quality_strictness` | `QualityStrictness` | per-finding quality gate | ok | enum valid/invalid; effect on findings (SC-007) |
| Phases | `phases` · `--phases` | `Phases` | phase selection | ok | selection honored; invalid rejected (SC-007) |
| Partition limit | `max_partitions` · `--max-partitions` · `max_partitions` | `MaxPartitions` | partition/augmentation ceiling | ok | limit honored; >0 required (SC-007) |
| Context limit | `num_ctx` · `--num-ctx` · `num_ctx` | `NumCtx` | ChatRequest num_ctx + prune | ok | reaches calls; >0 (SC-005) |
| Output limit | `max_output_tokens` · `--max-output-tokens` · `max_output_tokens` | `MaxOutputTokens` | ChatRequest max output | ok | reaches calls incl. repair (SC-005) |
| Reasoning effort | `reasoning_effort` · `--reasoning-effort` · `reasoning_effort` | `ReasoningEffort` | ChatRequest reasoning | ok (dropped on repair) | reaches calls incl. repair retry (SC-005) |
| Temperature | `temperature` · `--temperature` ★ | `Temperature` ★ populate | ChatRequest temperature; `0` real | ok | recording provider: value (incl. 0) reaches calls; not defaulted (SC-005) |
| Budget cap | `max_budget_usd` · `--max-budget-usd` ★ · `max_budget_usd` | `MaxBudgetUSD` | real accounting; stop at boundary; disclose unpriced | ok | cap stops new work; in-flight accounted; missing pricing disclosed (SC-006) |
| Model | `model` · `--model` | `Model` | default model | ok | recording provider: effective model (SC-005) |
| Backend/Host | `backend`/`host` · `--backend`/`--host` | `Backend`/`Host` | default provider | ok | provider reaches calls; enum validated |
| Per-role model | `verify_model`/`recon_model`/`reproduce_model` · `--*-model` | `VerifyModel`/`ReconModel`/`ReproduceModel` | per-role model string | ok (same provider) | recording provider: per-role model (SC-005) |
| Per-role backend/host | `verify_backend`/`verify_host`/… | `VerifyBackend`/`VerifyHost`/… ★ | per-role provider; blank inherits | ok | recording provider: per-role backend/host reaches its calls; no silent switch (SC-005) |
| Resume | `resume` · `--resume` | `Resume` | resume with compatible config + validate deliverables | ok (config-compat needed) | incompatible change → invalidate/replan or error (FR-022) |
| Output location | `out` · `--out` | `ResultsDir` | results dir | ok | honored; allow-root confined |
| Application name | `app_name` (+`name`) · `--app-name` ★ | `AppName` | app registration name | ok | name honored; effective config |
| Profile selection | (server: none) · `--profile` · N/A | (applies overrides) | structural knobs only; overrides preserved | ok (CLI) | benchmark seeding-off applies; explicit override wins; no stale reset (SC-007) |
| Sweep mode | (profile `sweep_mode` only) | none | orphaned | resolved (removed) | resolved: removed from profile allowed set (no silent accept, FR-026) |

Cross-cutting for every row: `false`/`0`/omitted/`null` are distinct; invalid values rejected pre-queue
with field-specific, deterministic errors (FR-003/004); requested vs applied recorded in `effective_config`
(secrets removed, FR-005/SC-010); equivalent UI/API/CLI/profile inputs resolve identically (FR-002).
