# Phase 1 Data Model: Complete, usable scan-to-report workflows

Entities and their operator-facing fields, derived from the reference aggregation semantics (research R1/R2) and the current Go/UI contract (R11). Field names match what both browser surfaces already consume (`web-react/src/lib/types.ts` and the legacy `vhlocal/web/index.html`), so the work is server-side aggregation and truthful propagation — not a UI reshape.

Convention: `null` (not `0`/`""`) means "unknown/absent" and MUST be distinguishable by the UI (e.g. no ledger ⇒ `open_findings=null`, not `0`).

---

## Application identity

- **slug** = `"{basename}-{sha1(resolved_repo_path)[:8]}"`. Stable handle used by every route. Two spellings of the same directory resolve to one slug; moving the directory changes the slug.
- Discovery set = `registry ∪ reports-by-slug ∪ ledgers` minus hidden slugs. An application exists if it has a registry entry **or** any report on disk under its slug **or** a ledger — **independent of whether tracking (ledger) was enabled**.

## AppSummary (applications list item)

| Field | Type | Meaning / rule |
|---|---|---|
| `slug` | string | stable identity |
| `name` | string | registry name → ledger target name → latest report repo/name → slug |
| `repo` | string | registry repo → ledger target → latest report repo → "" |
| `named` | bool | slug has a registry entry (hidden entries included in the registry) |
| `scans` | int | number of reports grouped under this slug |
| `last_scanned` | int (epoch) | latest report time, else registry `updated`, else 0 |
| `latest_findings` | int | substantiated findings of the newest report, else 0 |
| `latest_severities` | map | newest report severity counts, else {} |
| `latest_coverage` | string | newest report `coverage_status`, else "" |
| `latest_report_id` | string | newest report id, else "" |
| `open_findings` | int \| null | ledger open count; **null when no ledger** |
| `ledger_total` | int \| null | ledger total; **null when no ledger** |
| `has_threat_model` | bool | any of the app's reports has `threat_model.md` |
| `has_sbom` | bool | any of the app's reports has `sbom.cdx.json` |

Sorted by `-last_scanned`. Hidden (forgotten) slugs are excluded from the list.

## AppDetail (extends AppSummary)

| Field | Type | Meaning |
|---|---|---|
| `scan_history` | ScanHistoryRow[] | one row per report, newest first |
| `has_ledger` | bool | a ledger exists for this slug |

Detail is fetchable for a hidden slug if a report/ledger remains (unlike the list).

### ScanHistoryRow

`id, created, model, findings, hypotheses, severities, coverage_status, coverage_degraded, has_report, has_threat_model, has_sbom, recall_pct, chains`.
Rules: `findings` = substantiated only (tiers `statically_supported`, `reviewed`); `hypotheses` = non-substantiated; `recall_pct` = **null unless** there were known open findings (an absent/first ledger is not 0%); availability flags are per-report here (aggregated with `any(...)` in the summary).

## Report

Existing rich record built per results dir. Operator-facing fields used by aggregation and lists: `id, path, name, repo, model, model_reported, created, findings, hypotheses, severities, coverage_status, coverage_degraded, recall_pct, chains, sbom_total, has_sbom, has_threat_model, has_report, has_consolidated, phases_present, slug`. Availability flags are **file-existence**; findings/severities come from `findings.json` (never scraped); `phases_present` is derived from deliverable presence and is the source of "how far a scan got."

## Scan / Job

Queue record for a run; persists across restart; dead in-flight jobs load as `interrupted`.

| Field | Type | Notes |
|---|---|---|
| `id` | string | |
| `spec` | object | requested options (repo, model, phases, threat_model, ledger, hunt_samples, phase2_mode, max_partitions, role models/providers, …) |
| `status` | enum | `queued \| running \| done \| failed \| cancelled \| interrupted` (queue axis; terminal set = last four) |
| `created_at`/`started_at`/`finished_at`/`elapsed` | time/int | |
| `results_dir` | string | link to the report/evidence |
| `error` | string \| null | queue-level error |
| `phase` | string | current phase label (from `phase_start`) |
| `agent_label`/`agent_index`/`agent_total`/`current_model` | string/int | live agent progress — **MUST be populated** (currently always 0) |
| `prompt_tokens`/`completion_tokens` | int | live token totals — **MUST be populated** (currently always 0) |
| `findings_count`/`findings_stage` | int/enum | `""\|confirmed\|final`; `final` never regresses to `confirmed` |
| `phase_outcomes` | PhaseOutcome[] | **NEW**: validated per-phase result for the UI (see below) |
| `execution_status`/`coverage_status`/`validation_mode` | string | **NEW on the scan surface**: the three engine axes, surfaced distinctly from `status` |

Queue `status` (queue axis) MUST stay distinct from `execution_status`, `coverage_status`, `validation_mode` (the three engine axes). A terminal `status=done` MUST NOT imply `execution_status=complete`.

### PhaseOutcome

`phase` (key), `label`, `requested` (bool), `completed` (bool), `produced` (bool — a valid deliverable exists), `reason` (why incomplete/skipped, when applicable). Derived from engine facts (`phases_requested`/`phases_completed`/`phases_skipped` + deliverable validity), never from the job's terminal flag or the current phase index. A partial run has ≥1 `requested && !completed`.

## RunStatus (three axes) — already computed, must be propagated

`execution_status` ∈ {complete, partial, incomplete, aborted, cancelled, unknown}; `coverage_status` ∈ {complete, partial, degraded} with `coverage_degraded_reasons[]`; `validation_mode` ∈ {static_reasoning/static, dynamic_execution}. No axis derived from another (constitution II). Computed by `consolidate.ComputeRunStatus`; this feature carries it faithfully to the job/API/report/UI.

## MaterialAvailability (threat model, SBOM, sweep leads, coverage)

Per artifact, an explicit state — never a bare present/absent boolean where a failure is possible:

`not_requested | pending | available | generation_failed | missing | unreadable | malformed`

Plus, when `available`: an open/download reference. Rules: SBOM is a deterministic artifact written inside Phase 1t before the threat agent; both are gated on 1t. Generation/parse/read failures MUST surface (the current discarded `sbom.Write` error becomes visible). Discovery of pre-existing on-disk material MUST NOT fabricate absence or rewrite evidence.

## Candidate & VerificationOutcome

A hunt candidate with a disposition and recovery accounting.

| Field | Meaning |
|---|---|
| `candidate_id` | stable `CAND-…`; never renumbered |
| `disposition` | `supported \| rejected \| unresolved \| missing_decision` (distinct meanings preserved) |
| `reason` | useful explanation, especially for unresolved/missing |
| `attempts`/`failures` | bounded recovery counts (recorded, explainable) |
| `stop_reason` | `complete \| tool_repair \| max_turns \| endpoint_failure` |
| `evidence` | source-grounded citations; distinct sites stay distinct |

Recovery is bounded (per-candidate turn/failure budget), measured (counts recorded), and never fabricates support. Authorization/logic candidates may be supported on evidence without an injection-style syntactic sink, while attacker-control/precondition/defense/impact/revision/exact-evidence requirements remain enforced.

## ReproductionArtifact

Authored material or an explicit deferral bound to a **supported** candidate.

| Field | Meaning |
|---|---|
| `candidate_id` | must reference a supported candidate |
| `kind` | `poc \| test \| deferred` |
| `path` | under `poc/` or `exploit_tests/` (for poc/test) |
| `status` | `authored` (never "executed") |
| `reason` | required for `deferred` |
| `validation` | `valid \| {errors[]}` — invalid bindings get bounded corrective feedback in a per-candidate loop |

Every supported candidate ends with registered valid material or a specific deferral; candidate IDs stay stable; remaining failures are explained and preserved as evidence.

## EffectiveConfiguration

The operator's requested options resolved to what the engine actually did, persisted in run metadata: threat_model, ledger, role model/provider selections, hunt sampling, and partition/coverage behavior including `max_partitions` (requested), `partition_source`, resolved partition **count** (actual), `coverage_partitions_added`/`coverage_files_added`/`coverage_uncovered_remaining`, `threat_model_partitions`. Every supported option is honored-or-explicitly-rejected (never silently ignored); the requested-vs-actual partition relationship and whether `max_partitions` is a cap or a starting point are visible and explained.

## Relationships

- Application 1—N Report (by slug); Application 0/1 Ledger (by slug); Report 1—1 Scan/Job (by results_dir); Report 1—N Candidate; Candidate 0/1 ReproductionArtifact; Scan 1—1 EffectiveConfiguration; Report/Scan 1—1 RunStatus; Report 0/1 each MaterialAvailability (threat/SBOM).
- Identity spine: everything hangs off the **slug** (from the resolved repo path).
