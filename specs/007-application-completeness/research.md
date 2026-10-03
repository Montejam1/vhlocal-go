# Phase 0 Research: Complete, usable scan-to-report workflows

All findings are from **reading** source (Go in this repo; Python reference in `../vhlocal`, read-only) and the handoff evidence. No Python was executed; no scan was run.

---

## R1 — Application aggregation & discovery semantics (reference oracle)

**Decision**: Port the reference's slug-keyed aggregation and union discovery; make registration and discovery independent of the tracking ledger.

**What the reference does** (`../vhlocal/vhlocal/{apps,server,reports,membank}.py`):

- **Identity**: `slug = "{basename}-{sha1(resolved_path)[:8]}"` (`membank._slug`). The slug is the stable handle; two spellings of the same directory collapse to one slug; the resolved path is normalized. Reports bind to a slug via their `scan_meta.json` `repo`.
- **Registration is unconditional** on scan submit — `apps.register(repo, name, when)` is called from `_create_scan` regardless of the `ledger` flag. Idempotent; re-hides→un-hides; keeps the existing name unless a new one is given.
- **Discovery = union** `set(registry) | set(reports_by_slug) | set(ledgers)` minus `hidden_slugs()`. A repo becomes an application if it has a registry entry **or** any report on disk under its slug **or** a ledger — none of which requires tracking to be enabled.
- **`_app_summary`** (list item) keys: `slug, name, repo, named, scans, last_scanned, latest_findings, latest_severities, latest_coverage, latest_report_id, open_findings, ledger_total, has_threat_model, has_sbom`. `name`/`repo` coalesce registry→ledger→latest-report; `open_findings`/`ledger_total` are **null (not 0)** when no ledger; availability flags are `any(...)` across the app's scans.
- **`_application_detail`** = the summary plus `scan_history[]` (per report: `id, created, model, findings, hypotheses, severities, coverage_status, coverage_degraded, has_report, has_threat_model, has_sbom, recall_pct, chains`) and `has_ledger`. Detail does not exclude hidden slugs (list does).
- **Report** availability flags are pure file-existence (`sbom.cdx.json`, `threat_model.md`, `SCAN_REPORT`, `README.md`); findings/hypotheses/severities come from `findings.json` (never scraped); `recall_pct` is null unless there were known open findings; `phases_present` is derived from deliverable presence.
- **Forgotten/hidden**: DELETE hides the slug and deletes its ledger but **keeps reports**; re-scan un-hides via `register`.

**Rationale**: This is the exact behavior the shipped UI expects; matching it closes the "bare registry fields" and "ledger-disabled app invisible" gaps (FR-007..FR-011).

**Alternatives considered**: Inventing a Go-native summary shape — rejected; it would diverge from the UI's expectations and the reference the operator recognizes.

---

## R2 — Threat model ↔ SBOM relationship (reference oracle)

**Decision**: Treat the SBOM as a deterministic artifact produced inside Phase 1t (before the threat-model agent), and expose `has_threat_model`/`has_sbom` as independent file-existence availability flags — documenting that both normally appear together only when Phase 1t runs.

**What the reference does**: Phase 1t is opt-in (`spec.threat_model` or explicit `1t`). Within the 1t iteration, `write_sbom()` writes `sbom.cdx.json` deterministically (CycloneDX inventory) **before** the threat agent runs, and its summary is injected into the threat prompt; the threat agent then writes `threat_model.md`. At report time the SBOM summary lands under `findings.json.application_intelligence.sbom`. A scan without 1t has neither file.

**Consequence for Go (confirmed gap)**: in the Go engine the SBOM write error is discarded (`_, _ = sbom.Write(...)`) inside the 1t path — so a generation/parse failure is invisible. FR-018 requires surfacing generation/parse/read failures; FR-021 requires documenting and consistently reflecting this relationship. The availability flags must be file-existence based (matching the reference) but the states (not-requested / pending / available / generation-failed / missing / unreadable / malformed) must be represented explicitly rather than collapsed to a boolean.

**Rationale/Alternatives**: Making SBOM its own phase or an LLM output was rejected — it must stay deterministic (Principle: determinism where possible) and gated with the threat phase to match the reference.

---

## R3 — Truthful status propagation (engine → queue → UI)

**Decision**: Keep the engine's already-correct three-axis derivation and **propagate per-phase outcomes + the three axes through the job/API to both UIs**; stop mapping "engine returned no fatal error" to "all steps complete."

**Evidence**:
- `consolidate.ComputeRunStatus` already derives execution (complete/partial/incomplete/aborted/cancelled/unknown), coverage (complete/partial/degraded + reasons), and validation mode independently — and the saved report correctly said `partial/degraded/static_reasoning`.
- `internal/report/report.go` already carries an honest incomplete-run banner and a per-phase outcome table derived from `phases_completed` (not agent stop reasons).
- The defect is downstream: the queue marks the job `done` on a nil engine error + empty `Aborted`, and the step tracker renders `done` as every step complete. The reference `Job` keeps distinct terminal states (`done/failed/cancelled/interrupted`), forces dead `running/queued` jobs to `interrupted` on load, and its per-scan progress is phase-label + agent index/total + token counts + a findings stage — with execution/coverage/recall/queue as four separate axes.

**Rationale**: The truthful data already exists; the fix is faithful propagation and a UI that reads validated phase outcomes, not the terminal flag (FR-012..FR-016).

**Alternatives considered**: Re-deriving status in the UI — rejected; status must be computed once, deterministically, server-side (Principle II).

---

## R4 — Scan/report history persistence & legacy shapes

**Decision**: Ensure the scans/reports/apps lists are built from durable on-disk state that survives restart, tolerate mixed/legacy persisted shapes, and never render a transport/schema error as an empty success.

**Evidence**: Reference jobs persist and, on load, force interrupted state for dead in-flight jobs (never silent re-run — Principle VI). Reports are enumerated from the reports dir (+ job result dirs) and identified tolerantly. The handoff confirms 8 jobs/8 reports are returned by the Go API, so the blank views are a **UI-side rendering/contract** issue (unverified exact root cause) — to be reproduced on the shipped surface before choosing a fix, capturing the first JS exception and failed request.

**Rationale**: Aligns with FR-002/003/004 and the handoff's instruction not to prematurely diagnose the blank views as missing data or a stale process.

---

## R5 — Verification recovery (bounded, measured)

**Decision**: Keep the bounded same-endpoint recovery model (20 turns/candidate, ≤3 failures) but make it **measured and actionable** — categorize the saved `tool_repair`/`max_turns` exits, improve tool/schema compatibility and validation feedback, and record per-candidate attempt/failure counts; do not blindly raise retries.

**Evidence**: `internal/engine/verify.go` runs one session per candidate with `verifyTurnsPerCandidate=20`, `verifyMaxFailures=3`, recovering tool-parse errors within budget and degrading generic transport failures to unresolved. The handoff run showed 72 `tool_repair` + 26 `max_turns` exits and 98 missing decisions — i.e., recovery was exhausted or sessions never submitted. The specific failing tool calls/validation messages live in the saved traces under the report dir and must drive the strategy (Phase-1 investigation, per FR-023).

**Open sub-question (resolve in tasks from saved traces, not by guessing)**: which validation checks (evidence line-coverage, entry-point match, schema shape) most often blocked submission — informs targeted, non-weakening feedback.

**Rationale/Alternatives**: Increasing retries or loosening evidence requirements to lift completion metrics is explicitly rejected (FR-024/FR-027; Principle I).

---

## R6 — Authorization/logic acceptance vs. syntactic sink

**Decision**: Allow evidence-based authorization/logic verdicts without requiring an injection-style syntactic sink, matching the reference, while keeping attacker-control/precondition/defense/impact/revision/exact-evidence requirements.

**Evidence**: `internal/consolidate/corroborate.go` treats logic/authorization CWEs as NA (never supportable on a sink), and `validateEvidenceBacked` requires source corroboration; a saved unresolved rationale explicitly cites inability to recognize a CWE-284 write as a sink. The reference treats "not syntactically assessable" differently from a boolean sink requirement. The exact reference acceptance path for authz/logic supported verdicts must be read from the reference verification/quality code and mirrored (Phase-1 task).

**Rationale**: Closes a real false-negative class without weakening evidence integrity (FR-024).

---

## R7 — Reproduction per-candidate corrective loop

**Decision**: Replace the single aggregate reproduction agent with a bounded per-candidate authoring+validation loop that returns actionable feedback on invalid registrations/headers/locations/missing files, preserves stable candidate IDs, and allows an explicit deferral.

**Evidence**: `internal/engine/reproduction.go` runs ONE aggregate agent for all supported candidates, then `ValidateArtifacts` records errors with **no repair opportunity** — exactly why 6 test bindings failed in the handoff run (unregistered files + missing canonical ID/location). Supported-only assignment and authored-not-executed status are already enforced and must be retained (FR-025/FR-027).

**Rationale/Alternatives**: A single retry of the whole aggregate would waste work and not isolate the failing candidate; a bounded per-candidate loop is the reference-aligned, evidence-preserving choice.

---

## R8 — Report enrichment from canonical evidence

**Decision**: Enrich the deterministic report (Markdown/HTML/machine-readable) to lead with supported findings, separate rejected/unresolved, present full review detail per supported finding, link intelligence, and never conflate candidate totals with confirmed vulnerabilities — without reintroducing model-authored consolidation.

**Evidence**: `internal/report/report.go` currently renders only CWE/location/entry/flow/classification/fix per finding, mixes all non-duplicate findings by severity, and omits the review record (attacker control, preconditions, defenses reviewed, security impact, rationale, evidence excerpt) and reproduction/deferral status, and provides no navigation to threat/SBOM/coverage/sweep. The review detail exists in the verification decision/records and reconciliation; the report must read from that canonical evidence.

**Rationale**: Satisfies FR-028..FR-033 and SC-006; keeps determinism (Principle: deterministic reports) while raising usefulness. Usefulness is judged by a reviewer against the reference's report content, not by file length.

---

## R9 — Honest options & partition-count explanation

**Decision**: Trace each supported option to effective configuration + persisted metadata (honored or explicitly rejected), and make the requested-vs-actual partition relationship visible with a documented meaning of `max_partitions`.

**Evidence**: The handoff run requested `max_partitions=8` but resolved 24 partitions (US1 coverage/threat-model augmentation adds partitions beyond the plan; the reference augments partitions from the threat model's Hunt targets when `threat_model.md` exists). Whether `max_partitions` is a hard cap or a coverage-driven starting point must be confirmed against the reference and this repo's `resolvePartitions`/`AugmentForCoverage`/`AugmentFromThreatModel`, then documented and surfaced (FR-035). Effective config already has fields in `scan_meta.json` (e.g., `max_partitions`, `partition_source`, `coverage_*`, `threat_model_partitions`).

**Rationale**: Operators must trust and understand what their settings do and why a run's workload grew (FR-034/FR-036); the visibility requirement is honest reporting, not a behavior change to augmentation.

---

## R10 — Acceptance strategy (offline-first; reference as read-only oracle)

**Decision**: Drive acceptance from seeded on-disk fixtures and recorded model transcripts offline; add real-browser acceptance on the shipped surfaces against a live Go server with seeded data; supply a behavior matrix vs. the reference derived by reading it; keep any live-model validation a bounded, operator-approved plan.

**Evidence/Constraints**: Constitution VII (offline `go test ./...`, fakes/fixtures); FR-039/SC-008/SC-009; standing constraint and user memory: **never execute Python** for parity — compare against reference behavior read from source. Existing `tests/parity` offline fixtures + independent reference-contracts are retained and extended (FR-038).

**Rationale/Alternatives**: A passing Go suite or Go-generated golden alone is explicitly insufficient (SC-008); a live multi-hour scan is not auto-launched (FR-039).

---

## R11 — Confirmed Go-side deltas (current state vs. required)

**Decision**: The gaps are concrete and server/UI-local; fix them without touching the correctness engine except for status propagation, verification recovery, reproduction loop, and report content.

**Confirmed (with locations) from the current tree:**

- **Apps handlers return bare registry entries.** `handleApplications`/`handleApplication` (`internal/server/handlers.go:327-351`) return `apps.Entry` = `{slug,name,repo,created,updated,hidden}` (`internal/apps/apps.go:35-42`). The browser types already declare the enriched shapes (`web-react/src/lib/types.ts` `AppSummary`/`AppDetail`/`ScanHistoryRow`, mirroring the Python API) and the legacy UI reads the same fields — so the fix is **server-side aggregation**, not a UI reshape. → FR-007..FR-011, R1.
- **Registration is ledger-gated.** `apps.Register(spec.Repo)` is called only inside `if spec.Ledger {` (`engine.go:497-501`) and its error is discarded — so a ledger-disabled scan never becomes an application. → FR-007.
- **`rec.Aborted` is never assigned;** per-phase failures only record into `rec` and the loop continues, so `engine.Execute` returns `(rec, nil)` for degraded runs. `runScan` (`internal/server/server.go:97-117`) maps nil+empty-Aborted to success; the worker maps it to `done` (`internal/jobs/jobs.go:210-232`); `StepTracker.tsx:19,29,42-43` (and legacy `index.html`) map `done`→every-step-complete. **No per-phase produced/completed signal is exposed to the UI.** → FR-012..FR-016, R3.
- **Job progress fields are always zero.** `jobs.onEvent` (`jobs.go:237-264`) never sets `prompt_tokens/completion_tokens/agent_index/agent_total`, and the engine never emits them — the UI reads them (Scans tiles, StepTracker). → FR-013 (progress fidelity).
- **`usePoll` errors are dropped by the consumers.** `usePoll` captures `error` but `Scans.tsx`/`Dashboard.tsx` read only `data`, so a failed `/api/scans` renders as "No scans yet." `Applications.tsx` does surface its own fetch error. → FR-003.
- **The live operator UI is the legacy `vhlocal/web/index.html`**, not React: the React build is not embedded (`vhlocal/web/app/` is absent), so `GET /app` 404s (`static.go` dispatch; `assets.go` embed). Blank-view reproduction and fixes must cover the legacy UI as the primary surface; `/app`'s absence is itself an inventory finding. → I-1, FR-001.
- **SBOM write is gated on 1t success and its error discarded** (`engine.go:275-280`: `_, _ = sbom.Write(...)`); other deterministic writers similarly discard errors (`authz.Write`, `membank.Update`, `apps.Register`). The consolidated report/SARIF writes do propagate errors. → FR-018, R2.
- **Jobs persist across restart** (`jobs.json`, atomic; dead in-flight jobs forced to `interrupted` on load) — so history survival is largely present; the SSE event ring is not persisted. → FR-002 (mostly satisfied; verify legacy shapes render).

**Rationale**: This inventory turns the spec's "confirmed contract mismatches" into a precise, bounded change set and confirms the UI already expects the reference-shaped contract.

## Open investigations carried into tasks (not blocking the plan)

- **I-1 (UI surface inventory)** — RESOLVED to: primary served surface is legacy `vhlocal/web/index.html` (`/`, plus `/legacy`, `/classic`); `/app` (React) is not embedded and 404s. Decision for tasks: fix the legacy UI's data rendering (it already expects the enriched contract) and either embed the React build or explicitly scope `/app` out; reproduce the blank Scans/Apps failure on the legacy UI first.
- **I-2 (verification exit categorization)**: classify the 72 tool_repair / 26 max_turns exits from saved traces to pick targeted, non-weakening feedback (R5).
- **I-3 (authz/logic acceptance path)**: read the reference's exact authz/logic supported-verdict path and mirror it (R6).
- **I-4 (max_partitions semantics)**: confirm cap-vs-starting-point against reference + `resolvePartitions` and document (R9).

## Post-design constitution re-check

The Phase 1 design (data model + contracts + quickstart) introduces no target execution, no provider fallback, no new runtime dependency, and no status derived from another axis; it preserves existing evidence and the audit protections. **Constitution Check remains PASS after design.**

## R5-addendum (T030) — verification exit categorization (from saved traces)

Read-only analysis of the handoff run's `verification_reconciliation.json`:
- **98/140 unresolved are "No verification decision supplied"** — the session ended
  (72 `tool_repair`, 26 `max_turns`) BEFORE emitting `submit_verification`. This is a
  *session-completion* problem, not a validation-strictness one.
- The remaining unresolved are **explicit model `unresolved` submissions**, many of
  them **authorization/logic** (IDOR, TOCTOU, missing-authz, hardcoded-secret) — the
  class where the Go gate over-refuses a *supported* verdict for lacking a syntactic
  sink (R6/T034).

Implications for US5:
- T032/T037: record per-candidate `attempts`/`failures`/`stop_reason` and make the
  "no decision" outcome name its cause (tool_repair vs max_turns) so it is actionable;
  keep the bounded budget (do not silently raise retries).
- T034: allow evidence-based authz/logic *supported* verdicts (block only on a source
  FAIL, not on NA), so a complete authz review is not auto-refused.
