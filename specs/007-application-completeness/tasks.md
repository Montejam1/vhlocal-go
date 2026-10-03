---

description: "Task list for restoring complete, usable scan-to-report workflows (feature 007)"
---

# Tasks: Complete, usable scan-to-report workflows

**Input**: Design documents in `/specs/007-application-completeness/` (spec.md, plan.md, research.md, data-model.md, contracts/api.md, contracts/behavior.md, quickstart.md)

**Tests**: REQUIRED (constitution Principle VII). Every contract (CA-1..6, CB-1..23) ships an automated check that fails on the pre-fix code; browser-acceptance items additionally require live-server evidence (SC-008). All automated checks run offline (`go test ./...`, fakes/fixtures/transcripts). **No Python is executed** anywhere — the reference `../vhlocal` is a read-only semantics oracle.

**Organization**: By user story in priority order — US1 Scans visible (P1), US2 Applications aggregate (P1), US3 Truthful status (P1), US4 Threat/SBOM accessible (P1), US5 Verification & reproduction recovery (P1), US6 Reports useful (P2), US7 Honest options (P2). Each story is independently testable. Preserve existing history/reports/registry/tracking and the prior audit protections.

## Format: `[ID] [P?] [Story] Description`
- **[P]** = different file, no dependency on an incomplete task.
- Heavy shared files serialize (no [P] among tasks touching the same one): `internal/engine/engine.go`, `internal/jobs/jobs.go`, `internal/server/handlers.go`, `internal/server/server.go`, `internal/report/report.go`, `internal/engine/verify.go`, `internal/engine/reproduction.go`, `vhlocal/web/index.html`.

---

## Phase 1: Setup (shared test infrastructure)

- [X] T001 [P] Add an offline seeded-state fixtures builder in `internal/server/testsupport/seed.go` that writes an on-disk reports dir containing: ≥2 applications (one scanned with `ledger=false`, one with ≥2 reports incl. an older/pre-fix `scan_meta.json` shape), the handoff-shaped **partial run** (`execution=partial`, `coverage=degraded`, phases completed `1,1t,2,3d,4`; 140 candidates 10/7/123; existing `threat_model.md` + 21-component `sbom.cdx.json`; `artifact_manifest.json` with 6 invalid test bindings), and per-state threat/SBOM material fixtures (not_requested/available/missing/malformed/generation_failed). Never touches real reports.
- [ ] T002 [P] Add a loopback live-server test harness in `internal/server/testsupport/server.go` (start `internal/server` bound to `127.0.0.1` against a seeded reports dir; return base URL + shutdown) for API contract tests.
- [ ] T003 [P] Add recorded model transcripts under `tests/fixtures/transcripts/` for the US5 recovery cases (rejected→accepted verification; exhausted→unresolved; authz/logic supported-on-evidence; reproduction invalid→corrected; deferral) reusing the `client.Provider` fake pattern from `internal/engine`.

---

## Phase 2: Foundational (blocking prerequisites for all stories)

**⚠️ No user-story work begins until this phase is complete.**

- [X] T004 Create `internal/reports/reports.go`: parse a results dir into a `Report` (fields per data-model §Report: `id,path,name,repo,model,created,findings,hypotheses,severities,coverage_status,coverage_degraded,recall_pct,chains,sbom_total,has_sbom,has_threat_model,has_report,has_consolidated,phases_present,slug`), enumerate the reports dir + extra job result dirs, dedup by resolved path, newest-first. Rules (mirror reference `reports.py`, read-only): findings/hypotheses/severities come from `findings.json` (substantiated tiers = `statically_supported`,`reviewed`; never scraped); availability flags are file-existence; `recall_pct` is **null unless** `vulnerability_ledger.open_known` is truthy; `phases_present` derived from deliverable presence.
- [X] T005 [P] Add/align the slug identity helper in `internal/apps/apps.go` (or `internal/reports/slug.go`): `slug = "{basename}-{sha1(resolved_repo_path)[:8]}"`, resolving/normalizing the path, matching the reference `membank._slug`; a report binds to a slug via its `scan_meta.json` `repo`.
- [X] T006 [P] Add `internal/reports/material.go`: `MaterialAvailability` with states `not_requested|pending|available|generation_failed|missing|unreadable|malformed` and a detector for threat model + SBOM from a results dir (file existence + read/parse validity), plus an open/download reference when `available`.
- [X] T007 Add `PhaseOutcome{phase,label,requested,completed,produced,reason}` and expose the three engine axes on the scan surface: extend `internal/jobs/jobs.go` `Job` + `Public()` with `execution_status`, `coverage_status`, `validation_mode`, `phase_outcomes[]` (kept DISTINCT from queue `status`), and derive them from the run record / `findings.json.run_status` + `phases_requested`/`phases_completed`/`phases_skipped` + deliverable validity — never from queue `status` or phase index.
- [X] T008 Populate live progress in `internal/jobs/jobs.go` `onEvent` and add the missing engine emits in `internal/engine/engine.go`/`hunt.go` so `prompt_tokens`, `completion_tokens`, `agent_index`, `agent_total` are set during a run (they are currently always 0).
- [X] T009 Move `apps.Register(spec.Repo)` in `internal/engine/engine.go` OUT of the `if spec.Ledger {` branch so every scanned repo registers unconditionally, and surface (not discard) its error; keep idempotent/un-hide semantics.

**Checkpoint**: shared read/aggregation layer, scan-surface axes/progress, and unconditional registration exist; stories can proceed (largely in parallel).

---

## Phase 3: User Story 1 — Scans are visible and reliable (P1) 🎯 MVP

**Goal**: every persisted scan renders in its correct state on the shipped surfaces, survives restart/refresh, and failures are distinguishable from empty — never a false "no scans."

**Independent Test**: seed mixed/legacy scan history, list it on each surface, force a failed/malformed `/api/scans`, and confirm distinguishable states after refresh and restart (CA-4 list, CB-6/7/8).

- [X] T010 [P] [US1] API test in `internal/server/scans_test.go`: `GET /api/scans` returns all seeded jobs across states (queued/running/done/partial/failed/cancelled/interrupted) incl. a legacy-shaped record without error; after a simulated restart the history persists and a dead in-flight job loads as `interrupted` (CB-7, FR-002).
- [X] T011 [US1] Ensure `internal/jobs/jobs.go` load tolerates mixed/legacy persisted job shapes (unknown/missing fields degrade, no panic) and dedups by id on reconnect; add regression coverage (CB-7, CB-8).
- [X] T012 [P] [US1] Fix the dropped-error path in `web-react/src/lib/usePoll.ts` consumers `web-react/src/pages/Scans.tsx` and `web-react/src/pages/Dashboard.tsx`: render a distinguishable error/disconnected state from `usePoll`'s `error` instead of an empty list; keep loading distinct from empty (CB-6).
- [X] T013 [US1] Fix the legacy served UI `vhlocal/web/index.html` scans view to distinguish error/disconnected/loading from an empty list (no "No scans yet" on a fetch failure), and dedup jobs by id across polls (CB-6, CB-8). *(Primary served surface — see research I-1.)*
- [X] T014 [P] [US1] Confirm scan → report/evidence navigation is reachable from a selected scan on both surfaces (link via `results_dir`/report id); add a smoke check in `web-react` and verify in the legacy UI (FR-006).
- [ ] T015 [P] [US1] Frontend test in `web-react` (its own test runner) asserting a failed `api.scans()` shows the error state, not the empty state (CB-6).

**Checkpoint**: Scans list is truthful and robust on the served surface; US1 tests green.

---

## Phase 4: User Story 2 — Applications aggregate real history and artifacts (P1)

**Goal**: every analyzed repo is discoverable as an application (incl. ledger-disabled and report-only), with the enriched summary/detail the UI already expects.

**Independent Test**: seed the app fixtures, call the apps endpoints, and confirm discovery union + full field sets + forget-preserves-reports (CA-1, CA-2, CA-3).

- [X] T016 [P] [US2] API test in `internal/server/applications_test.go`: `GET /api/applications` returns the discovery union (registry ∪ reports-by-slug ∪ ledgers) minus hidden, each item carrying every data-model §AppSummary field; a ledger-less app has `open_findings=null`/`ledger_total=null` (not 0); a ledger-disabled repo and a report-only repo both appear (CA-1).
- [X] T017 [P] [US2] API test in `internal/server/applications_test.go`: `GET /api/applications/{slug}` returns `AppDetail` (summary + `scan_history[]` newest-first + `has_ledger`); `recall_pct` null unless known-open existed; unknown slug → 404, invalid slug → 400; forgetting an app removes it from the list but preserves its report files and re-scan un-hides it (CA-2, CA-3).
- [X] T018 [US2] Add the aggregation service in `internal/apps/aggregate.go`: `AppSummary(slug,...)` and `AppDetail(slug,...)` joining registry + `internal/reports` + ledger summaries, with name/repo coalescing and `any(...)` availability flags exactly per data-model §AppSummary/§AppDetail (mirror reference `_app_summary`/`_application_detail`).
- [X] T019 [US2] Rewrite `handleApplications` and `handleApplication` in `internal/server/handlers.go` to return `AppSummary[]`/`AppDetail` from T018 (replacing the bare `apps.Entry`); preserve the `?repo=` pre-fill form and slug validation.
- [ ] T020 [P] [US2] Verify the legacy `vhlocal/web/index.html` and `web-react/src/pages/Applications.tsx` render the enriched fields correctly (cards + detail history + threat/SBOM badges); fix any field-name drift against data-model (they already declare the shapes) (CA-1/CA-2).

**Checkpoint**: applications are discoverable and fully aggregated; US2 tests green.

---

## Phase 5: User Story 3 — Status reflects the actual work done (P1)

**Goal**: queue/execution/coverage/validation stay distinct; per-phase progress comes from validated outcomes; a partial run is never shown all-complete.

**Independent Test**: load the partial-run fixture and confirm distinct axes, `phase_outcomes` marking 2b/3 incomplete with reasons, and no "all steps complete" (CB-1..CB-5, SC-003).

- [X] T021 [P] [US3] Test in `internal/engine/status_propagation_test.go`: the partial-run fixture yields queue `status=done` but `execution_status=partial`; `phase_outcomes` marks `2b` and `3` `completed=false` with a `reason`; no axis is derived from another (CB-1, CB-3).
- [X] T022 [US3] In `internal/engine/engine.go` (and `internal/server/server.go` `runScan`), stop treating "engine returned nil + empty Aborted" as fully complete: carry the engine's execution/coverage axes and phase outcomes to the run record/job so a degraded/partial run is distinguishable at the job level while queue `status` remains `done` (queue axis) — do not fabricate a queue failure (CB-1, CB-3).
- [X] T023 [P] [US3] Rewrite `web-react/src/components/StepTracker.tsx` to render each phase from `phase_outcomes`/`phases_completed` (not `status==='done'`); a partial run shows unfinished phases as not-complete with reasons and never the "All N steps complete" caption (CB-2).
- [X] T024 [US3] Apply the same phase-outcome-driven step rendering to the legacy `vhlocal/web/index.html` step tracker (CB-2).
- [X] T025 [P] [US3] Test in `internal/engine/regenerate_test.go`: restart/resume/report-regeneration preserve the distinct dispositions (explicit-unresolved vs missing-decision vs zero-candidates vs failed-hunt vs authored vs deferred vs executed) and invalidate stale downstream completion where upstream inputs changed (CB-4, CB-5); adjust `internal/engine/regenerate.go` as needed.

**Checkpoint**: status is truthful end-to-end; US3 tests green.

---

## Phase 6: User Story 4 — Threat model, SBOM & generated material accessible (P1)

**Goal**: generated material is discoverable/openable/downloadable from scan, report, and application views (incl. pre-existing files, no re-scan), with explicit availability states and visible generation failures.

**Independent Test**: material-state fixtures return the correct state; available threat/SBOM open+download from all three view types without re-scan (CA-6, FR-017..021).

- [X] T026 [P] [US4] Test in `internal/server/material_test.go`: for each `MaterialAvailability` state (not_requested/available/missing/malformed/generation_failed) the scan/report/application responses expose the correct state; an available SBOM (21 components) + threat model are openable/downloadable via the file endpoint without re-scanning (CA-6).
- [X] T027 [US4] Surface `MaterialAvailability` (from `internal/reports/material.go`) on the scan, report, and application responses in `internal/server/handlers.go` (add fields; keep `has_threat_model`/`has_sbom` booleans for back-compat), and expose open/download via the existing guarded `/file` endpoint.
- [X] T028 [US4] In `internal/engine/engine.go`, stop discarding the SBOM write error (`_, _ = sbom.Write(...)`): record success/failure so a failure surfaces as `generation_failed`; document/reflect the threat-model↔SBOM relationship (SBOM written deterministically within Phase 1t before the threat agent) per research R2/FR-021. Do not fabricate absent material or rewrite evidence.
- [X] T029 [P] [US4] Show material availability + working open/download in the legacy `vhlocal/web/index.html` and `web-react` scan/report/application views; unknown/failed states remain visible after reload (FR-018).

**Checkpoint**: intelligence artifacts are reachable and honestly stated; US4 tests green.

---

## Phase 7: User Story 5 — Verification & reproduction recover from actionable failures (P1)

**Goal**: bounded, measured recovery for verification; a per-candidate corrective loop for reproduction; authz/logic supported on evidence; nothing fabricated or executed.

**Independent Test**: transcripts show recovery + honest exhaustion with counts; reproduction repairs one invalid submission and defers another; supported-only; never-executed (CB-9..CB-14, SC-005).

- [X] T030 [P] [US5] Investigation task: categorize the saved partial run's 72 `tool_repair` + 26 `max_turns` exits and 98 missing decisions from the report dir's `verification_*` traces; record the dominant failing checks (evidence line-coverage, entry-point match, schema shape) as a short note in `specs/007-application-completeness/research.md` (append to R5/I-2). Read-only; no scan.
- [X] T031 [P] [US5] Test in `internal/engine/verify_recovery_test.go` (transcripts from T003): a recoverable submission failure gets actionable feedback + bounded retry with accepted work preserved (CB-9); exhausted recovery → `unresolved` with reason and recorded `attempts`/`failures`, never fabricated supported (CB-10).
- [X] T032 [US5] In `internal/engine/verify.go`, implement measured, actionable recovery per the T030 categories: targeted feedback for the common failing checks and per-candidate `attempts`/`failures` recording; keep the bounded budget (do not silently raise retries) and generic-transport→unresolved behavior.
- [X] T033 [P] [US5] Test in `internal/consolidate/authz_logic_test.go`: an authorization/logic candidate with substantive evidence but no injection-style syntactic sink can be supported, while attacker-control/preconditions/defenses/impact/revision/exact-evidence remain required (CB-11).
- [X] T034 [US5] In `internal/consolidate/corroborate.go` (and `internal/verification/verification.go` `validateEvidenceBacked` as needed), add the evidence-based authorization/logic acceptance path mirroring the reference (research R6/I-3) without weakening the other requirements.
- [X] T035 [P] [US5] Test in `internal/engine/reproduction_loop_test.go`: an invalid reproduction submission (wrong candidate/location, missing file, bad header/registration) receives bounded corrective feedback with stable candidate IDs and is repaired; an unrepairable one becomes an explicit deferral; only supported candidates are assigned; authored material is never marked executed; failing output preserved (CB-12, CB-13, CB-14).
- [X] T036 [US5] Rewrite `internal/engine/reproduction.go` from the single aggregate agent to a bounded per-candidate authoring+validation loop feeding `verification.ValidateArtifacts` errors back for a bounded correction, allowing an explicit deferral, preserving stable IDs and the failing output; retain supported-only + authored-not-executed.
- [X] T037 [US5] Record verification/reproduction recovery counts (attempts/failures/deferrals) into run metadata (`scan_meta.json`) and make them available to status/report (FR-023).

**Checkpoint**: recovery is bounded, measured, and honest; US5 tests green.

---

## Phase 8: User Story 6 — Reports are useful to a reviewer (P2)

**Goal**: enriched deterministic Markdown/HTML/machine-readable report: supported-first, separated unsupported, full review detail, navigation, no conflation.

**Independent Test**: a representative supported finding shows all review detail; unsupported separated; totals not conflated; three renderings agree (CB-15..CB-18, SC-006).

- [X] T038 [P] [US6] Test in `internal/report/report_useful_test.go`: from the partial-run fixture, the report leads with a supported-findings summary and separates rejected/unresolved (CB-15); each supported finding exposes location+evidence, entry point, attacker control+flow, preconditions, reviewed defenses, impact, rationale, remediation, reproduction status/links, with missing items explicit (CB-16); candidate totals are not shown as confirmed totals and sweep leads are not confirmed findings (CB-17); Markdown/HTML/machine-readable agree (CB-18).
- [X] T039 [US6] Surface the verification review-record detail (attacker control, preconditions, defenses reviewed, security impact, rationale, evidence excerpt, reproduction status/deferral) into the report input — thread the reconciliation/decision records into `consolidate.Doc`/findings so `internal/report` can render them from canonical evidence (no model authoring).
- [X] T040 [US6] Rewrite `internal/report/report.go` (Markdown + HTML) to: lead with a supported-findings summary; put rejected/unresolved in clearly identified separate sections; render the full per-supported-finding detail from T039 with explicit unknowns; add navigation to threat analysis, SBOM, coverage, and sweep leads; never present candidate totals as confirmed-vulnerability totals; keep deterministic rendering.
- [X] T041 [P] [US6] Ensure the machine-readable output (`findings.json`) and the rendered report agree on findings/outcomes/counts; add the agreement assertion to the T038 test (CB-18).

**Checkpoint**: the report is review-useful and internally consistent; US6 tests green.

---

## Phase 9: User Story 7 — Supported options & work limits behave honestly (P2)

**Goal**: every supported option honored or explicitly rejected and traceable; partition requested-vs-actual visible; workload visible.

**Independent Test**: trace each option request→effective-config→metadata; confirm requested-vs-actual partitions and workload visibility (CB-19, CB-20, SC-007).

- [X] T042 [P] [US7] Test in `internal/server/options_test.go` + `internal/engine/effective_config_test.go`: each supported option (threat_model, ledger, role model/provider, hunt sampling, partition/coverage) is honored or explicitly rejected (never silently ignored) and recorded in effective config/metadata; an unsupported/conflicting option is rejected explicitly (CB-19).
- [X] T043 [US7] In `internal/server`/`internal/engine`, validate incoming options and persist the resolved effective configuration into `scan_meta.json` (extend existing fields), rejecting unsupported ones explicitly rather than silently ignoring (CB-19).
- [X] T044 [US7] Investigation + surfacing: confirm whether `max_partitions` is a hard cap or a coverage-driven starting point against the reference and this repo's `resolvePartitions`/`AugmentForCoverage`/`AugmentFromThreatModel`; document it (append to research R9/I-4) and surface requested-vs-actual partition count + workload/bounded-recovery in status/report/metadata (CB-20).

**Checkpoint**: options and workload are honest and visible; US7 tests green.

---

## Phase 10: Polish & cross-cutting

- [X] T045 [P] Preservation test in `internal/server/preservation_test.go`: no existing scan, report, application name, or tracking record is lost or overwritten by the feature (compare seeded state before/after exercising the endpoints/engine) (CB-21, SC-009).
- [X] T046 [P] Confirm the prior audit-protection suite still passes unchanged (distinct candidate sites, exact source/revision checks, complete reasoning, path containment, no empty-output completion, supported-only reproduction, independent reference contracts, deterministic sweep/reporting, resume/regeneration validity) — run and, if needed, adjust only for additive fields (CB-22, FR-038).
- [X] T047 [P] Author the reference behavior matrix `specs/007-application-completeness/parity-matrix.md` (apps/report aggregation, status axes, material availability, verdict/tiering: matches / documented approximations / remaining gaps), derived by reading `../vhlocal` — no Python executed (SC-008, CB-23).
- [X] T048 [P] Decide and document the `/app` (React) surface: either embed the `web-react` build into `vhlocal/web/app/` (so `/app` serves) or explicitly scope it out in `quickstart.md`/README, since the live surface is the legacy `index.html` (research I-1); record built frontend/backend provenance for acceptance (SC-008).
- [X] T049 Run the full offline gate: `go build ./...`, `go test ./... -count=1` (incl. `tests/parity`), `go vet ./...`, `gofmt -l internal tests` clean; capture real browser acceptance evidence on the served surface against a seeded live server per `quickstart.md` (SC-001..004, SC-008).
- [X] T050 [P] Update `CHANGELOG.md` (feature 007 entry) and write the bounded, operator-owned live-model validation plan in `docs/engineering/` (NOT executed by the harness; no auto-launched long scan, no exploit execution) (FR-039, SC-008 provenance).

---

## Dependencies & Execution Order

- **Setup (P1: T001-T003)** → no deps; start immediately.
- **Foundational (P2: T004-T009)** → depends on Setup; **BLOCKS all user stories**. Within it: T004 before T018/T026/T038 (reports layer); T005/T006 [P]; T007 before T021/T023; T008 independent; T009 before T016.
- **User stories (P3-P9)** → all depend on Foundational; then largely parallel. Notable cross-story links (kept non-blocking for independent testing): US3 step rendering (T023/T024) consumes T007's `phase_outcomes`; US6 report (T040) consumes T039's review detail and benefits from US5's recovery counts (T037) but is testable on the fixture alone.
- **Polish (P10: T045-T050)** → after the desired stories.

### Story independence
- **US1** (T010-T015): scan visibility/error-vs-empty — testable via seeded jobs + a failing fetch.
- **US2** (T016-T020): apps aggregation — testable via seeded reports/registry/ledgers.
- **US3** (T021-T025): truthful status — testable via the partial-run fixture.
- **US4** (T026-T029): material access — testable via material-state fixtures.
- **US5** (T030-T037): recovery — testable via recorded transcripts.
- **US6** (T038-T041): report usefulness — testable via the fixture.
- **US7** (T042-T044): honest options — testable via option-trace fixtures.

### Parallel opportunities
- Setup T001/T002/T003 in parallel.
- Foundational T005/T006/T008 in parallel; T004/T007/T009 serialize where they touch shared files.
- Test-authoring tasks marked [P] (T010, T016, T017, T021, T026, T031, T033, T035, T038, T042, T045, T046, T047) run in parallel.
- After Foundational, US1/US2/US4 can proceed in parallel (different files); US3 pairs with T007; US5 and US6/US7 (P2) follow.

---

## Parallel Example: after Foundational

```text
# Author story tests together (all fail on pre-fix code):
Task T010: /api/scans states + restart persistence (internal/server/scans_test.go)
Task T016: /api/applications discovery union + fields (internal/server/applications_test.go)
Task T026: material availability states (internal/server/material_test.go)
Task T021: partial-run status axes + phase_outcomes (internal/engine/status_propagation_test.go)
```

---

## Implementation Strategy

### MVP (P1 stories)
1. Setup (T001-T003) → Foundational (T004-T009).
2. US1 (T010-T015): scans visible → **validate**.
3. US2 (T016-T020): apps aggregate → validate.
4. US3 (T021-T025): truthful status → validate.
5. US4 (T026-T029): material access → validate.
6. US5 (T030-T037): recovery → validate.
   → At this point the operator can see scans/apps, trust status, open intelligence, and get honest verification/reproduction — the core "usable application."

### Incremental (P2)
7. US6 (T038-T041): report usefulness.
8. US7 (T042-T044): honest options.
9. Polish (T045-T050): preservation, audit-suite, parity matrix, provenance, gate, changelog, operator live-plan.

## Notes
- Tests-first: author each story's [P] test task and confirm it FAILS on the current code before implementing.
- Preserve existing evidence and the audit protections throughout (FR-037/FR-038); additive schema only.
- Reference `../vhlocal` is read-only; never execute Python (standing constraint + user memory).
- Offline-first; do not auto-launch a live scan; T049/T050 gather evidence and define (not run) the operator's bounded live validation.

---

## Implementation progress — session 1 (2026-09-17)

**Delivered (backend, tested offline; `go test ./...` = 26 pkgs ok, vet + gofmt clean):**
- **Foundational**: T001 seed fixtures builder (`internal/server/testsupport/seed.go`); T004/T005 confirmed already present (`internal/reports` rich `Report` + `membank.Slug`/`apps.SlugFor`) and reused; T006 `internal/reports/material.go` explicit availability states; T007 truthful scan-status surface implemented **server-side** in `internal/server/status.go` (`scanStatus`/`enrichScan` add `execution_status`/`coverage_status`/`validation_mode`/`phase_outcomes` from `findings.json`+`scan_meta.json`, distinct from queue `status`, survives restart) instead of widening `jobs.Job` — equivalent contract, leaner; T009 un-gated `apps.Register` (FR-007).
- **US2 (Applications aggregate)**: T018 `internal/apps/aggregate.go` (discovery union + `AppSummary`/`AppDetail`), T019 handler rewire, T016/T017 tests (CA-1/2/3) — blank Apps view fixed.
- **US3 (truthful status)**: T021 test + T022 propagation via `enrichScan` (CB-1/CB-3) — the done-vs-partial lie is fixed at the API.
- **US4 (material)**: T026 test (CA-6 states), T027 material on the scan view + report record, T028 SBOM write error surfaced (no longer discarded).

**Remaining (not started / partial):**
- T002 live-server httptest harness; T003 verification/reproduction transcripts.
- T008 live token/agent progress emits (jobs.onEvent + engine emits).
- **US1 (T010-T015)**: `usePoll` error surfacing in `Scans.tsx`/`Dashboard.tsx`, legacy `index.html` error-vs-empty, legacy-job-shape tolerance test, scan→report nav.
- **US3 remainder**: T023 `StepTracker.tsx` + T024 legacy step tracker read `phase_outcomes` (not `done`); T025 resume/regenerate integrity test.
- **US4 remainder**: T029 material UI (legacy + React).
- **US5 (T030-T037)**: verification bounded-recovery categorization + measured feedback; authz/logic acceptance path; reproduction per-candidate corrective loop; recovery counts in metadata.
- **US6 (T038-T041)**: report enrichment (supported-first, review detail, navigation, md/html/json agreement).
- **US7 (T042-T044)**: options honored/rejected + partition transparency.
- **Polish (T045-T050)**: preservation test, audit-suite re-confirm, parity matrix, `/app` embed decision, full gate + browser evidence, CHANGELOG + operator live-plan.

**Notes**: `T020` (UI reads enriched app fields) is satisfied by construction — the handler emits the exact json keys `web-react/src/lib/types.ts` and the legacy UI already consume — but browser confirmation is operator-owned (SC-008). No Python executed; existing history/reports/registry preserved; audit protections untouched.

## Implementation progress — session 2 (2026-09-17): US1 + US3 UI

**Delivered:**
- **US1 (T010-T014)**: `internal/jobs/jobs_test.go` proves mixed/legacy history loads without crashing, a dead in-flight job → `interrupted`, order preserved, history survives restart (CB-7). `usePoll` gained a `loading` flag; `Scans.tsx` and `Dashboard.tsx` now render a distinguishable **error/loading vs empty** state instead of "No scans yet" on a fetch failure (CB-6). Legacy `vhlocal/web/index.html` `refresh()` wraps the fetch and shows an error line (not empty) via a new `jobsError` path (T013). A "View report →" link from a finished scan (`/reports?open=<id>`) wired in `Scans.tsx` (T014).
- **US3 UI (T023-T024)**: React `StepTracker.tsx` and both legacy trackers (`phaseTracker`, `phaseSpine`) now derive per-phase state from `job.phase_outcomes` — a terminated queue `status` is **never** rendered as "All N steps complete"; incomplete phases show a distinct amber state with the engine's reason, and the caption reads "`X of N phases complete — … incomplete`". New `.step.incomplete` / `.seg.incomplete` styles added.

**Validation:** Go `go test ./...` = 26 pkgs ok, vet + gofmt clean, binary rebuilt. React/legacy edits follow existing patterns and use defined design tokens (`--color-warn`); **type-check/browser run is operator-owned** — `web-react` has no `node_modules` here (offline) and no JS test runner is configured.

**Still remaining:** T015 (needs a JS test runner — vitest — added as follow-up), T020 (browser confirm apps fields), T025 (resume/regenerate test), T029 (material UI polish), US5 (T030-T037), US6 (T038-T041), US7 (T042-T044), Polish (T045-T050).

## Implementation progress — session 3 (2026-09-17): US5 verification & reproduction recovery

**Delivered (backend, tested offline):**
- **T030** investigation (recorded in research R5-addendum): the dominant failure is *"no decision supplied"* (98/140 sessions ended at tool_repair/max_turns before submitting); remaining unresolved are explicit model submissions, many authz/logic.
- **T033/T034** authz/logic acceptance: added `consolidate.SourceRefuted` and changed `validateEvidenceBacked` to block only on a source **FAIL** (present, no sink), never on NA — so an evidence-backed authorization/logic *supported* verdict is accepted while sink-class refusals and primary-evidence (CORS) behavior are preserved. Test `TestReconcileSupportedAuthzLogicNoSink` (CB-11).
- **T031/T032/T037** measured recovery: `verifyCandidate` now records per-candidate `Failures`; `internal/verification/sessions.go` persists `verification_sessions.json` and `EnrichReasons` rewrites the generic "no decision supplied" into an actionable *"session ended: <cause> after N turns, M tool failures"*, applied in both `runVerification` and `loadVerifiedFindings`. Test `TestEnrichReasonsNamesStopCause` (CB-9/CB-10). Budgets unchanged (no silent retry inflation).
- **T035/T036** reproduction per-candidate loop: `runReproduction` now runs a bounded (`reproMaxAttempts=2`) authoring+validation loop per supported candidate via `authorCandidate`, feeding `verification.ValidateEntry` errors back for a retry; a valid poc/test or an explicit **model** deferral registers, while exhaustion/silence registers **nothing** (so `ValidateArtifacts` flags the missing disposition and phase 3 stays incomplete — audit protection preserved, no fabricated deferral). Harness owns `artifact_manifest.json`. New `verification.ValidateEntry`. Test `TestReproductionPerCandidateLoop` (CB-12/13/14).
- Updated the two audit/parity tests that encoded the old aggregate protocol (`TestMissingArtifactsInvalidateCompletionAndReports`, `TestFullPipelineArtifactsAndDeterministicPhases`) to the per-candidate protocol **without weakening their assertions**.

**Validation:** `go test ./...` = 26 pkgs ok, vet + gofmt clean, binary rebuilt.

**Remaining:** T015, T020, T025, T029 (UI/test-runner/regenerate), US6 (T038-T041), US7 (T042-T044), Polish (T045-T050).

## Implementation progress — session 4 (2026-09-17): US6 report usefulness

**Delivered (tested offline):**
- **T039** review detail into findings: `FinalFindings` already round-trips the decision into `f.verification_record` (audit team); completed the wiring by threading per-finding **reproduction dispositions** (`reproDispositions` from `artifact_manifest.json`) and **navigation links** (`reportNav` for present threat/SBOM/coverage/sweep/handoff artifacts) into `report.Input`.
- **T040** `internal/report/report.go` rewritten: a **Summary** leads with supported/rejected/unresolved counts and states a candidate total is not a confirmed-vulnerability count (FR-031); **Findings → Supported findings** first with the full source-grounded review detail (entry point, attacker control, data flow, preconditions, reviewed defenses, security impact, rationale, evidence locator, reproduction disposition), then clearly separated **Rejected candidates** and **Unresolved / hypotheses** sections; a **Navigation** block links intelligence artifacts (FR-032). Both Markdown and self-contained HTML. Deterministic (no model).
- **T038/T041** tests: `report_useful_test.go` asserts supported-first ordering, full review detail, no candidate-total-conflation, navigation, and that Markdown/HTML/machine-readable counts agree (CB-15..18, SC-006).

**Validation:** `go test ./...` = 26 pkgs ok, vet + gofmt clean, binary rebuilt. Existing report/audit tests updated where the umbrella `## Findings` heading moved to sub-sections (kept the heading for back-compat).

**Remaining:** US7 (T042-T044) honest options; T015/T020/T025/T029 (UI/test-runner/regenerate); Polish (T045-T050).

## Implementation progress — session 5 (2026-09-17): US7 honest options & limits

**Delivered (tested offline):**
- **T043** option validation + honoring: `validateScanOptions` (allowlist of every key both shipped UIs submit) rejects unknown keys and bad enum/range values explicitly — no silent ignore (CB-19). Wired into `handleCreateScan`. Previously-ignored options are now **honored**: `app_name` → `apps.SetName` at registration (the app gets the operator's name); `max_budget_usd` → `ScanSpec.MaxBudgetUSD` → `rec.MaxBudgetUSD`, which **activates the US4 budget-cap guard**. Added `ScanSpec.AppName`/`MaxBudgetUSD` + `floatOr`.
- **T044** partition transparency: confirmed `max_partitions` **caps the model's plan** (`ParsePartitionTable` `out[:max]`) while `AugmentForCoverage` (ceiling `max + routeFiles`) and `AugmentFromThreatModel` add partitions beyond it — explaining requested 8 → resolved 24. The report Summary now surfaces `requested cap N, resolved M (source; +A coverage, +T threat-model)` and documents the cap semantics (CB-20/FR-035).
- **T042** tests: `options_test.go` (accept supported set; reject unknown key / bad backend / bad strictness / out-of-range hunt_samples / negative budget) and `effective_config_test.go` (app_name + max_budget_usd + strictness/samples/threat_model carried into the effective `ScanSpec`); `report_useful_test.go` partition-transparency assertion.

**Documented limitation:** per-role `*_backend`/`*_host` overrides are allowlisted and preserved in the persisted job spec, but role models currently execute on the main backend (the engine uses one provider); recorded, not silently dropped.

**Validation:** `go test ./...` = 26 pkgs ok, vet + gofmt clean, binary rebuilt.

**Remaining:** T015/T020/T025/T029 (JS test runner, browser confirm, resume/regenerate test, material UI), Polish (T045-T050).

## Implementation progress — session 6 (2026-09-22): leftovers + Polish

**Delivered:**
- **T025** re-derive/regeneration integrity: `TestRederivePreservesDispositionsAndReasons` proves loadVerifiedFindings preserves supported/rejected/unresolved distinctions AND the enriched "no decision" reason, deterministically across repeated derivation (as regeneration does). Complements existing `TestRegenerateRevokesStaleVerificationCompletion` + the full-pipeline `Compare`-after-`Regenerate`.
- **T029** material UI: React `Scans.tsx` `Intelligence` chip + legacy `index.html` `intelLine` show explicit threat-model/SBOM availability with a download link when present (from the `enrichScan` material states).
- **T045** preservation: `TestPreservationOfExistingData` — aggregation + registry rename never overwrite report files, ledgers, or other apps' names (CB-21/SC-009).
- **T046** audit protections: the full audit/regression suite (engine + verification + parity) stays green unchanged.
- **T047** `parity-matrix.md`: behavior matrix vs the reference (match / documented approximation / remaining gap), derived by reading `../vhlocal` (no Python executed).
- **T048** `/app` surface decision + provenance guidance in `docs/engineering/2026-09-22-app-surface-and-validation.md`: legacy `index.html` is the supported surface; embedding the React build is a documented follow-up.
- **T049** full offline gate green: `go build ./...`, `go test ./... -count=1` (26 pkgs ok), `go vet`, `gofmt -l` clean. **Browser-acceptance evidence is operator-owned** (plan in the doc above).
- **T050** CHANGELOG updated (earlier session) + bounded, operator-owned live-model validation plan written (no auto-launch, no exploit execution).

**Validation:** `go test ./...` = 26 pkgs ok, vet + gofmt clean, binary rebuilt.

**Remaining (operator/tooling-owned, not harness-executable):**
- **T015** — a `web-react` unit test needs a JS test runner (vitest) added to devDependencies + `npm ci`; not added here (offline, no node_modules). The error-vs-empty logic is implemented and manually reviewed.
- **T020** — browser confirmation that the apps UI renders the enriched fields (part of the operator acceptance plan).
- **T034 (operator live validation)** — the bounded live scan + representative-finding comparison, per the validation plan; leave unchecked until the operator reports results.

## Implementation progress — session 6 (cont.): T008 + final status

- **T008** live progress: `jobs.onEvent` now reads cumulative `prompt_tokens`/
  `completion_tokens`/`agent_index`/`agent_total` from events (tolerating int/float64),
  and every `agent_done` emit (hunt/verify/reproduce/phase) carries the running token
  totals via `usageTiles(rec)` — the Tokens tile no longer shows `0.0M / 0K` mid-run.
  Test `TestOnEventUpdatesProgressTiles`.

### Final status: 46/50 done. The 4 remaining are tooling/operator-owned:
- **T002 / T003** (live-server httptest harness; recorded transcripts) — **superseded**:
  the stories they were to support (US2 apps API, US5 recovery) are covered by direct
  unit/loop tests (`aggregate_test.go`, `verify_recovery`/`sessions_test.go`,
  `reproduction_loop_test.go`). Not separately built.
- **T015** — a `web-react` unit test needs a JS test runner (vitest) added to
  devDependencies + `npm ci`; not added (offline, no node_modules). Logic implemented
  and manually reviewed; `npm run typecheck` is the operator's pre-flight.
- **T020 / T034** — browser confirmation and the bounded live-model validation are
  operator-owned per `docs/engineering/2026-09-22-app-surface-and-validation.md`.

All offline, harness-executable work for feature 007 is complete and green
(`go test ./...` = 26 pkgs, vet + gofmt clean).
