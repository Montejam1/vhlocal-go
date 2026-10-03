---

description: "Task list for feature 014: Reliable scan evidence and review completion"
---

# Tasks: Reliable scan evidence and review completion

**Input**: Design documents from `/specs/014-scan-reliability/`

**Prerequisites**: plan.md, spec.md, research.md (R0–R13), data-model.md, contracts/evidence-api.md, contracts/records.md, quickstart.md

**Tests**: INCLUDED — the specification mandates them (SC-001..SC-012 are fixture-driven acceptance gates; FR-027 requires a leak regression; constitution VII). Test tasks precede their implementation within each story and must FAIL first.

**Organization**: Grouped by user story. All five stories are P1; ordered by dependency (observability plumbing first, since every later story's evidence lands in the records it creates).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: US1–US5 (Setup/Foundational/Polish carry no story label)
- Exact file paths included.

## Path Conventions

Single Go module `vhlocal` at repo root. Build: `export PATH=$PATH:/usr/local/go/bin`; `CGO_ENABLED=0 go build -o bin/vhlocal ./cmd/vhlocal`. Offline gate: `gofmt -l . && go vet ./... && go build ./... && go test ./...` plus `go test -race ./internal/engine/... ./internal/jobs/... ./internal/server/... ./internal/agent/...`.

**Standing constraints (every task):** static-only (never execute target code, PoCs, or exploit tests); offline only (fake/recording/delayed/silent providers — never a live model, never Ollama); **fully isolated storage** in every test (never touch `~/.vhlocal` or `~/vulnhunter-reports`); `../vhlocal` read-only; stdlib only (no new runtime dependency); all persisted changes additive; credentials never persisted; preserve features 008–013 (coordinate with 013's option contract, never replace it) and all operator data; nothing deleted except by explicit operator action with a backup.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Empty homes for new code and the shared offline fixtures every story uses.

- [X] T001 Create `internal/engine/prompts.go`, `internal/engine/scanlog.go`, `internal/engine/review_units.go`, `internal/apps/cleanup.go`, `internal/cli/apps.go` as package-clause stubs with doc comments (filled in their stories).
- [X] T002 [P] Add offline provider doubles to `internal/engine/testdoubles_test.go`: **delayed** (writes deliverable, then blocks on a channel until released — proves the live-visibility window), **reading** (issues `Read` tool calls over caller-specified handler spans, then writes a valid deliverable), and a **failure-class** provider parameterised by class (`transport`, `tool_envelope` repairable/persistent, `invalid_tool_args`, `invalid_submission`, `turn_exhaustion`). Reuse the existing `silentProvider` and `pathWriter`.
- [X] T003 [P] Create deterministic fixture `testdata/coverage100/` — 100 entry points across Python (Flask/FastAPI), Go (net/http), and JS/TS (Express), including **sibling handlers in one file** and **duplicate route names** across files — plus `testdata/coverage100/paired8.json` naming the 8 handler spans the reading provider reads in the negative variant. Fixture is static source only (never executed).
- [X] T004 [P] Create `testdata/replay-audit/` — a sanitized replay fixture of the audited run's failure categories as persisted **records** (not prompts): 1 missing hunt file, unresolved candidates spread across the five failure classes, 1 missing reproduction disposition, 2 unregistered artifacts, `threat_model=false`.
- [X] T005 Run `gofmt -w` on new files and confirm `go build ./...` and `go vet ./...` pass with the empty scaffolding.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Test isolation, the evidence-state resolver, and additive record fields every story writes into. NO story can start until this phase is done.

**⚠️ CRITICAL**: Blocks all user stories. T006 in particular stops the ongoing pollution of the operator's real registry on every test run.

- [X] T006 Add `TestMain` to `internal/engine/main_test.go` setting `VHLOCAL_LEDGER_DIR`, the reports dir, `config.LogFile()` path, jobs path, and profiles dir to a `t`-independent temp root (mirroring `internal/apps`/`internal/server`/`internal/membank`/`tests/parity`), so the 40+ `Execute` call sites never write to `~/.vhlocal/applications.json` (FR-027). Add the same to `internal/jobs` and any other package that runs `Execute`.
- [X] T007 Write the leak regression `internal/engine/isolation_test.go`: snapshot the real home stores (or point HOME at temp), run `Execute` on a temp repo, assert **nothing** was written outside the isolated root — the test that would have caught the current pollution (FR-027, SC-011).
- [X] T008 Add the **evidence-state resolver** in `internal/jobs/jobs.go`: `EvidenceState(id) (state, dir, reason)` returning exactly `unknown | not_started | running_no_files | ready | empty | unavailable` per contracts/evidence-api.md (unknown = id absent; not_started = queued or cancelled before start; unavailable = bound dir missing/unreadable). Add `Started` marker to `Job`.
- [X] T009 [P] Extend records additively in `internal/engine/record.go`: `AgentRecord.Produced bool` (`json:"produced"`); `RunRecord.PromptCaptureVersion int` (`json:"prompt_capture_version,omitempty"`); `RunRecord.Outcome *OutcomeSummary` (`json:"outcome,omitempty"`) with the exact shape in data-model "OutcomeSummary" (`units{total,assigned,attempted,reviewed_with_findings,reviewed_no_issue,partial,failed,skipped,unsupported,not_reviewed}`, `candidates{supported,rejected,unresolved}`, `failed_assignments[]`, `failed_candidates[]`, `missing_artifacts[]`, `disabled_optional_phases[]`, `recovery_steps[]`).
- [X] T010 [P] Extend `agent.Result` in `internal/agent/agent.go` with `Reads []ReadSpan{File string; Start, End int}` populated from **successful** `Read`/`Grep` tool dispatches (repo-relative, confined paths; line span from args/result), and ensure `Result.Produced` is set truthfully. Add a unit test in `internal/agent/agent_test.go` asserting a Read of lines a–b records `{file,a,b}` and a failed/denied read records nothing.
- [X] T011 [P] Extend `internal/verification/sessions.go` `SessionOutcome` additively with `FailuresByClass map[string]int` (keys exactly `transport, tool_envelope, invalid_tool_args, invalid_submission, turn_exhaustion`), `LastOperation string`, `LastContractViolation string`.
- [X] T012 [P] Extend `internal/engine/hunt.go` `huntExecution` additively: `Files []HuntFile{Path, Status (valid|missing|empty|malformed|misplaced|duplicate), UnitID string, Attempts int}` while keeping the legacy `files []string` + `complete` readable (graceful load in `loadHuntExecution`).

**Checkpoint**: Tests are isolated, the state resolver exists, and every record has its additive fields — stories can begin.

---

## Phase 3: User Story 1 - Live, durable scan observability (Priority: P1) 🎯 MVP

**Goal**: Bind jobs to their results directory at engine start; produce real prompt records and a scan-tagged log; make Artifacts/Prompts/Log update live with distinguishable states and no cross-scan bleed, in the main UI and React `/app`; survive disconnect and restart.

**Independent Test**: Delayed offline scan → artifact, prompt record, and tagged log line visible via API and open tab ≤5 s while `running`; states distinguishable; disconnect/restart preserve evidence; scan switching never mixes; legacy scan reads "not recorded by this version".

### Tests for User Story 1 ⚠️ (write first, ensure they FAIL)

- [X] T013 [P] [US1] Binding test in `internal/jobs/jobs_test.go`: on a `scan_start` event carrying `results_dir`, the job's `results_dir` is set and **persisted** before the run function returns; a path outside the allowed roots is rejected (confinement) (FR-001).
- [X] T014 [P] [US1] State-contract test in `internal/server/evidence_state_test.go`: for unknown / not_started / running_no_files / ready / empty / unavailable, Artifacts, File, Prompts, and Log return the exact status+body per contracts/evidence-api.md and **no two states share a response** (FR-002).
- [X] T015 [P] [US1] Live-visibility test in `internal/server/live_evidence_test.go` using the delayed provider: while the job is `running`, `/artifacts` lists the written file, `/prompts` returns ≥1 record, `/log` returns ≥1 tagged line — all within 5 s of the write (SC-001).
- [X] T016 [P] [US1] Prompt-capture test in `internal/engine/prompts_test.go`: every `Chat` call of every role and kind (`main|repair|canary|repartition`) yields one `PromptRecord` with strictly increasing `seq`, correct `phase/label/role/model/ts`, actual `system`/`task` content; a planted API key / `Authorization` value / credentialed host in provider config or content **never** appears; `redactions[]` labels masks; run under `-race` with concurrency 3 (FR-005/007, SC-003).
- [X] T017 [P] [US1] Scan-log test in `internal/engine/scanlog_test.go`: phase/agent transitions, a tool failure, a validation failure, a retry, an output write, stop reason, and terminal outcome each produce a tagged line readable via `logsetup.ReadLog(tag)`; detail is clamped; concurrent writers never interleave mid-line (`-race`); no credential appears (FR-006/007).
- [X] T018 [P] [US1] Durability test in `internal/jobs/restart_test.go`: reload `jobs.json` after a simulated crash mid-run → job is `interrupted`, `results_dir` retained, prompts/log still readable, no duplicate records on a later resume (FR-008, SC-002).
- [X] T019 [P] [US1] Not-recorded test in `internal/server/evidence_state_test.go`: a scan whose `scan_meta.json` lacks `prompt_capture_version` returns `state:"not_recorded"` from `/prompts` (FR-009).
- [X] T020 [P] [US1] Shipped-form contract additions in `internal/server/scan_launch_test.go`: the embedded `index.html` uses the new `/prompts` and `/log` endpoints (not `file?path=prompts.jsonl`), contains a per-pane abort/sequence guard, resolves the pane element before `await`, and renders distinct strings for each evidence state and for "not recorded by this version" (FR-003/004/009).

### Implementation for User Story 1

- [X] T021 [US1] In `internal/jobs/jobs.go` `onEvent`, add `case "scan_start"`: confine + bind `j.ResultsDir` from `ev["results_dir"]`, set `Started`, and `persist()`; also `persist()` on `phase_start` so restart keeps progress (FR-001/008).
- [X] T022 [US1] Implement `internal/engine/prompts.go`: `promptSink` (mutex, append-only `prompts.jsonl` in the results dir, whole-line writes) and the `client.Provider` decorator `promptRecorder{inner, sink, meta{scan_tag, phase, label, role, model, kind}}` writing a `PromptRecord` per `Chat` with `system`/`task` passed through `redact` + `redactURL`, clamped with `truncated:true`; set `RunRecord.PromptCaptureVersion = 1` (FR-005/007).
- [X] T023 [US1] Wrap providers per unit/agent in `internal/engine/engine.go`, `hunt.go`, `hunt_parallel.go`, `verify.go`, `reproduction.go` (and the canary/repartition calls in `hunt.go`) with a per-unit `promptRecorder` so every real call — including `repairChat` — is captured race-free (FR-005).
- [X] T024 [US1] Implement `internal/engine/scanlog.go`: subscribe to engine events and write bounded, redacted scan-tagged lines via `logsetup.Logger` for `phase_start|phase_skip|phase_done|agent_start|agent_stop|tool_failure|validation_failure|retry|output_written|budget|breaker|cancel|resume_invalidated|terminal`; add the missing fine-grained emits (`tool_failure`, `validation_failure`, `retry`, `output_written`) in `internal/agent/agent.go`, `internal/engine/hunt.go`, `internal/engine/verify.go` (FR-006).
- [X] T025 [US1] Initialise `logsetup` in production: `internal/server/server.go` `runScan` and `internal/cli/run.go` create a `Logger` tagged with the job id / scan tag at `config.LogFile()` and pass it to the engine's log subscriber (FR-006).
- [X] T026 [US1] Refactor `internal/server/handlers.go`: make `handleScanArtifacts` (paged `?offset&limit`), `handleScanFile`, new `handleScanPrompts` (`?after&limit` → `ready|no_records|not_recorded`), and `handleScanLog` (`?tail&after` → `ready|no_lines`, cursor) all consult `store.EvidenceState`, returning the contract's distinct status+body per state; register the two new routes (FR-002/003/006/009).
- [X] T027 [US1] Main UI `vhlocal/web/index.html`: in the same-tab branch refresh **Artifacts and Log** quietly while running (diff-aware), refresh once on terminal status; preserve selected file, `<details>` expansion, scroll; add a log-follow toggle; add per-pane `AbortController` + request sequence checked against `sel` before writing; resolve pane elements **before** `await`; switch Prompts to `/prompts` and Log to `/log`; render distinct messages per evidence state and "not recorded by this version"; page artifacts (200), tail log (500 lines), clamp prompt content (8 KB, expand fetches by `seq`) per contracts/evidence-api.md "Bounds" (FR-003/004/009).
- [X] T028 [P] [US1] Classic/legacy `vhlocal/web/index.classic.html`, `vhlocal/web/index.legacy.html`: point Prompts (classic) and Log at the new endpoints, render the state messages (incl. "not recorded by this version" and `legacy-unavailable` where a tab does not exist), keep supported behavior working; record the entrypoint inventory (classic = Artifacts+Prompts+Log; legacy = Artifacts+Log; neither has Applications) in `specs/014-scan-reliability/contracts/evidence-api.md` (FR-009).
- [X] T029 [P] [US1] React `web-react/src/lib/api.ts`: add `artifacts(id, offset, limit)`, `prompts(id, after, limit)`, `scanLog(id, tail, after)`; `web-react/src/pages/Scans.tsx` `ScanDetail`: add Artifacts / Prompts / Log sections polling while running, with explicit loading/empty/not_recorded/unavailable/error states, abort + stale guards, and final refresh (FR-003/004/009). Operator runs `npm run build`.

**Checkpoint**: Live evidence is real, durable, distinguishable, and equivalent across surfaces. MVP.

---

## Phase 4: User Story 2 - Evidence-backed review coverage that drives work (Priority: P1)

**Goal**: Every eligible entry point maps to an assignment or an explicit reason; every attempted unit ends in one validated disposition backed by tool evidence; `reviewed_no_issue` becomes real; coverage enforcement reconciles plan vs records with bounded follow-up; gaps are exposed.

**Independent Test**: `coverage100` with the reading provider → **100/100** evidenced dispositions (8 with findings); paired-8 → **8/100** with 92 reasons; mentions/out-of-span reads/prose/stale revision/malformed records never count; enforcement off keeps honest counts.

### Tests for User Story 2 ⚠️ (write first, ensure they FAIL)

- [X] T030 [P] [US2] Positive coverage test in `internal/engine/review_units_test.go` on `testdata/coverage100` with the reading provider reading every assigned handler span: `review_units.json` has 100 assignments, 100 dispositions (8 `reviewed_with_findings`, 92 `reviewed_no_issue`), and `coverage_ledger.json` reports 100 reviewed / 0 not_reviewed across Python, Go, JS/TS, sibling handlers, and duplicate route names (SC-004, FR-010..013).
- [X] T031 [P] [US2] Negative coverage test in `internal/engine/review_units_test.go` with `paired8.json`: exactly 8 reviewed, 92 gaps each with a reason; a path **mention**, a read **outside** the span, a prose "reviewed everything" claim, a unit with `produced:false`, a **stale revision**, and a malformed/rejected record each yield **no** reviewed disposition; sibling-handler findings never mark the sibling reviewed (SC-005, FR-014).
- [X] T032 [P] [US2] Enforcement test in `internal/engine/review_units_test.go`: with `EnforceCoverage` on, each gap gets ≤1 bounded follow-up attempt under budget/cancel/breaker then a `retry_exhausted`/limiting reason; with it off, `gaps[]` is still populated and counts unchanged (FR-015).
- [X] T033 [P] [US2] Aggregation/regeneration test in `internal/engine/review_units_test.go`: verification unresolved ≠ review not_reviewed (separate axes); regenerating an older scan **without** `review_units.json` produces no `reviewed_no_issue`; a prior finding is not marked fixed because an incompletely reviewed unit produced no new finding (FR-013/016).

### Implementation for User Story 2

- [X] T034 [US2] Implement assignments in `internal/engine/review_units.go`: after partitions resolve, map every inventory route (stable 012 id) to the hunt unit(s) whose partition scope covers its file/subsystem; routes with no covering unit get `unit_id:null` + reason (`unsupported_scope`, over partition cap, excluded) (FR-011).
- [X] T035 [US2] Implement per-unit dispositions in `internal/engine/review_units.go` from `agent.Result.Reads`: `reviewed_no_issue` **only if** deliverable `valid` ∧ route handler span (`recognize.EnclosingScope`) intersected by a unit `ReadSpan` ∧ route within unit scope ∧ `revision` == current commit; `reviewed_with_findings` via the existing in-span finding rule; `partial` / `failed` / `skipped` / `unsupported` / `not_reviewed` otherwise; persist unit id, attempts, revision, reads, rationale, evidence refs (prompt `seq`, log refs) to `review_units.json` (FR-012/014).
- [X] T036 [US2] Extend `inventory.BuildLedger` in `internal/inventory/inventory.go` with a review-evidence input so it **produces** `reviewed_no_issue` and `excluded_with_reason` (plus `unit_id`, `reason`, `evidence_ref` on `LedgerEntry`), keeps the span-exact `finding_emitted` rule, never loosens to whole-file, and keeps `Reviewed`/`Complete` honest; update `internal/inventory/inventory_test.go` (FR-013/014).
- [X] T037 [US2] Implement bounded follow-up in `internal/engine/hunt.go` (after the fan-out, before sink/IaC passes): with `spec.enforceCoverage()`, reconcile plan vs completed unit records and re-assign **one** bounded unit per gap under `ctx`/budget/breaker; record `gaps[]` with the limiting reason either way (FR-015).
- [X] T038 [US2] Expose unreviewed units + reasons on the scan-detail API (`internal/server/handlers.go`, additive field from `review_units.json`) and in the report (`internal/report/report.go` "Review coverage" section); confirm dashboard counts (`internal/apps/aggregate.go`, `internal/reports`) are unchanged by a regression in `internal/server/preservation_test.go` (FR-016).

**Checkpoint**: Coverage is honest in both directions and drives bounded work.

---

## Phase 5: User Story 3 - Hunt, verification, and reproduction completion (Priority: P1)

**Goal**: Agent stop ≠ assignment success with bounded recovery of missing deliverables; verification failures classified per candidate and operation with durable checkpoints (incl. on cancel); every candidate has a provenance-bearing outcome; reproduction integrity preserved and fixture-tested.

**Independent Test**: Silent provider → one bounded re-run, then valid file or explicit failed assignment + partial run; failure-class fixtures recover only the repairable case and leave others unresolved with class + contract reason, checkpointed incl. on cancel; missing repro disposition / unregistered artifact block completion; no evidence check weakened.

### Tests for User Story 3 ⚠️ (write first, ensure they FAIL)

- [X] T039 [P] [US3] Missing-deliverable test in `internal/engine/hunt_recovery_test.go` with `silentProvider`: `AgentRecord.Produced=false` alongside `stopped_reason:"complete"`; `hunt_execution.json` marks the exact path `missing` with `attempts:2`; **one** re-run occurs; on persistent failure the assignment is `failed`, the run is partial, completed work is preserved; a variant that succeeds on the re-run yields `valid`. Also cover `empty`, `malformed`, `misplaced`, `duplicate` (SC-006, FR-017).
- [X] T040 [P] [US3] Failure-taxonomy test in `internal/engine/verify_classes_test.go`: for each class provider — repairable tool_envelope recovers; persistent transport / invalid_tool_args / invalid_submission / turn_exhaustion stay `unresolved` with `failures_by_class` naming the class, `last_operation`, and a `last_contract_violation` that explains the failed contract; reconciliation reason cites the dominant class; evidence validation rules unchanged (SC-007, FR-018/019).
- [X] T041 [P] [US3] Checkpoint test in `internal/engine/verify_classes_test.go`: `verification_sessions.json` is written after **every** session (decision or not) and both cancellation paths flush before returning; no duplicate candidates on resume; valid prior decisions preserved under 013 compatibility (FR-018/019).
- [X] T042 [P] [US3] Reproduction fixture test in `internal/engine/reproduction_integrity_test.go`: a missing disposition and an unregistered artifact each block completion and appear in `artifact_errors`; the orphan file still exists afterwards; a repaired manifest keeps candidate ids and `status:"authored"`; the report says not executed (SC-008, FR-020).

### Implementation for User Story 3

- [X] T043 [US3] In `internal/engine/hunt.go` and `hunt_parallel.go`: record `Produced` on each `AgentRecord`; after a unit's agent stops classify its deliverable (`valid|missing|empty|malformed|misplaced|duplicate`) into `huntExecution.Files`; on any non-valid status run **one** bounded re-run (fresh context, same provider/endpoint, label + `.retry1`) under `ctx`/budget/breaker; on persistent failure record `failed` with the exact path; fold per-file status deterministically in the parallel path (FR-017).
- [X] T044 [US3] In `internal/engine/verify.go`: replace the single `failures` counter with per-class counting — `transport` (generic TransportError), `tool_envelope` (KindToolParse), `invalid_tool_args` (Read/Grep/capture_evidence argument errors — **now counted**), `invalid_submission` (buildDecision/reconcile-rejected), `turn_exhaustion` (max_turns); set `LastOperation`/`LastContractViolation`; make repair feedback name the violated contract; call `checkpoint()` after **every** session and in both cancellation paths (FR-018).
- [X] T045 [US3] In `internal/verification/sessions.go` `EnrichReasons`: cite the dominant failure class and last contract violation in the `unresolved` reason; keep `Reconcile` fail-closed and evidence validation untouched (FR-019).
- [X] T046 [US3] Reproduction (`internal/engine/reproduction.go`, `internal/verification/artifacts.go`): no behavior change — add doc comments cross-referencing FR-020 and ensure `artifact_errors` surface in `OutcomeSummary.missing_artifacts` (T049) (FR-020).

**Checkpoint**: "Complete" means validated; failures are diagnosable and durable.

---

## Phase 6: User Story 4 - Honest outcomes and an actionable report (Priority: P1)

**Goal**: Distinct axes with counts, named failures, missing artifacts, disabled optional phases, and recovery steps — consistent across API, scan detail, application history, dashboard drill-downs, Markdown/HTML report, SARIF semantics, and regenerated views.

**Independent Test**: Sanitized replay fixture → identical `outcome` counts and partial/degraded reasons across API, report, and regenerated view; original evidence and human decisions unchanged.

### Tests for User Story 4 ⚠️ (write first, ensure they FAIL)

- [X] T047 [P] [US4] Consistency test in `internal/engine/outcome_test.go` on `testdata/replay-audit`: `run_status.outcome` counts (units, candidates, failed assignments/candidates, missing artifacts, disabled optional phases, recovery steps) are identical in `findings.json`, the rendered Markdown/HTML report, and the regenerated view; execution `partial` + coverage `degraded` with reasons; job termination remains a separate field (SC-009, FR-021..023).
- [X] T048 [P] [US4] Immutability test in `internal/engine/outcome_test.go`: regeneration alters no finding evidence and no human review decision (byte-compare the evidence + review files before/after) (FR-023).

### Implementation for User Story 4

- [X] T049 [US4] Assemble `OutcomeSummary` in `internal/engine/engine.go` `finalize` from `review_units.json`, reconciliation, `hunt_execution.json`, `artifact_errors`, and `PhasesSkipped` (e.g. `"1t (threat_model=false)"`), with deterministic `recovery_steps` (resume, re-run failed assignments, raise budget, enable threat model, inspect log seq…); write it to `RunRecord.Outcome` and `findings.json` `run_status.outcome` via `internal/consolidate/status.go` (additive) (FR-021/022).
- [X] T050 [US4] Render a "Completion" section in `internal/report/report.go` (Markdown + HTML) showing reviewed/total units, supported/rejected/unresolved, failed assignments and candidates (with class), missing artifacts, disabled optional phases, recovery steps, each linked to `review_units.json` / `hunt_execution.json` / `verification_sessions.json` / `artifact_manifest.json`; keep SARIF semantics unchanged; make `internal/engine/regenerate.go` re-render from persisted records only (FR-022/023).
- [X] T051 [P] [US4] Surface the same block on scan detail and application history (`internal/server/handlers.go`, `internal/apps/apps.go`) and in dashboard drill-downs (`internal/apps/aggregate.go`) without changing existing metric values (FR-021).

**Checkpoint**: Every surface tells the same honest story.

---

## Phase 7: User Story 5 - Reachable application details and existing artifacts (Priority: P1)

**Goal**: Visible, keyboard- and deep-link-reachable application detail with correct historical artifact selection and honest error states; tests isolated from operator stores; explicit, backed-up cleanup of the polluted registry.

**Independent Test**: Hundreds of apps → click/keyboard opens visible detail, deep link/back work, rapid switching never shows stale detail, errors show retry, older SBOM/threat model shown with disclosure in root and `/app`; repeated tests leave real stores byte-identical; cleanup preview keeps legitimate zero-scan apps and all reports; apply is explicit with a backup.

### Tests for User Story 5 ⚠️ (write first, ensure they FAIL)

- [X] T052 [P] [US5] Artifact-selection test in `internal/apps/apps_test.go`: with a history whose latest scan omitted the threat model/SBOM, the API returns the newest **valid** artifact of each kind from that application's own history with `scan_id/created/revision`, `older_than_latest:true`; an invalid/malformed file is skipped with a reason; another application's file is never selected; `threat_model=false` on the latest → explained absence (FR-025/026).
- [X] T053 [P] [US5] Error-distinction test in `internal/server/reports_test.go`: report-file endpoints keep **404 (absent) distinct from 5xx (error)**; React `api.ts` mapping is asserted by the shipped-asset contract in `internal/server/scan_launch_test.go` where feasible (FR-025).
- [X] T054 [P] [US5] Shipped-form contract additions in `internal/server/scan_launch_test.go`: embedded `index.html` application rows carry `tabindex="0"`, `role="button"`, a `keydown` handler; `openApplication` writes `#applications?app=<slug>` and calls `scrollIntoView`; hash readers parse the `app` query; a selection sequence guard exists; list rendering is bounded to the pinned 100 rows/page (contracts/evidence-api.md "Bounds") (FR-024; SC-010 shipped-asset half).
- [X] T055 [P] [US5] Cleanup test in `internal/apps/cleanup_test.go`: preview selects **only** entries matching `^/tmp/Test[A-Za-z0-9_]+\d+/\d{3}$` ∧ zero history ∧ path gone, each with a reason; a legitimate zero-scan app and a real `/tmp` repo are preserved; apply without the preview token changes nothing; apply writes `applications.json.bak-<ts>` **before** removing exactly the previewed ids and touches no reports/ledgers (FR-028, SC-011).

### Implementation for User Story 5

- [X] T056 [US5] Main UI `vhlocal/web/index.html`: `openApplication` updates the hash to `#applications?app=<slug>` (readers parse the query; back restores the list), `scrollIntoView({block:'start'})` on the detail pane (or a dedicated detail view for long lists), rows get `tabindex=0 role=button` + Enter/Space `keydown`, bounded list rendering (100 rows/page + “show more”, per contracts/evidence-api.md "Bounds"), a selection sequence guard dropping stale detail responses; preserve list/table controls and management actions (FR-024/025; SC-010).
- [X] T057 [US5] Implement newest-valid artifact selection in `internal/apps/apps.go` (per kind across the application's own report history; validate parse; `older_than_latest`; explained absence for `threat_model=false`) and expose `artifacts{threat_model, sbom}` on `/api/applications/{slug}` in `internal/server/handlers.go`; render originating scan/time/revision + disclosure in `index.html` (FR-025/026).
- [X] T058 [P] [US5] React `web-react/src/pages/Applications.tsx` + `lib/api.ts`: explicit error + retry states for detail and intel (no permanent "Loading…"), effect cleanup/stale guards on slug/tab switches, `reportText` distinguishing 404 (absent) from 5xx (error), render the selection with disclosure, keyboard/deep-link/back parity (FR-024/025; SC-010 `/app` half).
- [X] T059 [US5] Implement `internal/apps/cleanup.go`: `PreviewSynthetic()` (criteria above, reasons, preserved count, preview token) and `Apply(token)` (backup first, remove exactly previewed ids); expose `GET/POST /api/applications/cleanup` in `internal/server/handlers.go` (POST requires `{"confirm":"<token>"}`) and CLI `vhlocal applications cleanup --preview|--apply` in `internal/cli/apps.go` (FR-028).
- [X] T060 [US5] Add build identity to `/api/config` in `internal/server/handlers.go` (`build{version, embedded_assets_hash, built_at}`, hash computed over `vhlocal.WebFS` at startup) and record it, with tested URLs, in the validation report template `specs/014-scan-reliability/quickstart.md` (SC-012).

**Checkpoint**: Applications are reachable and honest; operator stores are safe.

---

## Phase 8: Polish & Cross-Cutting Concerns

- [X] T061 [P] Update `specs/014-scan-reliability/contracts/evidence-api.md` and `contracts/records.md` status notes from the as-built code; document intentional differences vs `../vhlocal` (read-only reference).
- [X] T062 [P] Run the full isolated offline gate: `gofmt -l .` (empty excl. pre-existing fixtures), `go vet ./...`, `go build ./...`, `CGO_ENABLED=0 go build -o bin/vhlocal ./cmd/vhlocal`, `go test ./...`, `go test -race ./internal/engine/... ./internal/jobs/... ./internal/server/... ./internal/agent/...`; then verify `~/.vhlocal/applications.json` and `~/vulnhunter-reports` are byte-identical to before the run (SC-011).
- [X] T063 [P] Run feature 012/013 parity + regression suites (`tests/parity/...`, `internal/server/preservation*_test.go`) and confirm dashboards, option contracts, verification integrity, and analyst decisions are unchanged (FR-029).
- [X] T064 Execute `quickstart.md` scenarios 1–12 offline; prepare the operator-run browser checklist (root, classic, legacy, `/app` after `npm run build`) against the fresh binary with build identity + tested URLs; report exactly what ran and what was unavailable. **SC-010 (hundreds-of-apps browser workflows, root + `/app`, rapid switching) is operator-verified here, not machine-verified by the offline gate** — state that explicitly in the report, mirroring SC-012's rule that source-only tests are insufficient evidence (SC-010, SC-012, FR-030).

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies.
- **Foundational (Phase 2)**: after Setup — **blocks all stories** (T006 isolation first; T008 resolver; T009–T012 additive record fields).
- **US1 (Phase 3)**: after Foundational. The MVP; creates the prompt/log evidence later stories reference.
- **US2 (Phase 4)**: after Foundational + T010 (`ReadSpan`) and T012 (`HuntFile`); references US1's prompt `seq`/log refs but is testable without the UI.
- **US3 (Phase 5)**: after Foundational (T011/T012); T043 and US2's T037 both touch `hunt.go` — sequence T043 before T037 or land the re-run hook in T043.
- **US4 (Phase 6)**: after US2 (`review_units.json`) and US3 (`hunt_execution` per-file status, `failures_by_class`) — it aggregates their records.
- **US5 (Phase 7)**: after Foundational (T006 isolation) — independent of US2–US4; T060 build identity pairs with the final polish run.
- **Polish (Phase 8)**: after all desired stories.

### Within Each Story

- Tests (T013–T020, T030–T033, T039–T042, T047–T048, T052–T055) are written first and fail before implementation.
- Records/models before services; engine behavior before UI re-wiring; server endpoints before UI consumers.

### Parallel Opportunities

- Setup: T002, T003, T004 in parallel.
- Foundational: T009, T010, T011, T012 in parallel (different files); T006 first, T007 after T006.
- Each story's test tasks marked [P] run together; US1 T028/T029, US4 T051, US5 T058 in parallel with their siblings.
- Cross-story: US2, US3, and US5 can proceed in parallel once Foundational lands (distinct files: `review_units.go` / `verify.go` / `apps`), coordinating only on `hunt.go` (T037 vs T043).

---

## Parallel Example: User Story 1 tests

```bash
# Launch US1 test tasks together (different files):
Task: "Binding test in internal/jobs/jobs_test.go (T013)"
Task: "State-contract test in internal/server/evidence_state_test.go (T014)"
Task: "Live-visibility test in internal/server/live_evidence_test.go (T015)"
Task: "Prompt-capture test in internal/engine/prompts_test.go (T016)"
Task: "Scan-log test in internal/engine/scanlog_test.go (T017)"
Task: "Durability test in internal/jobs/restart_test.go (T018)"
```

---

## Implementation Strategy

### MVP First (US1)

1. Phase 1 Setup → Phase 2 Foundational (**T006 first** — it stops the ongoing real-registry pollution on every test run).
2. Phase 3 US1 → **STOP and VALIDATE**: delayed scan shows artifact, prompt record, and tagged log within 5 s while running; states distinguishable; restart preserves; no cross-scan bleed.

### Incremental Delivery

1. Foundation → US1 (live, durable observability) — MVP.
2. US2 (evidence-backed coverage) — the 100/100 vs 8/100 fixtures.
3. US3 (completion integrity) — silent-provider recovery, failure taxonomy, reproduction fixtures.
4. US4 (honest outcomes) — aggregates US2/US3 records into every surface.
5. US5 (applications + isolation + cleanup) — can run in parallel with 2–4.
6. Polish: contract refresh, isolated full gate, 012/013 regression, quickstart + operator browser run.

An early observability fix is **not** feature completion — coverage honesty, completion integrity, outcome consistency, and application access remain in scope.

---

## Notes

- [P] = different files, no incomplete-task dependency.
- Agent stop, file existence, prose claims, path mentions, and ticked checklists never establish completion (FR-012/014/017; SC-006/012).
- Offline + isolated only: fake/delayed/silent/failure-class providers, `-race`; no live model, no Ollama, no target execution, `../vhlocal` read-only; never touch `~/.vhlocal` or `~/vulnhunter-reports` from tests.
- Persisted changes additive; preserve features 008–013 + all operator data; cleanup only by explicit action with backup.
- Commit after each task or logical group; keep partially completed tasks unchecked.
