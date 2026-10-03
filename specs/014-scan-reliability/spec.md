# Feature Specification: Reliable scan evidence and review completion

**Feature Branch**: `014-scan-reliability`

**Created**: 2026-09-28

**Status**: Draft

**Input**: User description: "Reliable scan evidence and review completion (from
`docs/engineering/2026-09-28-scan-reliability-speckit-specify.md`, 'Specification input') — an operator must
be able to observe real work while a scan runs, understand exactly what scope was reviewed and what failed,
retrieve durable evidence afterward, and open an application's existing analysis artifacts. Recheck the
audit evidence against current code. Preserve features 012 and 013 and existing operator data."

## Overview

A 2h17m scan (`gpt-oss:120b`) finished with job status `done` while its work was **incomplete**: execution
`partial`, coverage `degraded`, 8 of 100 entry points attributed as reviewed, 81 of 128 candidates
unresolved, one planned hunt file missing although its agent "stopped complete", and reproduction left one
missing disposition plus two unregistered artifacts. During the run the operator's Artifacts, Prompts, and
Log tabs were empty; afterward Prompts returned 404 and Log returned a placeholder; clicking an application
appeared to do nothing.

**Audit evidence rechecked against the current source (2026-09-28, read-only — no scan, model, server, or
Python was run):**

| Claim | Result | What the code shows |
|---|---|---|
| Job's results directory bound only after the engine returns; live tabs can't retrieve files | **Verified** | The job store assigns `results_dir` only after the run function returns; its event handler has no case for the engine's `scan_start` event even though that event already carries the real directory. Artifacts/File handlers read the job's `results_dir`, so they are empty for the whole run. Unknown job id and unbound (queued/running) job are **indistinguishable** on Artifacts (both `200 {files:[]}`) and File (same 404 body). Live progress is not persisted between job start and end; the event ring is runtime-only. |
| Main UI loads Artifacts/Log once; only Prompts refreshes live | **Verified** | The 4-second repaint loads a tab once per (scan, tab) entry; the only same-tab live refresh is Prompts. Classic/legacy have the *opposite* defect: unconditional re-fetch every 4 s (flashing/collapsing content). Legacy has no Prompts tab. |
| No producer of prompt records; UI shows a reassuring message on 404 | **Verified** | Zero Go writers of `prompts.jsonl` (it was a Go-port contract marked done but never implemented; only the Python reference writes it). The UI fetches it as a plain file and shows "No prompts captured yet — they appear as each phase starts." on any non-success response, even after completion. |
| No production scan log; Log shows a placeholder | **Verified** | The central logger is never initialised in production, so no scan-tagged line is ever written; the handler returns `200 "(no log lines for this scan)"`, which the UI renders verbatim as if it were content. |
| No request cancellation / stale-response guard | **Verified** | No abort or sequence guard anywhere. Artifacts loading re-queries the pane *after* awaiting, a concrete vector for one scan's list landing in another scan's view. |
| React `/app` lacks Artifacts/Prompts/Log | **Verified** | Only a live SSE feed, stat tiles, and threat-model/SBOM availability chips. No artifacts, prompt, or per-scan log calls exist in its API client. |
| Application click neither navigates nor scrolls; detail renders below the full list | **Verified** (both UIs) | Detail pane is a sibling after the list; the click handler changes neither route nor scroll; rows are not keyboard-operable; no deep link (hash query is discarded); first application auto-opens; no stale-response guard. React: a failed detail request collapses into a **permanent "Loading…"**; intel fetches have no error handling and map 404 and 500 alike to "none". |
| Coverage: only in-handler findings count as reviewed; no "reviewed, no issue" records exist | **Verified** | Disposition is evidence-backed (finding inside the handler span → `finding_emitted`, else `not_reviewed`; unresolved span → exact declaration line only). `reviewed_no_issue`, `covered_by_parent_analysis`, `excluded_with_reason` are declared but have **zero producers**. Reviewed = total − not_reviewed, so a route can only be "reviewed" by having a finding. |
| Hunt: agent "complete" ≠ deliverable produced; no recovery for a missing file | **Verified** | A unit counts only when its file passes validity, so the hunt cannot complete with a missing planned file — but the agent record has no "produced" field, so `stopped_reason: complete` sits beside an absent file; the execution record lists planned paths with no per-file status; there is **no bounded re-run** of a unit whose model said "done" and wrote nothing (only in-agent nudges and tool-call repair). |
| Verification: outcomes fail-closed; failure causes diagnosable | **Partially** — outcomes verified, diagnosis **refuted as sufficient** | Reconciliation is fail-closed per candidate and system-unresolved reasons name the stop reason/turns/failures. But provider tool-envelope errors and invalid evidence/decision submissions share **one** failure counter and one `tool_repair` stop reason; invalid tool *arguments* do not increment failures at all (invisible); decision-less sessions are flushed only at the next accepted decision or run end, and both cancellation paths return **without** flushing them. |
| Reproduction: dispositions + manifest; orphans deleted? | **Verified (healthy)** | Missing-disposition and unregistered-artifact errors come from manifest validation; orphan files are **reported, never deleted**; the harness writes the manifest; artifacts must be `authored` and every surface labels them not executed. |
| Engine registers every scanned repo into the real registry; tests don't isolate it | **Verified — pollution confirmed empirically** | Registration runs unconditionally at finalize (including cancelled/aborted runs and regeneration). The registry is `~/.vhlocal/applications.json`. **Zero** `t.Setenv` across the engine test package while 40+ tests call the engine on temp repos; the operator's real registry is ~100 KB of `/tmp/Test…/001` entries whose names match those tests. Other packages isolate correctly; no regression covers this path. |
| Job termination, execution, coverage, validation are separate axes | **Verified** | Four independent axes; a job can be `done` while execution is `partial`. |

This feature repairs those gaps as **real behavior with evidence**, coordinating with — never replacing —
feature 013's option contracts and feature 012's multi-language inventory. Static-only, offline-validated,
`../vhlocal` read-only.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Live, durable scan observability (Priority: P1)

An operator watching a running scan sees its real artifacts, the actual prompts sent to the model, and a
scan-tagged operational log appear **while the tab stays open** — no navigation or refresh — and can retrieve
all of it after completion and after a server restart. Queued, unknown, unavailable, empty, and failed
states are each distinguishable. A browser disconnect never stops the scan; reconnecting recovers the
retained evidence without duplication.

**Why this priority**: The operator's primary complaint; today the live tabs are structurally empty
(directory unbound during the run; no prompt or log producer exists) and failures are hidden behind
reassuring messages.

**Independent Test**: A deterministic delayed offline scan writes a real artifact, a prompt record, and a
tagged log line before finishing; each is visible via its API and its open UI tab within 5 seconds while the
job is still running; disconnect/reconnect and server restart preserve them; switching scans mid-request
never mixes evidence; an old scan without captured prompts reads "not recorded by this version".

**Acceptance Scenarios**:

1. **Given** a job whose engine has started, **When** its first artifact is written, **Then** the job is
   already bound to its actual results directory (persisted, confinement/ownership/identity preserved) and the
   Artifacts API returns that file — before the run ends.
2. **Given** a queued job, an unknown id, an unavailable/unreadable directory, and an empty directory,
   **When** evidence is requested, **Then** each yields a **distinguishable** response and UI state (never the
   same empty list or same error body for different conditions).
3. **Given** the Artifacts, Prompts, or Log tab is open on a running scan, **When** new data lands, **Then**
   the tab updates within 5 s on a healthy local connection without navigation, refreshes once more when the
   run terminates, and preserves selected file, expanded prompt, reading position, and a controllable
   log-follow setting.
4. **Given** the operator switches scans while a request is in flight, **When** the stale response arrives,
   **Then** it is discarded (cancelled or sequence-guarded) and never overwrites the newly selected scan's view.
5. **Given** any model call (recon, threat modeling, each hunt sample, verification, reproduction, and every
   repair call), **When** it is made, **Then** a prompt record is produced at the model-call boundary
   identifying scan, phase, agent/assignment, role/model, call order, and timestamp, showing the actual
   system/task content sent with any redactions clearly labeled — never reconstructed from templates after
   the fact and never implying all roles share one prompt.
6. **Given** a running scan, **When** phases/assignments transition, tools fail, validation fails, retries
   occur, outputs are written, or agents stop, **Then** scan-tagged log records persist with bounded,
   actionable detail sufficient to diagnose tool-repair failures; no authorization header or provider
   credential ever appears in prompts or logs; the existing redaction contract is applied before exposure.
7. **Given** the browser disconnects or the server restarts, **When** the operator returns, **Then** the scan
   was not stopped by the disconnect, interrupted status and partial evidence are preserved, logs/prompts
   remain available, and nothing is duplicated (restart need not resume model work).
8. **Given** a scan recorded before prompt capture existed, **When** Prompts is opened, **Then** it says
   "not recorded by this version" — never an indefinite "not captured yet".
9. **Given** the main UI and React `/app`, **When** evidence is viewed, **Then** both offer equivalent
   Artifacts/Prompts/Log access; classic/legacy entrypoints are inventoried with their supported behavior
   preserved and explicit loading/empty/disabled/legacy-unavailable/failed/disconnected states — no error is
   hidden behind an empty list or endless spinner.

---

### User Story 2 - Evidence-backed review coverage that drives work (Priority: P1)

An operator can trust the coverage number: every eligible entry point maps to a concrete review assignment
or an explicit exclusion reason; every attempted unit ends in a **validated disposition** (reviewed with
findings / reviewed with no issue identified / partial / failed / skipped / unsupported / not reviewed), backed
by observed source evidence and the repository revision — never a model's bare claim, a path mention, a file
read, or a normal agent stop. Coverage enforcement reconciles the plan against completed unit records and
schedules bounded follow-up or names the specific limiting reason.

**Why this priority**: "8/100" today means "8 handlers had an in-span finding", not "8 were reviewed" — a
completed no-issue review is currently impossible to record, so coverage can never be honest about work that
found nothing.

**Independent Test**: A deterministic 100-entry-point fixture (Python, Go, JS/TS; sibling handlers;
duplicate route names) completes 100 explicitly evidenced unit reviews when only 8 yield findings; a paired
fixture that truly reviews only 8 stays 8/100 with 92 explained gaps; missing ids, unsupported scope, source
mentions, reads without dispositions, stale-revision evidence, and rejected/malformed records never inflate
completed review; disabling enforcement preserves honest counts.

**Acceptance Scenarios**:

1. **Given** the multi-language inventory (feature 012) and stable entry-point identities, **When** a scan
   plans review, **Then** discovered scope, supported inventory, assignment, attempted review, completed
   review, findings, and verification are **separate measures** — no competing Python-only tracker.
2. **Given** an eligible entry point, **When** planning completes, **Then** it maps to a concrete assignment
   or carries an explicit unassigned/excluded reason.
3. **Given** an attempted unit, **When** it finishes, **Then** it has exactly one validated disposition with
   persisted assignment/unit identity, repository revision, relevant source locations, scope/rationale, and
   links to observed tool evidence — validated against the assigned scope and actual tool evidence.
4. **Given** a unit reviewed with no issue identified, **When** coverage is computed, **Then** it counts as
   reviewed **without** manufacturing a finding and is never presented as proof the code is vulnerability-free;
   unresolved candidate verification and completed source review remain separate axes with explicit
   aggregation rules.
5. **Given** a missing record, stale revision evidence, a sibling-handler finding, a path mention, a read
   without a disposition, or a normal agent stop, **When** coverage is computed, **Then** none of them
   establishes completed review.
6. **Given** coverage enforcement is on under the effective feature-013 options, **When** completed unit
   records fall short of the plan, **Then** bounded follow-up is scheduled or the specific limiting reason is
   surfaced (unsupported scope, assignment failure, cancellation, budget, model/tool failure, exhausted retry
   allowance) — no promise of universal 100% coverage; with enforcement off, coverage stays visible.
7. **Given** scan details and reports, **When** viewed, **Then** unreviewed units and their reasons are
   exposed; dashboard counts are preserved; historical regeneration never invents evidence an older scanner
   did not capture; prior findings are not marked fixed merely because an incompletely reviewed unit produced
   no new finding.

---

### User Story 3 - Hunt, verification, and reproduction completion (Priority: P1)

An operator can rely on "complete": a hunt assignment succeeds only after its required deliverable and unit
dispositions pass validation (a model saying "done" without writing its file is a failure that gets bounded
repair, then an explicit failed assignment); verification failures are diagnosed per candidate by failed
operation and checkpointed durably; every candidate ends supported/rejected/unresolved with provenance;
every supported candidate requiring reproduction has a candidate-bound disposition and validated artifact
registration or an explicit inability reason.

**Why this priority**: The audited run's 69 sessions stopped by repair/turn limits map to its
reconciliation errors, and its one missing hunt file was invisible next to an agent that "stopped complete";
without per-operation diagnosis the fix would be guesswork.

**Independent Test**: A fake provider that stops normally without writing reproduces the missing-hunt-file
failure; bounded recovery either produces valid evidence or leaves an explicit failed assignment and a partial
run (a normal stop alone cannot pass). Verification fixtures cover repairable and persistent tool errors,
invalid evidence/decisions, and turn exhaustion: repairable cases recover; persistent ones stay unresolved
with actionable, durable reasons; no evidence check is weakened. Missing reproduction dispositions and
unregistered artifacts stay visible and block false completeness.

**Acceptance Scenarios**:

1. **Given** a hunt agent stops normally, **When** its expected file is missing, empty, malformed, misplaced,
   or duplicated, **Then** agent stop and assignment success are recorded **separately**; bounded repair/retry
   runs within existing cancellation and budget rules; completed work is preserved; on failure the exact
   missing assignment is identified and the run is partial.
2. **Given** a verification session fails, **When** it is recorded, **Then** the failure is attributed to the
   candidate **and the failed operation**, distinguishing provider transport/tool-envelope errors, invalid tool
   arguments, invalid evidence/decision submissions, and turn exhaustion; repair feedback explains the failed
   contract; decisions **and** failed session outcomes are checkpointed during the run (including on
   cancellation).
3. **Given** the verification pass ends, **When** outcomes are reconciled, **Then** every candidate has a
   supported/rejected/unresolved outcome with provenance; system-generated unresolved outcomes identify the
   missing model decision and never convert failure into completion; fail-closed evidence validation is
   retained; no candidate is promoted or removed to improve the percentage.
4. **Given** resume or targeted recovery, **When** it runs, **Then** no duplicate candidates are created and
   valid prior work is preserved under the existing revision/configuration compatibility rules (feature 013).
5. **Given** a supported candidate requiring reproduction, **When** the phase ends, **Then** it has a
   candidate-bound disposition and validated artifact registration or an explicit failure/inability reason;
   files are reconciled with the manifest; a file's existence is not proof of reproduction; generated static
   PoCs/tests are labeled not executed; orphan files are never silently deleted.

---

### User Story 4 - Honest outcomes and an actionable report (Priority: P1)

An operator reading any surface — API, scan details, application history, dashboard drill-downs, Markdown/
HTML report, SARIF — sees job termination, phase execution completeness, review coverage, candidate
verification, artifact completeness, and validation mode as **distinct** facts. A job that stopped normally
but left required work incomplete visibly says partial/degraded, explains why, and tells the operator what to
do next.

**Why this priority**: "done + partial + degraded" is correct but currently opaque; without counts, named
failures, and recovery steps the operator cannot act.

**Independent Test**: Replay a sanitized fixture reflecting the audited run's failure categories; assert
consistent partial/degraded outcomes and identical counts across API, UI, and report, without requiring the
live model to reproduce the same findings.

**Acceptance Scenarios**:

1. **Given** a run that terminated normally with incomplete required work, **When** any surface shows it,
   **Then** it reads partial/degraded with reasons — never "complete".
2. **Given** the report, **When** rendered, **Then** it shows reviewed/total units, supported/rejected/
   unresolved counts, failed assignments and candidates, missing artifacts, disabled optional phases, and
   actionable recovery steps, each linked to the underlying record.
3. **Given** JSON, Markdown/HTML, SARIF semantics, and regenerated views, **When** compared, **Then** they are
   consistent, and regeneration never alters original evidence or human review decisions.

---

### User Story 5 - Reachable application details and existing artifacts (Priority: P1)

An operator clicking an application **sees** its detail open (clear navigation or a reliably visible pane),
can operate it by keyboard, share a deep link, and go back; the detail shows scan history, SBOM, threat
model, and report/ledger links, selecting the newest valid artifact of each kind from **that** application's
history with its originating scan/time/revision and an explicit "older than the latest scan" disclosure.
Missing/malformed/inaccessible artifacts show errors or explained absence. Tests and fixtures never touch the
operator's real registry, ledger, jobs, reports, reviews, or logs, and the already-polluted registry gets a
previewable, backed-up, explicitly-applied cleanup.

**Why this priority**: The operator could not reach material that already exists (nine history rows, a
threat model, and an SBOM from an earlier scan) and the registry holds ~390 synthetic test entries created by
the project's own tests.

**Independent Test**: Browser tests with hundreds of applications demonstrate immediate visible detail
access, keyboard/deep-link/back navigation, error/retry behavior, older SBOM/threat-model access when the
latest scan omitted them, and rapid switching without stale results, in both root and `/app`. Repeated test
runs leave the real registry and other stores byte-identical; a cleanup preview keeps legitimate zero-scan
applications and all reports; applying it requires an explicit operator action.

**Acceptance Scenarios**:

1. **Given** hundreds of applications, **When** one is clicked (or activated by keyboard), **Then** its detail
   is visibly opened via navigation or a reliably visible pane, is deep-linkable, supports back navigation,
   renders bounded lists, and preserves existing list/table controls and management actions.
2. **Given** an application whose latest scan omitted the threat model/SBOM, **When** its detail opens,
   **Then** the newest valid artifact of each kind from its own history is shown with originating
   scan/time/revision and an explicit older-than-latest disclosure; another application's material is never
   substituted; missing/malformed/inaccessible artifacts show an error or explained absence.
3. **Given** rapid switching between applications, **When** earlier requests resolve late, **Then** they never
   overwrite the current selection; a failed detail request shows an error with retry — never an indefinite
   "Loading…"; a server error is never reported as "no artifact".
4. **Given** the effective threat-model/SBOM settings (feature 013 contract), **When** disabled, **Then** the
   absence is explained; when enabled, generation produces and validates its artifacts or reports failure; no
   unsolicited model scan is launched to open existing material.
5. **Given** the test suite, **When** it runs repeatedly, **Then** the real registry, ledger, job state,
   reports, reviews, and logs are unchanged; a regression proves engine finalization cannot register test
   repositories outside isolated storage.
6. **Given** the polluted registry, **When** cleanup is previewed, **Then** only demonstrably synthetic
   entries are proposed, legitimate zero-scan applications and all reports are preserved, a backup is taken,
   and nothing is deleted until the operator explicitly applies it — never as an automatic side effect.

---

### Edge Cases

- A job is cancelled or fails before the engine emits its start: evidence endpoints report "not started" —
  distinct from unknown id and from "started, no files yet".
- Results directory becomes unreadable mid-run (permissions/removed): a read-error state, not an empty list.
- Very large runs (hundreds of files, multi-MB logs/prompt records): retrieval and rendering are bounded
  (paging/tailing) without dropping evidence.
- Concurrent hunt units (feature 013 concurrency) writing prompt/log records simultaneously: records stay
  well formed and attributable; a temporarily partial (mid-write) record is tolerated by readers.
- Two scans open in two browser tabs: neither view receives the other's evidence.
- Server restart mid-scan: the job reads `interrupted`, partial evidence remains retrievable, nothing resumes
  automatically, nothing is duplicated on later resume.
- Duplicate route names and sibling handlers in one file: a finding in one handler never marks its sibling
  reviewed; unit identities remain distinct.
- A unit's source changed since the recorded revision: its evidence is stale and does not count as completed
  review for the current revision.
- A model claims "reviewed all handlers" in prose with no tool evidence: no unit is marked reviewed.
- A hunt agent writes its file to the wrong path, writes an empty/malformed file, or writes two files: each is
  a distinct explicit failure with bounded repair, not a pass.
- Verification cancelled mid-pass: session outcomes gathered so far are flushed and remain visible.
- Reproduction leaves an orphan file: reported and retained, never deleted to make validation pass.
- Application whose only SBOM/threat model predates several later scans: shown with the disclosure; a scan
  with `threat_model=false` explains the absence rather than showing nothing.
- A legitimate application with zero scans, or a real repository that happens to live under `/tmp`: excluded
  from any synthetic-cleanup proposal.

## Requirements *(mandatory)*

### Functional Requirements

**Live, durable observability (US1)**

- **FR-001**: The system MUST bind each running job to its actual results directory as soon as the engine
  announces it (before the first artifact can exist), persist that association, and preserve path
  confinement, ownership, and scan identity.
- **FR-002**: Evidence endpoints and UI states MUST distinguish: unknown job, queued/not-started job,
  running job with no files yet, empty directory, unavailable/unreadable directory, read error, and
  "not recorded by this version" — with distinct responses, never a shared empty list or shared error body.
- **FR-003**: Artifacts, Prompts, and Log MUST update while their tab remains open, publishing new data within
  5 seconds on a healthy local connection, refreshing once more on run termination, preserving selected file,
  expanded prompts, reading position, and a controllable log-follow setting.
- **FR-004**: The system MUST cancel or sequence-guard obsolete evidence requests so one scan's response
  never overwrites another scan's view, and MUST bound retrieval/rendering for large runs.
- **FR-005**: The system MUST produce prompt records at the model-call boundary for recon, threat modeling,
  each hunt sample, verification, reproduction, and every repair call, recording scan, phase,
  agent/assignment, role/model, call order, and timestamp, with the actual system/task content sent and
  redactions clearly labeled; it MUST NOT reconstruct prompts from templates after the run nor imply all roles
  share one prompt; it MUST define which follow-up/tool exchanges are captured and link them to diagnostics;
  hidden model reasoning is not required.
- **FR-006**: The system MUST persist scan-tagged operational logs covering phase/assignment transitions,
  tool failures, validation failures, retries, output writes, stop reasons, and terminal outcomes, with
  bounded, actionable error detail sufficient to diagnose tool-repair failures.
- **FR-007**: Authorization headers and provider credentials MUST never be persisted in prompts or logs; the
  existing redaction contract MUST be applied before new telemetry is exposed; concurrent records MUST remain
  well formed and attributable.
- **FR-008**: Browser disconnection MUST NOT stop server-side execution or recording; reconnection MUST
  recover retained evidence without duplication; logs and prompts MUST survive completion and server restart;
  restart MUST preserve interrupted status and partial evidence and need not resume model work.
- **FR-009**: Prompts for scans predating capture MUST read "not recorded by this version"; the main UI and
  React `/app` MUST offer equivalent Artifacts/Prompts/Log access; classic/legacy entrypoints MUST be
  inventoried and their supported behavior preserved; every surface MUST explain loading, empty, disabled,
  legacy-unavailable, failed, and disconnected states rather than hiding errors.

**Evidence-backed review coverage (US2)**

- **FR-010**: The system MUST maintain separate measures for discovered scope, supported inventory,
  assignment, attempted review, completed review, findings, and verification, using the existing
  multi-language inventory and stable entry-point identities (feature 012) — no competing Python-only tracker.
- **FR-011**: Each eligible entry point MUST map to a concrete review assignment or carry an explicit
  unassigned/excluded reason.
- **FR-012**: Each attempted unit MUST finish with exactly one validated disposition among: reviewed with
  findings, reviewed with no issue identified, partial, failed, skipped, unsupported, not reviewed — persisting
  assignment/unit identity, repository revision, relevant source locations, scope/rationale, and links to
  observed source evidence, validated against the assigned scope and actual tool evidence. A bare model claim
  is insufficient.
- **FR-013**: A completed no-issue review MUST count as reviewed without manufacturing a finding and MUST NOT
  be presented as proof of absence of vulnerabilities; unresolved verification and completed review MUST remain
  separate axes with explicitly defined aggregation rules.
- **FR-014**: Missing records, stale revision evidence, sibling-handler findings, path mentions, reads
  without a disposition, and normal agent stops MUST NOT establish completed review; handler binding MUST NOT
  be loosened to whole-file matching.
- **FR-015**: Coverage enforcement (per the effective feature-013 options) MUST reconcile the plan with
  completed unit records and either schedule bounded follow-up work or surface the specific limiting reason
  (unsupported scope, assignment failure, cancellation, budget, model/tool failure, exhausted retry
  allowance); it MUST NOT promise universal 100% coverage; coverage MUST stay visible when enforcement is off.
- **FR-016**: Scan details and reports MUST expose unreviewed units and their reasons; dashboard counts MUST
  be preserved; regeneration MUST NOT invent evidence an older scanner never captured; prior findings MUST NOT
  be marked fixed solely because an incompletely reviewed unit produced no new finding.

**Hunt, verification, reproduction completion (US3)**

- **FR-017**: Agent stop and assignment success MUST be recorded separately; a hunt assignment succeeds only
  after its required deliverable and unit dispositions pass validation; missing, empty, malformed, misplaced,
  and duplicate output (including a "done" with no file) MUST be handled explicitly with bounded repair/retry
  under existing cancellation and budget rules, preserving completed work and identifying the exact missing
  assignment on failure.
- **FR-018**: Verification failures MUST be diagnosed per candidate and per failed operation, distinguishing
  provider transport/tool-envelope errors, invalid tool arguments, invalid evidence/decision submissions, and
  turn exhaustion; repair feedback MUST explain the failed contract; both decisions and failed session
  outcomes MUST be checkpointed during the run, including on cancellation; raising turn limits alone is not
  an accepted fix.
- **FR-019**: Every candidate MUST receive a supported, rejected, or unresolved outcome with provenance;
  system-generated unresolved outcomes MUST identify the missing model decision and MUST NOT convert failed
  verification into completion; fail-closed evidence validation MUST be retained; candidates MUST NOT be
  promoted or removed to improve the success rate; resume/recovery MUST avoid duplicate candidates and
  preserve valid prior work under existing compatibility rules.
- **FR-020**: Every supported candidate requiring reproduction MUST have a candidate-bound disposition and
  validated artifact registration or an explicit failure/inability reason; files MUST be reconciled with the
  manifest; existence is not proof of reproduction; generated static PoCs/tests MUST be labeled not executed;
  orphan files MUST NOT be silently deleted.

**Honest outcomes and report (US4)**

- **FR-021**: APIs, scan details, application history, dashboard drill-downs, and reports MUST distinguish
  job termination, phase execution completeness, review coverage, candidate verification, artifact
  completeness, and validation mode.
- **FR-022**: A normally terminated job with incomplete required work MUST visibly read partial/degraded with
  reasons; its report MUST show reviewed/total units, supported/rejected/unresolved counts, failed assignments
  and candidates, missing artifacts, disabled optional phases, and actionable recovery steps, linked to the
  underlying records.
- **FR-023**: JSON, Markdown/HTML, SARIF semantics, and regenerated views MUST stay consistent, and
  regeneration MUST NOT change original evidence or human review decisions.

**Application details, artifacts, isolation (US5)**

- **FR-024**: Clicking or keyboard-activating an application MUST visibly open its detail through clear
  navigation or a reliably visible pane, with a shareable deep link, back navigation, bounded large-list
  rendering, and preserved list/table controls and management.
- **FR-025**: The detail MUST show scan history, SBOM, threat model, and report/ledger links, selecting the
  newest valid artifact of each kind from that application's own history, showing its originating
  scan/time/revision, explicitly disclosing when it is older than the latest scan, never substituting another
  application's material, and handling missing/malformed/inaccessible artifacts with errors or explained
  absence; stale responses from rapid switching MUST never overwrite the current selection; a failed request
  MUST show an error (with retry), never indefinite loading; server errors MUST NOT be reported as absence.
- **FR-026**: Effective threat-model/SBOM settings MUST be honored per the feature-013 contract: disabled →
  explained absence; enabled → generation produces and validates its artifacts or reports failure; opening
  existing material MUST NOT launch a model scan; SBOM MUST NOT become an independent option here.
- **FR-027**: All tests and development fixtures MUST be isolated from the real application registry, ledger,
  job state, reports, reviews, and logs; a regression MUST prove engine finalization cannot register a test
  repository outside isolated storage.
- **FR-028**: The system MUST provide a previewable, backed-up cleanup of demonstrably synthetic registry
  entries that preserves legitimate zero-scan applications and all reports, never classifies every `/tmp`
  repository as synthetic, and deletes nothing except by explicit operator action — never as an automatic side
  effect of this feature.

**Preservation & safety (cross-cutting)**

- **FR-029**: The feature MUST preserve features 008–013 (dashboard metrics/charts, multi-language coverage,
  functional scan options and their contracts, verification integrity, application management, analyst
  review decisions) and all existing operator data.
- **FR-030**: The feature MUST NOT modify target source or execute target code, dependencies, generated
  PoCs, or generated exploit tests; `../vhlocal` is a read-only behavioral reference; validation is offline
  with fake providers and fully isolated storage.

### Key Entities *(include if feature involves data)*

- **Job–results binding**: the persisted association of a job to its actual results directory, established
  at engine start, with confinement/ownership/identity.
- **Prompt record**: one model call's actual sent content (system/task, labeled redactions) with scan, phase,
  agent/assignment, role/model, call order, timestamp, and links to follow-up/tool diagnostics.
- **Scan log record**: a scan-tagged operational event (transition, tool/validation failure, retry, output
  write, stop reason, terminal outcome) with bounded actionable detail, credential-free.
- **Review unit disposition**: an attempted unit's single validated outcome with identity, revision, source
  locations, scope/rationale, and evidence links.
- **Coverage measures**: the separate counts — discovered, supported, assigned, attempted, completed,
  findings, verification — plus per-unit gap reasons.
- **Assignment outcome**: a hunt assignment's separately recorded agent stop and validated success/failure,
  with the exact missing deliverable on failure.
- **Verification failure record**: a per-candidate, per-operation failure classification (transport/
  tool-envelope, invalid tool arguments, invalid evidence/decision, turn exhaustion) with repair feedback,
  checkpointed durably.
- **Candidate outcome**: supported/rejected/unresolved with provenance and, when system-generated, the
  missing decision.
- **Reproduction disposition**: a candidate-bound disposition and validated artifact registration, or an
  explicit inability reason; artifacts labeled not executed.
- **Outcome summary**: the distinct axes (termination, execution, coverage, verification, artifacts,
  validation mode) with counts, named failures, and recovery steps, consistent across surfaces.
- **Application artifact selection**: the newest valid SBOM/threat model from an application's own history
  with originating scan/time/revision and older-than-latest disclosure.
- **Registry cleanup preview**: the proposed set of demonstrably synthetic entries, a backup, and an explicit
  apply action.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001 (Live evidence)**: A deterministic delayed offline scan produces a real artifact, a prompt record,
  and a tagged log line before finishing; each is visible through its API **and** its open UI tab within
  5 seconds while the job is still running.
- **SC-002 (Durability)**: Browser navigation/disconnection and reconnection do not terminate that scan;
  switching scans during delayed requests never mixes evidence; restarting the server preserves recorded
  evidence and honest job status.
- **SC-003 (Telemetry robustness)**: Tests cover concurrent writes, a temporarily partial record, large
  output, permission/read failures, unknown jobs, legacy scans, and the final refresh; zero credentials appear
  in telemetry fixtures or served evidence.
- **SC-004 (Coverage honesty, positive)**: A deterministic 100-entry-point fixture (Python, Go, JS/TS;
  sibling handlers; duplicate route names) completes **100** explicitly evidenced unit reviews when only 8
  yield findings.
- **SC-005 (Coverage honesty, negative)**: A paired fixture that truly reviews only 8 remains **8/100** with
  92 explained gaps; missing ids, unsupported scope, source mentions, reads without dispositions, stale
  evidence, and rejected/malformed records never inflate completed review; disabling enforcement preserves
  the honest counts.
- **SC-006 (Missing hunt file)**: A fake provider that stops normally without writing reproduces the
  missing-hunt-file failure; bounded recovery either yields valid evidence or leaves an explicit failed
  assignment and a partial run — a normal stop alone never passes.
- **SC-007 (Verification diagnosis)**: Fixtures for repairable and persistent tool errors, invalid
  evidence/decisions, and turn exhaustion show recovery for repairable cases and unresolved outcomes with
  actionable reasons and durable session records for persistent ones; no evidence check is weakened.
- **SC-008 (Reproduction integrity)**: Missing dispositions and unregistered artifacts remain visible and
  block false completeness; repaired manifests keep candidate attribution and the static/not-executed label.
- **SC-009 (Cross-surface consistency)**: Replaying a sanitized fixture of the audited run's failure
  categories yields consistent partial/degraded outcomes and identical counts across API, UI, and report,
  without requiring the live model to reproduce the same findings.
- **SC-010 (Application access)**: Browser tests with hundreds of applications demonstrate immediate visible
  detail access, keyboard/deep-link/back navigation, error/retry behavior, and older SBOM/threat-model access
  when the latest scan omitted them, in both root and `/app`, including rapid switching.
- **SC-011 (Isolation & cleanup)**: Repeated test runs leave the real registry and other operator stores
  unchanged; the synthetic-cleanup preview preserves legitimate zero-scan applications and all reports;
  applying cleanup is an explicit operator action.
- **SC-012 (Build provenance)**: A freshly built binary serving its embedded assets is validated with build
  identity and tested URLs recorded; source-only tests or a checklist of ticked tasks are not accepted as
  evidence of working browser workflows.

## Assumptions

- **Rechecked baseline**: the audit table above is the authoritative current state; where the audit and code
  differ (verification failure taxonomy coarser than implied; reproduction already healthy; registry
  pollution empirically present) the code wins.
- **Feature-013 contracts are reused, not replaced**: coverage enforcement, concurrency, seeding, budget,
  resume-compatibility, and threat-model/SBOM coupling follow 013's option contract; this feature adds
  unit-level dispositions, follow-up scheduling, and diagnostics beneath them.
- **Feature-012 inventory is the scope source**: stable entry-point identities come from the existing
  multi-language recognizer; review units are keyed to them.
- **"Demonstrably synthetic" registry entry** (default for FR-028): repository path matches the Go test
  temporary-directory pattern (`/tmp/Test<Name><digits>/<NNN>`), has zero scan history, and the path no
  longer exists. Anything else — including real repositories under `/tmp` and any application with history —
  is preserved. The preview lists each proposal with its reason.
- **Bounded follow-up** (default for FR-015/017): one re-assignment per gap/unit within the existing budget,
  cancellation, and circuit-breaker rules; exhaustion becomes the recorded limiting reason.
- **Prompt capture scope** (default for FR-005): full system and task content of every model call plus the
  first assistant tool-call/repair exchange; longer tool transcripts are linked to the scan log rather than
  duplicated; the existing redaction contract is applied.
- **Offline, isolated validation**: fake/recording providers, deterministic fixtures, and fully isolated
  storage; browser workflow tests run against a freshly built binary's embedded assets; a separately
  authorized live-model run may measure real improvement but never substitutes for reproducible tests.
- **No redesign**: existing UI shapes are extended (tabs, panes, routes) rather than rebuilt.

### Explicit Exclusions / Non-Goals

- Capturing hidden model reasoning.
- Guaranteeing 100% review coverage on arbitrary code.
- Making SBOM generation an independent option (feature-013 contract stands).
- Automatically resuming model work after a server restart.
- Deleting any operator data automatically, or classifying all `/tmp` repositories as synthetic.
- Executing target code, dependencies, generated PoCs, or exploit tests; running a live model in validation.
- Completing feature 012's remaining language stages (tracked separately).
