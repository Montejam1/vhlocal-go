# Claude handoff: Live scan evidence, review coverage, and application access

Prepared: 2026-09-28. Read-only audit of source, saved results, and the running
server at port 8421. No new model scan was launched; no application code, saved
results, or registry entries were changed. Browser interactions were not
reproduced, so the application-navigation diagnosis below remains a hypothesis
supported by the layout and API evidence.

Follow-up: the September 29 live scan exposed specific citation and verification
repair defects. See [Validated citations and bounded verification repair](2026-09-29-citation-repair-speckit-specify.md)
for the additional Claude-ready specification input. Its observations supersede
this document's earlier description of absent logging for the newer live build.

## Start in Claude

```text
/speckit-specify Read docs/engineering/2026-09-28-scan-reliability-speckit-specify.md and use its entire "Specification input" section as the feature description. Use the preceding audit evidence as the starting point, rechecking it against current code. Specify repairs for live Artifacts/Prompts/Log, evidence-backed entry-point review coverage, incomplete hunt/verification/reproduction work, and application detail access. Preserve features 012 and 013 and existing operator data. Produce a new specification and requirements checklist, with measurable end-to-end acceptance scenarios. Stop after specification and checklist generation; do not implement yet.
```

This document is input for Claude's specification workflow. Its preparation did
not change `.specify/feature.json`, which currently points to feature 013.

## Audit evidence

### Run inspected

- Job: `5a88287ce3f4`.
- Report directory:
  `/home/br0kan/vulnhunter-reports/vc-claude-code-seeded-v2-logistics-dispatch-fastapi_VULNHUNT_RESULTS_gptoss120b_2026-09-28-135446`.
- Model: `gpt-oss:120b`; elapsed time: 8,216.9 seconds (about 2 hours 17 minutes).
- Job status: `done`; execution status: `partial`; coverage status: `degraded`.
  These describe different things: the job stopped, but its work was incomplete.

| Evidence | Observed result |
| --- | --- |
| `coverage_ledger.json` | 100 entry points; 8 `finding_emitted`; 92 `not_reviewed`; incomplete |
| `verification_reconciliation.json` | 128 candidates: 36 supported, 11 rejected, 81 unresolved; incomplete |
| `verification_sessions.json` | 59 sessions stopped `complete`, 51 `tool_repair`, 18 `max_turns` |
| `hunt_execution.json` | 265 planned files; one missing, `results/sg-12_nav.s3.md`; incomplete |
| `scan_meta.json` | The corresponding `hunt:sg-12:nav.s3` agent nevertheless stopped `complete` |
| Reproduction validation | One missing candidate disposition and two unregistered artifacts |
| Completed phases | `1`, `3d`, `4`; hunt, verification, and reproduction did not pass completion checks |
| Latest job request | `threat_model=false`; no latest-run threat model or SBOM is expected under the current coupled generation behavior |

The three reproduction errors were:

```text
no reproduction disposition for CAND-a98bed1f76c2d216b8523e2c
unregistered artifact: poc/CAND-20f862f93f36ba5475287165_test.py
unregistered artifact: exploit_tests/test_job_code_race.py
```

Do not interpret 128 candidates as 128 verified vulnerabilities. Do not interpret
an agent's normal stop as a validated deliverable. The 69 sessions stopped by
repair/turn limits match the count of reconciliation errors; investigate their
underlying failures using new diagnostics rather than assuming all 81 unresolved
candidates have the same cause.

### Why the live tabs are empty

1. `internal/jobs/jobs.go` assigns `ResultsDir` only after the engine call
   returns. Its event handler does not bind the directory from the engine's
   `scan_start` event. The Artifacts and file handlers in
   `internal/server/handlers.go` depend on that job field. This prevents live
   retrieval even when the engine has already written files.
2. The main UI in `vhlocal/web/index.html` loads Artifacts and Log once on entering
   the tab. Its same-tab refresh branch refreshes only Prompts during a run.
   Correcting the server alone will not make both other tabs update live.
3. The UI fetches `prompts.jsonl`, but no production writer for that file was
   found in the Go implementation. The completed job's endpoint returns 404.
   The UI turns non-success responses into a reassuring "not captured yet"
   message, even after completion.
4. The Log handler reads the central log filtered by job ID. No production
   `logsetup.New` call was found under `internal`. The completed job's log
   endpoint returns `(no log lines for this scan)`. SSE events are a separate
   channel and do not constitute a persisted scan log.
5. The completed job's Artifacts endpoint does return files. This is not an
   across-the-board failure to produce any files.
6. React's `web-react/src/pages/Scans.tsx` currently provides a live feed, but
   lacks equivalent Artifacts, Prompts, and Log views. The root UI and `/app/`
   are distinct shipped entrypoints.

### What the 8/100 figure can and cannot establish

`internal/inventory/inventory.go:BuildLedger` currently derives review status
from finding locations inside route handler spans. Its implementation explicitly
states that the pipeline emits no per-unit "reviewed, no issue" records. Without
an in-span finding it uses `not_reviewed`; unresolved handler spans fall back to
an exact declaration-line match.

Consequently, eight is the count backed by this limited attribution mechanism,
not proof that the model examined exactly eight handlers. Conversely, files
read, route names mentioned, or agent sessions completed do not prove that the
other 92 handlers received adequate review. Repair assignment and evidence
production before changing the reported coverage number. Check handler binding
across supported languages; do not loosen it to whole-file matching.

### Application access and deployment observations

- `/api/applications` returned 391 entries; 390 had no scan history. Many named
  entries point to `/tmp/Test.../001` Go test directories.
- Engine finalization calls application registration unconditionally. Some
  engine tests invoke it without isolating registry storage. The registry lives
  beside `config.LedgerDir()`. The existing stray-report-directory regression
  does not cover this different source of registry pollution.
- Main and React application views render details below the full application
  list. The main click handler neither navigates to a dedicated detail route nor
  scrolls to the detail pane. A detail change below hundreds of entries plausibly
  appears to do nothing. Verify this in a browser before declaring it the sole
  root cause.
- The real application's detail API succeeds and includes nine scan-history
  rows. Its September 17, 19:56:39 report supplies both `threat_model.md` and
  `sbom.cdx.json`, and both report-file endpoints return content. A new scan is
  not required to access those historical artifacts.
- React detail-request errors can leave the screen at "Loading…" indefinitely;
  artifact requests also need explicit error and stale-response handling.
- The running root HTML differs from the current source HTML. That proves a
  served/source mismatch, not which revision introduced each observed failure.
  Record build provenance and validate the rebuilt embedded assets.

## Specification input

Create a feature named **Reliable scan evidence and review completion** for
vhlocal-go. An operator must be able to observe real work while a scan runs,
understand exactly what scope was reviewed and what failed, retrieve durable
evidence afterward, and open an application's existing analysis artifacts.

Read the constitution, relevant existing specifications, and the current source
before planning. Preserve features 008–013, especially dashboard metrics/charts,
multi-language coverage, functional scan options, verification integrity,
application management, and analyst review decisions. Coordinate with feature
013 rather than replacing its option contracts. Use `../vhlocal` as a read-only
behavioral reference. Do not modify target source or execute target code,
dependencies, generated PoCs, or generated exploit tests.

### P1 — Live, durable scan observability

Bind each running job to its actual results directory before its first artifact
becomes available. Persist the association and preserve confinement, ownership,
and scan identity. Queued jobs, unknown IDs, unavailable directories, empty
directories, and read errors must have distinguishable responses and UI states.

Artifacts, Prompts, and Log must update while their tab remains open, without
requiring navigation or a page refresh. Publish new data within five seconds on
a healthy local connection. Refresh once more when a run terminates. Preserve
selected files, expanded prompts, and reading position; provide controllable
log following. Cancel obsolete requests and prevent one scan's responses from
overwriting another scan's view. Bound retrieval/rendering for large runs.

Produce actual prompt records at the model-call boundary, covering recon,
threat modeling, hunt samples, verification, reproduction, and repair calls.
Identify scan, phase, agent/assignment, role/model, call order, and timestamp.
Show the actual system/task content sent, with any redactions clearly labeled;
do not reconstruct prompts from templates after the run or imply all roles
share one prompt when they do not. Define which follow-up/tool exchanges are
captured and link to their diagnostics. Do not require hidden model reasoning.

Persist scan-tagged operational logs, including phase/assignment transitions,
tool failures, validation failures, retries, output writes, stop reasons, and
terminal outcomes. Capture actionable, bounded error details sufficient to
diagnose tool-repair failures. Never persist authorization headers or provider
credentials in either channel. Apply the existing redaction contract before
new telemetry is exposed. Keep concurrent records well formed and attributable.

Browser disconnection must not stop server-side scan execution or recording.
Reconnection must recover retained evidence without duplication. Logs and
prompts must remain available after completion and server restart; restarting
the server need not automatically resume model work. Preserve interrupted
status and available partial evidence. Old scans without captured prompts must
say "not recorded by this version", not indefinitely "coming soon".

Deliver equivalent evidence access in the main UI and React `/app/`. Inventory
classic/legacy entrypoints and preserve their supported API behavior. Explain
loading, empty, disabled, legacy-unavailable, failed, and disconnected states.
Do not hide errors behind empty lists or endless loading indicators.

### P1 — Evidence-backed review coverage that drives work

Maintain separate measures for discovered scope, supported inventory,
assignment, attempted review, completed review, findings, and verification.
Use the existing multi-language inventory and stable entry-point identities;
do not create a competing Python-only route tracker.

Each eligible entry point must map to a concrete review assignment, or have an
explicit reason it was unassigned/excluded. Each attempted unit must finish
with a validated disposition: reviewed with findings, reviewed with no issue
identified, partial, failed, skipped, unsupported, or not reviewed. Persist
assignment and unit identity, repository revision, relevant source locations,
review scope/rationale, and links to observed source evidence. Validate these
records against the assigned scope and actual tool evidence; accepting a model's
bare claim that it reviewed everything is insufficient.

A completed no-issue review must count as reviewed without manufacturing a
finding. It must not be presented as proof the code is vulnerability-free.
Unresolved vulnerability verification and completed source review are separate
axes. Define the aggregation rules explicitly. Missing records, stale revision
evidence, sibling-handler findings, path mentions, reads without a review
disposition, and successful agent stops cannot establish completed review.

Coverage enforcement must reconcile the plan with actual completed unit
records. Under the effective feature-013 options, schedule bounded follow-up
work for gaps or surface the specific limiting reason: unsupported scope,
assignment failure, cancellation, budget, model/tool failure, or exhausted
retry allowance. Do not promise universal 100% coverage on arbitrary code.
Keep coverage visible when enforcement is disabled.

Expose the unreviewed units and their reasons in scan details and reports.
Preserve dashboard counts. Historical regeneration must not invent evidence
that an older scanner never captured. Do not mark prior findings fixed solely
because an incompletely reviewed unit produced no new finding.

### P1 — Hunt, verification, and reproduction completion

Treat agent stop and assignment success separately. A hunt assignment succeeds
only after its required deliverable and unit dispositions pass validation.
Handle missing, empty, malformed, misplaced, and duplicate output explicitly,
including a model that says "done" without writing its expected file. Use
bounded repair/retry within existing cancellation and budget rules. Preserve
completed work and identify the exact missing assignment if recovery fails.

Diagnose verification failures by candidate and failed operation. In particular,
distinguish provider transport/tool-envelope errors, invalid tool arguments,
invalid evidence/decision submissions, and turn exhaustion. Repair feedback
must explain the failed contract. Tune prompt/schema/loop behavior based on
reproducible evidence; increasing turn limits alone is not an adequate fix.
Checkpoint both decisions and failed session outcomes during the run.

Every candidate must receive a supported, rejected, or unresolved outcome with
provenance. System-generated unresolved outcomes must identify missing model
decisions and must not convert failed verification into successful completion.
Retain fail-closed evidence validation; do not promote unsupported candidates
or remove difficult candidates to improve the success percentage. Resume or
targeted recovery must avoid duplicate candidates and preserve valid prior
work under the existing revision/configuration compatibility rules.

Each supported candidate requiring reproduction must have a candidate-bound
disposition and validated artifact registration, or an explicit failure or
inability reason. Reconcile files with the manifest. A file's existence is
not proof of successful reproduction, and generated static PoCs/tests must be
labeled not executed. Do not silently delete orphan files to pass validation.

### P1 — Honest outcomes and an actionable report

Distinguish job termination, phase execution completeness, review coverage,
candidate verification, artifact completeness, and validation mode in APIs,
scan details, application history, dashboard drill-downs, and reports.

A job that stopped normally but left required work incomplete must visibly say
partial/degraded and explain why. Its report must show reviewed/total units,
supported/rejected/unresolved counts, failed assignments and candidates,
missing artifacts, disabled optional phases, and actionable recovery steps.
Link summaries to the underlying records. Maintain consistency across JSON,
Markdown/HTML reports, SARIF semantics, and regenerated views without changing
the original evidence or human review decisions.

### P1 — Reachable application details and existing artifacts

Clicking an application must visibly open its detail view through clear
navigation or a reliably visible pane. Support keyboard operation, a shareable
application selection/deep link, back navigation, and bounded large-list
rendering. Preserve existing list/table controls and application management.

Display scan history, SBOM, threat model, and relevant report/ledger links.
Select the newest available valid artifact of each kind from that application's
history, display its originating scan/time/revision, and explicitly disclose
when it is older than the latest scan. Never substitute another application's
material. Handle missing, malformed, and inaccessible artifacts with errors or
explained absence rather than silent failure. Prevent stale responses when
switching applications quickly.

Honor effective threat-model/SBOM settings. When disabled, explain that absence;
when enabled, generation must produce and validate its promised artifacts or
report failure. Do not launch an unsolicited model scan merely to open existing
material. Changing SBOM generation into an independent option is not required
by this feature; respect the agreed feature-013 contract.

Isolate all tests and development fixtures from real application registry,
ledger, job state, reports, reviews, and logs. Add a regression for engine
finalization registering test repositories outside test storage. Audit the
existing polluted registry and provide a previewable, backed-up cleanup path
for demonstrably synthetic entries. Do not erase legitimate zero-scan
applications or classify every `/tmp` repository as synthetic. Do not delete
operator data as an automatic side effect of this feature.

### Acceptance evidence and completion gates

1. A deterministic delayed scan creates a real artifact, prompt record, and
   tagged log before finishing. Each becomes visible through its API and open
   UI tab within five seconds, while the job remains running.
2. Browser navigation/disconnection and reconnection do not terminate that
   scan. Switching scans during delayed requests does not mix their evidence.
   Restarting the server preserves recorded evidence and honest job status.
3. Tests cover concurrent writes, a temporarily partial record, large output,
   permission/read failures, unknown jobs, legacy scans, and final refresh.
   No credentials appear in telemetry fixtures or served evidence.
4. A deterministic 100-entry-point fixture completes 100 explicitly evidenced
   unit reviews even when only eight yield findings. A paired fixture that
   actually reviews only eight remains 8/100 with 92 explained gaps. Include
   sibling handlers, duplicate route names, and Python, Go, and JS/TS cases.
5. Missing IDs, unsupported scope, source mentions, reads without dispositions,
   stale evidence, and rejected or malformed review records never inflate
   completed-review coverage. Disabling enforcement preserves honest counts.
6. Reproduce the missing hunt-file failure with a fake provider that stops
   normally. Bounded recovery either produces valid evidence or leaves an
   explicit failed assignment and partial run; a normal stop alone cannot pass.
7. Verification fixtures cover repairable and persistent tool errors, invalid
   evidence/decisions, and turn exhaustion. Recovery succeeds for the repairable
   cases; persistent failures remain unresolved with actionable reasons and
   durable session records. No weakening of evidence checks is accepted.
8. Missing reproduction dispositions and unregistered artifacts remain visible
   and prevent false completeness. Successfully repaired manifests retain
   candidate attribution and the static/not-executed validation label.
9. Replay a sanitized fixture reflecting this audited run's failure categories.
   Assert consistent partial/degraded outcomes and counts across API/UI/report
   surfaces. Do not require the live model to produce identical findings.
10. Browser tests with hundreds of application entries demonstrate immediate
    detail access, keyboard/deep-link navigation, error/retry behavior, and
    older SBOM/threat-model access when the latest scan omitted them. Test both
    root and `/app/` interfaces and rapid application switching.
11. Repeated tests leave the real registry and other user stores unchanged.
    Synthetic cleanup previews preserve legitimate zero-scan applications and
    all reports; applying cleanup must be an explicit operator action.
12. Validate a freshly built binary serving its embedded assets, recording the
    build identity and tested URLs. Source-only tests and a checklist of checked
    tasks are insufficient evidence of working browser workflows.

Use offline fake-provider integration tests for deterministic acceptance, plus
the project's required Go/frontend checks and browser workflow tests. Run them
with fully isolated storage. State what was actually executed, including any
failed or unavailable checks. A separately authorized live-model validation may
measure real improvements, but must not substitute for reproducible tests.

For planning, inspect at least `internal/jobs`, `internal/server`,
`internal/engine` (hunt/parallel hunt, verify, reproduction, record, resume,
regenerate), `internal/agent`, `internal/client`, `internal/logsetup`,
`internal/inventory`, `internal/recognize`, `internal/verification`,
`internal/apps`, `internal/reports`, `internal/report`, and both UI trees.
Trace data from production through persistence, API, and actual served UI.
Report existing functionality accurately and extend it rather than duplicating
it. Specification approval is followed by plan/tasks/implementation; this
handoff does not authorize skipping those stages.
