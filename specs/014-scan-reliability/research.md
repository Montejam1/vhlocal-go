# Phase 0 Research: Reliable scan evidence and review completion

Grounded in a read-only recheck of the current source (three parallel verifications; no scan, model,
server, or Python run). Each decision cites what exists so the fix is real behavior with evidence.

## R0 — Verified current state (the gap map)

- **Binding**: `jobs.go` sets `ResultsDir` only after `run` returns; `onEvent` handles `phase_start`,
  `agent_start`, `findings` + token/agent counters — **no** `scan_start` case, though that event carries
  `results_dir` (engine.go scan_start payload). `persist()` is not called from `onEvent`; event ring is
  runtime-only. `jobResultsDir` returns `""` for unknown **and** unbound → Artifacts `200 {files:[]}` and
  File `404 "no results directory"` are the same for both; Log checks `store.Status` (404 "no such job").
- **Prompts**: zero Go writers of `prompts.jsonl` (002-port contract T043 marked done, never
  implemented; Python reference writes it). UI: `fetch('/api/scans/'+id+'/file?path=prompts.jsonl')`, on
  `!r.ok` → "No prompts captured yet — they appear as each phase starts." Quiet refresher silently returns.
- **Log**: no production `logsetup.New`; `ReadLog` filters the central file by `"["+tag+"]"`; handler
  returns `200 "(no log lines for this scan)"`; UI renders it verbatim in a `<pre>`.
- **UI refresh**: 4 s repaint; `hasPrev` → Artifacts/Log load once per (scan, tab); only
  `tab==='prompts' && running` refreshes. No AbortController/sequence guard; `loadFiles` re-queries
  `$('tabbody')` after `await` (cross-scan overwrite); `loadLog/loadPrompts` capture the node before
  `await` (stale data dropped by accident). `select` resets to Live tab. Classic/legacy: unconditional
  re-fetch each poll (flash); legacy lacks Prompts. React: SSE feed + intel chips only; `api.ts` has no
  artifacts/prompts/per-scan log.
- **Applications**: detail is a sibling below the list; `openApplication` neither navigates nor scrolls;
  rows lack `tabindex`/`role`/`keydown`; `navigate` writes only the view name to the hash and readers
  strip `?`; `_apps[0]` auto-opens; no stale guard. React: detail below list; `.catch(()=>setDetail(null))`
  → permanent "Loading…"; `IntelTab` fetches have no `.catch`/cleanup; `api.reportText` maps any non-ok to
  `null` (404 ≡ 5xx → "No threat model / No SBOM … yet").
- **Coverage**: `disposition()` → `finding_emitted` iff finding inside handler span (unresolved span → exact
  declaration line), else `not_reviewed`; constants `reviewed_no_issue`, `covered_by_parent_analysis`,
  `excluded_with_reason` have **zero producers**; `Reviewed = Total − NotReviewed`.
- **Hunt**: `execution.Complete` requires every planned file `deliverableValid`; `AgentRecord` lacks
  `Produced` (agent.Result.Produced exists but isn't recorded); `huntExecution{files[], complete}` has no
  per-file status; no per-unit retry loop (only in-agent nudges + tool-call repair); `silentProvider`
  regression asserts non-completion, not recovery.
- **Verification**: `Reconcile` fail-closed (missing/duplicate decisions → unresolved + error);
  `EnrichReasons` writes "no decision submitted — session ended: <stop> after N turn(s), M recoverable tool
  failure(s)". Taxonomy: `max_turns`, `endpoint_failure` (transport), and **one** `failures` counter +
  `tool_repair` stop shared by provider tool-parse errors, rejected `buildDecision`, and reconcile-rejected
  submissions; invalid tool *args* return "ERROR:" text and do **not** increment `failures`. `checkpoint()`
  runs before the loop, after each accepted decision, and at the end — decision-less sessions wait; both
  cancellation paths `return false` without flushing.
- **Reproduction**: `ValidateArtifacts` emits "no reproduction disposition for <id>" and "unregistered
  artifact: <rel>"; orphans **reported, never deleted**; `reproMaxAttempts = 2`; harness writes the
  manifest; `status` must be `authored`; every surface says not executed. **Healthy — preserve.**
- **Registry**: `finalize` calls `apps.Register`/`SetName` unconditionally (also on cancelled/aborted and
  from `regenerate`); registry at `filepath.Dir(config.LedgerDir())/applications.json` (`VHLOCAL_LEDGER_DIR`
  override). Engine tests: **zero** `t.Setenv`; 40+ `Execute` sites on temp repos → real registry polluted
  (~100 KB of `/tmp/Test…/001`). Other packages isolate correctly; no regression for the engine leak.
- **Axes**: four independent (job termination in `jobs`, execution/coverage/validation in
  `consolidate.ComputeRunStatus`); degraded reasons assembled in `finalize` and rendered in findings.json,
  manifest, report, reports index.

## R1 — Early job↔results-dir binding + state contract (US1)

**Decision**: In `jobs.onEvent`, handle `scan_start`: set `j.ResultsDir` from `ev["results_dir"]`
(confined: must be under the allowed roots/reports dir and owned by this job), set an explicit
`Started` marker, and `persist()`. Expose a **job evidence state** derived from store facts:
`unknown` (404 "no such job"), `not_started` (queued/cancelled-before-start; `202`/`409` with state body),
`running_no_files` (200, `files:[]`, `state:"running"`), `ready` (200 with files), `unavailable`
(directory missing/unreadable → `503`/`500` with reason), `empty` (bound, exists, no files after completion
→ 200 `state:"empty"`). Artifacts/File/Prompts/Log all consult the same resolver so responses are
distinguishable (FR-002). Also `persist()` on `scan_start`/`phase_start` so restart keeps binding +
`interrupted` status (FR-008).

**Rationale**: the engine already emits the authoritative path at start; binding late is the sole cause of
empty live tabs. **Alternatives**: computing the dir in the server before `Execute` — also viable
(`buildScan` knows it), but binding from the engine event keeps CLI/server parity and confinement checks
in one place.

## R2 — Prompt records at the model-call boundary (US1)

**Decision**: `internal/engine/prompts.go`: a `promptSink` (mutex, append-only `prompts.jsonl` in the
results dir, one whole JSON line per write, fsync-free but atomic per line) and a `client.Provider`
decorator `promptRecorder{inner, sink, meta}` created **per unit/agent** with fixed
`{scan_tag, phase, label/assignment, role, model}`. Every `Chat` (main turns, `repairChat`, canary,
repartition, verify, reproduce) passes through the decorator, so **all** calls are captured without
touching agent internals; per-unit instances make it race-free under 013 concurrency. Record: `seq`
(per-scan monotonic), `ts`, `phase`, `label`, `role`, `model`, `kind` (`main|repair|canary|repartition`),
`system`, `task`/last user content, `messages_count`, `tool_calls` summary, `response_stop`, and a
`redactions[]` list naming what was masked. Apply `redact` + host-credential stripping; providers hold API
keys outside `ChatRequest`, so content is credential-free by construction — verified by test (FR-007).
Capture scope (spec Assumption): full system + task of every call plus the first assistant tool-call/
repair exchange; longer tool transcripts link to the scan log by `seq`. Record `prompt_capture_version`
in `scan_meta.json`; a scan lacking it reads "not recorded by this version" (FR-009). New paged endpoint
`GET /api/scans/{id}/prompts?after=<seq>&limit=` (UI stops fetching the raw file).

**Rationale**: FR-005; a decorator at the provider boundary is the only place that sees every real call,
including repairs the agent makes internally. **Alternatives**: an agent `Observer` hook — misses canary/
repartition/verify calls made outside `agent.Run`; template reconstruction — forbidden (FR-005).

## R3 — Scan-tagged operational log (US1)

**Decision**: initialise `logsetup` in production (server `runScan` and CLI `run`) and create a
`Logger` tagged with the job id/scan tag per run. `internal/engine/scanlog.go` subscribes to engine
events and writes bounded, redacted lines: phase/assignment start/skip/done, agent start/stop reason,
tool failure (class + bounded message), validation failure, retry/repair attempt + outcome, output write
(path), budget/breaker/cancel, terminal outcome, `resume_invalidated`. Add the missing fine-grained emits
(`tool_failure`, `validation_failure`, `retry`, `output_written`) from `agent`/`hunt`/`verify`. Whole-line
writes under a mutex keep concurrent records well formed; each line carries the tag + label. New
`GET /api/scans/{id}/log?tail=&follow=` (tail window; UI follow toggle) instead of the full-file read;
empty → explicit `state:"no_lines"` (never a prose sentinel). Never log headers/credentials; apply
`redact` before write.

**Rationale**: FR-006/007; the reader/filter already exists — only the writer is missing.

## R4 — Live refresh, state UX, stale-response guards (US1)

**Decision**: main UI — when the scan is running, the same-tab branch refreshes **Artifacts and Log** too
(quiet, diff-aware like `refreshPromptsQuietly`), plus one refresh on terminal status; preserve selected
file, `<details>` expansion, and scroll position; add a log-follow toggle. Introduce a per-pane
`AbortController` and a request sequence number checked against the current selection before writing;
resolve the pane element **before** awaiting. Render distinct messages for each R1 state and for
`not recorded by this version`. Bound rendering: artifacts paged, log tailed, prompt content clamped with
expand. Classic/legacy: inventory (classic = Artifacts+Prompts+Log, legacy = Artifacts+Log; neither has
Applications), keep their API behavior working against the new state contract, add state messages — no
redesign (fixing their unconditional re-fetch is optional polish). React: add Artifacts/Prompts/Log
sections to `ScanDetail` using the new endpoints, with error states and stale guards.

**Rationale**: FR-003/004/009; the polling loop exists — the per-tab load-once logic and missing guards
are the defects.

## R5 — Evidence-backed review units, assignments, follow-up (US2)

**Decision**: new `internal/engine/review_units.go` + `review_units.json`.
- **Assignment**: after partitions resolve, map every inventory route (stable id from 012) to the hunt
  unit(s) whose partition scope covers its file/subsystem; routes with no covering unit get
  `unassigned` + reason (unsupported language/scope, over partition cap, excluded).
- **Evidence trace**: `agent.Result` gains `Reads []ReadSpan{File, Start, End}` populated from
  successful `Read`/`Grep` tool dispatches (paths confined; line spans from the tool args/result). Cheap,
  factual, already observable in the sandbox dispatch.
- **Disposition** per unit and per assigned route: `reviewed_with_findings` (in-span finding, existing
  rule), `reviewed_no_issue` **only if** the unit's deliverable validated **and** the route's handler
  span (from `recognize.EnclosingScope`) was actually read by that unit **and** the unit's assigned scope
  includes the route **and** the recorded repo revision matches; `partial` (unit ran, read outside span
  only / stopped on max_turns); `failed` (deliverable invalid/missing after recovery); `skipped`
  (cancel/budget/breaker); `unsupported`; `not_reviewed`. Persist unit id, assignment, revision, spans
  read, rationale, evidence links (prompt `seq`, log lines).
- `inventory.BuildLedger` gains an evidence input (reviewed spans + dispositions) and now **produces**
  `reviewed_no_issue` and `excluded_with_reason`; `finding_emitted` rule unchanged; handler binding stays
  span-exact (never whole-file) (FR-014). Aggregation: coverage = evidenced dispositions over supported
  inventory; verification is a separate axis (FR-013).
- **Follow-up**: with `EnforceCoverage` on (013), after the hunt reconcile plan vs completed unit records;
  schedule **one** bounded re-assignment per gap under budget/cancel/breaker; otherwise record the limiting
  reason per unit; with enforcement off, still compute and expose gaps (FR-015).

**Rationale**: FR-010..016, SC-004/005; reads-within-span by a validated unit is real tool evidence, not a
claim; path mentions, reads outside the span, and unvalidated units do not qualify. **Alternatives**: asking
the model for a per-handler checklist — rejected (bare claim); whole-file read = reviewed — rejected (FR-014).

## R6 — Hunt assignment success ≠ agent stop; bounded recovery (US3)

**Decision**: `AgentRecord` gains `produced bool` (from `agent.Result.Produced`) and
`hunt_execution.json` gains per-file `{path, status: valid|missing|empty|malformed|misplaced|duplicate,
unit, attempts}`. After a unit's agent stops, validate its deliverable; on missing/empty/malformed (or a
file written to the wrong path / a duplicate), run **one** bounded re-run of that unit (fresh context, same
provider/endpoint, same label + attempt suffix) subject to `ctx`, budget, and breaker; if still invalid,
record `failed` with the exact missing path and keep the run partial. Preserve completed work; parallel
path folds per-file status deterministically.

**Rationale**: FR-017, SC-006; the validity gate exists — recovery and attribution do not.

## R7 — Verification failure taxonomy + durable checkpoints (US3)

**Decision**: split the single counter into classified failures recorded per session/candidate:
`transport` (provider TransportError kind generic), `tool_envelope` (KindToolParse), `invalid_tool_args`
(Read/Grep/capture_evidence argument errors — now counted), `invalid_submission` (buildDecision/
reconcile-rejected evidence or decision), `turn_exhaustion` (max_turns). `SessionOutcome` gains
`failures_by_class` and `last_operation`; repair feedback names the violated contract (e.g. "quote must
byte-match live source lines a–b"). `checkpoint()` runs after **every** session (decision or not) and in
both cancellation paths before returning. Reasons in reconciliation cite the dominant class. No change to
evidence validation strength; turn limits unchanged (FR-018).

**Rationale**: FR-018/019, SC-007; the audited 69 failed sessions cannot be diagnosed today because three
different failures share one bucket and one is invisible.

## R8 — Reproduction: preserve + fixture (US3)

**Decision**: no behavioral change; add fixtures proving missing-disposition and unregistered-artifact
errors block completion, orphans persist, repaired manifests keep candidate ids and the `authored`/
not-executed label (FR-020, SC-008).

## R9 — Outcome counts and report (US4)

**Decision**: `finalize` assembles an additive `outcome` block in `run_status`: `units {total, assigned,
attempted, reviewed_with_findings, reviewed_no_issue, partial, failed, skipped, unsupported, not_reviewed}`,
`candidates {supported, rejected, unresolved}`, `failed_assignments[]`, `failed_candidates[]` (with class),
`missing_artifacts[]`, `disabled_optional_phases[]`, `recovery_steps[]` (deterministic strings: resume,
re-run failed assignments, raise budget, enable threat model, inspect log seq…). Report Markdown/HTML gains
a "Completion" section rendering the same block with links to `review_units.json`, `hunt_execution.json`,
`verification_sessions.json`, `artifact_manifest.json`; SARIF semantics unchanged; regeneration re-renders
from persisted records only (FR-021..023, SC-009). Cross-surface consistency test compares API, report, and
regenerated view on the sanitized replay fixture.

## R10 — Applications: reachable detail + correct artifact selection (US5)

**Decision**: main UI — `openApplication` updates the hash to `#applications?app=<slug>` (readers parse the
query), `scrollIntoView({block:'start'})` on the detail pane (or a dedicated detail view when the list is
long), rows get `tabindex=0 role=button` + Enter/Space `keydown`, back navigation restores the list, list
rendering is bounded (page/“show more”), and a selection sequence guard drops stale detail responses. Newest
valid artifact per kind is selected from the application's own scan history (validate JSON/markdown
parse; skip invalid), rendered with originating scan id/time/revision and an "older than latest scan"
disclosure; `threat_model=false` → explained absence (013 contract). React: `Applications.tsx` gets
explicit error + retry states (detail and intel), cleanup flags for stale effects, and `api.ts`
distinguishes 404 (absent) from 5xx (error). No unsolicited scan.

**Rationale**: FR-024..026, SC-010.

## R11 — Test isolation + registry cleanup (US5)

**Decision**: `internal/engine` `TestMain` sets `VHLOCAL_LEDGER_DIR`, reports dir, log file, jobs path, and
profiles dir to a temp root (matching what `apps`/`server`/`membank`/parity already do); a regression
asserts that `Execute` on a temp repo writes **nothing** under the real home stores (FR-027). New
`internal/apps/cleanup.go`: `PreviewSynthetic()` returns entries matching **all** of: path matches
`^/tmp/Test[A-Za-z0-9_]+\d+/\d{3}$`, zero scan history, path no longer exists — each with its reason;
`Apply(preview)` first writes `applications.json.bak-<ts>`, then removes exactly the previewed ids.
Exposed as CLI `vhlocal applications cleanup --preview|--apply` and `GET/POST /api/applications/cleanup`
(POST requires an explicit confirm token). Never touches reports or ledgers; legitimate zero-scan apps and
real `/tmp` repos are excluded (FR-028).

## R12 — Build provenance for browser validation (US1/SC-012)

**Decision**: expose build identity (version + embedded-asset content hash) via `/api/config` and record it
with tested URLs in the validation evidence; browser workflow tests run against a freshly built binary's
embedded assets (operator-run script), never source-only.

## R13 — Tests & validation posture

**Decision**: offline fixtures — delayed provider (5-second visibility), silent provider (missing
deliverable → recovery/failed assignment), failure-class providers (repairable/persistent tool errors,
invalid submissions, turn exhaustion), `testdata/coverage100` (Python/Go/JS-TS, sibling handlers,
duplicate route names) with a paired only-8 variant, sanitized audited-run replay; `-race` on writers;
TestMain isolation everywhere; browser tests operator-run with build identity. Report exactly what ran and
what was unavailable (FR-030, SC-001..012).

## Post-design constitution re-check

Additive records, a provider decorator and event subscribers around existing calls, evidence-derived
dispositions, split failure classes, bounded retries under existing rules, explicit backed-up cleanup, and
stdlib-only concurrency — no new dependency, no boundary widening, no invented evidence, no silent
fallback, no automatic data deletion. **Constitution Check remains PASS after design.**
