# Changelog

Notable feature updates to vulnhunt-local. Newest first.

## 2026-10-03 — Actionable vulnerability reports (016)

Everything below is offline-tested and additive. Existing scans, features 012-015 and
operator data are preserved; no live model run was part of validation (operator-owned).

- **The reporting unit is one established defect**, not one detection. The acceptance
  corpus moves from 64 candidates presented as findings to **34 issues to fix**, each
  backed by its detections with every citation, evidence excerpt and recorded identity
  intact and counted exactly once. Repeated citations of one line are one affected
  location with a citation count, never several locations. No merge is ever inferred from
  a matching title, weakness or route: two established groups describing the same defect
  at one route stay two issues, with their shared location visible so a person can judge
  the merge.
- **The opening is bounded and accurate** — 114 rendered words against a 557-word
  baseline, with the severity split, up to five prioritised actions, and one plain
  review-scope line carrying the three independent status facts. The coverage figure is
  the *completed* count over its denominator; the exposure axis appears only where it is
  labelled as exposure. The old banner that read "64 finding(s) were produced" is gone.
- **Reviewed, weakness-specific remediation guidance** (`internal/guidance`) for all 27
  weakness families, compiled into the binary and never generated at report time. It
  replaces the single generic "validate/encode untrusted input at the sink" answer in
  both the report and the `--remediate` records. `fix not provided` went from **54
  occurrences to 0**. A recorded recommendation wins when it addresses the observed
  mechanism; when it does not, the mechanism fix is used, the divergence is disclosed and
  the recorded text is kept for reference. Where the fix needs a policy decision the
  records cannot establish, the recommendation names the decision instead of inventing
  it.
- **Investigation, follow-up and scanner maintenance no longer compete.** "Needs review"
  (inconclusive vs assessment not completed) and dismissed candidates are separate,
  labelled sections that never enter a vulnerability or severity total; any proposed
  severity is marked proposed, not established. "Technical diagnostics" — failure
  classes, stop reasons, per-call records, provider provenance with credentials redacted,
  configuration, phase detail, raw statuses and recovery steps — is collapsed in the
  browser and excluded from the default print body.
- **One projection, six surfaces.** `report_model.json` gains a versioned `presentation`
  projection that `SCAN_REPORT.md`, `SCAN_REPORT.html`, the three shipped viewers and the
  React app all read; none of them recomputes grouping, severity, counts or guidance. A
  report saved before this feature carries no projection and renders through the
  unchanged feature-015 path, with unavailable values disclosed rather than back-filled.
- **Honest limits.** Credentials in a recorded endpoint URL are redacted everywhere. The
  report still claims no CVSS score, no CVE, no vendor identifier, no host attribute and
  no executed exploit, because the records contain none. Browser, print and timed-reader
  acceptance are **not run** and are recorded separately; a green offline suite and a
  checked task list are not evidence of reader comprehension, browser quality or print
  quality.

## 2026-09-29 — Analyst reports and measured efficacy (015)

- Summary-first reports with supported-only totals, navigable evidence, remediation
  groups and separate candidate/execution appendices; per-diagram repair/fallback.
- Coverage v2 distinguishes source exposure from completed handler review and
  preserves v1 historical semantics.
- Citation validation/repair, candidate amendment, structured verifier feedback,
  per-call provenance and sanitized failure diagnostics with optional full context.
- `bench efficacy` scores supported detections and safe controls; `verify-compare`
  isolates frozen-manifest verification variants and discloses unexecuted runs.
- Application identity exists from scan start through interruption/cancellation;
  unmapped legacy reports remain separate. Report switching rejects stale responses.
- Offline transcript baseline and browser test specifications included. Browser and
  live-model efficacy runs are **not run**; checked tasks do not establish accuracy.

## 2026-09-29 — Scan reliability: live evidence, evidence-backed coverage, honest completion (014)

Everything below is offline-tested and additive; existing scans, features 012/013 and operator data are
preserved. No live model run was part of validation (operator-owned).

- **Live, durable evidence while a scan runs** — the job binds its results directory on the engine's
  `scan_start`; one evidence-state resolver (`unknown | not_started | running_no_files | ready | empty |
  unavailable`) backs `/api/scans/{id}/artifacts` (paged), `/file`, the new `/prompts` (every model call
  of every role/kind as redacted, clamped `prompts.jsonl` records; legacy scans read `not_recorded`) and
  `/log` (scan-tagged JSON window with a cursor). All three UIs refresh Artifacts/Log/Prompts live with an
  abort/sequence guard and explicit state messages.
- **Evidence-backed review coverage** — `review_units.json`: every entry point is assigned to a hunt unit
  and gets a disposition only from evidence (a valid deliverable **and** a `Read` over the handler span at
  the current revision); `coverage_ledger.json` gains `reviewed_no_issue` / `excluded_with_reason`. A
  provider that reads only 8 of 100 handlers stays 8/100 with 92 reasoned gaps; one bounded follow-up unit
  per partition under coverage enforcement. Go registration-style routes resolve to the handler function.
- **Completion integrity** — verification failures classified per operation (`transport`, `tool_envelope`,
  `invalid_tool_args`, `invalid_submission`, `turn_exhaustion`) in `verification_sessions.json`, flushed
  after every session and on cancel; one bounded re-run of a unit/sink/IaC pass whose deliverable is
  invalid after a normal stop; `hunt_execution.json.detail` per-file status (misplaced files reported,
  never deleted).
- **Honest completion block** — `run_status.outcome` (also in `scan_meta.json`, the report's
  `## Completion` and `## Review coverage`, scan detail and application history) counts units, candidates,
  failed assignments/candidates (with class), missing artifacts, disabled optional phases
  (`1t (threat_model=false)`) and deterministic recovery steps — assembled from records only, so
  `vhlocal report` regeneration reproduces it byte-for-byte without touching evidence or human decisions.
- **Application access** — keyboard-activatable rows/cards, `#applications?app=<slug>` deep links with Back,
  bounded list (100/page), stale-response guard, error + retry; `/api/applications/{slug}.artifacts` selects
  the newest **valid** threat model / SBOM from that application's own history with originating
  scan/time/revision and an "older than the latest scan" disclosure; report-file 404 (absent) is distinct
  from 500 (error).
- **Registry cleanup + isolation** — `vhlocal applications cleanup --preview | --apply --confirm <token>`
  and `GET/POST /api/applications/cleanup` remove only demonstrably synthetic `/tmp/Test…/NNN` entries
  (zero history, path gone) after writing `applications.json.bak-<ts>`; every test package now isolates
  HOME and all `VHLOCAL_*` stores (`internal/testisolate`) — the full suite leaves `~/.vhlocal` and
  `~/vulnhunter-reports` byte-identical. `/api/config.build` carries version, embedded-asset hash and
  build time for validation reports.

## 2026-09-28 — Restore scan launch from the served UIs

- Fixed scan requests rejected as `unsupported option: seed_routes` (and the
  related `seed_prior`, `enforce_coverage`, and `concurrency` keys). Older pages
  may submit seeding off, coverage planning on, and concurrency 1; these values
  match the current engine behavior. Unsupported values remain explicit errors.
- Main, classic, and legacy scan forms no longer submit these fixed/unavailable
  controls and explain their current behavior. Profiles cannot enable them;
  unsupported profile overrides are disclosed. This does not implement seeding
  or parallel agents.

## 2026-09-26 — Multi-language scan coverage: recognizer core + Go (012, in progress)

First increment of first-class multi-language coverage (feature 012). Backend-only, additive, and
self-contained; no scanner integration is wired yet (that is the next increment), so existing scans and
all prior features are unaffected.

- **New `internal/recognize` package** — a language-agnostic, static, offline recognition core built
  **stdlib-first with no CGO and zero new runtime dependencies** (research R1, the constitution's
  dependency budget): a language/application-type-agnostic `InvestigationUnit` model (8 surface kinds,
  beyond HTTP routes), a `Recognizer` registry, deterministic unit ids, a whole-repository **census**
  (classifies production/test/generated/dependency/unreadable, path/symlink-confined), and an
  **enclosing-scope resolver** (Go via the standard-library `go/ast`; brace-based for C-family/JS/TS/
  Java/Kotlin/C#/Rust/PHP; indentation for Python; def/end for Ruby).
- **Go recognizer** (`lang_go.go`) via the standard-library AST — recognizes `net/http` (incl. the
  Go 1.22 `"METHOD /path"` ServeMux form), Gin, and Chi web routes plus Cobra CLI commands, with
  method/path/handler/inputs; routes in comments or string literals are correctly ignored, and a
  malformed file yields a per-file limitation without dropping its siblings.
- Offline tests (`CGO_ENABLED=0`) cover the model/registry/id determinism, the census classification,
  the per-language scope resolver, and the Go recognizer (exact-fixture match + negative controls +
  determinism + parse-error isolation). No live model, no network, no target-language runtimes.

### Increment 2 — Go integrated into the live scan denominator (2026-09-26)

- **Go recognition wired into the real scan path.** `internal/inventory.EnumerateRoutes` now augments its
  native Python enumeration with non-Python entry points recognized via `internal/recognize` (Go today),
  so a Go or mixed-language repository is no longer scanned against a Python-empty denominator. `Route`/
  `LedgerEntry` carry an additive `language` tag; the source-size/degradation counter is generalized to
  all recognized languages. Python enumeration and the parity golden are unchanged (preserved behavior).
- **Offline engine end-to-end proof** (`tests/parity/goapp_test.go` over a new `testdata/goapp`):
  discovered Go entry points reach partitioning and the coverage ledger through the real
  `engine.Execute` pipeline, and with no analysis produced every Go route is honestly `not_reviewed`
  (coverage is not reported complete); a route in a comment is not enumerated. No live model, no network,
  no Go toolchain.
### Increment 3 — Go scan-to-report checkpoint + evidence-backed coverage (2026-09-26)

- **Evidence-backed coverage disposition** (T048, FR-025/026): `inventory.BuildLedger` now dispositions a
  route from resolved finding locations, not free-text mentions — a route is `finding_emitted` only when a
  finding falls inside its handler span (via `recognize.EnclosingScope`), so a finding in a sibling handler,
  or a bare filename/path mention, no longer marks a route reviewed. The prior mention-based
  `reviewed_no_issue` heuristic is removed. The vulnapp parity golden was deliberately re-baselined for the
  three routes that were only mention-reviewed (`reviewed_no_issue`→`not_reviewed`); candidates, verdicts,
  tiers, and run-status are unchanged.
- **Go end-to-end offline checkpoint** (T019/T052): a new `tests/parity/transcript/goapp.json` drives the
  real `engine.Execute` over `testdata/goapp` through discovery → hunt → verification → published report,
  demonstrating a **supported**, a **rejected (with a real defense)**, and an **unresolved** Go candidate in
  `findings.json` and `SCAN_REPORT.md`; a sibling route with no in-handler finding stays `not_reviewed` and
  coverage is not reported complete. Offline: no live model, no network, no Go toolchain. (The offline verify
  harness's candidate-location matching was generalized beyond `.py` — test code only.)
- **Still open** (tracked, unchecked): source-grounded verification for Go **injection-class** sinks (the
  supported checkpoint candidate is an authorization/logic finding, which needs no injection sink; a Go
  command-injection "supported" candidate still hits the Python-only sink table — T049 + Go sink patterns);
  Go sensitive-operation detection (T050); the support-matrix truthfulness gate (T053); richer hunt-task unit
  context / cross-module availability (T047, FR-021); and the remaining 11 languages (T054). No language is
  marked "supported" in a published matrix yet.

## 2026-09-25 — Applications & Ledger: multi-select delete in table views (011)

Served-UI (`vhlocal/web/index.html`) change only; no Go, data, endpoints, or scan behavior changed.

- **Reports-style multi-select delete on the Applications and Ledger Table views.** Each table row
  now has a selection checkbox and the header a select-all, with a bulk bar showing "N selected"
  and a "Delete selected (N)" action (disabled when nothing is selected) — matching the Reports
  tab. Deleting runs as one operator action behind a single confirmation, reusing the existing
  delete endpoints per row (forget application keeps its reports; clear ledger keeps reports and
  other ledgers); partial failures are reported honestly and the list reflects the true result.
- The per-row delete is retained; the selection controls appear only in Table view (the List/cards
  view is unchanged); selection is cleared after a delete, a refresh, or a Table↔List switch. The
  Reports tab's existing multi-select is unchanged. The Go suite remains green; browser confirmation
  is operator-owned. No Python executed.

## 2026-09-22 — Analyst workspace: findings queue, reviews, saved views (010, in progress)

Backend-first first increment of the evidence-centered analyst workspace (feature 010).
Additive Go packages + HTTP endpoints, fully offline-tested; no scanner/data changes and
scan evidence is never rewritten. React UI, evidence viewer, comparison, dashboard queues,
and contextual AI are subsequent increments (operator-owned browser validation).

- **Cross-scan findings queue.** New `internal/findings` indexes findings from every saved
  scan — including scans run with the ledger disabled — reusing the engine's cross-run
  identity precedence (`internal/lifecycle`). `GET /api/findings` filters/sorts/searches and
  distinguishes filtered-empty from no-findings; `GET /api/findings/{occ}` returns an
  occurrence's detail (row + raw finding + its review record), 404 for a missing record.
- **Durable human review decisions.** New `internal/review` stores an operator's disposition
  (needs-review / investigating / accepted-risk / dismissed / resolved) with notes and
  rationale as an append-only history under `~/.vhlocal/reviews/`, separate from scan
  evidence (never overwritten). Rationale is required for dismissal/accepted-risk/resolution;
  a later decision supersedes without erasing history; an optimistic version check returns a
  conflict (409) rather than letting a stale browser overwrite a newer decision.
  `GET`/`POST /api/findings/{stable}/review`.
- **Saved views.** New `internal/views` persists named queue filters/sort under
  `~/.vhlocal/views/`; `GET`/`POST /api/views`, `DELETE /api/views/{id}`.
- **Revision-bound evidence viewer.** New `internal/evidence` returns a finding's source
  excerpt bound to the scanned revision — it reads the repo only when it is verifiably at the
  recorded commit (HEAD read from `.git`, not executed; not dirty), and otherwise reports
  `revision-unavailable` rather than silently substituting the working tree. Path-contained,
  static-only. Narrative (entry point, attacker control, defenses, impact, remediation) comes
  from the verification record. `GET /api/findings/{occ}/evidence`.
- **Honest baseline comparison.** New `internal/findings/comparison.go` diffs a scan against
  an operator-selected comparable baseline by stable identity (new/recurring/regressed);
  an absent baseline finding is marked fixed only when current coverage is complete, otherwise
  unknown/incomparable — never auto-fixed — and no rescans are triggered.
  `GET /api/findings/{occ}/comparison?baseline=`.
- **Honest scan status & validated artifact manifest.** `GET /api/scans/{id}/status` surfaces
  the three independent axes (execution / coverage / validation) and per-phase outcomes,
  distinct from the queue/job status and never inferred from a completion label (reuses the
  feature-007 `scanStatus`). New `internal/reports` manifest (`GET /api/scans/{id}/manifest`)
  reports each expected artifact (findings report, README, threat model, SBOM, verification,
  reproduction) as not_requested / available / missing / unreadable / malformed /
  generation_failed / unknown_historical, where "available" requires content-validated
  material — not merely a present filename; missing optional artifacts never hide the others.
- **"Needs attention" dashboard queues.** New `internal/attention` + `GET /api/attention`
  computes six queues (supported Critical/High awaiting review; new supported Critical/High
  vs a comparable baseline, with an explicit no-baseline note; unresolved needing review or
  evidence; regressions; incomplete scans + failed/missing artifacts; applications not
  scanned within an editable threshold defaulting to 7 days). Counts are deduplicated by
  stable identity so a recurring finding is counted once, each queue links to the matching
  filtered destination, and unknown data is reported honestly rather than as zero. The
  endpoint is **separate from `/api/stats`** so a queue failure never blanks the preserved
  dashboard, and queue filters never change the stats population. A dashboard-preservation
  golden test locks the feature-008 metric set (incl. whole-number average findings and the
  zero-scan clean state) as a regression baseline.
- **Contextual AI (finding-scoped).** New `internal/assist` + `POST /api/findings/{occ}/assist`,
  `GET .../assist?action=`, `POST .../assist/cancel` run one bounded action per finding
  (explain flow / find mitigations / challenge / draft test / propose fix). Each call goes to
  the operator-configured provider with **no silent fallback** (a missing/unknown provider is
  an explicit error), runs with **no tools** so it can never execute target code, install
  dependencies, or touch the working tree, and treats the finding data as untrusted input.
  Results carry real provider/model provenance, are labeled generated-analysis distinct from
  scan evidence, mark draft actions as non-executed artifacts, persist under `~/.vhlocal/assist/`,
  and are not resubmitted when revisited with the same request id. Failures and cancellation
  are explicit.
- Offline Go tests cover identity/index/queue, the review store (rationale/history/conflict/
  evidence-change), saved views, the evidence viewer (revision match/mismatch/dirty/path
  containment), comparison (complete vs partial coverage, no-baseline), the status axes, the
  validated manifest, the attention queues (count-matches-destination, dedup, no-baseline,
  staleness threshold, independence from stats), the dashboard-preservation baseline, and the
  contextual-AI path (all five actions, failure, cancellation, provenance, no-tools,
  no-resubmit) via the in-repo fake provider — plus all new endpoints. No live model, no Python.

## 2026-09-22 — Applications & Ledger: Table/List view toggle (009)

Served-UI (`vhlocal/web/index.html`) change only; no Go, data, metrics, delete
semantics, or scan behavior changed.

- **Reports-style Table/List toggle on Applications and Ledger.** Each view now has
  the same segmented Tiles/Table control as Reports, remembering the choice per view
  (`vhlocal.apps.view`, `vhlocal.ledger.view`, default Tiles) and never re-fetching on
  a switch. The Applications table shows name, repository, scans, latest severity, last
  scan, threat/SBOM, and open findings; the Ledger table shows application/target,
  tracked total, open, runs, and last updated — every column sortable (click to sort,
  again to reverse), mirroring the Reports table.
- **Replaces the previous sprint's fixed single-column list**, not the delete: the
  feature-008 per-row Delete is retained in both layouts behind the same confirmation,
  with unchanged semantics (forget an application keeping its reports; clear a ledger
  keeping reports). Empty and error states stay distinct in both modes.
- React (`web-react/`) is intentionally out of scope — its Reports page has no view
  toggle to mirror. The Go suite remains green; browser confirmation is operator-owned.
  No Python executed.

## 2026-09-22 — Dashboard metrics & application/ledger management (008)

Operator-facing fixes on the served UI, all computed from data the tool already
records (no new scan behavior).

- **Dashboard metrics populate.** The stats aggregate now returns tokens used,
  average tokens/scan (over runs that recorded usage), and total/average scan time
  from each run's `scan_meta.json`, and reports real per-model tokens instead of a
  hardcoded zero. Average vulnerabilities/scan is a whole number. Zero scans render a
  clean zero state (no NaN/divide-by-zero).
- **No phantom applications.** Restored the report-directory guard: a directory is a
  report only if its name matches the results pattern or it holds a recognized
  deliverable. Stray subdirectories no longer become empty applications, and none
  reappear on restart; report-only discovery is preserved and nothing on disk is
  deleted.
- **Applications & ledgers: list + delete.** Both views render as a list with a
  per-row delete behind a confirmation. Deleting an application forgets it (reports
  kept; re-scan restores it); deleting a ledger removes only its tracking data.
- Offline tests cover the metric aggregation, the report-dir guard, phantom
  exclusion, and preservation; browser confirmation of the list/delete views is
  operator-owned. No Python executed.

## 2026-09-17 — Application completeness: apps, truthful status, material access (007, in progress)

Restoring the operator-facing scan-to-report workflow (feature 007). This entry
covers the first backend slice; UI wiring and verification/reproduction/report work
remain (see `specs/007-application-completeness/tasks.md`).

- **Applications aggregate their real history.** `/api/applications` and
  `/api/applications/{slug}` now return the discovery union (registry ∪ reports ∪
  ledgers, minus forgotten) with the enriched summary/detail the UI expects —
  scan counts/history, latest outcome, supported/open counts, severity/coverage,
  and threat/SBOM availability. Registration no longer requires the ledger, so
  ledger-disabled scans are discoverable. `open_findings`/`ledger_total` are null
  (not 0) when there is no ledger.
- **Status tells the truth.** The scans API now carries the three engine axes
  (execution/coverage/validation) and per-phase outcomes derived from validated
  engine facts, distinct from the queue `status` — a partial run is no longer
  indistinguishable from a complete one at the API.
- **Threat model & SBOM are honestly stated.** Explicit availability states
  (not_requested / available / missing / unreadable / malformed / generation_failed)
  for threat model and SBOM on the report record and scan view; the SBOM write
  error is surfaced as a degraded reason instead of being discarded.
- Existing history/reports/registry/tracking preserved; prior audit protections
  untouched; all checks offline (no Python executed).

Later increments in this feature (US1/US3 UI, US5, US6, US7):

- **Scans & status UI**: `usePoll` distinguishes loading/error/empty so a failed
  `/api/scans` no longer reads as "No scans yet"; the React and legacy step trackers
  render per-phase state from validated `phase_outcomes`, never mapping a `done`
  queue status to "all steps complete"; a finished scan links to its report.
- **Verification & reproduction recovery**: evidence-backed authorization/logic
  verdicts are accepted without an injection-style syntactic sink (block only on a
  source FAIL); per-candidate session outcomes are recorded and the "no decision"
  reason names its cause + attempt/failure counts; reproduction runs a bounded
  per-candidate authoring+validation loop (repair → register or explicit model
  deferral), with exhaustion/silence left as a missing disposition (never a
  fabricated pass).
- **Useful reports**: deterministic report leads with supported findings and their
  full source-grounded review detail (attacker control, preconditions, defenses,
  impact, rationale, evidence, reproduction), separates rejected/unresolved, links
  threat/SBOM/coverage/sweep, and never presents a candidate total as a confirmed
  count.
- **Honest options**: unsupported scan options are rejected explicitly; `app_name`
  and `max_budget_usd` are now honored (the latter activates the hunt budget cap);
  the report surfaces requested-vs-actual partitions and documents that
  `max_partitions` caps the model plan, not the total.

## 2026-09-16 — Audit fixes for scanner completion and evidence

- Phase 3 now receives the reproduction contract and writes an artifact manifest.
  Empty/missing manifests are validated before status and report publication;
  supported candidates require authored material or a reasoned deferral. Model
  output cannot overwrite the harness's assignment table or sweep.
- Phase 3d enumerates source-pattern leads deterministically. Phase 4 renders the
  canonical report; README uses the same content as SCAN_REPORT.md.
- Supported and rejected verification require complete reasoning, a matching
  manifest revision and exact source evidence covering the candidate. Symlink
  escapes are rejected in evidence, corroboration and artifact reads.
- Candidate identities retain lexical Python owners and repeated-statement
  occurrences; consolidation preserves distinct canonical candidates. Ambiguous
  or non-Python locations are kept conservatively instead of merging by prose.
- Empty sample merges no longer masquerade as hunt output. The harness records
  planned hunt files in `hunt_execution.json` and requires every deliverable for
  completion/resume. Missing verification decisions keep Phase 2b incomplete.
- Verification decisions are checkpointed per candidate. Upstream reruns
  invalidate downstream completion; regeneration refreshes verification,
  artifact errors and saved metadata rather than preserving stale success.
- Added regression tests for the audit failures, a full offline artifact pipeline,
  and independently exported Python-reference contract expectations. The older
  Go-derived golden remains a regression snapshot, not proof of full parity.

## 2026-09-16 — Go-only parity-behavior gate (006 US2)

A standing, offline regression gate pins the scanner's semantic behavior to the
Python reference methodology on the shared `testdata/vulnapp` fixture — **no Ollama,
no Python** (the operator remains the final parity judge).

- A scripted **transcript** (`tests/parity/transcript/vulnapp.json`) + Go
  `transcriptProvider` drive the engine deterministically through recon → partition
  plan → hunt fan-out → per-candidate verification; an unmatched verify candidate
  errors loudly so the fixture can't silently under-exercise a phase.
- A semantic **projector** reduces a results dir to canonical JSON (dispatch,
  candidates by `norm_id`, dispositions, tiers, coverage, handoffs/artifacts,
  three-axis run status); a **comparator** diffs it against the committed golden and
  names the diverging dimension + candidate. Incidental differences (ordering,
  timestamps, temp paths, raw `CAND-` ids) are normalized away.
- `golden/vulnapp.json` is reference-derived (authored by reviewing each projected
  value against the reference code, not a Python run — see `tests/parity/README.md`).
- Additive-schema guard confirms `scan_meta.json` keeps every declared top-level key
  and serializes the feature-006 fields additively.

## 2026-09-16 — Coverage, artifacts & hunt safety parity (006 US4)

Coverage denominator, artifact validation, and hunt safety controls now track the
reference.

- **Route denominator**: `APIRouter(prefix=…)` / `Blueprint(url_prefix=…)` prefixes
  are resolved onto decorated paths, websocket routes are enumerated (method `WS`),
  and a method-less `@app.route`/`api_route` is labelled `ROUTE` (the reference
  sentinel) rather than assuming `GET` (FR-012).
- **Artifact validation**: `ValidateArtifacts` binds each artifact entry to a
  supported candidate and its on-disk file — flagging unknown/unverified
  candidates, missing dispositions, orphaned/unregistered files, non-canonical
  PoCs, and assertion-less authored tests. It never claims execution. Wired into
  finalize (recorded as `artifact_errors`) without clobbering a real manifest
  (FR-013).
- **Hunt safety**: a canary preflight runs one cheap same-endpoint call before the
  fan-out and aborts on a transport failure (recording `hunt_halted_reason`),
  while a non-transport (tool-parse) quirk proceeds; a budget-cap guard records
  `budget_halted_reason` when spend reaches the ceiling (FR-014).
- Divergence recorded: USD budget accounting is not ported (local Ollama is free,
  so the cap is inert — matching the reference's inert cap for free backends);
  the coverage corpus needed no reconciliation once the denominator matched.

## 2026-09-16 — Verification & publication fidelity (006 US3)

Verdicts and publication tiers now match the Python reference on identical evidence.

- A supported verdict requires the cited evidence to cover the **complete
  containing function** (decorators + defenses), computed by an indentation/`def`
  span scan — a context check can no longer bleed into a neighbouring handler
  (FR-009).
- When the cited location resolves to a route handler, a supported verdict's
  `entry_point` must equal the resolved route guard (`METHOD PATH`); a mismatch
  refuses support (FR-010).
- Class-evidence battery gains **SSTI constant-template refutation** (a constant
  template source is not injectable) and explicit **broken-access-control NA**
  handling (guard-name detection can neither establish nor refute effective
  permissions) (FR-011).
- New distinct **`reviewed`** tier: a finding carrying a validated, source-grounded
  review record ranks above `statically_supported` (FR-011).
- Documented approximations vs the AST-based reference: function span and
  route-handler resolution are heuristic (Go has no Python AST / route end-lines);
  review-record currency is enforced by live-source byte-match rather than a
  git-commit equality check.

## 2026-09-16 — Partition parity: hunt over the model's plan (006 US1)

The hunt now fans out over the model's Phase-1 Subgraph-Partitions plan instead of
one coarse deterministic partition — the biggest live-behavior gap vs the Python
reference.

- Parses the model's partition table; on an unparseable table, performs one
  corrective strict-JSON repartition (a bounded same-endpoint call) before falling
  back to deterministic subsystem partitions or a single whole-repo partition.
- Augments the plan with coverage partitions for enumerated route files it omitted
  and additive threat-model partitions; scope beyond the cap is recorded as
  uncovered (never dropped).
- Records the resolution: `partition_source` (model_table/model_retry/deterministic/
  single_fallback), `partition_fallback`, `partition_parse_error`, `partition_collapsed`,
  `coverage_partitions_added`/`_files_added`, `coverage_uncovered_remaining`,
  `threat_model_partitions`. Each hunt unit's scope carries its concrete routes.

## 2026-09-16 — Honest reporting + verification robustness (parity fixes)

Fixes found by inspecting a live run that produced 11 confirmed findings but was
reported as an empty "incomplete" scan.

- **The report no longer hides findings.** The broken-run banner counted every
  agent (~61) as a "phase" and hardcoded "a zero-finding result" even when findings
  existed. It now reports real requested-vs-completed phases and states the actual
  finding count ("N finding(s) produced, but coverage degraded — partial scan").
- **Coverage reasons no longer flood.** A per-candidate `max_turns`/`tool_repair`
  in a verification session is no longer emitted as a separate run-level coverage
  reason (one per candidate); verification health is summarized once
  ("verification left N candidate(s) unresolved") and reasons are de-duplicated.
- **No duplicate candidates.** The candidate manifest is built only from the merged
  per-unit hunt files (not the per-sample `.sN.md` files) and de-duplicated by
  identity, so candidates are no longer verified twice ("duplicate decisions").
- **Verification survives tool-parse 500s.** A provider tool-call-parse rejection
  during a verification session is now steered and retried within the session's
  budget (parity with the hunt loop), instead of failing the candidate as an
  endpoint outage.

## 2026-09-16 — Scanner parity: truthful coverage & resume (US5 core)

- **Coverage denominator fidelity.** Test files (`test_*.py`, `*_test.py`,
  `conftest.py`, `tests/`) are excluded from the attack-surface denominator, and
  duplicate `(method, path, file)` routes are de-duplicated — the coverage
  percentage now reflects real entry points.
- **Resume counts valid work.** A resumed phase whose deliverable is present and
  valid counts toward effective completion, so a fully-resumed run is no longer
  reported `incomplete`.
- **Per-unit attribution.** `scan_meta.agents[]` records each hunt unit's
  `partition` and `vuln_class` (additive), so partial hunt evidence is attributable.

## 2026-09-16 — Scanner parity: adversarial verification engine (US3)

Phase 2b is now the reference candidate-bound verifier, not a generic summarizer.

- **Candidate manifest before verification.** Built from the hunt output with a
  line-shift/prose-insensitive identity, written before 2b as the falsification
  spine.
- **Per-candidate evidence sessions.** Each candidate gets a fresh session exposing
  `capture_evidence` (registers immutable, source-matched evidence) and
  `submit_verification` (supported/rejected/unresolved) alongside read-only
  Read/Grep. Every candidate receives a disposition; a session that stops without
  submitting, exhausts its budget, or hits an endpoint failure leaves the candidate
  explicitly unresolved — never confirmed.
- **Fail-closed reconciliation.** A "supported" verdict requires cited evidence
  covering the location AND source corroboration; "rejected" requires evidence; a
  missing/duplicate/malformed decision stays unresolved and marks the run
  incomplete. Writes `verification_decisions.json`, `verification_metrics.json`,
  `verification_reconciliation.json`, the disposition table (`phase2b_output.md`),
  and the supported-only `phase2b_handoff.md` (now consumed by phase 3).
- **Verification precedence.** A verification disposition overrides the quality
  battery: a rejected/unresolved candidate is never statically supported even if a
  sink is present; findings are derived from the reconciled manifest, so a
  zero-survivor pass publishes zero supported findings and never resurrects raw hunt
  output (completes FR-C1/FR-C2). Phase 2b and its handoff are now harness-owned.
- Documented approximations (plan Complexity #2): heuristic candidate identity (no
  Go AST), evidence-covers-location in place of a parsed function span, no authz
  route-guard entry-point match.

## 2026-09-16 — Scanner parity: file tools, hunt methodology, source-grounded support

Increments 2–4 of `specs/005-scanner-parity-evidence/` (US1, US2 core, US4 evidence
gate). Directly addresses the zero-detection failed run.

- **Usable file tools (US1).** `Read` now pages via offset/limit and returns
  line-numbered content with a continuation hint (reliable file:line citation);
  `Glob` uses fnmatch semantics (`**` recursion) and returns absolute, round-trippable
  paths resolved against the repo root; `Grep` supports path/glob/ignore_case/
  files_with_matches with skip-dir excludes and absolute paths; writes to
  harness-owned artifacts are refused and symlinked results parents resolve
  correctly. A missing methodology/prompt file is now an explicit configuration
  failure (surfaced + recorded), never a placeholder agent run. Agent tasks are
  grounded with the absolute repo path, writable location, assigned scope, and exact
  deliverable.
- **Harness-controlled hunt (US2).** Phase 2 runs the reference methodology: the
  INJ/NAV/LOG class split with the shared + per-class prompts (or a combined mode),
  a sink-driven pass, a conditional IaC pass (only when IaC is present), and
  `hunt_samples` repeated samples merged by candidate identity with vote provenance
  (`hunt_votes.json`). `--phase2-mode` is a real option and the run manifest records
  the mode actually executed. A partition cap now records uncovered scope instead of
  silently dropping it, and a circuit breaker halts a failing hunt with a recorded
  reason. (Deferred, documented: consuming the model's Phase-1 partition table +
  coverage/threat-model augmentation; canary/budget.)
- **Source-grounded support (US4).** A finding is "statically supported" only when
  the cited source actually contains a matching CWE-family sink — never a prose
  data-flow arrow / text field alone; logic/authorization classes and classes the
  checker has no rule for retain uncertainty. A per-class veto battery further
  refutes support where a sink alone is insufficient: XSS reflected into a JSON
  response, weak randomness with no security consumer, and safe (non-credentialed-
  wildcard) CORS. (Deferred, documented: the distinct `reviewed` tier, full
  artifact-manifest validation.)
- Additive schema only; feature-004 behaviors/tests preserved; every change ships an
  offline regression test. Live validation remains operator-owned.

## 2026-09-16 — Evidence-integrity hardening (scanner parity, increment 1)

First slice of `specs/005-scanner-parity-evidence/` — the correctness-critical
Evidence-Integrity fixes (the larger parity work — file tools, hunt orchestration,
structured verification, publication, differential parity — is in progress).

- **No raw-hunt resurrection (FR-C1).** A verification pass that confirms nothing
  (absent/empty/unparseable `phase2b_output.md`) now yields zero supported
  findings; the raw `results/*.md` hunt output is never resurrected. (Full
  evidence-gated promotion lands with the verification story.)
- **Artifact manifest preserved (FR-C3).** `finalize` and `vhlocal report`
  regeneration no longer overwrite a real `artifact_manifest.json` with `[]`.
- **Produced is truthful (FR-C4).** An agent is "produced" only when its declared
  deliverable exists and is non-empty; a write to an empty or unrelated file no
  longer counts or suppresses the write nudge.
- **Cancellation is distinct (FR-C5).** A cancelled run reports
  `execution_status=cancelled` (not `aborted`), and a cancelled in-flight agent is
  no longer mislabeled an endpoint failure.
- **Deterministic regeneration (FR-C6).** The real provider backend and
  endpoint-failure degradation reasons are persisted (additive `scan_meta` fields
  `backend`, `endpoint_failures`) and preserved on regeneration — no fabricated
  `ollama` attribution, no lost reasons.
- Additive schema only; feature-004 behaviors/tests preserved; every fix has an
  offline regression test that fails before it. Live validation is operator-owned.

## 2026-09-15 — Provider tool-call-parse recovery, per-phase degradation (Go)

Fixes a live run that aborted at phase 2b on an Ollama HTTP 500 "error parsing
tool call" (the model interleaved prose with tool-call JSON; the provider rejected
the blob). The harness had treated that 500 as a fatal transport error, retried
the identical request, then discarded the whole run. See
`specs/004-ollama-toolparse-repair/`.

- **Provider tool-call-parse recovery.** A provider tool-call-parse rejection is
  now classified distinctly from a real outage (`TransportError.Kind`), the
  model's intended action is extracted from the error, and it is routed into the
  existing bounded fresh-context repair on the *same* endpoint — never a naive
  replay of the failing request, never a provider/model switch. Applies to the
  Ollama and OpenAI-compatible backends.
- **Per-phase degradation, not whole-run abort.** An unrecoverable endpoint
  failure in one phase now degrades that phase (an explicit
  `coverage_degraded_reason`) and the scan continues to the remaining phases and
  always finalizes the artifact set. `scan_meta.aborted` is reserved for
  cancellation; a systemic outage (all phases fail) is reported as an incomplete,
  lifecycle-suppressed run — never clean.
- **Deliverable-aware completion.** An agent that stops before writing its
  declared deliverable gets one final write nudge (complementing the near-
  `max_turns` nudge); a phase counts produced only if the file lands.
- No artifact/API/status-field-name changes (`TransportError` is not serialized;
  the new degradation reasons reuse `coverage_degraded_reasons`); every fix has an
  offline regression test that fails pre-fix.

## 2026-09-15 — Scan-run reliability & honesty remediations (Go)

Fixes surfaced by a real failed run (recon/verify/report died after 2 turns on
malformed tool calls; the hunt ran to max_turns writing nothing; the honesty
layers then misreported). See `specs/003-scan-run-remediations/`.

- **Agent resilience.** Malformed tool-call JSON now triggers a bounded repair in
  a minimal fresh context on the *same* endpoint (no silent fallback); a single
  malformed turn no longer kills an agent. Recoverable tool errors (missing/
  renamed arg, aliasable tool name) return a corrective result and the agent
  continues. Long sessions are context-pruned so prompts stay bounded (the
  4M-prompt-token blow-up is gone). Fan-out agents are nudged to write before
  `max_turns`.
- **Honest degraded reporting.** Cross-run lifecycle reconciliation is suppressed
  on unreliable runs (no more false "all prior findings fixed" dump); coverage
  marks a route `reviewed_no_issue` only when it was actually hunted; failed
  agents and a missing recon map become explicit `coverage_degraded_reasons`; and
  a broken zero-finding run is now visibly distinct from a clean one.
- **Provenance.** `usage.calls` now counts real model calls (turns + repairs),
  not agents; each `scan_meta.agents[]` entry carries its own prompt/completion
  tokens.
- **Diagnosability.** The report gains a per-phase outcome table and an
  "Incomplete run" banner listing why a run under-delivered.
- No artifact/API/schema changes (per-agent token fields are additive to
  `agents[]`); every fix has an offline regression test.

## 2026-09-15 — Go port (interface parity)

- **Reimplemented on Go** as a single self-contained binary (`vhlocal`) with no
  runtime prerequisite; the bundled scanning methodology (`skill/`) and browser
  UI are embedded via `go:embed`. See `specs/002-golang-port/`.
- **Interface preserved.** Every entry point is now a subcommand of one binary:
  `python3 -m vhlocal.<module>` → `vhlocal <module>` (`run`, `server`, `report`,
  `logs`, `sbom`, `bench`, `batch`, `authz`, `membank`, `policy-bench`). Flags,
  the HTTP/JSON API + SSE, the result-artifact set and formats, the `VHLOCAL_*`
  env vars, and the honesty/safety guarantees are unchanged.
- **New capabilities:** self-contained single-binary distribution and
  cross-platform release binaries (`make release` → linux/macOS, amd64/arm64).
- **Governance:** constitution amended to v1.1.0 (Go runtime + small reviewed
  dependency budget as the stdlib-only analog); offline test gate is now
  `go test ./...`.
- **Migration:** the Python tree remains during migration and will be retired
  once the differential parity suite (`tests/parity/`) is green against it; the
  Go binary is the delivered product. It reads artifacts, ledgers, and job state
  written by the Python implementation without loss.
- **Known gaps in this port:** `/api/models` currently lists Ollama models only
  (OpenAI/OpenRouter return an empty set); `DELETE /api/ledgers/{slug}/finding`
  is not yet implemented; `/api/stats` omits token aggregation; the `authz` map
  uses a file-level auth heuristic; the verification set is a minimal port
  (candidate/artifact manifests only — no falsification-session decisions).

## 2026-08-27 — App Intel by application, reports multi-delete; Phase 1t validated

- **App Intel is now organized by application, not a scan dropdown.** Scanning the
  same folder is the same app, so reports are grouped by target repo; the tab shows
  a list of applications (with Threat model / SBOM badges + scan count), and
  clicking one opens that application's most recent threat model + SBOM. The report
  listing now carries `has_sbom` / `has_threat_model` so grouping needs no per-file
  probing.
- **Reports table: checkbox multi-select + bulk delete.** Per-row and select-all
  checkboxes, a selection bar, and a guarded "Delete selected (N)".
- **Phase 1t validated end-to-end.** A recon+threat-model run on gvisor (2 min,
  local gpt-oss) correctly characterized it as a *container/OS sandbox runtime*,
  produced a data-flow diagram and PASTA threats, and emitted hunt targets for the
  real sandbox surface — `pkg/sentry/platform/systrap` (syscall processing),
  `runsc/cmd/exec.go`, the admission webhook — exactly what recon's web-only
  enumeration missed. (The prompt must live in the skill dir the scan uses; it is
  in `skill/phases/` — point `--skill-dir` there.)

## 2026-08-27 — Application Intelligence tab + coverage-honesty fix

### Application Intelligence tab
- New top-level **App Intel** tab. Pick a scan; view its intelligence in two
  sub-tabs: **SBOM** (rendered from `sbom.cdx.json` — component table + ecosystem
  summary + CycloneDX download) and **Threat model (PASTA)** (the `threat_model.md`
  rendered, including the data-flow diagram). Reuses the existing report-file
  endpoint and client markdown renderer — no new backend. (Live Mermaid diagram
  rendering is a follow-up; the DFD currently renders as a labeled source block.)

### Coverage-honesty fix — a shallow run can no longer report "complete"
- The gvisor scan enumerated **0 entry points across 2,970 source files** yet
  reported `coverage_status: complete`. `compute_run_status` now flags two
  deterministic shallowness signals as **degraded**, regardless of `max_partitions`:
  recon enumerating **no entry points** over a non-trivial codebase, and a large
  codebase (150+ source files) hunted in a **single partition**. The reasons name
  the file count and point at scoping / the PASTA threat model as the fix.
- Suppressed when the threat model already added partitions. 6 new tests.

## 2026-08-27 — Phase 1t: PASTA threat model (opt-in) — coverage fix for non-web targets

- **Root problem it fixes:** recon's attack-surface enumeration is web/RPC-shaped
  (routes → inputs → sinks), so on an unusual target it under-covers. A gvisor scan
  collapsed to one partition (the docs website) and missed the entire sandbox —
  its real attack surface (syscall handlers, packet/9P parsers) was never
  partitioned or hunted, and the run still reported "complete."
- **New Phase 1t (post-recon, pre-hunt), gated on `ScanSpec.threat_model`.** Follows
  **PASTA**: characterize the app + its **archetype**, threat-model *that class* of
  software (a sandbox → guest→host escape; a parser → memory corruption; a crypto
  lib → side channels), produce a **data-flow diagram** (Mermaid) with trust
  boundaries, and emit a `Hunt targets` block mapping threats → concrete code paths.
- **Purely additive to the hunt.** `augment_partitions_from_threat_model` appends a
  partition for each threat target whose code recon didn't already cover
  (existence-checked, priority-ordered, bounded). Web apps are unaffected; unusual
  targets *gain* the syscall/parser partitions they were missing. Also generates the
  SBOM (PASTA Stage II) and feeds the report's Application Intelligence.
- UI: **Build threat model (PASTA)** toggle. CLI: `--threat-model`. Prompt in
  `skill/phases/phase1t_threat_model.md`. 13 new tests.
- Report rendering of the threat model + DFD is the next step (the model + partition
  drive land first).

## 2026-08-26 — Application Intelligence, findings quality, ledger view

Development thread paired with the web-UX effort. All changes are static-only,
stdlib-only (Python 3.9), and covered by tests (`python3 -m unittest discover -s tests`).

### Application Intelligence — SBOM
- **CycloneDX 1.5 Software Bill of Materials**, generated deterministically from
  the target's dependency manifests — no model, no network (`vhlocal/sbom.py`).
  Parses Python (`requirements*.txt`, `pyproject.toml` — PEP 621 + Poetry), npm
  (`package.json`), Go (`go.mod`), Maven (`pom.xml`), Ruby (`Gemfile.lock`),
  Rust (`Cargo.toml`), and PHP (`composer.json`); skips vendored trees; dedups;
  deterministic ordering. Runs standalone: `python -m vhlocal.sbom <repo>`.
- Written per run as `sbom.cdx.json`, surfaced as an **Application Intelligence ›
  Software Bill of Materials** section in the report, an
  `application_intelligence.sbom` block in `findings.json`, and in the UI a
  **SBOM (CycloneDX) ↓** download plus a `📦 N deps` health chip.
- First piece of a planned Application Intelligence area (SBOM → STRIDE threat
  model → architecture diagram → LLM enrichment).

### Findings quality — deterministic hunt-evidence parser
- Reports no longer collapse when the model-authored Phase 4 is thin. The report
  now parses the **raw per-partition hunt evidence** (`results/sg-*.md`) directly
  and makes it authoritative when it yields substantially more *well-formed*
  findings (real CWE + descriptive title) than the Phase 4 / Phase 2b sources.
- Robust to the class agents' format variance: mixed heading styles
  (`### [VULN-001]`, `## 3. VULN-001 —`, `### NAV-01 — … — HIGH`), **header-aware**
  Summary-table parsing (column order differs between files — CWE/Severity swap),
  severity/CWE prefixes baked into title cells, and cross-reference index rows
  that merge into their write-up.
- Impact: on a real run this turned an 11-fragment report (verdict-table cells as
  titles, missing CWEs, wrong locations) into 32 clean, deduplicated findings.

### Vulnerability Ledger view
- New top-level **Ledger** tab: a per-application memory of findings across every
  scan, aligned to the analyzed application. Lists each app with
  tracked / open / fixed / regressed / reliable counts and a severity breakdown;
  selecting one shows the full finding history — title, CWE, location, status,
  cross-run confirmation count (with a cross-model-family marker), and confidence.
- Backend: `membank.list_ledgers()` / `load_ledger(slug)`; server endpoints
  `GET /api/ledgers` and `/api/ledgers/<slug>`. Path-traversal safe (slug matched
  against the enumerated directory, never joined to a path).

### CLI parity with the web UI
- `vhlocal/run.py` now exposes every scan knob the UI has: `--hunt-samples`,
  `--iac-lens/--no-iac-lens`, `--remediate`, `--redact`, `--ledger`,
  `--max-budget-usd`, `--max-output-tokens`, `--backend openrouter`, per-role
  models (`--recon-*`, `--verify-*`, `--reproduce-*`), and `--profile`, with
  correct default < profile < explicit-flag precedence.

## Earlier in this thread (already pushed)
- Visa-harness capability tranches 1–5 (SARIF, run manifest, redaction, scan
  health, multi-sample voting, exploit chains, memory bank, remediation DTOs,
  profiles, batch) + prompt transparency.
- Location/CWE backfill from hunt evidence (unblocks dedup/votes/chains);
  multi-sample near-duplicate merge.
- Retry transient paid-backend resets; opt-in budget cap.
- Skill prompts mirrored into `skill/` so the repo is self-contained.
