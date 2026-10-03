# Feature Specification: Complete, usable scan-to-report workflows

**Feature Branch**: `007-application-completeness`

**Created**: 2026-09-17

**Status**: Draft

**Input**: User description: "Restore complete, usable scan-to-report workflows in vhlocal-go and close the application integration gaps with the Python reference in ../vhlocal." (full brief and handoff evidence in `docs/engineering/2026-09-17-handoff.md` and `docs/engineering/2026-09-17-evidence.json`)

## Overview

A live scan surfaced that vhlocal's scanner-correctness protections are in place but the surrounding **application** is unusable end to end: the operator cannot see their scans or applications, cannot open the threat model or SBOM that were generated, sees a scan reported as fully "done" while the saved report says it was only partial, and reads a consolidated report that under-serves review even when evidence exists. This feature restores the operator-facing scan-to-report workflow and closes the application-integration gaps against the established behavior of the reference tool, **without** rolling back the scanner-correctness protections and **without** claiming full scanner parity.

Scope discipline: this feature restores **data visibility, truthful status, artifact access, bounded verification/reproduction recovery, and report usefulness**. It is not a UI redesign, not a cosmetic pass, and not a re-litigation of detection accuracy (which remains an operator-owned, live empirical question).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Scans are visible and reliable (Priority: P1)

An operator opens the tool and sees every scan — existing and newly queued, running, completed, partial, failed, cancelled, or interrupted — can select one, follow its progress and evidence, and reach its report. The list survives a service restart and a page refresh. Loading, empty, disconnected, malformed-response, and error states are visibly distinct; a failure never appears as an empty successful list or an endless spinner.

**Why this priority**: This is the operator's front door. At handoff the backend held 8 scans and 8 reports, yet the operator's Scans view was blank — the most immediate blocker to using the tool at all.

**Independent Test**: Seed persisted scan history, open each supported operator surface, and confirm the scans render with correct states; then force a malformed/disconnected response and confirm the view shows a distinguishable error rather than "no scans." Repeat after refresh and restart.

**Acceptance Scenarios**:

1. **Given** persisted history of scans in mixed states (running, done, partial, failed, cancelled) including older/legacy-shaped records, **When** the operator opens the Scans view, **Then** every scan is listed with its correct state and none crashes the page.
2. **Given** the service is restarted and the page refreshed, **When** the operator returns to the Scans view, **Then** the same history is still present and selectable.
3. **Given** the scan-list request fails or returns a malformed body, **When** the view renders, **Then** the operator sees a distinguishable error/disconnected state — not an empty "no scans yet" and not an indefinite loading state.
4. **Given** a scan is selected, **When** the operator inspects it, **Then** they can follow its progress and reach its report and evidence.
5. **Given** live progress updates arrive (polling or event stream) and the connection drops and reconnects, **When** the view updates, **Then** state stays coherent with no duplicated scans and no false "complete."

---

### User Story 2 - Applications aggregate their real history and artifacts (Priority: P1)

Every analyzed repository is discoverable as an application — including scans run with vulnerability tracking (ledger) disabled and reports created before this fix. Each application shows the information an operator needs to navigate its history: name, repository, scan counts and history, the latest report with its time and outcome, supported/unresolved counts, severity and coverage summaries, optional tracking information, and whether threat-model and SBOM material is available.

**Why this priority**: At handoff the applications list/detail returned only bare registry fields (name, repo, slug, created, updated) — omitting all history and intelligence the operator needs — and a repository only became an application when tracking was enabled, so this run's application was effectively invisible.

**Independent Test**: Seed at least two applications (one with tracking disabled, one with multiple reports including an older one), open the Applications views, and confirm each application is discoverable and its summary/detail expose the aggregated history and artifact-availability fields.

**Acceptance Scenarios**:

1. **Given** a repository scanned with tracking disabled, **When** the operator opens Applications, **Then** that repository is still discoverable as an application.
2. **Given** an application with several reports including one created before this fix, **When** the operator opens its detail, **Then** the full scan history and each report's outcome are shown.
3. **Given** an application whose latest scan produced threat/SBOM material, **When** the operator views its summary, **Then** the availability of that material is indicated.
4. **Given** optional aggregated data (e.g., tracking ledger) is absent, **When** the detail renders, **Then** history and existing artifacts still display rather than being suppressed.
5. **Given** an application was previously named or hidden/forgotten, **When** aggregation runs, **Then** its name and forgotten state and stable repository identity are preserved.

---

### User Story 3 - Status reflects the actual work done (Priority: P1)

The operator always sees status that matches reality. Queue termination, engine execution status, coverage status, and validation mode are reported as distinct facts. Per-phase progress reflects validated engine outcomes, not a job's "done" flag or the current phase index. A partial run is never shown as "all steps complete," and the reason each incomplete phase stopped is surfaced while its useful partial results remain accessible.

**Why this priority**: At handoff a job was `done` with no error while the saved report was `partial`/`degraded` with phases 2b and 3 unfinished, and the step tracker rendered every step complete — actively misleading the operator, which violates the tool's evidence-integrity and orthogonal-status principles.

**Independent Test**: Load a fixture representing the saved partial run and confirm phases 2b and 3 display as incomplete with reasons, the three status axes are shown distinctly, and no surface labels the run fully complete.

**Acceptance Scenarios**:

1. **Given** a scan whose queue entry terminated without a fatal error but whose engine finished only some phases, **When** the operator views its status, **Then** the incomplete phases are shown as incomplete with reasons, not as complete.
2. **Given** the same scan, **When** its status is displayed, **Then** queue state, execution status, coverage status, and validation mode are each shown as separate facts and none is derived from another.
3. **Given** a partial run with useful intermediate results, **When** the operator inspects it, **Then** those results remain accessible rather than being discarded or hidden behind an error.
4. **Given** distinct outcomes (explicit unresolved review, missing decision, zero candidates after a valid hunt, failed hunt, authored artifact, deferred artifact, executed test), **When** they are reported, **Then** each is represented distinctly and not collapsed together.
5. **Given** a scan is restarted, resumed, or its report regenerated, **When** status is recomputed, **Then** those distinctions are preserved and stale dependent results are invalidated where appropriate.

---

### User Story 4 - Threat model, SBOM, and generated material are accessible (Priority: P1)

When threat-model or SBOM generation was selected and produced material, the operator can find, open, and download it from the scan, report, and application views — including for scans that already ran, without re-scanning. The tool distinguishes the states of this material — not requested, pending, available, generation-failed, missing, unreadable, malformed — and surfaces generation/parse failures rather than hiding them.

**Why this priority**: At handoff both files existed on disk and returned successfully from the API, yet were invisible in the operator's workflow — the intelligence the operator paid hours of scan time for was unreachable.

**Independent Test**: With fixtures covering each material state, confirm available material is openable/downloadable from every relevant view (including pre-existing on-disk files with no re-scan), and each non-available state is shown explicitly.

**Acceptance Scenarios**:

1. **Given** a completed scan whose threat model and SBOM exist on disk, **When** the operator opens the scan/report/application view, **Then** both are listed and can be opened and downloaded.
2. **Given** a scan that did not request this material, **When** the operator views it, **Then** the material is shown as "not requested" rather than as missing or broken.
3. **Given** generation was requested but failed, or the file is missing/unreadable/malformed, **When** the operator views it, **Then** that specific state is shown explicitly.
4. **Given** another phase failed after this material was generated, **When** the run is reported, **Then** the generated material is still accessible and not silently dropped.
5. **Given** pre-existing scans created before this fix, **When** the operator browses them, **Then** their on-disk material becomes discoverable without re-running the scan and without altering the original evidence.

---

### User Story 5 - Verification and reproduction recover from actionable failures (Priority: P1)

Verification and reproduction handle recoverable failures within bounded, measured limits instead of leaving most candidates undecided. Recoverable tool/schema/validation problems get bounded corrective feedback and retry; accepted work is preserved; and when the allotted work cannot reach a conclusion, the candidate is reported unresolved with a useful reason. Authorization/logic candidates can be reviewed on evidence without requiring an injection-style syntactic sink where the reference tool does not. Reproduction material is authored only for supported candidates, each of which ends with registered authored material or a specific deferral.

**Why this priority**: At handoff, of 140 candidates only 10 were supported and 123 unresolved, with 98 missing decisions and 72 tool-repair + 26 max-turns session exits — verification effectively did not complete, and 6 of the authored test artifacts failed structural validation.

**Independent Test**: With controlled model fixtures, demonstrate recovery from at least one rejected verification submission and one invalid reproduction submission; confirm exhausted recovery yields a bounded, explained unresolved/incomplete outcome with attempt/failure counts, and that supported-only reproduction produces registered material or an explicit deferral.

**Acceptance Scenarios**:

1. **Given** a verification submission that fails a recoverable validation/tool check, **When** the session runs within its bounded budget, **Then** the candidate receives actionable feedback and a retry, and accepted work is preserved.
2. **Given** recovery is exhausted, **When** the candidate is reconciled, **Then** it is reported unresolved with a useful reason and the attempt/failure counts are recorded — never fabricated as supported.
3. **Given** an authorization/logic candidate with substantive evidence but no injection-style syntactic sink, **When** it is reviewed, **Then** it can be assessed on that evidence rather than being auto-refused for lacking a sink, while attacker-control/precondition/defense/impact/revision/exact-evidence requirements remain enforced.
4. **Given** the set of supported candidates, **When** reproduction runs, **Then** only supported candidates are assigned, and each ends with registered authored material or a specific deferral.
5. **Given** an invalid reproduction submission (wrong candidate/location, missing file, bad header), **When** it is validated, **Then** it receives bounded corrective feedback, candidate IDs stay stable, remaining failures are explained, and no material is labeled executed.

---

### User Story 6 - Reports are useful to a reviewer (Priority: P2)

The consolidated report (Markdown, HTML, and the machine-readable outcome) is coherent and evidence-based. It states scope and run/coverage/phase limitations, leads with a clear supported-findings summary, and keeps rejected/unresolved candidates in clearly separate sections. Each supported finding presents its source location and evidence, entry point, attacker control and flow, preconditions, reviewed defenses, security impact, rationale, remediation, and the status/links for its reproduction material or deferral — with missing information made explicit. The report never presents candidate totals as confirmed-vulnerability totals or syntactic leads as confirmed findings, and offers navigation to threat analysis, SBOM, coverage, and sweep leads.

**Why this priority**: Deterministic reporting made the report honest but sparse; the 90KB report listed 140 candidates with only 10 supported, and a short field list per finding under-serves review. This is high-value but ranks below restoring visibility and truthful status.

**Independent Test**: Generate the report from canonical evidence for a representative supported finding and confirm all review detail is present (with explicit unknowns), unsupported cases are clearly separated, totals are not conflated, and a reviewer judges it usable — assessed against the reference tool's known report content, not by file length.

**Acceptance Scenarios**:

1. **Given** a run with supported and unsupported candidates, **When** the report renders, **Then** supported findings lead in their own summary and rejected/unresolved candidates appear in clearly identified separate sections.
2. **Given** a supported finding, **When** it is presented, **Then** it includes location + evidence, entry point, attacker control and flow, preconditions, reviewed defenses, impact, rationale, remediation, and reproduction status/links, with any missing item marked explicit.
3. **Given** syntactic sweep leads and a raw candidate count, **When** the report renders, **Then** leads are not shown as confirmed findings and the candidate total is not presented as a confirmed-vulnerability total.
4. **Given** threat/SBOM/coverage/sweep material exists, **When** the operator reads the report, **Then** it provides navigation to that material.
5. **Given** the same canonical evidence, **When** the Markdown, HTML, and machine-readable outputs are compared, **Then** they agree on findings, outcomes, and counts.

---

### User Story 7 - Supported options and work limits behave honestly (Priority: P2)

Every operator-supplied option is honored or explicitly rejected — never silently ignored — and the effective configuration and the work it produced are visible. This includes threat model, tracking, role model/provider selection, hunt sampling, and partition/coverage behavior. The relationship between a requested partition cap and the partitions actually run is made explicit, and the resulting workload and any bounded recovery are visible so a run cannot silently balloon into hours of retries.

**Why this priority**: A request for `max_partitions=8` produced 24 partitions and 217 phase-2 agents over ~2h40m and 4,353 model calls; the operator needs to understand and trust what their settings do. Important, but below restoring visibility and truthful status.

**Independent Test**: For each supported option, trace a request through to the effective configuration and persisted metadata and confirm it was honored or explicitly rejected; confirm the requested-vs-actual partition relationship and the resulting workload are visible.

**Acceptance Scenarios**:

1. **Given** an operator sets a supported option, **When** the scan runs, **Then** the effective configuration reflects it and it is recorded in run metadata.
2. **Given** an operator supplies an unsupported or conflicting option, **When** the request is processed, **Then** it is explicitly rejected rather than silently ignored.
3. **Given** a requested partition cap, **When** the hunt expands coverage beyond it, **Then** the requested value, the actual partition count, and whether the control is a cap or a starting point are visible and explained.
4. **Given** a run in progress, **When** its work grows, **Then** the resulting workload and any bounded recovery are visible so unbounded expansion is not silent.

---

### Edge Cases

- A persisted scan or report from an older schema is present → it must render (or degrade gracefully) without crashing any view.
- The scan-list or application request returns an error, empty body, or malformed data → the operator sees a distinguishable state, never a false "no scans/apps."
- Threat/SBOM was requested but the file is missing, empty, unreadable, or malformed → the specific state is surfaced, not a generic absence.
- A repository has been scanned many times, or the same repository is reachable under more than one path form → it resolves to one stable application identity without duplicates.
- The engine finalizes a partial run and the queue marks the job terminated → no surface reports the run as fully complete.
- Verification/reproduction recovery is exhausted → the outcome is a bounded, explained unresolved/incomplete result with counts, not an inflated success.
- A scan is resumed or regenerated after upstream inputs changed → stale downstream completion is invalidated and not preserved as success.
- Report regeneration runs against saved evidence → it reflects the true dispositions and never resurrects unsupported candidates as supported.

## Requirements *(mandatory)*

### Functional Requirements

**Scan visibility (US1)**

- **FR-001**: The tool MUST present all persisted scans across every state (queued, running, completed, partial, failed, cancelled, interrupted) on the operator's supported surfaces, with each scan's state shown correctly.
- **FR-002**: Scan history MUST persist across service restart and page refresh and remain selectable.
- **FR-003**: Loading, empty, disconnected, malformed-response, and error states MUST be visually distinguishable; a transport or schema failure MUST NOT be rendered as an empty successful list or an indefinite loading state.
- **FR-004**: Previously persisted scan/report shapes MUST NOT crash any view; unknown or missing fields MUST degrade gracefully.
- **FR-005**: Live progress updates (polling and/or event stream) MUST tolerate disconnect/reconnect without duplicating scans or reporting false completion.
- **FR-006**: From a selected scan the operator MUST be able to follow progress and reach that scan's report and evidence.

**Application aggregation (US2)**

- **FR-007**: Every analyzed repository MUST be discoverable as an application regardless of whether vulnerability tracking (ledger) was enabled for its scans.
- **FR-008**: Application summary and detail MUST include the fields the operator needs to navigate history: name, repository, scan counts/history, latest report with time and outcome, supported and unresolved counts, severity and coverage summaries, optional tracking information, and threat/SBOM availability.
- **FR-009**: Application aggregation MUST match the established report/registry/tracking aggregation semantics of the reference tool (derived by reviewing the reference behavior, not by executing it).
- **FR-010**: Aggregation MUST preserve existing application names, hidden/forgotten-application behavior, and a stable repository identity, and MUST NOT overwrite or discard existing report files.
- **FR-011**: Missing optional aggregated data MUST NOT prevent an application's history or existing artifacts from being displayed.

**Truthful status (US3)**

- **FR-012**: Queue termination, engine execution status, coverage status, and validation mode MUST be reported as four independent facts; no surface MAY derive one from another.
- **FR-013**: Per-phase progress MUST be derived from validated engine phase outcomes, not from a job's terminal flag or the current phase index; a partial run MUST NOT be shown as all-steps-complete.
- **FR-014**: Each incomplete phase MUST carry a surfaced reason, and the run's useful partial results MUST remain accessible.
- **FR-015**: The tool MUST preserve distinct meanings for: explicit unresolved review, missing decision, zero candidates after a valid hunt, failed hunt, authored artifact, deferred artifact, and executed test — and MUST NOT collapse them.
- **FR-016**: Restart, resume, and report regeneration MUST preserve these status distinctions and invalidate stale dependent results where upstream inputs changed.

**Artifact accessibility (US4)**

- **FR-017**: When generated, threat-model and SBOM material MUST be discoverable, openable, and downloadable from the scan, report, and application views, including for scans that already ran, without re-scanning.
- **FR-018**: The tool MUST represent each material state explicitly: not requested, pending, available, generation-failed, missing, unreadable, malformed — and MUST surface generation/parse/read failures rather than hiding them.
- **FR-019**: Selected threat/SBOM material MUST remain accessible even when another phase of the same run failed.
- **FR-020**: Discovery of pre-existing on-disk material MUST NOT fabricate absent material and MUST NOT overwrite or alter original scan evidence.
- **FR-021**: The intended relationship between threat analysis and deterministic dependency inventory (per the reference tool) MUST be documented and reflected consistently in what the operator sees.

**Verification & reproduction recovery (US5)**

- **FR-022**: Verification sessions MUST give candidates bounded, measured corrective feedback and retry on recoverable tool/schema/validation failures, and MUST preserve already-accepted work.
- **FR-023**: When recovery is exhausted, a candidate MUST be reported unresolved with a useful reason, and per-candidate attempt/failure counts and retry/turn limits MUST be recorded and explainable.
- **FR-024**: Verification MUST support evidence-based authorization/logic review without requiring an injection-style syntactic sink where the reference tool does not, while continuing to require attacker control, preconditions, reviewed defenses, impact, matching revision, and exact source evidence for a supported verdict.
- **FR-025**: Reproduction assignments MUST bind only to supported candidates; each supported candidate MUST end with registered authored material or a specific deferral.
- **FR-026**: Invalid reproduction submissions (wrong candidate/location, missing file, malformed header/registration) MUST receive bounded corrective feedback with stable candidate IDs; unresolved failures MUST be explained and preserved as evidence.
- **FR-027**: The tool MUST NOT describe authored material as executed, accept output-only tests as proof, run target code or exploit material automatically, or weaken evidence requirements to improve completion metrics.

**Report usefulness (US6)**

- **FR-028**: The consolidated report (Markdown, HTML, and machine-readable) MUST be derived from canonical evidence and MUST state scope and run/coverage/phase limitations.
- **FR-029**: The report MUST lead with a supported-findings summary and keep rejected and unresolved candidates in clearly identified separate sections.
- **FR-030**: Each supported finding MUST present source location and evidence, entry point, attacker control and flow, preconditions, reviewed defenses, security impact, rationale, remediation, and reproduction status/links or deferral — with missing information marked explicit.
- **FR-031**: The report MUST NOT present candidate totals as confirmed-vulnerability totals, and MUST NOT present syntactic sweep leads as confirmed findings.
- **FR-032**: The report MUST provide navigation to threat analysis, SBOM, coverage, and sweep leads.
- **FR-033**: The Markdown, HTML, and machine-readable outputs MUST agree on findings, outcomes, and counts for the same evidence.

**Honest options & limits (US7)**

- **FR-034**: Every supported operator option (including threat model, tracking, role model/provider, hunt sampling, and partition/coverage behavior) MUST be honored and recorded in effective configuration and run metadata, or explicitly rejected — never silently ignored.
- **FR-035**: The requested partition cap, the actual partition count produced, and whether the control is a hard cap or a coverage-driven starting point MUST be visible and explained.
- **FR-036**: The resulting workload and any bounded recovery MUST be visible so a run cannot silently expand into unbounded retries.

**Preservation & non-regression (cross-cutting)**

- **FR-037**: This feature MUST preserve existing scan history, reports, application registry names, tracking data, and uncommitted work; it MUST NOT reset the working tree or migrate by overwriting original evidence.
- **FR-038**: The scanner-correctness protections from the prior audit MUST remain in force and covered by tests: distinct candidate sites, exact source and revision checks, complete reasoning, path containment, no empty-output completion, supported-only reproduction, independent reference-contract checks, deterministic sweep/reporting, and resume/regeneration validity.
- **FR-039**: Acceptance MUST rely on saved outputs and offline fixtures first; any live-model validation MUST be a bounded, operator-approved plan and MUST NOT automatically launch another long scan or execute generated exploit material.

### Key Entities *(include if feature involves data)*

- **Scan (job/run)**: One analysis of a target repository. Attributes an operator relies on: identity, target repository, requested vs. completed phases, queue state, the three status axes (execution, coverage, validation mode), timings, workload (calls/agents/partitions), and links to its report and evidence.
- **Application**: A tracked repository aggregating its scans. Attributes: name, repository, stable identity, hidden/forgotten state, scan history and counts, latest report/outcome, supported/unresolved counts, severity/coverage summaries, optional tracking, and threat/SBOM availability.
- **Report**: The saved output of a scan: canonical findings/evidence plus human-readable Markdown/HTML, and its status axes and limitations.
- **Candidate & disposition**: A hunt finding with a verification disposition (supported / rejected / unresolved / missing-decision) and its recorded reasoning, attempts, and evidence; distinct sites stay distinct.
- **Generated material (threat model / SBOM / sweep leads)**: Optional intelligence artifacts with an explicit availability state and open/download access.
- **Reproduction artifact**: Authored PoC/test material or an explicit deferral bound to a supported candidate, with a validated (never "executed") status.
- **Effective configuration**: The operator's requested options resolved to what the engine actually did, recorded in run metadata.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: From seeded persisted history, an operator opening each supported surface sees 100% of persisted scans in their correct states, with zero uncaught errors and zero silent empty-state fallbacks; the same holds after a refresh and a service restart.
- **SC-002**: 100% of analyzed repositories in the seeded data are discoverable as applications — including at least one scanned with tracking disabled and at least one with a report created before this fix — and each application's summary/detail exposes every operator-facing field in FR-008.
- **SC-003**: For a fixture of the saved partial run, every incomplete phase (including 2b and 3) is shown as incomplete with a reason, all four status axes are shown distinctly, and no surface labels the run fully complete (0 false "all steps complete").
- **SC-004**: For each of the material states (not requested, pending, available, generation-failed, missing, unreadable, malformed), the corresponding view shows the correct state; available threat/SBOM material (including pre-existing on-disk files, with no re-scan) is openable and downloadable from the scan, report, and application views.
- **SC-005**: In controlled model fixtures, at least one rejected verification submission and one invalid reproduction submission recover to an accepted outcome, and at least one exhausted-recovery case yields a bounded, explained unresolved/incomplete result with recorded attempt/failure counts — with zero fabricated confirmations.
- **SC-006**: A representative supported finding's report entry contains every review element in FR-030 (with explicit "unknown" where data is absent); unsupported candidates are in separate sections; the candidate total is never presented as a confirmed-vulnerability total; and the Markdown, HTML, and machine-readable outputs agree.
- **SC-007**: 100% of supported operator options are traceable from request to effective configuration and metadata as honored or explicitly rejected (0 silently ignored), and the requested-vs-actual partition relationship is visible and explained.
- **SC-008**: All prior audit-protection tests plus this feature's new acceptance fixtures pass offline, and acceptance is accompanied by real browser evidence on the shipped surfaces and a behavior matrix versus the reference tool showing matches, documented approximations, and remaining gaps — a passing offline suite alone is treated as insufficient.
- **SC-009**: No existing scan, report, application name, or tracking record is lost or overwritten by this feature, verified before and after the changes.

## Assumptions

- **Supported operator surfaces**: The operator uses the root web UI and the `/app` browser UI; any additional surfaces are inventoried during planning and treated as in/out of scope there. The blank-view root cause is reproduced on the actual shipped surface before a fix is chosen (it is not assumed to be missing files, no scanning activity, or a stale process).
- **Reference as semantics oracle, not a runtime dependency**: The reference tool in `../vhlocal` defines the target aggregation/report/threat-vs-SBOM semantics; parity is established by reviewing its behavior and comparing outputs, never by executing Python as part of this tool's runtime or its acceptance gate. Live-model detection parity remains a separate, operator-owned empirical question.
- **Prior audit changes are a starting baseline, not proof of parity**: Their protections are retained and covered; where they over-constrain (e.g., a strict syntactic-sink requirement blocking evidence-based authorization/logic review), this feature adjusts behavior toward the reference without weakening evidence requirements.
- **Offline-first acceptance**: Saved outputs and fixtures drive acceptance; the tool never auto-launches another multi-hour scan or executes target/exploit code, consistent with the static-only safety boundary.
- **Preservation**: The working tree is dirty and largely untracked; the feature preserves existing work, history, and reports and does not reset or overwrite to obtain a clean baseline.
- **The partition-count question is an investigation, not a spec decision**: Whether `max_partitions` is a hard cap or a coverage-driven starting point is determined and documented during planning against the reference behavior; the requirement here is only that the relationship be honest and visible.
