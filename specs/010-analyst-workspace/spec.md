# Feature Specification: Evidence-centered analyst workspace

**Feature Branch**: `010-analyst-workspace`

**Created**: 2026-09-22

**Status**: Draft

**Input**: User description: "Evidence-centered analyst workspace (from `docs/engineering/2026-09-22-analyst-workspace-speckit-specify.md`) — make finding investigation, evidence evaluation, scan-completeness tracking, and action decisions efficient, understandable, and auditable, while preserving the operator's existing dashboard metrics and the behavior delivered in features 007–009."

## Overview

vhlocal is a local-first, AI-enabled source-code vulnerability analysis application run
by a single operator on their own machine. Today the operator can run scans and browse
reports, applications, and a ledger, but the day-to-day analyst work — finding a specific
result, judging whether its evidence holds up, recording a defensible decision, and
reaching every artifact a run produced — is scattered and hard to audit.

This feature adds an **evidence-centered analyst workspace**: Findings become a primary
destination with a searchable/sortable queue, a source/evidence pane bound to the scanned
revision, and review controls that persist a durable, inspectable decision history. It
adds honest scan-completeness and artifact surfaces, a "Needs attention" set of actionable
queues appended **below** the existing dashboard, contextual AI assistance scoped to the
selected finding, and a modernized navigation/interaction layer.

**Preservation is a binding part of this feature, not a side effect.** Every pre-existing
dashboard metric, chart, model breakdown, ordering, and latest-scan action stays with its
current meaning and formatting; the new queues are added below them. Feature 009's
Table/List choice, per-surface persistence, sorting, selection, and delete/forget
semantics are preserved. Forgetting an application or clearing a ledger continues to keep
saved reports on disk, and findings review must not silently recreate tracking history the
operator deliberately cleared.

Scope discipline: this is one product feature delivered in independently testable
increments. It requires genuine backend support (evidence access, durable decisions,
comparison, honest aggregates/status, contextual AI) — frontend-only mock success does not
satisfy it. It does not change scanner detection algorithms, add authentication/multi-user
support, add third-party integrations, or require a full legacy-UI rewrite.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Review a finding without losing investigation context (Priority: P1)

An operator makes Findings a primary destination and works a queue of results without
losing their place. They discover findings from saved scans — **including scans made with
ledger tracking disabled** — and open a finding directly from an application, a scan, a
report, or a dashboard queue. The workspace shows a searchable, sortable finding queue, a
code/evidence area, and review/AI controls together. On wide screens the panes are
resizable with remembered sizes; at smaller widths secondary panes collapse into
accessible views without losing the selected finding or its essential actions. Filters,
sorting, selection, and queue position survive navigation and browser back/forward, and a
stable finding link reopens the same scan-specific finding.

**Why this priority**: This is the core of the workspace — without a reliable place to find
and open a finding while keeping context, none of the evidence, decision, or AI work is
reachable. It is the MVP slice.

**Independent Test**: With a seeded history (including one ledger-disabled scan), open
Findings, filter and sort the queue, open a finding from each entry point, resize/collapse
panes, navigate away and back, and confirm the same finding, filters, sorting, and queue
position are restored; confirm a copied finding link reopens the same scan-specific finding.

**Acceptance Scenarios**:

1. **Given** a saved scan that ran with the ledger disabled, **When** the operator opens
   Findings, **Then** that scan's findings appear and can be opened, searched, and filtered
   without enabling or recreating a ledger.
2. **Given** a finding, **When** the operator opens it from an application, a scan, a
   report, or a dashboard queue, **Then** the same scan-specific finding opens with its
   context (application, repository, scanned revision where recorded, scan, and selected
   comparison baseline) shown persistently.
3. **Given** an active queue with filters, sorting, selection, and a scroll position,
   **When** the operator navigates to another view and back, or uses browser
   back/forward, **Then** the filters, sorting, selection, and queue position are restored.
4. **Given** a wide screen, **When** the operator resizes panes, **Then** the sizes are
   remembered; **and** at a narrow width the secondary panes collapse into accessible views
   without losing the selected finding or essential actions.
5. **Given** a saved filter set, **When** the operator names and later re-applies it,
   **Then** the same population is produced; **and** a clear reset returns to the unfiltered
   queue. An empty search result is visibly distinct from an application that has no
   findings.
6. **Given** a copied finding link, **When** it is opened in a new session, **Then** the
   intended scan-specific finding opens; **and** if the linked record is missing or
   deleted, a useful state and a route back to the remaining history are shown.

---

### User Story 2 - Inspect evidence and make a durable, defensible decision (Priority: P1)

An operator inspects a finding's evidence against the scanned source and records a durable
decision. Source is shown syntax-highlighted with line numbers and highlighted locations,
bound to the scanned revision or captured source — never silently substituting the current
working tree. The finding's four independent dimensions (severity, evidence assessment,
human review disposition, reproduction state) are always visible and explained. The
operator can save notes and a disposition with rationale (rationale required for dismissal,
accepted risk, or resolution); decisions survive refresh and restart, retain an inspectable
change history, and can be superseded without erasing history. Baseline comparison shows
new/recurring/regressed findings honestly, using explicit unknown/incomparable states when
identity, scope, or coverage cannot support a conclusion.

**Why this priority**: The workspace's purpose is defensible decisions backed by real
evidence. This is what makes the tool auditable and is the second half of the MVP.

**Independent Test**: With fixtures covering supported/rejected/unresolved/unknown evidence,
authored-only vs. deferred vs. failed-execution vs. executed reproduction, a missing source
revision, and comparable/partial baselines, confirm each state is distinguishable, record a
decision with rationale, reload and restart the service, and confirm the decision and its
history persist without altering the original scan evidence.

**Acceptance Scenarios**:

1. **Given** a finding whose scanned revision is recorded, **When** the operator views its
   evidence, **Then** the source shown is bound to that revision/captured source with line
   numbers and highlighted locations and surrounding context where available; **and** if the
   revision or source cannot be retrieved, that is stated and access to other available
   evidence is preserved (the current working tree is never substituted silently).
2. **Given** any finding, **When** the operator reviews it, **Then** severity (with its
   recorded basis), evidence assessment (supported/rejected/unresolved/unknown), human
   review disposition (needs review/investigating/accepted risk/dismissed/resolved), and
   reproduction state (not requested-or-attempted / authored-but-not-executed / deferred /
   attempted-inconclusive-or-failed / reproduced-with-evidence) are each shown and explained,
   without deriving one from another and without an unsupported numeric confidence score.
3. **Given** an authorization or business-logic finding, **When** the operator reviews it,
   **Then** it is fully reviewable without an artificial injection-style source-to-sink
   trace; observed references, model inferences, syntactic leads, and missing evidence are
   distinguished, and every claimed source citation resolves or is explicitly marked
   unavailable or invalid.
4. **Given** a finding, **When** the operator saves a disposition of dismissal, accepted
   risk, or resolution, **Then** a rationale is required; **and** the decision, notes, and
   rationale survive refresh and server restart and appear in an inspectable change history
   that a later decision can supersede without erasing prior entries. Human decisions do not
   overwrite the original scan evidence or AI verdict.
5. **Given** a stale browser holding an older decision, **When** it attempts to save over a
   newer decision, **Then** the conflict is surfaced and the newer decision is not silently
   lost.
6. **Given** comparable scan history, **When** the operator views baseline comparison,
   **Then** new, recurring, and regressed findings and evidence differences are shown with
   relevant provenance; **and** a finding absent from a partial or incomparable scan is
   **not** marked fixed — an explicit unknown/incomparable state is used instead, and a
   dismissal is not silently carried across materially changed evidence.

---

### User Story 3 - Understand scan completion and reach every available artifact (Priority: P1)

An operator understands exactly how complete a scan is and can reach every artifact it
produced. Requested stages and recorded stage outcomes are shown with useful failure or
degradation reasons; queue/job termination is distinguished from execution status, coverage
status, and validation mode, and all three constitution status axes are carried on each
run-status surface (or an axis is marked unavailable). An artifact manifest is reachable
from scans, reports, and application history, listing the findings report, threat
model/report, SBOM, and generated verification/remediation material, each with an honest
state (not requested / pending / available / failed / missing / unreadable / malformed /
unknown-historical). Availability means validated material, not merely a filename or a
successful process exit. Available artifacts can be viewed and downloaded; missing optional
artifacts do not hide other results.

**Why this priority**: Trustworthy completeness and artifact access underpin every decision.
A green "done" label that hides degraded coverage or an unreadable artifact makes the whole
workspace untrustworthy.

**Independent Test**: With complete, partial, failed, cancelled, interrupted, and
historical-unknown run fixtures and artifacts in each state (requested/unrequested/pending/
valid/missing/unreadable/malformed/failed), confirm each status axis and artifact state
displays correctly, that available artifacts view/download and missing ones don't hide
others, and that a failed detail fetch leaves loading with a retry while out-of-order
responses don't corrupt the active view.

**Acceptance Scenarios**:

1. **Given** any run, **When** the operator views its status, **Then** requested stages and
   recorded stage outcomes are shown with failure/degradation reasons, and execution,
   coverage, and validation are shown as independent axes (or explicitly marked unavailable);
   coverage or validation is never inferred from a completion label.
2. **Given** a run's artifacts, **When** the operator opens the manifest from a scan, a
   report, or application history, **Then** each artifact (findings report, threat
   model/report, SBOM, verification/remediation material) shows the correct state, where
   "available" requires validated material rather than a present filename or a clean exit.
3. **Given** available artifacts, **When** the operator opens or downloads one, **Then** it
   is shown/downloaded; **and** a missing optional artifact does not hide the other results.
4. **Given** a partial or interrupted scan, **When** the operator views it, **Then** its
   usable outputs are retained and the unfinished work is explained; any resume/retry action
   describes its scope, requires an explicit operator action, and appears only where
   supported — no work is silently rerun while a page loads.
5. **Given** any workspace surface (findings, applications, scans, ledger, reports,
   dashboard), **When** data is loading, empty, filtered-empty, refreshing, stale,
   disconnected, or failed, **Then** these states are distinguishable; a failed detail
   request leaves loading and offers retry, a failed refresh preserves usable prior data
   with a stale indicator, a late response does not replace another selection, and a failed
   mutation does not appear saved or deleted.

---

### User Story 4 - Actionable dashboard queues below the preserved dashboard (Priority: P2)

An operator gets a "Needs attention" area appended **below all existing dashboard sections**
with navigable queues for the work that matters, while every existing metric and chart stays
exactly as it is. Each queue shows its scope, definition, count, and a link that opens the
matching filtered destination, and displays unknown/unavailable data honestly rather than as
zero. The new section fails independently — if queue data is unavailable it does not blank or
block the existing dashboard, and queue filters never change the population behind the
existing numbers and charts.

**Why this priority**: High operator value, but it depends on the finding/evidence/status
foundations (US1–US3) to define what each queue counts and links to; it is added without
disturbing the trusted existing dashboard.

**Independent Test**: With a fixed seeded history and a selected baseline, scope, and age
threshold, confirm every pre-existing metric/chart/model-breakdown/latest-scan action is
unchanged in value, semantics, formatting, and relative order; confirm each new queue's
count matches its filtered destination; and confirm a simulated queue-data failure leaves
the existing dashboard fully usable.

**Acceptance Scenarios**:

1. **Given** the same seeded history, **When** the operator opens the dashboard, **Then**
   every pre-existing metric (scans run; findings/vulnerabilities found; average findings per
   scan as a whole number; total tokens with input/output breakdown; average tokens per scan;
   recorded usage counts; total scan time; average scan duration), the findings-per-scan
   chart, the per-model breakdowns, and the refresh and latest-scan progress/details/actions
   remain available in their prior relative order with unchanged values and semantics, and
   feature 008's missing-data handling is retained.
2. **Given** the dashboard, **When** it renders, **Then** a "Needs attention" area appears
   **below** all existing sections with queues for: supported Critical/High findings awaiting
   review; new supported Critical/High findings vs. a selected comparable baseline (with an
   explicit no-baseline state); unresolved findings needing review or more evidence;
   regressions supported by comparable history; incomplete/interrupted scans and
   failed/missing requested artifacts; and applications whose latest scan is older than an
   operator-selected age threshold (default seven days, visible and editable).
3. **Given** a fixed history, baseline, scope, and age threshold, **When** the operator
   reads a queue count and opens its link, **Then** the count matches the filtered
   destination, with duplicate occurrences deduplicated so the same item does not inflate the
   count, and unavailable data shown honestly rather than as zero.
4. **Given** unavailable queue data, **When** the dashboard renders, **Then** the existing
   metrics and charts remain populated and usable, and no queue filter changes the population
   used by the existing numbers; new supported-finding counts are distinguished by explicit
   labels (existing numbers are not switched to supported-only).

---

### User Story 5 - Use AI assistance in the context of the selected finding (Priority: P2)

An operator invokes contextual AI actions scoped to the selected finding: explain the flow,
look for mitigating checks, challenge the finding, draft a regression test, and propose a
fix. Each request and response is bound to the selected finding, scan revision, and supplied
evidence, shows actual provider/model provenance and source citations, and is labeled
distinctly from recorded scan evidence. The selected provider and local/external destination
are clear before submission; source transmission and paid/cloud use follow explicit operator
configuration with no silent fallback. Failures, bounded retries, and cancellation are
visible; revisiting a finding does not resubmit, and navigating away does not misattach an
in-flight result. Drafted tests and fixes are reviewable artifacts/diffs that do not execute
code, install dependencies, modify the working tree, or auto-update severity/disposition.

**Why this priority**: Valuable assistance, but it must sit on top of a trustworthy finding
context and provenance model; delivering it before US1–US3 would risk misattributed or
unprovenanced output.

**Independent Test**: Using offline provider fixtures, exercise all five actions plus
citation/provenance display, navigation during generation, failure, and cancellation;
confirm results attach to the correct finding/revision, remain retrievable, and that no
action executes code, changes a finding, applies a patch, or reaches a different provider;
confirm saved drafts are distinguishable from execution evidence.

**Acceptance Scenarios**:

1. **Given** a selected finding, **When** the operator runs any of the five contextual
   actions, **Then** the request/response is bound to that finding, scan revision, and
   evidence, shows real provider/model provenance and citations, and is labeled as generated
   analysis distinct from recorded scan evidence.
2. **Given** a contextual request, **When** it is submitted, **Then** the selected provider
   and local/external destination were shown beforehand and honored with no silent
   provider/model fallback; source transmission and paid/cloud use followed explicit operator
   configuration.
3. **Given** an in-flight request, **When** it fails, is retried within bounds, or is
   cancelled, **Then** each state is visible; revisiting the finding does not resubmit, and
   navigating to another finding does not misattach the in-flight result.
4. **Given** a drafted test or proposed fix, **When** it is produced, **Then** it is a
   reviewable artifact/diff that does not execute target code, install dependencies, modify
   the working tree, or automatically change the finding's severity or disposition; it is
   distinguishable from recorded execution evidence.
5. **Given** a provider or historical record that cannot support an action, **When** the
   operator invokes it, **Then** the limitation is explained (a permanently disabled button
   or canned response does not satisfy the requirement).

---

### User Story 6 - Modernize navigation, configuration, and interaction consistency (Priority: P2)

An operator moves through a coherent, accessible interface. A collapsible primary sidebar
keeps Overview/Dashboard, Applications, Findings, and Scans prominent, with Reports and
Activity as secondary destinations and Docs/Settings discoverable; existing links keep
working or redirect. Application and scan context is maintained while moving between related
views. The interface uses a consistent visual foundation (spacing, typography, semantic
colors, focus styles, tables, forms, dialogs, empty states), supports light and dark themes,
preserves the operator's Table/List choices, and provides text/icon cues in addition to
color. Native prompt/confirm interactions are replaced with consistent dialogs that preserve
confirmation semantics and restore focus. Core interactions are keyboard-operable with
visible focus and meaningful accessible names, reduced-motion is respected, and narrow/zoomed
layouts avoid page-wide overflow. Scan setup is understandable, using user-facing labels and
a pre-launch review of effective choices including inference destination.

**Why this priority**: Consistency and accessibility multiply the value of US1–US5, but the
underlying data and flows must exist first; this journey refines how they are presented.

**Independent Test**: Run the main review flow by keyboard alone in both themes at 1440px,
1024px, and 390px widths and at 200% desktop zoom; confirm sidebar navigation preserves
context, existing links resolve or redirect, dialogs replace native prompts and restore
focus, scan setup shows understandable labels and a pre-launch review, and no advertised
setting ships as an empty placeholder.

**Acceptance Scenarios**:

1. **Given** the workspace, **When** the operator navigates via the collapsible sidebar,
   **Then** Overview/Dashboard, Applications, Findings, and Scans are prominent, Reports and
   Activity and Docs/Settings are reachable, application/scan context is maintained across
   related views, and existing links resolve or redirect to an equivalent destination.
2. **Given** any destructive or confirming action (e.g., delete/forget), **When** it is
   triggered, **Then** a consistent in-app dialog (not a native prompt/confirm) preserves the
   confirmation semantics and restores focus correctly afterward.
3. **Given** the main review flow, **When** the operator uses only the keyboard in light and
   dark themes, **Then** navigation, finding selection, tabs (with proper focus movement and
   associated panels), pane controls, sorting, filtering, dialogs, and review actions are
   operable with visible focus and meaningful accessible names, and reduced-motion is
   respected.
4. **Given** narrow widths and 200% zoom, **When** the operator uses the workspace, **Then**
   there is no page-wide overflow and essential actions remain reachable; source and data
   regions scroll within their own labeled containers, and the Table/List choice is preserved.
5. **Given** scan setup, **When** the operator configures a scan, **Then** repository and
   revision (when known), analysis scope, inference provider/model, and requested outputs use
   user-facing labels (not implementation terms), presets expand visibly to supported
   settings, unsupported settings are rejected explicitly, no invented time/cost estimates or
   coverage guarantees are shown, and a pre-launch review of effective choices — including
   output expectations and inference destination — is presented.

---

### Edge Cases

- A saved scan ran with the ledger disabled: its findings, evidence, and review controls
  must be fully available without enabling or recreating a ledger, and recording a decision
  must not recreate deliberately cleared tracking history.
- The scanned revision or source cannot be retrieved: say so explicitly and preserve access
  to available evidence; never substitute the current working tree.
- A finding is absent from a later partial or incomparable scan: mark it unknown/incomparable,
  never automatically "fixed."
- Evidence for a finding materially changed between scans: do not silently carry a prior
  dismissal across it.
- Two updates race (stale browser vs. newer decision): surface the conflict; do not silently
  lose the newer decision.
- A queue's data is unavailable: show it honestly (not as zero) and keep the existing
  dashboard fully usable.
- An artifact filename exists but the artifact is unreadable/malformed, or the process exited
  cleanly without valid material: show unreadable/malformed/failed, not "available."
- A contextual AI request is in flight when the operator navigates away or returns: do not
  misattach the result and do not resubmit on revisit.
- A referenced report/finding link points to a deleted record: show a useful missing-record
  state with a route back to the remaining history.
- Untrusted repository text, Markdown, diagrams, or AI output is rendered: it must not execute
  embedded content or be treated as instructions authorizing extra tools, destinations, or
  state changes.
- Zero scans, or runs with missing usage/timing metadata: dashboard renders a clean state
  with feature 008's missing-data handling; no NaN or divide-by-zero.

## Requirements *(mandatory)*

### Functional Requirements

**Findings discovery, queue, and context (US1)**

- **FR-001**: The system MUST provide Findings as a primary destination exposing findings
  from saved scans, including scans made with ledger tracking disabled.
- **FR-002**: Users MUST be able to open a finding directly from an application, a scan, a
  report, and a dashboard queue, arriving at the same scan-specific finding.
- **FR-003**: The system MUST present a searchable, sortable finding queue alongside a
  code/evidence area and review/AI controls in one workspace.
- **FR-004**: On wide screens the system MUST support resizable panes with remembered sizes;
  at smaller widths it MUST collapse secondary panes into accessible views without losing the
  selected finding or its essential actions.
- **FR-005**: The system MUST persistently display the finding's context: application,
  repository, scanned revision (where recorded), scan, and selected comparison baseline.
- **FR-006**: The system MUST support filters for application, scan, severity, evidence
  assessment, human review state, file/path, and new/regressed status (the last only when
  comparison data permits), plus named saved filters and a clear reset.
- **FR-007**: The system MUST make an empty search result distinguishable from an application
  that has no findings.
- **FR-008**: Stable finding links MUST reopen the same scan-specific finding; browser
  back/forward and navigation between views MUST preserve filters, sorting, selection, and
  queue position; changing Table/List view MUST NOT discard this context.
- **FR-009**: The system MUST provide accessible next/previous finding controls and document
  any optional keyboard shortcuts.
- **FR-010**: A missing or deleted linked record MUST receive a useful state and a route back
  to the remaining history.

**Evidence inspection (US2)**

- **FR-011**: The system MUST show readable, syntax-highlighted source with line numbers and
  highlighted finding locations, plus surrounding function/context where available.
- **FR-012**: Source excerpts MUST be bound to the scanned revision or captured source and
  MUST NOT silently substitute the current working tree; if the revision or source cannot be
  retrieved, the system MUST say so and preserve access to available evidence.
- **FR-013**: For each finding the system MUST present the entry point, attacker-controlled
  input, relevant flow, dangerous operation, preconditions, reviewed guards/sanitizers,
  impact, rationale, and remediation guidance, where recorded.
- **FR-014**: The system MUST support a clickable source-to-sink trace where evidence
  supports it, while making authorization and business-logic findings fully reviewable
  without an artificial injection-style trace.
- **FR-015**: The system MUST distinguish observed references, model inferences, syntactic
  leads, and missing evidence; every claimed source citation MUST resolve or be explicitly
  marked unavailable or invalid; long generated prose MUST NOT obscure key evidence.

**Four finding dimensions (US2)**

- **FR-016**: The system MUST keep four independent dimensions visible and explained on a
  finding: (1) severity and its recorded basis; (2) evidence assessment
  (supported/rejected/unresolved/unknown); (3) human review disposition (needs
  review/investigating/accepted risk/dismissed/resolved); (4) reproduction state (not
  requested-or-attempted / authored-but-not-executed / deferred / attempted-inconclusive-or-
  failed / reproduced-with-recorded-execution-evidence).
- **FR-017**: The system MUST NOT derive one dimension from another, MUST NOT invent new
  certainty from a legacy state, and MUST NOT display an unsupported numeric confidence score;
  a failed execution MUST NOT by itself refute a vulnerability, and authored code MUST NOT be
  presented as successful execution.

**Durable decisions and history (US2)**

- **FR-018**: Users MUST be able to save notes and a review disposition with rationale, with
  rationale required for dismissal, accepted risk, or resolution.
- **FR-019**: Decisions MUST survive browser refresh and server restart and retain an
  inspectable change history; a later decision MUST be able to supersede an earlier one
  without erasing history.
- **FR-020**: Human decisions MUST NOT overwrite the original scan evidence or the AI verdict.
- **FR-021**: The system MUST use stable identities to relate findings across scans where
  supported, MUST NOT silently carry a dismissal across materially changed evidence, and MUST
  define conflict behavior so a stale browser cannot silently overwrite a newer decision.
- **FR-022**: Recording a review decision MUST NOT enable or recreate a ledger or other
  tracking history the operator deliberately disabled or cleared.

**Baseline comparison (US2)**

- **FR-023**: The system MUST provide baseline comparison showing new, recurring, and
  regressed findings, evidence differences, and relevant provenance where supported.
- **FR-024**: A finding absent in a partial or incomparable scan MUST NOT automatically
  become "fixed"; the system MUST use explicit unknown/incomparable states when identity,
  scope, or coverage cannot support the conclusion, and MUST NOT invent historical data or
  trigger automatic expensive rescans to fill gaps.

**Scan completion and status axes (US3)**

- **FR-025**: The system MUST show requested stages and recorded stage outcomes with useful
  failure or degradation reasons, and MUST distinguish queue/job termination from execution
  status, coverage status, and validation mode.
- **FR-026**: Each run-status surface MUST carry the three constitution status axes
  (execution, coverage, validation) or explicitly mark a missing axis unavailable, and MUST
  NOT infer coverage or dynamic validation from a green completion label.

**Artifacts (US3)**

- **FR-027**: The system MUST provide an artifact manifest reachable from scans, reports, and
  application history, including the findings report, threat model/report, SBOM, and generated
  verification/remediation material appropriate to the run.
- **FR-028**: The manifest MUST distinguish not requested, pending, available, failed,
  missing, unreadable, malformed, and unknown-historical states as applicable, where
  "available" requires validated material (not merely a filename or a successful process
  exit).
- **FR-029**: Users MUST be able to view and download available artifacts; missing optional
  artifacts MUST NOT hide other results.
- **FR-030**: Partial and interrupted scans MUST retain usable outputs and explain unfinished
  work; any resume/retry action MUST describe its scope, require explicit operator action, and
  appear only where supported — the system MUST NOT silently rerun work while loading a page.

**Cross-workspace states (US3)**

- **FR-031**: Across applications, scans, ledger, reports, findings, and dashboard, the system
  MUST distinguish initial loading, empty, filtered-empty, refreshing, stale, disconnected,
  and failed states.
- **FR-032**: A failed detail request MUST leave a loading/retry affordance (not blank); a
  failed refresh MUST preserve usable prior data with a stale indicator; a late/out-of-order
  response MUST NOT replace another application's or finding's current selection; and a failed
  mutation MUST NOT appear saved or deleted.

**Dashboard preservation and queues (US4)**

- **FR-033**: The system MUST preserve every pre-existing dashboard metric, chart, model
  breakdown, latest-scan progress/details/actions, refresh control, and their formatting and
  relative order, with unchanged values and semantics — specifically: scans run;
  findings/vulnerabilities found; average findings per scan (whole number); total tokens with
  input/output breakdown; average tokens per scan; recorded usage counts; total scan time;
  average scan duration; findings-per-scan chart; per-model breakdowns (including average
  findings per scan and scan counts). It MUST retain feature 008's missing-data handling.
- **FR-034**: The system MUST NOT move existing metrics to another page, hide them behind a
  tab, change their population to supported-only findings, remove the model comparison, or
  replace them with review queues.
- **FR-035**: The system MUST add a "Needs attention" area below all existing dashboard
  sections with navigable queues for: supported Critical/High findings awaiting review; new
  supported Critical/High findings vs. a selected comparable baseline (with an explicit
  no-baseline state); unresolved findings needing review or more evidence; regressions
  supported by comparable history; incomplete/interrupted scans and failed/missing requested
  artifacts; and applications whose latest scan is older than an operator-selected age
  threshold defaulting to seven days (visible and editable).
- **FR-036**: Each queue MUST show its scope, definition, count, and a link opening the
  matching filtered destination; MUST display unknown/unavailable data honestly rather than as
  zero; and MUST define counting/deduplication so the same item does not inflate a queue.
- **FR-037**: The "Needs attention" section MUST fail independently — unavailable queue data
  MUST NOT blank or block the existing dashboard metrics, and queue filters MUST NOT change
  the population used by the existing numbers and charts.
- **FR-038**: New supported-finding counts MUST be distinguished by explicit labels; time
  staleness MUST NOT be presented as proof of incomplete coverage, and a scan revision
  mismatch MUST be shown separately when known.

**Contextual AI (US5)**

- **FR-039**: The system MUST provide contextual actions for the selected finding to explain
  the flow, look for mitigating checks, challenge the finding, draft a regression test, and
  propose a fix, each bound to the selected finding, scan revision, and supplied evidence.
- **FR-040**: The system MUST show actual provider/model provenance and source citations for
  each AI request/response and label generated analysis and drafts distinctly from recorded
  scan evidence.
- **FR-041**: The system MUST make the selected provider and local/external destination clear
  before submission; source transmission and paid/cloud use MUST follow explicit operator
  configuration; there MUST be no silent provider/model fallback.
- **FR-042**: Failures, bounded retries, and cancellation MUST be visible; revisiting a
  finding MUST NOT resubmit a request; navigating to another finding MUST NOT misattach an
  in-flight result.
- **FR-043**: Draft tests and fixes MUST be reviewable artifacts/diffs that do not execute
  target code, install dependencies, modify the working tree, or automatically update finding
  severity/disposition; executing tests or applying patches is out of scope, and existing
  explicitly authorized isolated-execution capabilities MUST retain their safeguards.
- **FR-044**: The system MUST treat repository text and AI output as untrusted content, never
  as instructions authorizing extra tools, network destinations, or state changes.
- **FR-045**: The specified contextual actions MUST deliver real behavior and persistence;
  when a provider or historical record cannot support an action, the limitation MUST be
  explained (a permanently disabled button or canned response does not satisfy this).

**Navigation, configuration, interaction, accessibility (US6)**

- **FR-046**: The system MUST provide a collapsible primary sidebar with Overview/Dashboard,
  Applications, Findings, and Scans prominent; Reports and Activity as secondary; and
  Docs/Settings discoverable — preserving existing links or providing equivalent redirects and
  maintaining application/scan context across related views.
- **FR-047**: The system MUST NOT ship newly advertised settings as empty placeholders.
- **FR-048**: The system MUST apply a consistent visual foundation (spacing, typography,
  semantic colors, focus styles, tables, forms, dialogs, empty states), support light and dark
  themes, preserve the operator's Table/List choices, and provide text/icon cues in addition
  to color.
- **FR-049**: The system MUST replace native prompt/confirm interactions with consistent
  in-app dialogs that preserve confirmation semantics and restore focus correctly.
- **FR-050**: Navigation, finding selection, tabs (with proper focus movement and associated
  panels), pane controls, sorting, filtering, dialogs, and review actions MUST be
  keyboard-operable with visible focus and meaningful accessible names, and MUST respect
  reduced-motion preferences.
- **FR-051**: At narrow widths and zoomed text the system MUST avoid page-wide overflow and
  keep essential actions reachable; source and data regions MAY scroll within their own
  labeled containers.
- **FR-052**: Scan setup MUST identify repository and revision (when known), analysis scope,
  inference provider/model, and requested outputs using user-facing labels (not implementation
  terms like "Write remediation DTOs"); provide presets that expand visibly to supported
  settings with advanced controls; avoid invented time/cost estimates or coverage guarantees;
  preserve existing role/model configuration; reject unsupported settings explicitly; and
  present a pre-launch review of effective choices including output expectations and inference
  destination.
- **FR-053**: Application details MUST keep scan history, findings, threat material, and SBOMs
  connected; where recorded evidence supports a relationship, a threat or component MAY lead to
  its related findings, and where no reliable mapping exists the system MUST say so rather than
  invent links. Reports MUST remain readable/exportable audit artifacts backed by the same
  canonical data used in the workspace.

**Preservation of features 007–009 and safety boundary (cross-cutting)**

- **FR-054**: The system MUST preserve feature 009's Table/List choice, per-surface preference
  persistence, sorting, selection, and existing delete/forget semantics in Applications and
  Ledger; Reports MUST remain accessible; forgetting an application or clearing a ledger MUST
  continue to preserve saved reports; and findings review MUST NOT silently recreate
  deliberately cleared tracking history.
- **FR-055**: The system MUST preserve the static-only default, independent status axes,
  engine-recorded provenance, explicit provider failures, and resumability/idempotency rules;
  the interface and exported reports MUST remain self-contained/offline-capable with no CDN or
  unconfigured network requests; opening untrusted code/Markdown/diagrams/artifacts MUST NOT
  execute embedded content; and repository/artifact path containment MUST be preserved.
- **FR-056**: Backend support required for evidence access, durable review decisions,
  comparison, contextual AI, or honest aggregate/status information MUST be delivered as real
  behavior and persistence — frontend-only mock success MUST NOT be used; existing artifact and
  report formats MUST be preserved where possible, with explicit compatibility handling for
  older records that does not rewrite original evidence.
- **FR-057**: The system MUST use the current single local-operator model without inventing
  authenticated reviewer identities; any operator attribution on a decision MUST be clearly
  described (e.g., "recorded by the local operator" with a timestamp).

### Key Entities *(include if feature involves data)*

- **Finding occurrence**: A specific finding as produced by a specific scan (scan-specific),
  carrying its severity and basis, evidence assessment, reproduction state, location(s),
  scanned revision where recorded, and the evidence references that support it. Related to
  other occurrences across scans by a stable identity where supported.
- **Review decision & history**: An operator's disposition (needs review/investigating/accepted
  risk/dismissed/resolved) with notes and rationale, attributed to the local operator with a
  timestamp. An append-only, inspectable history where later decisions supersede earlier ones
  without erasing them; separate from and non-overwriting of scan evidence and the AI verdict.
- **Evidence reference**: A citation to source (path, revision/captured source, line range) or
  an inference/syntactic lead, classified as observed / model-inferred / syntactic /
  missing, and resolvable or explicitly marked unavailable/invalid.
- **Comparison baseline**: A selected prior scan (or none) used to compute new/recurring/
  regressed status and evidence differences, with explicit unknown/incomparable results when
  identity, scope, or coverage do not support a conclusion.
- **Artifact state**: The status of a run's artifact (findings report, threat model/report,
  SBOM, verification/remediation material): not requested / pending / available / failed /
  missing / unreadable / malformed / unknown-historical, where available means validated.
- **Run status**: A run's independent execution, coverage, and validation axes plus requested
  stages and recorded stage outcomes, distinct from queue/job termination; an axis may be
  marked unavailable.
- **Saved view / filter**: A named, reusable set of queue filters and sort/selection scope,
  persisted per the operator's surface preferences.
- **Contextual AI result**: A generated analysis or draft (explanation, mitigation search,
  challenge, regression-test draft, fix proposal) bound to a finding occurrence, scan
  revision, and supplied evidence, carrying provider/model provenance and citations, labeled
  distinct from recorded scan evidence, and (for drafts) a non-executed reviewable
  artifact/diff.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001 (Dashboard preservation)**: With the same seeded history, 100% of pre-existing
  metrics, charts, model breakdowns, and the latest-scan action remain available in their
  prior relative order with unchanged values and semantics; all new queues render below them;
  and a simulated queue failure leaves the existing content fully usable. Verified for zero
  scans, runs with missing usage/timing, and populated history.
- **SC-002 (Findings without ledger)**: A saved scan with the ledger disabled exposes its
  findings, source/evidence, and review controls, and a saved decision survives browser reload
  and service restart without enabling/recreating a ledger or altering the saved scan
  evidence.
- **SC-003 (Complete review flow)**: An operator can filter a queue, open a finding, follow an
  available source citation, record a decision and rationale, open an artifact, and return to
  the same queue position — repeated for ten findings with zero lost context or decisions; a
  copied finding link and browser back/forward restore the intended finding and scope.
- **SC-004 (Evidence honesty)**: Supported, rejected, unresolved, unknown, authored-only,
  deferred, failed-execution, and executed-reproduction examples are all visually
  distinguishable; a missing source revision is reported without substituting current code;
  and no inference-only trace is displayed as observed.
- **SC-005 (Comparison honesty)**: For comparable fixtures, known new/recurring/regressed
  findings are shown correctly; a partial scan missing an earlier finding does not mark it
  fixed; changed evidence does not silently inherit a dismissal; and a conflicting review
  update is surfaced without silently losing the newer decision.
- **SC-006 (Status/artifact matrix)**: Complete, partial, failed, cancelled, interrupted, and
  historical-unknown runs each retain independent execution/coverage/validation information,
  and requested/unrequested/pending/valid/missing/unreadable/malformed/failed artifact cases
  each show the correct state and preserve access to other outputs; an unsuccessful detail
  fetch leaves loading and presents retry; out-of-order responses do not corrupt the active
  view.
- **SC-007 (Queue accuracy)**: For a fixed history, baseline, scope, and age threshold, every
  new dashboard queue count matches its filtered destination, including duplicate occurrences
  (deduplicated), a no-baseline case, unavailable data (shown honestly, not zero), and stale
  applications.
- **SC-008 (Contextual AI)**: Using offline provider fixtures, all five actions plus
  citation/provenance display, navigation-during-generation, failure, and cancellation behave
  correctly; results attach to the correct finding/revision and remain retrievable; no action
  executes code, changes findings, applies a patch, or reaches a different provider; and saved
  drafts are distinguishable from execution evidence.
- **SC-009 (Existing workflows)**: Applications, Ledger, and Reports retain their Table/List
  behavior and preferences; existing delete/forget confirmations preserve reports and
  unrelated data; and known report/finding links either resolve or show a useful
  missing-record state.
- **SC-010 (Usability/accessibility)**: The main review flow is completable by keyboard alone
  in both light and dark themes at 1440px, 1024px, and 390px widths and at 200% desktop zoom,
  with essential controls reachable, focus visible and restored after dialogs, secondary panes
  collapsing appropriately, and verified accessible names, tab behavior, contrast, and
  reduced-motion handling.
- **SC-011 (Responsiveness)**: With a documented local fixture of 1,000 findings, changing
  filters, selecting a finding, and moving to the next finding each display the requested local
  result within two seconds on the recorded acceptance machine (excluding live inference), with
  measured results recorded as acceptance targets.
- **SC-012 (Delivered application)**: Acceptance is validated against the actual built frontend
  served by the Go application — including direct-link reloads and restart — with recorded
  build provenance and captured browser console/network failures; offline regression tests and
  deterministic browser fixtures are used with no live paid model or multi-hour scan required,
  and any skipped check is explicitly reported rather than counted as passed.

## Assumptions

- **Primary surface is the React application served by the Go binary.** The actual shipped
  entrypoints and embedded frontend build are to be inventoried during planning; existing
  reports and links from other supported entrypoints remain accessible. This feature does not
  require a second full redesign of the legacy interface or a framework migration; shared
  behavior stays compatible.
- **Single local operator.** No authentication or multi-user system is introduced; review
  decisions are attributed to the local operator with a timestamp. No authenticated reviewer
  identities are invented.
- **Offline, deterministic validation.** Acceptance uses offline provider fixtures and seeded
  deterministic history — no live paid model, no multi-hour scan, and (per standing project
  constraint) no direct workloads to a live model and no Python execution are required for
  acceptance. Browser validation against the built frontend is operator-owned.
- **Features 007, 008, and 009 are dependencies and preservation constraints.** Their accepted
  behavior (application aggregation and truthful status/material access; dashboard metrics and
  application/ledger management with missing-data handling and whole-number average findings;
  Table/List toggle with per-surface persistence, sorting, and delete/forget semantics) is
  reused where it satisfies this feature and preserved otherwise; current uncommitted work is
  preserved. Their current implementation is to be inspected during planning rather than
  assumed complete.
- **"Needs attention" default age threshold is seven days**, visible and operator-editable.
- **Baselines are operator-selected comparable scans**; when no comparable baseline exists,
  an explicit no-baseline/incomparable state is shown rather than a computed default.
- **Reproduction and execution remain governed by the constitution's static-only default.**
  Contextual AI drafts are never executed and never modify the working tree; existing
  explicitly authorized isolated-execution capabilities keep their safeguards.
- **Backend work is in scope** wherever evidence access, durable decisions, comparison,
  contextual AI, or honest aggregates/status cannot be delivered by the frontend alone; existing
  artifact/report formats are preserved with explicit compatibility handling for older records.
- **Delivered in independently testable increments**, prioritizing a complete saved-finding
  review flow and trustworthy scan/artifact states before contextual AI and visual
  refinements; unfinished increments are marked explicitly with a completion matrix in the
  eventual implementation handoff.
- **Development/test tooling dependencies are distinct** from the dependencies required by the
  delivered application, consistent with the constitution's reviewed dependency budget.
