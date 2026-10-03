# Claude handoff: Evidence-centered analyst workspace

Prepared: 2026-09-22

This document is input for Claude's `speckit-specify` skill, not an executed
specification workflow. Preparing it does not create a feature branch, change
`.specify/feature.json`, or implement application changes.

## How to use

Open Claude in `vhlocal-go` and paste this instruction:

```text
Use the repository's speckit-specify skill. Read docs/engineering/2026-09-22-analyst-workspace-speckit-specify.md and use its entire "Specification input" section as the feature description. Create one new feature specification and its requirements quality checklist. Preserve all existing dashboard numbers, charts, and functionality; add the new review queues below the existing dashboard content. Preserve the in-progress work and requirements in features 008 and 009. Do not start implementation during the specify step.
```

If `/speckit-specify` is recognized in your Claude session, it may be used with
the same instruction. The plain-language skill request above avoids depending
on slash-command registration.

After reviewing the specification, ask Claude to use `speckit-plan`, then
`speckit-tasks`, then `speckit-analyze`. Resolve material inconsistencies before
using `speckit-implement`. The plan must cover backend support and browser
validation as well as visual changes.

## Specification input

Create one feature specification named "Evidence-centered analyst workspace"
for vhlocal-go. The product is a local-first, AI-enabled source-code
vulnerability analysis application. Its primary users investigate findings,
evaluate evidence, track scan completeness, and decide what deserves action.
Make those tasks efficient, understandable, and auditable while preserving the
operator's existing workflows and valued dashboard metrics.

### Context and binding constraints

Read `.specify/memory/constitution.md` and the specifications for features 007,
008, and 009 before drafting. Inspect their current implementation; do not
assume every requirement is already delivered. Preserve existing uncommitted
work. Reuse established behavior where it satisfies this feature and identify
remaining dependencies explicitly instead of duplicating or undoing it.

The primary design target is the React application. During planning, identify
the actual shipped entrypoints and embedded frontend build. Preserve access to
existing reports and links from other supported entrypoints. This feature does
not require a second full redesign of the legacy interface or a framework
migration. Shared behavior must remain compatible.

**Operator correction to the original review: all existing dashboard numbers
are useful and must stay.** Retain their meaning, aggregation, visibility,
formatting requirements, and current functionality, including:

- Scans run, findings/vulnerabilities found, and average findings per scan.
- Total tokens, input/output breakdown, average tokens per scan, and recorded
  usage counts.
- Total scan time and average scan duration.
- Findings-per-scan chart and per-model breakdowns, including average findings
  per scan and scan counts.
- Refresh and latest-scan progress/details/actions.
- Any additional dashboard metrics or controls present when implementation
  begins; inventory these in the plan and baseline them for regression checks.

Keep the existing dashboard content in its current relative order. Add a new
"Needs attention" area **below all existing dashboard sections**. Do not move
metrics to another page, hide them behind a tab, change their population to
supported-only findings, remove the model comparison, or replace them with
review queues. Distinguish new supported-finding counts by explicit labels.
Retain feature 008's missing-data handling and whole-number headline average
findings requirement. Visual refinements must preserve readability and access.

Preserve feature 009's Table/List choice, per-surface preference persistence,
sorting, selection, and existing delete/forget semantics in Applications and
Ledger. Reports remain accessible. Forgetting an application or deleting its
ledger must continue to preserve saved reports. Findings review must not
silently recreate deliberately cleared tracking history.

### Prioritized user journeys and requirements

#### P1: Review a finding without losing investigation context

Provide Findings as a primary destination. An operator can discover findings
from saved scans, including scans made with ledger tracking disabled, and open
a finding directly from an application, scan, report, or dashboard queue.

The workspace provides a searchable, sortable finding queue; a code/evidence
area; and review/AI-assistance controls. On wide screens, support resizable
panes with remembered sizes. At smaller widths, collapse secondary panes into
accessible views without losing the selected finding or essential actions.

Display application, repository, scanned revision where recorded, scan, and
selected comparison baseline persistently enough to prevent context mistakes.
Support filters for application, scan, severity, evidence assessment, human
review state, file/path, and new/regressed status when comparison data permits.
Allow named saved filters and a clear way to reset filtering. Empty search
results must be distinguishable from an application with no findings.

Stable finding links must reopen the same scan-specific finding. Browser
back/forward and navigation between views must preserve filters, sorting,
selection, and queue position. Provide accessible next/previous controls and
document any optional keyboard shortcuts. Changing Table/List view must not
discard context. Missing or deleted linked records receive a useful state and
a route back to the remaining history.

#### P1: Inspect evidence and make a durable, defensible decision

Show readable, syntax-highlighted source with line numbers and highlighted
locations. Provide surrounding function/context where available. Bind excerpts
to the scanned revision or captured source; never substitute the current
working tree silently. If the recorded revision or source cannot be retrieved,
say so and preserve access to available evidence.

Show the finding's entry point, attacker-controlled input, relevant flow,
dangerous operation, preconditions, reviewed guards/sanitizers, impact,
rationale, and remediation guidance. A clickable source-to-sink trace is
appropriate where supported by evidence; authorization and business-logic
findings must also be reviewable without an artificial injection-style trace.
Distinguish observed references, model inferences, syntactic leads, and missing
evidence. Every claimed source citation must resolve or be explicitly marked
unavailable or invalid. Long generated prose must not obscure key evidence.

Keep four independent finding dimensions visible and explained:

1. Severity and its recorded basis.
2. Evidence assessment: supported, rejected, unresolved, or unknown.
3. Human review disposition: needs review, investigating, accepted risk,
   dismissed, or resolved.
4. Reproduction state: not requested/attempted, authored but not executed,
   deferred, attempted with an inconclusive or failed outcome, or reproduced
   with recorded execution evidence.

Map existing terms explicitly during planning. Do not invent new certainty
from a legacy state or use an unsupported numeric confidence score. A failed
execution does not by itself refute a vulnerability; authored code does not
establish successful execution.

Allow the operator to save notes and a review disposition with rationale;
require rationale for dismissal, accepted risk, or resolution. Decisions must
survive refresh and server restart and retain an inspectable change history.
Allow a later decision to supersede an earlier one without erasing history.
Human decisions do not overwrite the original scan evidence or AI verdict.
Use stable identities to relate findings across scans where supported; do not
silently carry a dismissal across materially changed evidence. Define conflict
behavior so a stale browser cannot silently overwrite a newer decision.

Provide baseline comparison showing new, recurring, and regressed findings,
evidence differences, and relevant provenance where supported. An absent
finding in a partial or incomparable scan must not automatically become fixed.
Use explicit unknown/incomparable states when identity, scope, or coverage
cannot support the conclusion. No invented historical data or automatic
expensive rescans to fill missing information.

#### P1: Understand scan completion and reach every available artifact

Show requested stages and recorded stage outcomes, with useful failure or
degradation reasons. Distinguish queue/job termination from execution status,
coverage status, and validation mode. Carry the constitution's three status
axes on each run-status surface, or mark missing axes unavailable. Never infer
coverage or dynamic validation from a green completion label.

Provide an artifact manifest accessible from scans, reports, and application
history. Include the findings report, threat model/report, SBOM, and generated
verification/remediation material appropriate to that run. Distinguish not
requested, pending, available, failed, missing, unreadable, malformed, and
unknown historical states as applicable. Availability requires validated
material, not just a filename or successful process exit.

Allow available artifacts to be viewed and downloaded. Missing optional
artifacts must not hide other results. Partial and interrupted scans retain
their usable outputs and explain unfinished work. Resume/retry actions must
describe their scope, require an explicit operator action, and appear only
where supported; do not silently rerun work while loading a page.

Across the workspace, applications, scans, ledger, reports, and dashboard,
distinguish initial loading, empty, filtered-empty, refreshing, stale,
disconnected, and failed states. Failed detail requests must leave loading and
offer a retry. Failed refreshes must preserve usable prior data with a stale
indicator. Late responses must not replace another application's or finding's
current selection. Failed mutations must not appear saved or deleted.

#### P2: Add actionable dashboard queues below the preserved dashboard

Append "Needs attention" with navigable queues for:

- Supported Critical/High findings awaiting review.
- New supported Critical/High findings relative to a selected comparable
  baseline, with an explicit no-baseline state when appropriate.
- Unresolved findings requiring review or additional evidence.
- Regressions supported by comparable scan history.
- Incomplete/interrupted scans and requested artifacts that failed or are
  missing.
- Applications whose latest scan is older than an operator-selected age
  threshold; default to seven days and make that assumption visible/editable.

Each queue shows its scope, definition, count, and a link opening the matching
filtered destination. Display unknown/unavailable data honestly rather than
zero. Define counting and deduplication across scans so the same item does not
inflate a queue unintentionally. Time staleness is not proof of incomplete
coverage; show scan revision mismatch separately when it is known.

The new section must fail independently: unavailable queue data must not blank
or block the existing dashboard metrics. Its filters must not silently change
the population used by the existing numbers and charts.

#### P2: Use AI assistance in the context of the selected finding

Provide contextual actions to explain the flow, look for mitigating checks,
challenge the finding, draft a regression test, and propose a fix. Bind each
request and response to the selected finding, scan revision, and supplied
evidence. Show actual provider/model provenance and source citations, and
label generated analysis and drafts distinctly from recorded scan evidence.

Before submission, make the selected provider and local/external destination
clear. Source transmission and paid/cloud use must follow explicit operator
configuration. No silent provider/model fallback. Failures, bounded retries,
and cancellation must be visible; revisiting a finding must not resubmit a
request. Navigating to another finding must not misattach an in-flight result.

Draft tests and fixes are reviewable artifacts/diffs. They do not execute
target code, install dependencies, modify the working tree, or update finding
severity/disposition automatically. Executing tests or applying patches is
outside this feature's required scope; existing explicitly authorized isolated
execution capabilities must retain their safeguards. Treat repository text
and AI output as untrusted content, not instructions authorizing extra tools,
network destinations, or state changes.

Deliver real behavior and persistence for the specified contextual actions.
If a provider or historical record cannot support an action, explain the
limitation. A permanently disabled button or canned response is not completion
of the contextual-assistance requirement.

#### P2: Modernize navigation, configuration, and interaction consistency

Use a collapsible primary sidebar with Overview/Dashboard, Applications,
Findings, and Scans prominently accessible. Keep Reports and Activity
accessible as secondary destinations and Docs/Settings discoverable. Preserve
existing links or provide equivalent redirects. Maintain application and scan
context while moving between related views. Do not ship newly advertised
settings as empty placeholders.

Use the existing visual foundation to establish consistent spacing, readable
typography, semantic colors, focus styles, tables, forms, dialogs, and empty
states. Support light and dark themes. Favor restrained hierarchy and useful
density; preserve the operator's Table/List choices. Provide text/icon cues in
addition to color. Replace native prompt/confirm interactions with consistent
dialogs that preserve confirmation semantics and restore focus correctly.

Make navigation, finding selection, tabs, pane controls, sorting, filtering,
dialogs, and review actions operable by keyboard with visible focus and
meaningful accessible names. Tabs require proper focus movement and associated
panels. Respect reduced-motion preferences. At narrow widths and zoomed text,
avoid page-wide overflow or inaccessible actions; source and data regions may
scroll within their own labeled containers.

Make scan setup understandable: identify repository and revision when known,
analysis scope, inference provider/model, and requested outputs. Provide
presets that expand visibly to supported settings, with advanced controls
available. Use user-facing labels instead of implementation terms such as
"Write remediation DTOs". Do not invent time/cost estimates or imply a preset
guarantees complete coverage. Preserve existing role/model configuration and
reject unsupported settings explicitly. Show a review of effective choices
before launch, including output expectations and inference destination.

Application details must keep scan history, findings, threat material, and
SBOMs connected. Where recorded evidence supports a relationship, allow a
threat or component to lead to its related findings. State when no reliable
mapping exists rather than inventing links. Reports remain readable/exportable
audit artifacts backed by the same canonical data used in the workspace.

### Scope, assumptions, and constitution impact

This is one product feature delivered in independently testable increments.
Prioritize a complete saved-finding review flow and trustworthy scan/artifact
states before expanding contextual AI and visual refinements. All requested
journeys remain in scope; mark unfinished increments explicitly.

Backend support required for evidence access, durable review decisions,
comparison, contextual AI, or honest aggregate/status information is in scope.
Do not implement frontend-only mock success. Preserve existing artifact and
report formats where possible; use explicit compatibility handling for older
records without rewriting original evidence.

No changes to scanner detection algorithms, artificial improvements in
supported-finding rates, new SaaS accounts, multi-user authorization system,
third-party issue integrations, or full legacy-UI rewrite are required. Use
the current local-operator model and do not invent authenticated reviewer
identities. Any necessary operator attribution must be clearly described.

Preserve the static-only default, independent status axes, engine-recorded
provenance, explicit provider failures, and resumability/idempotency rules.
The interface and exported reports remain self-contained/offline-capable with
no CDN or unconfigured network requests. Opening untrusted code, Markdown,
diagrams, or artifacts must not execute embedded content. Preserve repository
and artifact path containment. Development/test tooling dependencies are
distinct from dependencies required by the delivered application.

### Acceptance scenarios and measurable outcomes

Translate these into prioritized Given/When/Then scenarios, numbered
requirements, and measurable success criteria in the generated specification:

1. **Dashboard preservation:** With the same seeded history, every pre-existing
   metric, chart, model breakdown, and latest-scan action remains available in
   its prior relative order with unchanged values/semantics. All new queues
   render below them. A queue failure leaves existing content usable. Cover
   zero scans and runs with missing usage/timing as well as populated history.
2. **Findings without ledger:** A saved scan with ledger disabled exposes its
   findings, source/evidence, and review controls. Saving a decision survives
   browser reload and service restart without enabling/recreating a ledger or
   altering the saved scan evidence.
3. **Complete review flow:** An operator filters a queue, opens a finding,
   follows an available source citation, records a decision and rationale,
   opens an artifact, and returns to the same queue position. Repeat for ten
   findings without lost context or decisions. A copied finding link and
   browser back/forward restore the intended finding and scope.
4. **Evidence honesty:** Supported, rejected, unresolved, unknown, authored-only,
   deferred, failed-execution, and executed-reproduction examples remain
   distinguishable. A missing source revision is reported; current code is not
   substituted silently. No inference-only trace is displayed as observed.
5. **Comparison honesty:** Comparable fixtures show known new/recurring/regressed
   examples correctly. A partial scan missing an earlier finding does not mark
   it fixed. Changed evidence does not silently inherit dismissal. Conflicting
   review updates are surfaced without silently losing the newer decision.
6. **Status/artifact matrix:** Complete, partial, failed, cancelled, interrupted,
   and historical-unknown runs retain independent execution/coverage/validation
   information. Requested, unrequested, pending, valid, missing, unreadable,
   malformed, and failed artifact cases show the correct state and preserve
   access to other outputs. An unsuccessful detail fetch leaves loading and
   presents retry; out-of-order responses do not corrupt the active view.
7. **Queue accuracy:** Each new dashboard count matches its filtered destination
   for a fixed history, baseline, scope, and age threshold. Include duplicate
   occurrences, no baseline, unavailable data, and stale applications.
8. **Contextual AI:** Offline provider fixtures exercise all five actions,
   citation/provenance display, navigation during generation, failure, and
   cancellation. Results attach to the correct finding/revision and remain
   retrievable. No action silently executes code, changes findings, applies a
   patch, or reaches a different provider. Saved drafts are distinguishable
   from execution evidence.
9. **Existing workflows:** Applications, Ledger, and Reports retain their
   Table/List behavior and preferences. Existing delete/forget confirmations
   preserve reports and unrelated data. Known report/finding links either
   resolve or show a useful missing-record state.
10. **Usability/accessibility:** Run the main review flow by keyboard alone and
    in both themes at 1440px, 1024px, and 390px viewport widths, plus desktop at
    200% zoom. Essential controls remain reachable, focus is visible and
    restored after dialogs, and secondary panes collapse appropriately. Verify
    accessible names, tab behavior, contrast, and reduced-motion handling.
11. **Responsiveness:** With a documented local fixture of 1,000 findings,
    changing filters, selecting a finding, and moving to the next finding each
    display the requested local result within two seconds on the recorded
    acceptance machine, excluding live inference. Record measured results;
    these are acceptance targets, not claims about current performance.
12. **Delivered application:** Validate against the actual built frontend served
    by the Go application, including direct-link reloads and restart. Record
    build provenance and browser console/network failures. Run offline
    regression tests and browser scenarios with deterministic fixtures; no live
    paid model or multi-hour scan is required for acceptance. Explicitly report
    any skipped checks instead of counting them as passed.

The fixture set should include multiple applications, multiple scans for one
application, a ledger-disabled scan, older incomplete metadata, source revision
mismatch, unavailable source, legitimate empty results, malformed material,
provider failure, and untrusted rendered content. Use existing compatible
fixtures where possible. Keep original reports and application/ledger data
intact. Record outstanding gaps rather than substituting screenshots or
successful builds for working behavior.

### Required Spec Kit output and implementation handoff

Create the feature specification and a separate requirements quality checklist
using the repository's active templates. Define key entities and relationships
for finding occurrences, review decisions/history, evidence references,
comparison baselines, artifact states, saved views, and contextual AI results.
Document reasonable assumptions explicitly; do not leave avoidable ambiguity
for engineering.

Keep implementation choices in the subsequent plan. That plan must inventory
existing capabilities, API/persistence gaps, migration/compatibility needs,
frontend build/embedding behavior, component reuse, and offline/browser tests.
Record the dashboard preservation baseline before changing its presentation.
Identify overlaps with features 007–009 and preserve their accepted behavior.

Generate dependency-ordered tasks that deliver the first complete review
workflow early. Every increment needs its acceptance evidence, including
negative/degraded cases. Update user-facing documentation for changed workflows
and provide a completion matrix of delivered, verified, and remaining work.
Specification completion is readiness for planning, not a claim that the
application has been implemented or browser-validated.

## Author review of this handoff

- The dashboard override explicitly preserves numbers, charts, ordering, and
  behavior, with additions below existing content.
- Features 008 and 009 remain dependencies and preservation constraints.
- Requirements cover the six recommendations, including genuine backend work
  where UI-only implementation would be insufficient.
- Review dispositions, evidence assessments, reproduction, and run status axes
  remain distinct; original evidence is preserved.
- Acceptance includes offline fixtures, degraded cases, browser workflows,
  build provenance, persistence, and accessibility.
- This review checks the handoff's content only. Claude must generate and
  validate the formal feature specification and checklist in its specify step.
