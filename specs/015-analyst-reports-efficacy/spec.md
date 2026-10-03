# Feature Specification: Actionable analysis reports and measured scan efficacy

**Feature Branch**: `015-analyst-reports-efficacy`

**Created**: 2026-09-29

**Status**: Draft

**Input**: User description: "Actionable analysis reports and measured scan efficacy (from
`docs/engineering/2026-09-29-analyst-reports-efficacy-speckit-specify.md`, the entire 'Specification input'
section including US8 and acceptance criteria 10–13) — operators must understand a scan's supported risks and
limitations quickly, navigate readable evidence and threat-model diagrams, and distinguish actual analytical
coverage and detection quality from activity counts; engineers must receive a prioritized remediation list
with traceable evidence rather than a dump of every candidate and agent operation. Preserve dashboard metrics,
saved results, review decisions, and features 012–014; incorporate (do not replace) the citation-repair work."

## Overview

The first full live run on the feature-014 binary (`843875fb0919`, gpt-oss:120b, ≈3 h) produced honest
records and an unusable analyst deliverable. Its report opened with 121 failed-candidate explanations and
438 agent rows before the findings summary (Markdown line 621); headline severity totals counted all 171
candidates although only 43 were supported; two threat models contained Mermaid the shipped renderer
rejects; the coverage ledger said 100/100 reviewed with 93 "no issue" dispositions earned by a validated
deliverable plus a file read overlapping the handler — no handler-specific analytical conclusion; repeated
samples of the same defect (pickle, XSS, XXE, NoSQL) appeared as separate supported findings; the newly
running scan had no application row until its final metadata existed; and 113 verification sessions ended
without a decision, mostly on citation contract violations the verifier's interface could not correct.

**Observations rechecked against the current source and saved records (2026-09-29, read-only; no scan,
model, regeneration, server restart or target code was run):**

| Claim | Result | What the code / records show |
|---|---|---|
| Report order buries the summary | **Verified** | Rendered order is scan summary → run status → completion (with every failed candidate listed inline) → review coverage → per-phase agent table → findings summary → findings. The live report's `## Summary` is at line 621. |
| Severity totals are candidate-wide | **Verified** | The document's severity counts are computed over all non-duplicate findings (171: High 69, High+ 25, Medium 70, Low 6, Unrated 1); only 43 are supported. |
| Threat-model diagrams contain invalid Mermaid | **Verified** | The live `threat_model.md` line 48 reads `B -.->|HTTP request (untrusted) .-> E` (missing label delimiter); both UIs render the file as-is with a generic syntax-error fallback and no diagram-specific state. |
| "Reviewed, no issue" is earned without an analytical conclusion | **Verified** | Disposition rule: a valid unit deliverable **and** any `Read` span intersecting the handler span ⇒ `reviewed_no_issue`. A single 400-line read across many handlers satisfies all of them; no per-handler rationale, checks or unresolved questions are required. |
| Equivalent findings are not grouped | **Verified** | Only exact-duplicate collapsing exists (`duplicate_of`); no root-cause/anchor/fix-based remediation groups. |
| Efficacy is measured by a class/keyword scorer | **Verified** | The bundled scorer matches by CWE family or a family word in the finding text plus a location hint over **all** findings; a rejected or unresolved candidate satisfies "recall". |
| A running scan has no application until final metadata | **Verified** | Applications are registered at finalize; report discovery requires a results-named directory or a deliverable, so the provisional directory appears only as a report row, not under an application, until the run ends. |
| Verifier failures are attributable to the model | **Refuted as established** | The submission tool cannot amend the original candidate location; 45 of 113 decision-less sessions ended on "candidate needs an exact source location" and 29 on entry-point mismatch — inputs the verifier could not correct through its interface. 17 of 27 turn-limit sessions also carry other failure classes; the summary events reuse the session's last operation/message for every class. |
| Prompt records are complete transcripts | **Refuted** | 4,745 of 4,784 records are `truncated:true` (8 KB clamp at write time); the stored record is telemetry, not a replayable transcript, and truncation is in storage, not in what the model received. |
| Go recognizer treats `url.Values.Get("q")` as a route | **Verified (open)** | Feature 014 documented the false positive and avoided the construct in its fixture; the recognizer defect itself is not fixed. |

This feature repairs those gaps as **real, evidenced behavior** in two workstreams: (A) reports and
threat-model usability (US1–US3), independently deliverable; (B) review integrity and measurable efficacy
(US4–US8). The feature is complete only when both workstreams pass. It is a focused repair of analyst
workflows and evidence quality — not a UI redesign, and not a promise to detect every vulnerability.
Static-only, source read-only, artifact access confined, all tests isolated from operator storage,
`../vhlocal` read-only; no in-flight scan is interrupted and no paid/live-model call is a side effect of
specification, report viewing or regeneration.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - An executive summary before diagnostic detail (Priority: P1)

An operator opens a finished report and, immediately below the title and a concise run-status warning,
reads a compact executive summary: the target and revision, the principal supported risks, the affected
surfaces, the prioritized actions, and the material limitations — at most 300 narrative words and at most
five leading issues/actions, each linking to the complete list. Summary metrics and a prioritized findings
index follow. Candidate lists, agent rows and expanded diagnostics come later. A scan with no supported
findings and incomplete work says so prominently instead of reading as clean.

**Why this priority**: The report is the product. Today the first 600 lines are failure diagnostics and the
headline severity totals over-count by 4×; an engineer cannot tell what to fix.

**Independent Test**: Render a large fixture matching the live baseline (171 candidates: 43 supported /
7 rejected / 121 unresolved; 438 agent rows) to Markdown, standalone HTML, the main UI and the React app;
assert the opening narrative ≤ 300 words with ≤ 5 leading items, the labelled totals visible before any
diagnostic section, and severity totals summing to 43.

**Acceptance Scenarios**:

1. **Given** the 171-candidate fixture, **When** the report is rendered on any surface, **Then** the
   executive summary appears directly under the title and one concise run-status line, contains the
   target/application and revision, ≤ 300 narrative words, ≤ 5 leading issues/actions each linked to its
   finding, and the labelled counts supported 43 · remediation groups · rejected 7 · unresolved 121 ·
   total candidates 171 · execution status · source-review coverage · validation mode — before any
   candidate list, agent row or expanded diagnostic.
2. **Given** the same fixture, **When** severity totals are shown, **Then** they count supported findings
   only (sum 43) with Unrated shown explicitly, and candidate-wide severity statistics remain available
   under an unambiguous "candidates" label.
3. **Given** a scan whose job terminated but whose execution is partial, **When** the summary renders,
   **Then** it never states or implies successful completion, and "supported by static reasoning" is never
   presented as an executed exploit.
4. **Given** a scan with zero supported findings and incomplete phases, **When** the summary renders,
   **Then** the limitation is the first statement of the summary, not "no vulnerabilities found".
5. **Given** the same warning applies to several sections, **When** the report renders, **Then** the long
   failure explanation appears once (in its diagnostics section) and other sections carry a one-line
   reference, not a repeat.
6. **Given** an AI narrative is enabled, **When** the summary is produced, **Then** every fact in it is
   drawn from validated records, every reference is validated, and a deterministic non-model summary is the
   fallback; **Given** no model is available, **When** a report is viewed or regenerated, **Then** it
   succeeds with the deterministic summary at zero inference cost and invents no impact, exploitability,
   severity or completeness.

---

### User Story 2 - A navigable remediation report with progressive detail (Priority: P1)

An engineer works down a prioritized findings index — searchable, filterable by severity and status, with
stable anchors and keyboard navigation — opening compact rows into structured finding details (impact,
attacker prerequisites, source-to-sink reasoning, reviewed defenses, captured source excerpts as readable
code with file/line attribution, recommended fix, reproduction status). Rejected and unresolved candidates
and per-agent execution diagnostics stay available in separate searchable views or appendices. Content and
counts are identical across the main UI, the React app, standalone HTML, Markdown and print/PDF.

**Why this priority**: Hundreds of candidates must not require scrolling through execution records to find
the risks; today evidence is a prose wall or a bare locator, and formatting/links break in-app.

**Independent Test**: With the 171-candidate fixture, browser tests on both UIs exercise filtering,
search, keyboard navigation, anchor links, collapsed-by-default details, reading-position preservation
across refresh and scan switching, loading and error states; exports are compared for section order,
counts, code formatting and declared scope.

**Acceptance Scenarios**:

1. **Given** the fixture report, **When** it renders, **Then** sections appear in this order: executive
   summary and outcome metrics → prioritized findings/remediation index → individual finding details →
   coverage and limitations → candidate investigation appendix → execution diagnostics appendix.
2. **Given** the findings index, **When** the engineer filters by severity or status or searches, **Then**
   matching rows show issue, severity, affected surface, evidence status and recommended action (where
   known); rows are compact and details collapsed by default; every row has a stable anchor reachable by
   keyboard; an active filter is disclosed in the view and in any export made from it.
3. **Given** a finding detail, **When** opened, **Then** impact, attacker prerequisites, source-to-sink
   reasoning, reviewed defenses, captured source evidence, recommended fix and reproduction status are
   separately labelled; captured excerpts render as escaped code with file/line attribution; a missing fix
   or missing evidence is stated explicitly, never fabricated.
4. **Given** rejected and unresolved candidates, **When** the engineer opens their views, **Then** each is
   listed with its reason and investigation action; a failed verification session is visibly distinct from
   an explicit unresolved decision; no candidate is removed to improve readability.
5. **Given** execution diagnostics, **When** the main report renders, **Then** execution is summarized per
   phase, and per-agent turns, tokens, raw errors and all artifact records are available on demand.
6. **Given** the report in the main UI, React app, standalone HTML, Markdown and print/PDF, **When**
   compared, **Then** summary order, counts and content match; Markdown uses compact indexes and linked
   appendices; print/export declares summary-versus-full scope, preserves readable code, tables and page
   breaks; standalone exports work offline with correct relative links; evidence/artifact links inside the
   app resolve through the owning report's file endpoint.
7. **Given** model-authored content containing nested lists, blockquotes, code fences or executable
   markup, **When** rendered, **Then** formatting is correct, content is escaped, links are validated and
   nothing model-controlled executes.
8. **Given** the engineer refreshes or navigates between findings and scans, **When** they return,
   **Then** reading position and selected findings are preserved and a stale response never overwrites the
   current view.

---

### User Story 3 - Threat-model diagrams that render reliably (Priority: P1)

An operator opening a threat model sees each diagram either rendered from a validated structure or replaced
by an honest, readable fallback — the narrative, a node/flow table, a diagram-specific actionable error, and
retry/source controls — never a generic syntax-error image in place of the content and never "valid"
merely because the file exists.

**Why this priority**: Both inspected threat models failed to render; the operator lost the whole
artifact's value to one malformed edge.

**Independent Test**: A regression corpus (missing node brackets, missing edge-label delimiters, inline
comments, quotes, parentheses, Unicode, multiple diagrams per file, malicious label content, and the audited
edge `B -.->|HTTP request (untrusted) .-> E`) is validated with the renderer version actually shipped;
each case either renders or produces the specified fallback; repairs are checked for topology preservation.

**Acceptance Scenarios**:

1. **Given** a threat model with a diagram, **When** it is generated or opened, **Then** the diagram is a
   validated artifact with explicit states (available/valid, invalid with error, repaired with history,
   missing), whose nodes, directed flows and trust boundaries are represented structurally with stable
   identifiers and source references where established, serialized deterministically.
2. **Given** the audited malformed edge, **When** the compatibility path processes it, **Then** a safe
   formatting repair is applied only if the intended structure is unambiguous; otherwise the diagram is
   marked invalid with the exact line and reason and the fallback table/narrative is shown — an edge is
   never guessed.
3. **Given** any repair or normalization, **When** applied, **Then** the original output and the repair
   history are preserved and inspectable, and the repair never invents a relationship or changes the meaning
   of one.
4. **Given** one of several diagrams fails, **When** the threat model renders, **Then** the other diagrams
   render normally, the failed one shows its own error with retry and view-source controls, and the failure
   is not recorded as permanently complete.
5. **Given** the operator switches application, report or diagram, **When** the view changes, **Then**
   previous render/error state is cleared.
6. **Given** both frontends, light and dark themes, offline operation, zoom and export, **When** a valid
   diagram renders, **Then** behavior is consistent and labels/links from the model are rendered safely.
7. **Given** a label containing script or markup, **When** rendered, **Then** nothing executes and the
   label is shown as text.

---

### User Story 4 - Review coverage that measures completed analysis (Priority: P1)

An operator reads coverage as separate axes — discovered scope, supported inventory, assigned work,
attempted work, source exposure, completed source review, finding verification — and knows that "reviewed,
no issue" means a handler-specific, structured analytical conclusion was recorded and validated for that
handler at that revision, not that a file read overlapped it.

**Why this priority**: 93 of the live run's 100 "no issue" dispositions were earned by overlapping reads;
the number is the one operators trust most and it currently measures activity.

**Independent Test**: Deterministic fixtures: a 400-line read overlapping many handlers, full handler
reads without dispositions, valid handler-specific dispositions, sibling handlers, missing checks,
fabricated identifiers, stale revisions and non-Python examples; paired 100-valid-reviews/8-findings vs
8-completed-reviews fixtures; legacy regeneration.

**Acceptance Scenarios**:

1. **Given** a unit that reads 400 lines spanning many handlers and writes a valid deliverable, **When**
   coverage is derived, **Then** none of those handlers is `reviewed_no_issue`; the reads count as source
   exposure only.
2. **Given** a unit that reads every handler completely but records no per-handler conclusion, **When**
   coverage is derived, **Then** the handlers are source-exposed but not completed reviews.
3. **Given** a unit that records, for a handler, a structured disposition tied to its assignment, the
   revision, the observed source evidence, the relevant defenses, the applicable weakness checks, a
   rationale and any unresolved questions, **When** validated for scope and evidence, **Then** that
   handler is a completed review; a bare "reviewed everything" claim never is.
4. **Given** a successful injection pass on a handler, **When** authorization, business-logic or other
   planned checks were not performed, **Then** those checks are not implied complete; each is recorded as
   done, explained non-applicable, or unresolved, and aggregation follows the defined rules.
5. **Given** the paired fixtures, **When** derived, **Then** 100 valid reviews with 8 findings report 100
   completed reviews, and 8 completed reviews report 8 even though all 100 handlers were read.
6. **Given** gaps, **When** coverage enforcement is on, **Then** gaps route into the existing bounded
   follow-up honoring scan options, budgets, cancellation and retry limits; no unbounded follow-ups are
   scheduled to reach 100%; partial outcomes are preserved and reasoned.
7. **Given** a record produced under the weaker (feature-014) semantics, **When** it is read or
   regenerated, **Then** it stays readable, is labelled with its coverage-semantics version, and no
   analytical conclusion is synthesized; **Given** an incomplete review, **When** lifecycle reconciles,
   **Then** prior issues are not marked fixed merely because the new scan omitted them.
8. **Given** a completed no-issue review, **When** presented, **Then** it is described as "no issue
   identified within the stated scope", verification status stays a separate axis, and stable
   multi-language source identities are reused.

---

### User Story 5 - Group remediation work without losing evidence (Priority: P1)

An engineer sees one actionable remediation group for multiple samples of the same defect — with linked
occurrences, all candidate identifiers, independent observations, verification decisions and review
history — while genuinely distinct defects on the same endpoint stay separate and uncertain equivalence is
only suggested.

**Why this priority**: Repeated pickle, XSS, XXE and NoSQL candidates inflated the live report and
obscured the fix list; naive merging would destroy evidence.

**Independent Test**: Grouping fixtures built from the observed repeated pickle/XSS/XXE/NoSQL candidates
plus negative controls with distinct defects on one endpoint; raw and grouped counts, anchors, review
decisions and identity are checked before and after regeneration.

**Acceptance Scenarios**:

1. **Given** supported findings sharing source anchors, root cause, attacker preconditions, affected
   scope and required fix, **When** grouped, **Then** one remediation group lists every occurrence with
   its evidence; raw and grouped counts are both reported.
2. **Given** findings that share only a CWE, a similar title, overlapping ranges or a route, **When**
   grouped, **Then** they are not merged; distinct sinks, preconditions, vulnerabilities and fixes remain
   distinguishable.
3. **Given** uncertain equivalence, **When** grouped, **Then** it is a suggested group with the members
   still individually visible; nothing is lost.
4. **Given** regeneration, **When** groups are rebuilt, **Then** group identity is stable, and human
   decisions on a group follow the defined rule when members change (decision stays attached to the
   members it was made on and is flagged, never silently extended to new members).
5. **Given** equivalence established before verification, **When** verification is planned, **Then**
   redundant work is avoided while provenance is preserved, and a supported verdict is never transferred to
   a new source anchor without applicable verification.

---

### User Story 6 - An efficacy benchmark that measures supported detections (Priority: P1)

A maintainer runs a reproducible benchmark over seeded vulnerabilities and safe controls in Python, Go and
JS/TS and reads per-language and per-weakness precision/recall of **supported, deduplicated** detections,
candidate-generation recall, false positives on safe controls, verification acceptance/recovery and terminal
failure causes, completed review coverage, artifact completeness, and time/tokens/cost per unique supported
issue — with explicit denominators, unknowns marked unknown, and run-to-run variation for live experiments.

**Why this priority**: Without a measured baseline, model or prompt changes cannot be judged; the current
scorer credits rejected/unresolved candidates and repeated hits.

**Independent Test**: Offline fake-provider runs over the benchmark fixture prove the scorer and pipeline
(rejected/unresolved/duplicate hits cannot inflate supported precision/recall; safe controls, language and
class breakdowns, ground-truth isolation and configuration comparisons); live-model measurement is a
separately identified operator action.

**Acceptance Scenarios**:

1. **Given** the benchmark, **When** scored, **Then** ground truth identifies source anchors/root causes,
   expected behavior and acceptable matches; it is absent from scan prompts and from the scanned target's
   visible files; seeded/prior-context runs are separated from unseeded runs.
2. **Given** a results set with rejected, unresolved and duplicate detections of a seeded issue, **When**
   scored, **Then** only supported detections count, each unique issue counts once, and denominators are
   explicit.
3. **Given** a safe control, **When** a supported finding is reported on it, **Then** it counts as a false
   positive in the per-language/per-class breakdown.
4. **Given** a frozen baseline, **When** published, **Then** it records target revision, build, effective
   options, models/providers, prompts, sampling, seeds and budgets, and the regression policy is versioned
   against it without asserting an unsupported quality threshold or universal detection rate.
5. **Given** the newest completed run and the audited baseline, **When** compared, **Then** configuration
   and build differences are accounted for and disclosed first; cost is reported as unknown where not
   priced; variation across repeated live runs is reported rather than one run presented as a guarantee.
6. **Given** ordinary tests, **When** run, **Then** no remote model call and no target execution occurs;
   any live evaluation not performed is labelled "not run".

---

### User Story 7 - Stable application identity while scans run (Priority: P2)

An operator watching a running scan finds its provisional report, threat model and SBOM under the same
application as the eventual final report — through running, completion, cancellation and restart — with no
duplicate application created and no unrelated repositories merged by display name.

**Why this priority**: Important for trust in the application hub, but the data is recoverable after the
run; the P1 stories change what the analyst reads.

**Independent Test**: A live-scan lifecycle fixture (created → running with provisional artifacts →
restart → completion/cancellation) is checked for one canonical application throughout; two repositories
with the same display name remain separate; older artifacts keep their provenance.

**Acceptance Scenarios**:

1. **Given** a scan is created, **When** its provisional results appear, **Then** they are attached to
   the canonical application identity persisted at creation, before any final metadata exists.
2. **Given** the scan completes, is cancelled, or the server restarts mid-run, **When** the application
   history is viewed, **Then** the same application lists the run once; no second application was created.
3. **Given** two different repositories with the same display name, **When** listed, **Then** they remain
   separate applications.
4. **Given** historical reports with ambiguous mapping, **When** migrated or displayed, **Then** the
   ambiguity is explicit and nothing is destructively guessed; existing names, reports and review data are
   preserved.

---

### User Story 8 - Diagnose verifier failures before attributing them to the model (Priority: P1)

A maintainer can tell, for every verification failure, whether it was malformed upstream candidate data, a
tool/schema or repair-interface defect, a model contract violation on valid input, a substantive lack of
evidence, a provider failure, or a session stop — with the actual operation, diagnostic arguments,
validation feedback and repair outcome recorded per attempt. Malformed original citations are caught before
expensive verification, receive actionable feedback, and can be corrected through the real ingestion and
amendment path without weakening evidence rules. Controlled, operator-triggered comparisons of prompts and
verifier models use frozen inputs and honest denominators.

**Why this priority**: 113 of 171 live sessions produced no decision, dominated by errors the verifier
could not fix through its interface; attributing that to the model would send tuning effort to the wrong
place. The citation-repair handoff's requirements are adopted here as explicit requirements unless already
satisfied with passing regression evidence.

**Independent Test**: Deterministic fake-provider fixtures reproduce each audited malformed citation,
mixed-failure sessions, and prompt/model comparisons over a frozen candidate set; diagnostics are replayed
offline; the Go inventory negative example is tested alongside genuine registrations.

**Acceptance Scenarios**:

1. **Given** a hunt output with a malformed original citation (each audited example), **When** ingested
   through the production path, **Then** unambiguous formatting is normalized with provenance, ambiguous
   or disjoint input receives field-specific feedback identifying candidate/submission, operation, field,
   error code, received value, expected contract and repairability, and the candidate is not sent to
   expensive verification until valid.
2. **Given** a valid, source-grounded amendment of an original citation, **When** submitted through the
   amendment path, **Then** original and amended citations, reason, revision, agent, attempt and validation
   outcome are retained; identity is preserved only under the documented same-anchor rule; a move to a
   different handler/anchor requires renewed evidence validation and inherits no supported decision; a
   perfect verdict alone cannot bypass invalid original evidence; persistent or ambiguous errors remain
   explicitly unresolved.
3. **Given** a session with an argument error followed by a submission error that ends at the turn limit,
   **When** recorded, **Then** each failure carries its own class, operation, message and attempt; neither
   receives the other's explanation; aggregates report occurrences, affected sessions, final stop reasons
   and successful explicit unresolved decisions as distinct, disclosed-overlap numbers.
4. **Given** the verifier's instructions, **When** tested with fixtures, **Then** they include worked
   examples of canonical citations, handler identities, complete required evidence, supported/rejected/
   unresolved decisions and correction after an error; canonical source/handler facts are supplied by the
   harness where available; an explicit unresolved decision is accepted as evidence of uncertainty and is
   neither a confirmation nor a reason to suppress the candidate.
5. **Given** a frozen candidate set and target revision, **When** the operator triggers a comparison
   (existing vs coached prompt on one model; one prompt on an alternate verifier model/provider), **Then**
   the effective role override is verified to reach every verifier call and is recorded; other
   configuration is held constant where supported and differences are disclosed; accepted supported/
   rejected/unresolved decisions, missing decisions, repair rate, evidence validity, ground-truth accuracy
   and cost/time are compared; a model that submits unresolved for everything cannot pass an efficacy gate on
   contract-compliance counts alone; no particular commercial model is required and source is never sent to
   another provider automatically.
6. **Given** a submission-contract failure, **When** diagnostics are saved, **Then** the complete failing
   submission, its exact validation feedback, tool-schema and prompt versions/hashes, and the source
   references needed for bounded offline replay are persisted with redaction; shared prompt content is
   deduplicated; a bounded, explicit diagnostic-capture mode exists for full sanitized context; retention and
   size limits never discard the decisive fields; full content is distinguished from previews; unrecoverable
   truncation is declared; telemetry truncation is never described as model-context truncation; no
   credentials or hidden model reasoning are persisted.
7. **Given** Go source using `url.Values.Get("q")` beside genuine route registrations, **When** the
   inventory is built, **Then** the data access is not a route and creates no HTTP review assignment, the
   genuine registrations are recognized, and legitimately ambiguous/unsupported constructs remain disclosed
   rather than all `Get` methods being excluded.
8. **Given** operator browser attestation and machine-executed browser tests, **When** recorded,
   **Then** attestation carries build, tested URLs, browser/version when known (else "unknown") and
   specific scenarios/results, and is never converted into or conflated with automated verification; a
   documentation change to an unmet contract is disclosed as a scope change.

---

### Edge Cases

- A report with zero candidates, or zero supported findings and complete execution: the summary states
  "no supported findings within the reviewed scope" with the coverage axes, never "clean".
- Supported findings without a recommended fix or without captured evidence: the detail says so; the
  index shows evidence status "missing".
- Severity "Unrated" among supported findings: counted and labelled explicitly in totals.
- A remediation group whose members later split (regeneration with amended anchors): the human decision
  stays attached to the original members and is flagged for review.
- A threat model with no diagram at all, or a diagram fence with an unsupported diagram type: "missing"
  or "unsupported" state with the narrative intact.
- Two diagrams with identical node identifiers in one file: isolated rendering; identifiers namespaced per
  diagram.
- A handler disposition citing evidence from a different revision or a fabricated evidence identifier:
  rejected; the handler stays source-exposed only.
- A handler assigned to a partition whose deliverable was invalid but whose disposition record is valid:
  the disposition is not credited (the assignment failed).
- Benchmark ground truth accidentally present in the scanned target: the run is marked "ground truth
  visible" and excluded from unseeded results.
- Verifier comparison where the alternate model returns unresolved for every candidate: reported as
  "no efficacy improvement demonstrated" regardless of zero contract violations.
- Application identity: a scan created for a repository later renamed by the operator keeps its history
  under the renamed application; a repository path that maps to an existing slug of a different repository
  is disclosed as a collision, not merged.
- Diagnostic capture exceeding the size limit: previews are truncated and declared; decisive fields
  (failing submission, feedback, schema/prompt hashes, source references) are never dropped.
- Report export from a filtered view: the export carries the filter disclosure and the unfiltered counts.

## Requirements *(mandatory)*

### Functional Requirements

**Workstream A — reports and threat-model usability**

- **FR-001**: Every report surface (main UI, React app, standalone HTML, Markdown, print/PDF) MUST place an
  executive summary directly below the title and a one-line run-status warning, before any candidate list,
  agent row or expanded diagnostic, containing target/application and revision, principal supported risks,
  affected surfaces, prioritized actions and material limitations, in ≤ 300 narrative words with ≤ 5
  leading issues/actions linked to the complete list, followed by summary metrics and a prioritized
  findings index.
- **FR-002**: Report counts MUST derive from one shared authoritative report model and MUST separately
  label supported findings, remediation groups, rejected candidates, unresolved candidates, total
  candidates, execution status, source-review coverage and validation mode; severity totals MUST count
  supported findings only with Unrated explicit; candidate severity statistics MUST remain available under
  an unambiguous candidate label.
- **FR-003**: Reports MUST never equate job termination with successful completion nor supported static
  reasoning with an executed exploit; a scan with no supported findings and incomplete work MUST lead with
  the limitation.
- **FR-004**: Summary facts MUST derive from validated records and link to their evidence; if AI narrative
  is used it MUST be constrained to those facts with validated references and a deterministic fallback;
  viewing or regenerating a report MUST NOT require model availability, incur inference cost, or invent
  business impact, exploitability, severity or completeness. The same warning and failure explanation MUST
  NOT be repeated across sections.
- **FR-005**: Reports MUST follow the order: executive summary and outcome metrics → prioritized
  findings/remediation index → finding details → coverage and limitations → candidate investigation
  appendix → execution diagnostics appendix.
- **FR-006**: The findings index MUST offer search, severity/status filters, stable anchors and keyboard
  navigation; rows MUST show issue, severity, affected surface, evidence status and recommended action
  where known; interactive views MUST default to compact rows and collapsed details; reading position and
  selection MUST survive refresh and navigation; a stale response MUST never overwrite the current view.
- **FR-007**: Finding details MUST separate impact, attacker prerequisites, source-to-sink reasoning,
  reviewed defenses, captured source evidence (escaped code with file/line attribution), recommended fix
  and reproduction status, and MUST state missing remediation/evidence explicitly.
- **FR-008**: Rejected and unresolved candidates MUST remain available in separate searchable views or
  appendices with reasons and investigation actions; failed verification sessions MUST be distinguishable
  from explicit unresolved decisions; no candidate is removed for readability. Execution MUST be
  summarized per phase in the main report with per-agent turns, tokens, raw errors and artifact records on
  demand.
- **FR-009**: Content and counts MUST be consistent across all surfaces; Markdown MAY use compact indexes
  and linked appendices; print/export MUST define summary-versus-full scope, preserve readable code, tables
  and page breaks, disclose active filters, keep correct relative links, and remain useful offline; in-app
  evidence/artifact links MUST resolve through the owning report's file endpoint.
- **FR-010**: Rendering MUST fix nested-list/blockquote/code formatting, support keyboard navigation and
  sensible heading structure, show visible errors, perform on large reports, escape model content and
  validate links; no model-controlled markup may execute.
- **FR-011**: Threat-model diagrams MUST be validated artifacts with explicit availability and error states,
  structurally represented (nodes, directed flows, trust boundaries; stable identifiers; source references
  where established), deterministically serialized and validated with the renderer version actually
  shipped; narrative, structure and rendering state MUST be distinguishable.
- **FR-012**: Diagram formatting MUST NOT invent relationships or change their meaning; original output and
  normalization/repair history MUST be preserved; existing Mermaid MUST be supported through a bounded
  compatibility path that distinguishes safe formatting repair from ambiguous structural change and prefers
  an honest fallback over guessing; an unparseable diagram MUST never be labelled valid because the file
  exists.
- **FR-013**: On diagram failure the system MUST retain the narrative and an accessible node/flow table,
  show a diagram-specific actionable error with retry and view-source controls, not mark the failure
  permanently complete, isolate it from other diagrams, and reset render/error state when application,
  report or diagram changes; both frontends MUST be consistent and support offline rendering, light/dark
  themes, zoom and export with safe rendering of model-controlled labels/links.
- **FR-014**: Diagram regression inputs MUST include missing node brackets, missing edge-label delimiters,
  inline comments, quotes, parentheses, Unicode, multiple diagrams and malicious labels, including the
  audited edge `B -.->|HTTP request (untrusted) .-> E`.

**Workstream B — review integrity and measurable efficacy**

- **FR-015**: Coverage MUST report separate axes — discovered scope, supported inventory, assigned work,
  attempted work, source exposure, completed source review, finding verification — reusing the existing
  multi-language inventory and stable source identities, never promoting one axis into another.
- **FR-016**: A handler MUST be credited as `reviewed_no_issue` only by a validated, structured disposition
  tied to its assignment, revision, observed source evidence, relevant defenses, applicable weakness
  checks, rationale and unresolved questions; an overlapping read plus a valid deliverable, a full read
  without a conclusion, or a bare "reviewed everything" claim MUST NOT credit it. Reads MUST still count as
  source exposure.
- **FR-017**: Completion of one weakness pass MUST NOT imply completion of other planned checks; each
  check's applicability and outcome (done, explained non-applicable, unresolved) MUST be recorded and
  aggregated by defined rules; a no-issue review MUST be described as scoped, with verification status a
  separate axis.
- **FR-018**: Gaps MUST route into the existing bounded coverage enforcement honoring scan options,
  budgets, cancellation and retry limits; no unbounded follow-ups; partial outcomes preserved.
- **FR-019**: Coverage semantics MUST be versioned; records under weaker semantics MUST stay readable and
  labelled; regeneration MUST NOT synthesize analytical conclusions; incomplete reviews MUST NOT mark prior
  issues fixed.
- **FR-020**: Potentially equivalent supported findings MUST be grouped by source anchors, root cause,
  attacker preconditions, affected scope and required fix into remediation groups with linked occurrences,
  retaining every candidate identifier, observation, decision and review record, and reporting raw and
  grouped counts; grouping MUST NOT rely solely on CWE, title similarity, overlapping ranges or shared route;
  uncertain equivalence MUST be a suggested group; group identity MUST be stable across regeneration; the
  effect of member changes on human decisions MUST be defined; a supported verdict MUST NOT transfer to a
  new anchor without applicable verification; pre-verification equivalence MAY avoid redundant work while
  preserving provenance.
- **FR-021**: A reproducible efficacy benchmark MUST cover seeded vulnerabilities and safe controls in
  Python, Go and JS/TS with per-language and per-weakness results; ground truth MUST name source
  anchors/root causes, expected behavior and acceptable matches, and MUST be absent from prompts and the
  scanned target's visible files; seeded/prior-context and unseeded runs MUST be separated.
- **FR-022**: The benchmark MUST measure supported deduplicated precision/recall, candidate-generation
  recall, safe-control false positives, verification acceptance/recovery and terminal failure causes,
  completed review coverage, artifact completeness, and time/tokens/cost per unique supported issue, with
  explicit denominators, unknowns marked unknown, and run-to-run variation for live experiments; the scorer
  MUST NOT credit rejected/unresolved candidates or repeated detections.
- **FR-023**: A frozen baseline MUST record target revision, build, effective options, models/providers,
  prompts, sampling, seeds and budgets; a versioned regression policy MUST reference it without inventing
  quality thresholds or a universal detection rate; comparisons with the audited baseline MUST first account
  for configuration and build differences; ordinary tests MUST make no remote model call and execute no
  target code; live evaluations MUST be operator-triggered and labelled "not run" until performed.
- **FR-024**: The canonical application/repository identity MUST be persisted at scan creation so
  provisional and final artifacts share one application history through running, completion, cancellation
  and restart; no second application may be created for missing final metadata; repositories MUST NOT be
  merged by display name; existing names, reports and review data MUST be preserved and ambiguous historical
  mappings kept explicit.
- **FR-025**: Citation validation at the first submission/ingestion boundary, precise field-level feedback
  with bounded correction/resubmission, safe amendment of original candidate citations, and per-operation
  failure records — as specified in the citation-repair handoff — are requirements of this feature unless
  current implementation already satisfies them with passing regression evidence; ingestion MUST be verified
  through the actual hunt-output path; a valid source-grounded amendment MUST permit independent
  verification without weakening evidence rules or silently rewriting identity/history; a perfect verdict
  MUST NOT bypass invalid original evidence.
- **FR-026**: Failures MUST be classified as upstream malformed candidate data, tool/schema or
  repair-interface defect, model contract violation on valid input, substantive lack of evidence, provider
  failure, or session stop; each MUST record its actual operation, diagnostic arguments, validation feedback
  and repair outcome with candidate/call/attempt provenance and redaction; the same final error MUST NOT be
  attached to unrelated classes; sessions and occurrences MUST be counted separately with overlaps
  disclosed.
- **FR-027**: Verifier instructions MUST include tested worked examples (canonical citations, handler
  identities, complete evidence, supported/rejected/unresolved decisions, correction after error); canonical
  source/handler facts MUST be supplied by the harness where available; explicit unresolved decisions MUST
  remain acceptable evidence of uncertainty.
- **FR-028**: Operator-triggered comparisons over a frozen candidate set and revision MUST support existing
  vs coached prompt on one model and one prompt across verifier models/providers, verify and record that the
  role override reaches every verifier call, hold other configuration constant where supported (disclosing
  differences), and compare decisions, missing decisions, repair rate, evidence validity, ground-truth
  accuracy and cost/time; an all-unresolved model MUST NOT pass an efficacy gate on compliance counts;
  no commercial model MUST be required and source MUST NOT be sent to another provider automatically.
- **FR-029**: Diagnostic capture MUST persist complete failing submissions, exact validation feedback,
  tool-schema and prompt versions/hashes and replay source references, redacted; deduplicate shared prompt
  content; offer a bounded explicit full-context capture mode; define retention/size limits that never drop
  decisive fields; distinguish full content from previews and declare unrecoverable truncation; never
  describe telemetry truncation as model-context truncation nor promise full-record expansion when only a
  truncated record exists; never persist credentials or hidden model reasoning.
- **FR-030**: The Go inventory MUST NOT recognize `url.Values.Get("q")` (or other ordinary data-access
  methods) as routes while continuing to recognize genuine registrations and disclosing ambiguous/
  unsupported constructs; regression tests MUST use the real negative example beside genuine registrations.
- **FR-031**: Operator attestation MUST remain a distinct evidence form recording build, tested URLs,
  browser/version when known (else unknown) and specific scenarios/results; repeatable browser tests MUST
  cover report/diagram workflows; attestation and source-string checks MUST never be presented as automated
  UI verification; documentation changes to an unmet contract MUST be disclosed as scope changes.

**Cross-cutting**

- **FR-032**: All existing dashboard metrics/charts, scan options, multi-language support, saved results,
  application names, ledgers, human review decisions, citation-repair functionality and features 012–014
  MUST be preserved with regression coverage; validation MUST exercise the built binary's embedded assets,
  not only frontend source files.
- **FR-033**: Scanning MUST remain static-only and source read-only, artifact access confined, and tests
  isolated from operator storage; specification, report viewing and regeneration MUST NOT interrupt an
  in-flight scan or trigger paid/live-model calls.

### Key Entities

- **Report model**: the single authoritative structure behind every surface — executive summary facts,
  labelled counts (supported, groups, rejected, unresolved, total candidates, execution, coverage,
  validation), findings index rows, finding details, appendices; each fact linked to its record.
- **Remediation group**: stable identity; grouping basis (anchors, root cause, preconditions, scope, fix);
  members (candidate identifiers with occurrences, decisions, review history); status (established or
  suggested); raw vs grouped counts.
- **Diagram artifact**: structural nodes/flows/boundaries with stable identifiers and source references;
  original text; normalization/repair history; validation state (valid, invalid+error, repaired, missing,
  unsupported) against the shipped renderer version.
- **Review disposition (v2)**: assignment, revision, handler identity, observed source evidence, defenses
  reviewed, weakness checks with applicability/outcome, rationale, unresolved questions, validation result;
  coverage-semantics version.
- **Coverage axes**: discovered scope, supported inventory, assigned, attempted, source exposure, completed
  review, verification — per handler and aggregated.
- **Benchmark ground truth & baseline**: seeded issues (anchor, root cause, expected behavior, acceptable
  matches), safe controls, language/class breakdown; frozen baseline configuration; results with explicit
  denominators and run variation.
- **Citation & amendment**: structured citation (path, one-based inclusive range, revision, primary
  location, handler binding); amendment record (original, amended, reason, revision, agent, attempt,
  validation outcome, identity rule applied).
- **Failure record**: class, operation, diagnostic arguments, feedback, outcome, candidate/call/attempt
  provenance; session/occurrence aggregation with overlap disclosure.
- **Diagnostic capture**: failing submission, feedback, schema/prompt hashes, replay references, capture
  mode, retention/size limits, truncation declaration.
- **Application identity**: canonical identity persisted at scan creation; provisional and final artifacts;
  collision/ambiguity disclosure.
- **Comparison run**: frozen candidate set and revision, prompt/model variants, verified role routing,
  disclosed configuration differences, compared outcomes and cost.
- **Attestation record**: build identity, tested URLs, browser/version-or-unknown, scenarios and results.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The 171-candidate / 438-agent-row fixture opens on every surface with an executive summary of
  ≤ 300 narrative words and ≤ 5 leading items, the 43/7/121 breakdown and severity totals summing to 43,
  all before any expanded diagnostic.
- **SC-002**: Every candidate and evidence record in that fixture is reachable through working
  report-bound links; browser tests on both UIs pass for filtering, keyboard navigation, large reports,
  loading/error states and scan switching; HTML, Markdown and PDF outputs preserve summary order, counts,
  source formatting and declared export scope.
- **SC-003**: 100% of diagram regression inputs either render under the shipped parser or show the
  specified readable fallback with an actionable error; no repair alters intended topology silently; one
  failure never breaks another diagram; changing artifacts clears obsolete state; malicious labels never
  execute.
- **SC-004**: A 400-line read overlapping many handlers credits zero completed reviews; full reads without
  dispositions credit zero; valid handler-specific dispositions credit exactly their handlers — across
  sibling handlers, missing checks, fabricated identifiers, stale revisions and non-Python examples.
- **SC-005**: The 100-valid-reviews/8-findings fixture reports 100 completed reviews; the paired
  8-completed-reviews fixture reports 8 with all 100 handlers read; legacy regeneration never upgrades weaker
  evidence.
- **SC-006**: Repeated equivalent detections (pickle, XSS, XXE, NoSQL fixtures) produce one group each with
  all source records retained; distinct defects on one endpoint stay distinct; group/raw counts, decisions,
  anchors and regeneration stay consistent.
- **SC-007**: Benchmark tests prove rejected/unresolved candidates and duplicate hits cannot inflate
  supported precision/recall; safe controls, language/class breakdowns, ground-truth isolation and
  configuration comparisons are tested; the frozen baseline is published and unexecuted live evaluation is
  reported as not run.
- **SC-008**: The live-scan lifecycle fixture stays attached to one canonical application before final
  metadata and after completion/restart; same-name different repositories stay separate; older artifacts
  keep provenance.
- **SC-009**: Existing dashboards, scan options, citation repairs, ledgers, saved results, analyst
  decisions and static-only boundaries keep passing regression coverage, exercised against the built
  binary's embedded assets.
- **SC-010**: A malformed original citation fails before expensive verification with actionable feedback,
  is corrected through the real ingestion/amendment path, and a perfect verdict alone cannot bypass invalid
  original evidence; persistent/ambiguous errors remain explicitly unresolved.
- **SC-011**: A mixed-failure session ending at the turn limit records its argument and submission errors
  separately; aggregates distinguish occurrences, affected sessions, final stop reasons and successful
  explicit unresolved decisions; saved diagnostics reproduce the contract failure despite bounded prompt
  previews.
- **SC-012**: Prompt/model comparison fixtures verify role routing, frozen inputs, honest denominators and
  cost/accuracy accounting; an all-unresolved model fails the efficacy gate; live comparisons are labelled
  not run until performed.
- **SC-013**: `url.Values.Get("q")` creates no route while genuine registrations remain recognized; browser
  acceptance records keep attested and machine-executed scenarios distinct.
- **SC-014**: Viewing or regenerating any report completes with zero model calls and zero inference cost;
  the full test suite makes no remote model call, executes no target code, and leaves operator storage
  byte-identical.

## Assumptions

- The 171-candidate live run (`843875fb0919`) is the acceptance fixture baseline; it will be replayed from
  sanitized records/deterministic doubles, never re-run against a model as part of tests.
- "Narrative words" excludes the metrics block and index; the ≤ 300 / ≤ 5 limits apply to the default
  opening only, with the complete list one link away.
- Workstream A may ship first; the feature is declared complete only when both workstreams' criteria pass.
- The citation-repair handoff's requirements are folded into US8/FR-025–FR-029; where planning finds a
  requirement already satisfied with passing regression evidence, it is recorded as such rather than
  re-implemented.
- Coverage semantics v2 supersedes the feature-014 disposition rule; existing `review_units` records are
  read as v1 and labelled, never rewritten.
- Human review decisions on a remediation group attach to the members present when the decision was made;
  a membership change flags the decision for re-review rather than extending or discarding it.
- Cost per supported issue is reported only where pricing is known (local inference is a real $0; unpriced
  paid backends are "unknown"), consistent with feature 013's budget disclosure.
- Live-model comparisons and browser attestation are operator actions outside the offline gate and are
  reported as such.

## Dependencies & Out of Scope

- Depends on features 012 (multi-language inventory), 013 (scan options, budget disclosure), 014 (evidence
  records, review units v1, completion block, application artifact selection, build identity) — all
  preserved, none replaced.
- Out of scope: a general UI redesign; new scan options; dynamic/exploit execution; any guarantee of
  detection rate; automatic model selection or sending source to a third-party provider; changing SARIF
  semantics; deleting or rewriting historical evidence or decisions.
