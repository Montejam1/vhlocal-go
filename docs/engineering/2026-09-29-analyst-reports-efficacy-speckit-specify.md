# Claude handoff: Analyst reports, reliable diagrams, and measurable scan efficacy

Prepared: 2026-09-29. This document combines the report/diagram usability work
and the scan-efficacy work from the application review. It is input for Claude;
preparing it does not implement changes or change the active feature pointer.

## Start in Claude

```text
/speckit-specify Read docs/engineering/2026-09-29-analyst-reports-efficacy-speckit-specify.md and use its entire "Specification input" section as the feature description. Read the linked audit and citation-repair handoff as supporting context and recheck observations against current code. Create one feature specification and requirements checklist covering analyst-first reports, validated threat-model diagrams, honest review coverage, evidence-preserving finding grouping, measured scan efficacy, and stable application identity. Preserve dashboard metrics, existing results and review decisions, and features 012–014 plus any newer citation-repair implementation. Organize the work into independently testable, prioritized user stories. Stop after specification and checklist generation; do not plan or implement yet.
```

## Supporting evidence

Read [the application review](2026-09-29-report-and-efficacy-review.md) for source
references and audit limitations, and [the citation-repair handoff](2026-09-29-citation-repair-speckit-specify.md)
to avoid duplicating that sprint's work. Inspect current code and feature
artifacts; do not assume an older review describes today's implementation.

The completed baseline `843875fb0919` had 171 candidates: 43 supported, 7
rejected, and 121 unresolved. Its findings summary began at Markdown line 621,
after 121 failed-candidate explanations and 438 agent rows. Its coverage ledger
reported 100/100 reviewed, including 93 no-issue dispositions, but current
coverage derivation accepted overlapping source reads without a handler-specific
analytical conclusion. The report had overlapping supported candidates and
candidate-wide headline severity totals. Both inspected threat models contained
invalid Mermaid syntax. The live run `fb52ee7dc462` was still in Hunt during the
review, so its final efficacy was not assessed.

### Additional review of the feature-014 delivery handoff

The [feature-014 handoff](2026-09-29-scan-reliability-handoff.md) correctly
distinguishes operator browser attestation from machine verification. Its test
results are recorded claims, not tests rerun during this review. The saved
verification records confirm 113 sessions without a decision: 86 repair-limit
stops and 27 turn-limit stops. Forty-five had a final exact-location violation
and 29 a final entry-point mismatch.

However, "the verifier model, not the engine, is the bottleneck" is not
established by those counts. Current validation inspects the original candidate
location, while the verdict submission tool cannot amend it. The pipeline can
therefore reject malformed input that the verifier cannot correct through its
interface. Prompt coaching and model changes are experiments, not substitutes
for the citation-submission and amendment requirements in the earlier handoff.

Additional limits verified in the saved records/current source:

- Seventeen of the 27 turn-limit sessions also recorded other failure classes.
  Stop reason and underlying failure class overlap; do not describe all 27 as
  sessions with only valid reads, or sum overlapping categories as distinct cases.
- Failure-class summary events still reuse the session's last operation/message.
  This does not provide reliable per-operation attribution for every category.
- 4,745 of 4,784 prompt records have `truncated:true`. Call-record coverage is not
  complete prompt-content capture or a replayable transcript. The truncation is
  in stored telemetry; it does not prove the model received truncated input.
- The handoff reports a Go recognizer false positive for `url.Values.Get("q")`
  and a fixture workaround. Reproduce and fix the recognizer defect; avoiding the
  construct in a fixture does not establish correct inventory coverage.
- Forty-three supported out of 171 candidates is a verification-yield statistic,
  not measured recall, precision, or evidence that the other 128 should pass.

The additional requirements below make these limitations explicit completion
criteria. No operator attestation is invalidated or upgraded by this amendment.

## Specification input

Create a feature named **Actionable analysis reports and measured scan efficacy**
for vhlocal-go. Operators must be able to understand a scan's supported risks
and limitations quickly, navigate readable evidence and threat-model diagrams,
and distinguish actual analytical coverage and detection quality from activity
counts. Engineers must receive a prioritized remediation list with traceable
evidence, rather than a dump of every candidate and agent operation.

Read the constitution and existing relevant specifications first. Preserve all
existing dashboard metrics/charts, scan options, multi-language support, saved
results, application names, ledgers, and human review decisions. Incorporate
existing citation-repair functionality rather than replacing it. Keep scanning
static-only, source read-only, artifact access confined, and tests isolated from
operator storage. Do not interrupt an in-flight scan or run paid/live-model
benchmarks as a side effect of specification, report viewing, or regeneration.

Use two workstreams under this feature: (A) reports and threat-model usability;
(B) review integrity and measurable efficacy. Make report/diagram improvements
independently deliverable, but do not declare the whole feature complete until
the integrity and measurement requirements also pass. This is a focused repair
of analyst workflows and evidence quality, not a general UI redesign or a
promise to detect every vulnerability.

### P1 / US1 — An executive summary before diagnostic detail

Place the executive summary immediately below the report title and concise
run-status warning, before candidate lists, agent rows, or expanded diagnostics.
It must state target/application and revision, principal supported risks,
affected surfaces, prioritized actions, and material limitations. Default to a
compact opening of at most 300 narrative words, followed by summary metrics and
a prioritized findings index. Show no more than five leading issues/actions in
that opening, with links to the complete list. Avoid repeating the same warning
and long failure explanation in multiple sections.

Keep useful numbers prominent. Separately label supported findings, remediation
groups, rejected candidates, unresolved candidates, total candidates, execution
status, source-review coverage, and validation mode. Compute counts from a
shared authoritative report model. Vulnerability severity totals must count
supported findings only, with Unrated explicitly accounted for. Candidate
severity statistics remain accessible under an unambiguous candidate label.
Never equate job termination with successful scan completion, or supported
static reasoning with an executed exploit.

Summary facts must derive from validated records and link to their evidence.
If AI narrative is used, constrain it to those facts, validate references, and
provide a deterministic fallback. Viewing or regenerating a report must not
require model availability, incur inference cost, or invent business impact,
exploitability, severity, or completeness. A scan with no supported findings and
incomplete work must prominently explain the limitation rather than claim clean.

### P1 / US2 — A navigable remediation report with progressive detail

Use this information order: executive summary and outcome metrics; prioritized
findings/remediation index; individual finding details; coverage and limitations;
separate candidate investigation and execution diagnostics.

Provide search, severity/status filters, stable anchors, and accessible navigation
for the findings index. Each row identifies the issue, severity, affected
surface, evidence status, and recommended action where known. Default to compact
rows and collapsed details in interactive views. A report with hundreds of
candidates must not require scrolling through execution records to find risks.
Preserve reading position and selected findings across refresh/navigation.

Finding details must separate impact, attacker prerequisites, source-to-sink
reasoning, reviewed defenses, captured source evidence, recommended fix, and
reproduction status. Render actual captured excerpts as escaped, readable code
with file/line attribution, rather than a prose wall or only a source locator.
Explain missing remediation/evidence explicitly; never fabricate it.

Keep rejected and unresolved candidates available in separate searchable views
or appendices, with reasons and investigation actions. Summarize execution by
phase in the main report; expose per-agent turns, tokens, raw errors, and all
artifact records on demand. Distinguish failed verification sessions from valid
explicit unresolved decisions. Do not delete hard cases to improve readability.

Apply consistent content and counts to the main UI, React `/app/`, standalone
HTML, Markdown, and print/PDF. Markdown exports may use compact indexes and
linked appendices instead of interactive controls. Define summary versus full
print/export scope, preserve readable code/tables/page breaks, and disclose any
active filter. Standalone exports must remain useful offline.

Fix nested-list/blockquote/code formatting and resolve evidence/artifact links
through the owning report's file endpoint inside the app. Preserve correct
relative links in portable exports. Support keyboard navigation, sensible
heading structure, visible errors, and large-report performance. Escape model
content and validate links rather than rendering arbitrary executable markup.

### P1 / US3 — Threat-model diagrams that render reliably

Treat a diagram as a validated artifact with explicit availability and error
states. Represent nodes, directed flows, and trust boundaries structurally, with
stable identifiers and source references where established. Serialize diagrams
deterministically and validate with the renderer version actually shipped.
Keep analysis narrative, diagram structure, and rendering state distinguishable.

The model may propose architecture and flows; formatting must not silently
invent relationships or change their meaning. Preserve original output and any
normalization/repair history. Support existing Mermaid artifacts through a
bounded compatibility path that distinguishes safe formatting repair from
ambiguous structural changes. Unparseable diagrams must never be labeled valid
merely because the Markdown file exists.

On failure, retain readable threat-model narrative and an accessible node/flow
table. Show an actionable diagram-specific error and retry/source controls.
Do not replace the useful content with only a generic syntax-error image, and
do not mark a failed render permanently complete. Reset render/error state when
the application, report, or diagram changes. Isolate one diagram's failure from
others. Make both frontends consistent and support offline rendering, light/dark
themes, zoom, and export. Use safe rendering for model-controlled labels/links.

Regression inputs must include missing node brackets, missing edge-label
delimiters, inline comments, quotes, parentheses, Unicode, multiple diagrams,
and malicious label content. In particular, cover the audited malformed edge:
`B -.->|HTTP request (untrusted) .-> E`. If its intended structure is ambiguous,
an honest fallback is preferable to guessing an edge.

### P1 / US4 — Review coverage that measures completed analysis

Separate discovered scope, supported inventory, assigned work, attempted work,
source exposure, completed source review, and finding verification. Reuse the
existing multi-language inventory and stable source identities. Keep useful
counts, but do not promote one axis into another.

An overlapping file read and a valid assignment deliverable are insufficient to
mark a handler reviewed-no-issue. Reading the whole handler is also insufficient
without a handler-specific analytical conclusion. Require an explicit structured
disposition tied to the assignment, revision, observed source evidence, relevant
defenses, applicable weakness checks, rationale, and unresolved questions.
Validate its scope and evidence; a model's bare "reviewed everything" claim
cannot complete coverage.

A successful injection pass must not automatically imply completion of relevant
authorization, business-logic, or other planned checks. Define applicability and
aggregation of those checks, including explained non-applicability and unresolved
work. A no-issue review means no issue identified within that stated scope, not
proof that the code is vulnerability-free. Verification status remains separate.

Credit source reads as source exposure even when review is incomplete. Identify
gaps and route them into existing bounded coverage enforcement, honoring scan
options, budgets, cancellation, and retry limits. Do not schedule unbounded
follow-ups to force a 100% number. Preserve meaningful partial outcomes.

Version coverage semantics. Historical records based on weaker evidence must
remain readable and labeled appropriately; regeneration must not synthesize
missing analytical conclusions. Incomplete reviews must not mark prior issues
fixed merely because a new scan omitted them.

### P1 / US5 — Group remediation work without losing evidence

Identify potentially equivalent supported findings using source anchors, root
cause, attacker preconditions, affected scope, and required fix. Multiple samples
of the same issue should produce one actionable remediation group with linked
occurrences and evidence. Keep all candidate IDs, independent observations,
verification decisions, and review history; report raw and grouped counts.

Do not merge solely on CWE, similar title, overlapping ranges, or shared route.
Distinct sinks, preconditions, vulnerabilities, and fixes remain distinguishable.
Uncertain equivalence should be a suggested group, not silent evidence loss.
Preserve stable group identity across regeneration and define the behavior of
human decisions when members change.

Where equivalence is established before verification, avoid redundant work while
preserving evidence provenance. Do not transfer a supported verdict to a new
source anchor without applicable verification. Test the observed repeated
pickle, XSS, XXE, and NoSQL candidates as grouping examples, plus negative
controls with genuinely distinct defects on the same endpoint.

### P1 / US6 — An efficacy benchmark that measures supported detections

Create a reproducible benchmark using seeded vulnerabilities and safe controls
across Python, Go, and JS/TS, with per-language and per-weakness results. Ground
truth must identify source anchors/root causes, expected behavior, and acceptable
finding matches. Keep it out of scan prompts and the scanned target's visible
ground-truth files. Separate seeded/prior-context runs from unseeded runs.

Measure supported, deduplicated detection precision/recall; candidate-generation
recall; false positives on safe controls; verification acceptance/recovery and
terminal failure causes; completed review coverage; artifact completeness; and
time/tokens/cost per unique supported issue. Use explicit denominators and mark
unavailable cost or metrics unknown. Report run-to-run variation for live-model
experiments rather than presenting one run as a stable guarantee.

Fix or replace the current broad class/keyword scorer for this purpose: a
rejected or unresolved candidate must not satisfy supported-finding recall.
Do not count repeated detections as additional true positives. Freeze a baseline
and preserve target revision, build, effective options, models/providers, prompts,
sampling, seeds, and budgets so comparisons are interpretable. Establish a
versioned regression policy based on that baseline without inventing unsupported
quality thresholds or a promised universal detection rate.

Offline fake-provider tests prove pipeline behavior; separately identified
operator-triggered live runs measure model efficacy. No automatic remote model
calls or target execution are required by ordinary tests. Compare the newest
completed run with the audited baseline only after accounting for configuration
and build differences. Use measured failure patterns to propose subsequent
source-to-sink, prompt, provider, or retry changes; simply adding agents or turns
is not the acceptance criterion for this feature.

### P2 / US7 — Stable application identity while scans run

Persist the canonical application/repository identity when a scan is created.
Its provisional report, threat model, SBOM, and later final report must appear
under the same application history throughout running, completion, cancellation,
and restart. Never create a second application merely because final scan
metadata is not written yet. Do not merge different repositories by display name.
Preserve existing names, reports, and review data; ambiguous historical mappings
must remain explicit rather than being destructively guessed.

### P1 / US8 — Diagnose verifier failures before attributing them to the model

Make the citation validation, bounded correction/resubmission, candidate amendment,
and per-operation diagnostics from the linked citation-repair handoff explicit
requirements of this feature unless current implementation already satisfies
them with passing regression evidence. Merely linking that handoff as optional
context is insufficient. Verify ingestion through the actual hunt-output path.
Reproduce malformed original citations with a deterministic provider and prove
that a valid, source-grounded amendment permits independent verification without
weakening evidence rules or silently rewriting identity/history.

Distinguish upstream malformed candidate data, tool/schema or repair-interface
defects, model contract violations on valid inputs, substantive lack of evidence,
provider failures, and session stop reasons. Record the actual operation,
arguments relevant to diagnosis, validation feedback, and repair outcome with
candidate/call/attempt provenance and redaction. Do not attach the same final
error to unrelated failure classes. Count sessions and failure occurrences
separately and disclose overlapping categories.

Provide tested verifier instructions and worked examples of canonical citations,
handler identities, complete required evidence, supported/rejected/unresolved
decisions, and correction after an error. Supply canonical source/handler facts
from the harness where available; do not make the model guess internal validator
expectations. Explicit unresolved decisions remain acceptable evidence of
uncertainty, not successful confirmation or a reason to suppress a candidate.

Support controlled, operator-triggered comparisons using a frozen candidate set
and target revision: existing versus coached prompt with the same model; and
the same prompt with an alternate verifier model/provider. Verify that the
effective role override actually reaches every verifier call and is recorded.
Hold other configuration constant where supported and disclose differences.
Compare accepted supported/rejected/unresolved decisions, missing decisions,
repair rate, evidence validity, ground-truth accuracy, and cost/time. A model
that avoids errors by submitting unresolved for everything has not demonstrated
better detection efficacy. Do not require a particular commercial model or
automatically send source to another provider.

Make diagnostic capture sufficient to reproduce submission-contract failures.
Persist complete failing submissions, their exact validation feedback, tool
schema and prompt versions/hashes, and the source references needed for bounded
offline replay. Deduplicate shared prompt content and provide a bounded,
explicit diagnostic-capture mode if full sanitized context is needed. Define
retention and size limits without discarding the decisive fields. Distinguish
full content from previews and declare unrecoverable truncation; a hash alone
cannot reconstruct content. Never promise full-record expansion when only a
truncated record is stored, or confuse telemetry truncation with model context
truncation. Never persist credentials or hidden model reasoning.

Use the actual `url.Values.Get("q")` negative example alongside genuine Go route
registrations in inventory regression tests. Ordinary data-access methods must
not enter the route denominator or trigger fictitious HTTP review assignments.
Preserve legitimate ambiguous/unsupported disclosure rather than broadly
excluding methods named Get.

Retain operator attestation as a distinct form of evidence, with build, tested
URLs, browser/version when known, and specific scenarios/results. Add repeatable
browser tests for report/diagram workflows. Missing browser metadata stays
unknown; never convert attestation or source-string checks into automated UI
verification. Documentation changes to an unmet contract must be disclosed as
scope changes, not described as implementation of the original behavior.

### Required acceptance evidence

1. A large fixture matching the baseline's 171 candidates and 438 agent rows
   opens with a summary of at most 300 narrative words and visible supported/
   rejected/unresolved totals, before expanded diagnostics. The candidate
   breakdown is 43/7/121; severity totals include only the 43 supported findings.
2. All candidate/evidence records remain accessible through working, report-bound
   links. Browser tests cover both UIs, filtering, keyboard navigation, large
   reports, loading/errors, and scan switching. HTML/Markdown/PDF outputs preserve
   summary order, counts, source formatting, and declared export scope.
3. Diagram fixtures either render successfully under the shipped parser or show
   an honest, readable fallback with actionable errors. Repair does not alter
   intended topology silently. One failure does not break other diagrams; changing
   artifacts clears obsolete state. Malicious labels cannot execute content.
4. A 400-line read overlapping many handlers cannot mark all reviewed-no-issue.
   Full reads without analytical dispositions also fail completed-review credit.
   Valid handler-specific evidence/dispositions pass. Include sibling handlers,
   missing checks, fabricated IDs, stale revisions, and non-Python examples.
5. A deterministic fixture with 100 valid reviews and eight findings reports
   100 completed reviews; a paired fixture with only eight completed reviews
   reports eight, even if all 100 handlers were read. Legacy regeneration does
   not upgrade the weaker evidence into the stronger coverage semantics.
6. Repeated equivalent detections group without losing source records. Distinct
   defects at one endpoint remain distinct. Group/raw counts, review decisions,
   anchors, and regeneration stay consistent.
7. Benchmark tests show that rejected/unresolved candidates and duplicate hits
   cannot inflate supported precision/recall. Safe controls, language/class
   breakdowns, ground-truth isolation, and configuration comparisons are tested.
   Publish the frozen baseline and report any unexecuted live evaluation honestly.
8. A live-scan lifecycle fixture remains attached to one canonical application
   before final metadata exists and after completion/restart. Same-name different
   repositories remain separate and older artifacts retain their provenance.
9. Existing dashboards, scan options, citation repairs, ledgers, saved results,
   analyst decisions, and static-only boundaries retain their regression coverage.
   Validate the built binary's embedded assets, not only frontend source files.
10. A malformed original candidate citation fails before expensive verification,
    receives actionable feedback, and is corrected through the real ingestion/
    amendment path. A perfect verdict alone cannot bypass invalid original
    evidence. Persistent or ambiguous errors remain explicitly unresolved.
11. A mixed-failure session records its argument and submission errors separately
    even when it ends at the turn limit. Aggregates distinguish occurrences,
    affected sessions, final stop reasons, and successful explicit unresolved
    decisions. Saved diagnostics reproduce the contract failure despite bounded
    general prompt previews.
12. Prompt/model comparison fixtures verify role routing, frozen inputs, honest
    denominators, and cost/accuracy accounting. An all-unresolved model cannot
    pass an efficacy improvement gate on contract-compliance counts alone.
    Live comparisons remain separately operator-triggered and are labeled not
    run until actually performed.
13. Go query access using `url.Values.Get("q")` does not create a route, while
    genuine supported registrations remain recognized. Browser acceptance records
    retain the distinction between attested and machine-executed scenarios.

During planning, inspect `internal/report`, completion/coverage rendering,
`internal/engine/review_units.go`, citation/verification machinery, grouping and
lifecycle code, `internal/reports`, `internal/apps`, Mermaid helpers/components,
both report viewers, artifact-link handling, and benchmark scorers/fixtures.
Use one authoritative data contract where practical. Record evidence for what
already works and implement only the remaining gaps. The specification must
not treat passing fake-provider tests or a checked task list as proof of actual
live-model detection efficacy.
