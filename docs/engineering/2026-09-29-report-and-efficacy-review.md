# Report usability and scan efficacy review

Reviewed 2026-09-29 through local APIs, saved artifacts, and source inspection.
No browser automation was available; visual layout conclusions are based on
the served templates and report structure, not a browser screenshot. The root
HTML served on port 8421 matches the current source HTML. No scan, application
code, or saved result was modified.

The active run, `fb52ee7dc462` (report suffix `2026-09-29-080013`), was still in
Phase 2 Hunt. It has a threat model but no final report or verification sessions
yet. Do not use the preceding completed run as proof that new citation repairs
have succeeded or failed.

The completed baseline, `843875fb0919` (suffix `2026-09-28-221735`), has 171
candidates: 43 supported, 7 rejected, 121 unresolved. Of its 171 verifier
sessions, 86 stopped at the repair limit, 27 at the turn limit, and 58 completed.
Eight completed decisions were explicitly unresolved. Execution is partial and
coverage degraded. Its review ledger nevertheless reports 100/100 reviewed,
including 93 reviewed-no-issue units.

## 1. P1: Make the report an analyst deliverable

The completed Markdown report is about 198 KB; HTML is about 240 KB. Its
`## Summary` starts at line 621, after approximately 71,593 characters. It is
preceded by 121 failed-candidate explanations and 438 agent rows under a section
called "Per-phase outcome". This is primarily an information hierarchy problem,
not a font or color problem.

Recommended order:

1. Executive summary: target/revision, important supported risks, affected
   surfaces, immediate actions, and a concise partial-scan warning.
2. Outcome strip: supported findings, rejected candidates, unresolved leads,
   execution status, review scope, and static validation mode. Keep the useful
   numbers; distinguish what each number measures.
3. Prioritized, filterable remediation table: severity, issue, affected entry
   points, evidence status, recommended fix, and stable detail links.
4. Selected finding details: source evidence in formatted code blocks, attacker
   preconditions, data flow, defenses considered, impact, remediation, and
   explicit reproduction status.
5. Coverage and limitations: a concise gap summary linked to unit-level records.
6. Separate candidate-investigation and execution-diagnostics views/appendices.
   Retain the full records without expanding them all by default.

Generate totals deterministically from validated records. Any AI-written
executive narrative must cite those records and may not invent impact, severity,
completeness, or successful exploit execution. Provide a deterministic fallback.
Keep the same meaning in the UI, standalone HTML, Markdown, and print/PDF views.

Specific defects:

- `internal/report/report.go` puts completion diagnostics and every agent before
  the meaningful findings summary. `completion.go` prints every failed candidate
  inline, and unresolved candidates appear again later.
- The HTML "Findings" tile totals all rated candidates (170 in this run; one
  additional candidate is Unrated), while only 43 findings are supported. Its
  severity breakdown is likewise candidate-wide. Use supported-only severity
  totals for vulnerability headlines and retain separate candidate statistics.
- Supported HTML findings are all open by default. Markdown puts long prose in
  bullets and exports all candidates into one continuous page.
- The root UI's small Markdown renderer flattens nested lists and blockquote
  content; React uses a different Markdown renderer. Fix the shared content model
  and output behavior, rather than correcting only one frontend.
- Relative evidence links such as `review_units.json` resolve incorrectly from
  an in-app Markdown view. The root paths `/review_units.json` and
  `/verification_sessions.json` return 404. Resolve artifact links through their
  owning report's confined file endpoint; preserve portable offline links in
  standalone exports.

## 2. P1: Treat diagrams as validated artifacts

The current threat-model diagram has missing closing node brackets and inline
comments after edges. The preceding run has malformed edge labels, for example:

```text
B -.->|HTTP request (untrusted) .-> E
```

That edge lacks the closing label delimiter and is not valid Mermaid. The UI's
repair helper can balance some brackets, but cannot reliably repair arbitrary
grammar. Root `runMermaid` suppresses rendering errors after marking nodes done;
React falls back to source and does not reset failed/rendered state on changed
chart input. Artifact availability checks currently accept nonempty threat-model
text without proving its embedded diagram parses.

Use structured nodes, edges, and trust boundaries with stable identifiers and
source references, then serialize Mermaid deterministically. Validate against
the shipped renderer version before calling the diagram available. Preserve
original output and record repairs. Reformatting must not silently change edges
or trust boundaries. If validation still fails, show the threat-model text and
an accessible architecture/flow table with an explicit diagram error and retry,
not an error graphic or raw source as the only usable representation.

Use the same rendering contract in both frontends, isolate errors per diagram,
reset state on artifact changes, and test offline rendering, theme changes,
zoom/export, malicious labels, and both failing examples. Prefer strict rendering
security for model-generated content; current renderers use `securityLevel: loose`.

## 3. P1: Strengthen what reviewed coverage actually means

`internal/engine/review_units.go:readIntersects` accepts any overlap between a
Read span and a handler. If the assignment produced a valid deliverable and no
finding is attributed to that handler, the pipeline synthesizes
`reviewed_no_issue`. It does not require a unit-specific analytical conclusion.
The saved records show multiple handlers credited from the same 1–400-line read.

This provides evidence of source exposure, not adequate evidence of completed
security review. Keep it as a useful separate metric. Require a structured
per-handler disposition tied to observed evidence, relevant source/defenses,
applied weakness lenses, and unresolved questions before claiming completed
review. A completed injection pass must not imply authorization, business-logic,
and all other applicable checks are complete. Full handler reads alone are also
insufficient to establish a reasoned review.

Preserve distinctions between discovered, assigned, source read, reviewed,
finding supported, and vulnerability absent. Findings with unresolved verification
must remain visible even when their source-review task completed. Historical
100/100 records must not be retroactively upgraded to stronger evidence.

## 4. P1/P2: Consolidate remediation work without discarding evidence

The completed run has several supported candidates with the same entry point,
CWE, and overlapping location ranges, with no `duplicate_of` marker. Examples
include two pickle-deserialization findings at `/ops/bundle/dispatch-thaw-172`
and five XSS findings at `/ops/blurb/dispatch-tile-320`.

These are candidates for grouping, not proof every pair is the same exploit.
Group by validated source anchor, root cause, attacker preconditions, and fix.
Show one remediation item with linked occurrences/evidence when appropriate.
Do not merge distinct sinks merely because they share a CWE or route. Preserve
original candidate IDs and independent samples, and show raw versus grouped counts.
Deduplicate verified-equivalent work early enough to avoid repeated verification
cost, while retaining all independently relevant evidence.

## 5. P1: Establish an efficacy baseline before tuning the model

After the active run finishes, compare citation correction/recovery, accepted
decisions, unresolved causes, reproduction completeness, and resource use against
the completed baseline. Compare effective configuration and build identity;
differences in prompt, seeds, sampling, or model undermine attribution.

Existing `testdata/score.go` is only a coarse class/keyword scorer. It does not
filter to supported findings and is not a measure of verified detection quality.
Do not treat its score or fake-provider parity tests as measured live-model recall.

Build a repeatable benchmark across known seeded bugs, safe controls, and Python,
Go, and JS/TS. Match supported, deduplicated findings to exact expected source
anchors/root causes. Measure supported-finding precision/recall, candidate recall,
false positives, per-class/per-language misses, verification recovery, time,
tokens/cost per unique supported issue, and run-to-run variance. Keep ground truth
hidden from scan prompts. Report seeded and unseeded runs separately. Retain
offline fake-provider tests for pipeline correctness.

## 6. P2: Keep a live run attached to its application

The application API currently exposes the active report under a second slug with
an empty repository, alongside the established `FastAPI_Seeded` application with
the real repository and ten historical scans. This appears to be a provisional
identity issue before final metadata is written; verify its lifecycle rather
than declaring it permanent duplication.

Persist canonical application/repository identity at scan creation. Keep the
same history, threat model, SBOM, and report navigation while a run is active and
after it finishes. Never join applications solely by a display name.

## Suggested delivery order

First deliver report hierarchy/count correctness and validated diagram rendering
as a bounded usability sprint. Next prioritize truthful review evidence and the
post-sprint verification benchmark. Then use measured results to tackle duplicate work, source-to-sink
analysis gaps, provider/prompt changes, and targeted recovery. Avoid adding more
agents or increasing turn limits before identifying which failures that would fix.
