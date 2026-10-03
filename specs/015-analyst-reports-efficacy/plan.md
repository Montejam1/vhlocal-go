# Implementation Plan: Actionable analysis reports and measured scan efficacy

**Branch**: `015-analyst-reports-efficacy` | **Date**: 2026-09-29 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/015-analyst-reports-efficacy/spec.md`

## Summary

Turn the report into an analyst deliverable and make its numbers mean what they say: one persisted
**report model** drives an executive summary (≤ 300 words, ≤ 5 leading items), supported-only severity
totals, a navigable findings index with captured evidence rendered as code, and appendices for candidates
and execution — identical across Markdown, HTML, main UI, React and print. Threat-model diagrams become
**validated artifacts** (a stdlib flowchart-subset parser, deterministic serialization, recorded bounded
repairs, honest fallback with a node/flow table, per-diagram isolation in both UIs). Coverage moves to
**semantics v2**: "reviewed, no issue" requires a validated, structured per-handler disposition whose cited
evidence the unit actually read; reads alone are source exposure; v1 records stay readable and labelled.
Equivalent supported findings form **remediation groups** without touching evidence. A **benchmark** with
seeded multi-language issues and safe controls scores supported, deduplicated detections against
out-of-target ground truth with a frozen baseline. Application identity is persisted **at scan creation**
with an initial `scan_meta.json`. And verifier failures become **diagnosable and repairable**: citation
validation at hunt ingestion with one correction turn, structured feedback, a bounded `amend_candidate` path
with explicit identity rules, per-call failure records with provenance, prompt/schema hashes, replayable
diagnostics, an operator-triggered comparison harness, and the Go recognizer receiver fix.

**Current state (verified this planning pass — full gap map in research.md R0):** four divergent
count/classification implementations, severity tiles over all candidates, `Doc.Assessment` never rendered,
evidence quotes present but not shown, relative report links broken in both viewers; no diagram validation
and a shared repair helper that cannot touch the audited edge; `reviewed_no_issue` earned by read∩span with
no conclusion and no semantics version; only exact-duplicate collapsing; a keyword scorer that credits
unresolved candidates; identity registered only at finalize with `scan_meta.json` written once at the end;
citations never validated before a full verification session, no amendment path, canonical handler facts
withheld from the verifier, per-class summaries reusing the session's last error, provenance discarded on 2b
calls, resume ignoring the verify model; `isRouteMethodCall` never inspecting the receiver.

**Approach**: Workstream A (US1–US3) ships first and independently (report model → rendering/exports →
diagrams); Workstream B (US4–US8) follows (identity → citation/diagnostics → coverage v2 → groups →
benchmark/comparison). Feature complete only when both pass. Extend existing packages in place; all
persistence additive and versioned; no new runtime dependency.

## Technical Context

**Language/Version**: Go 1.23+ (module `vhlocal`), single static binary (`CGO_ENABLED=0`). Front-ends: served
`vhlocal/web/*.html` (vanilla JS, embedded) + React `web-react/` (operator-built, `/app`); Mermaid 11.17.2
already embedded in both.

**Primary Dependencies**: standard library only (`go/ast` already used by the Go recognizer; `regexp`,
`encoding/json`, `crypto/sha256`, `text/template`-free string building as today). No new runtime dependency.
Browser test tooling (Playwright) is operator-installed dev tooling, outside the runtime budget and never
required by `go test`.

**Storage**: additive, versioned results-dir records — `report_model.json` (v1), `threat_model_diagram.json`
(v1), `remediation_groups.json` (v1), `review_units.json` (`semantics_version: 2`), `coverage_ledger.json`
(`semantics_version`), `candidate_manifest.json` (schema 2: citations, amendments, supersedes),
`hunt_execution.json` (`citation` detail), `verification_calls.jsonl`, `verification_sessions.json` (calls,
provenance, explicit_unresolved), `prompts.jsonl` (candidate id, hashes), `diagnostics/<candidate>.json`,
initial `scan_meta.json` at scan start, `comparison.json`; benchmark truth/baseline under `testdata/benchmark`.

**Testing**: offline Go suite with fake/transcript providers and isolated storage; sanitized 171-candidate
replay fixture; diagram corpus; disposition/grouping/benchmark/identity/citation fixtures; `-race` on
writers; embedded-asset contract tests on the built binary; Playwright specs operator-run and recorded as
machine-executed only when run; live-model efficacy separately operator-triggered.

**Target Platform**: loopback single-binary server + CLI; browsers on `/`, `/classic`, `/legacy`, `/app`.

**Performance Goals**: report model build and render are linear in findings (171 candidates / 438 agent
rows render without per-agent DOM by default); HTML report with hundreds of candidates stays interactive
(details collapsed, filters client-side); diagram validation is bounded by file size (≤ 1 MB per fence).

**Constraints**: static-only, source read-only (citation resolution via the confined `source` package);
artifact reads confined to the owning results dir; no model call during report build/regeneration; no
inference as a side effect; no in-flight scan interrupted (records are read, never rewritten, by viewers);
credentials and hidden reasoning never persisted; evidence rules unchanged; preserve 012/013/014 contracts,
dashboards, ledgers, review decisions, SARIF semantics.

**Scale/Scope**: touches `report`, `consolidate`, `verification`, `engine` (verify/hunt/review_units/finalize/
regenerate/resume), `citation` (new), `threatmodel` (new), `benchmark` (new), `recognize` (Go), `inventory`,
`apps`, `reports`, `jobs`, `server`, `cli`, `skill/phases`, the three HTML entrypoints, React (`Reports.tsx`,
`Applications.tsx`, `Markdown.tsx`, `Mermaid.tsx`, `api.ts`, `types.ts`), `testdata/`, `tests/parity`.

## Constitution Check

*GATE: passed before Phase 0; re-checked after Phase 1 design. Constitution v1.1.0.*

- **I. Evidence Integrity** — summary facts and counts come only from records via one classification;
  evidence excerpts are the byte-validated captured quotes; a diagram is valid only if it parses (never
  because the file exists); coverage credit requires a harness-validated disposition tied to reads the unit
  performed; the benchmark counts only supported, deduplicated detections; regeneration invents nothing
  (v1 records never upgraded; citations never rewritten). PASS.
- **II. Orthogonal Status** — execution, coverage (now seven separate axes), validation mode and job status
  remain distinct on every surface; supported vs candidate severity are separately labelled; explicit
  unresolved decisions are distinct from failed sessions. PASS.
- **III. Static-Only Safety** — no execution; citation resolution and diagram validation read source/
  artifacts through existing confinement; benchmark scans a fixture target; comparison harness re-runs
  only the static verification phase. PASS.
- **IV. Provenance** — per-call 2b provenance recorded; prompt and tool-schema hashes on records and in
  `scan_meta`; comparison variants record the effective role config on every call; build identity reused.
  PASS.
- **V. Explicit Failure / No Silent Fallback** — invalid citations, invalid diagrams, out-of-scope or
  stale dispositions, unknown costs and not-run live evaluations are all explicit states; malformed tool
  arguments are rejected, never coerced; no provider/model fallback (variants are operator inputs). PASS.
- **VI. Resumable / Idempotent** — amendments replay idempotently and reject stale revisions; resume
  compatibility now includes the verify role; initial `scan_meta` is replaced atomically by the final; group
  and diagram records regenerate deterministically. PASS.
- **VII. Testable offline** — every FR maps to a scenario in quickstart.md with fixtures/doubles; browser
  and live-model evidence are separately labelled and never counted as offline verification. PASS.
- **Safety & Technical Constraints** — zero new runtime dependency; UI stays self-contained/offline
  (Mermaid already embedded; classic/legacy get a table fallback rather than the 3.5 MB script); model
  markup escaped, links validated, `securityLevel: strict`; deterministic counts, grouping and scoring. PASS.

**Gate result: PASS** (pre- and post-design). No Complexity Tracking rows.

## Project Structure

### Documentation (this feature)

```text
specs/015-analyst-reports-efficacy/
├── plan.md
├── research.md      # R0 gap map + R1–R10 decisions + 014 carry-overs
├── data-model.md    # report model, diagram artifact, review v2, groups, truth/baseline, citation, calls, diagnostics
├── quickstart.md    # offline gate, 14 scenarios, fixtures, operator-owned evidence template
├── contracts/
│   ├── report-and-diagrams.md          # C-A1..A17
│   ├── coverage-grouping-identity.md   # C-B1..B16
│   └── citation-benchmark.md           # C-C1..C18
└── tasks.md         # /speckit-tasks (not created here)
```

### Source Code (repository root)

```text
internal/consolidate/classify.go     # NEW: one Classify(); SupportedCounts/CandidateCounts on Doc (Counts kept)
internal/consolidate/groups.go       # NEW: remediation groups (established/suggested; stable ids)
internal/report/model.go             # NEW: ReportModel built in finalize; report_model.json; summary text (deterministic, word-counted)
internal/report/report.go            # render from the model; new section order; heading hierarchy; evidence code blocks; index/anchors
internal/report/html.go              # HTML split out: search/filters over all rows, print scope, page breaks, per-agent on demand
internal/threatmodel/                # NEW: flowchart-subset parser, serializer, bounded repairs, threat_model_diagram.json
internal/reports/material.go         # Material.Diagram sub-state; reports.go passes diagram state
internal/apps/selection.go           # narrative vs diagram selections
internal/engine/dispositions.go      # NEW: parse+validate "## Handler dispositions" (scope/revision/evidence/checks/identity)
internal/engine/review_units.go      # semantics_version 2, axes, source_exposed; v1 loader labels
internal/inventory/inventory.go      # ledger semantics_version + source_exposed; lifecycle gating helper
internal/engine/engine.go            # finalize: report model, groups, diagram validation, identity at scan_start, lifecycle gate
internal/engine/regenerate.go        # regenerate model/groups/diagram from records; never upgrades v1
internal/citation/                   # NEW: Parse/Normalize/Resolve/Bind, error codes, aids
internal/engine/verify.go            # canonical facts in task; amend_candidate; structured feedback; repeated-submission stop;
                                     #   strict arg decoding; verification_calls.jsonl; diagnostics capture; provenance per call
internal/engine/hunt.go              # ingestion validation + one correction turn; hunt_execution citation detail
internal/verification/verification.go# manifest schema 2 (citations, amendments, supersedes); Reconcile rejects invalid_citation
internal/verification/sessions.go    # calls, provenance, explicit_unresolved; occurrence vs session aggregates
internal/engine/prompts.go           # candidate_id label, kind=repair for 2b, prompt_hash/tool_schema_hash
internal/engine/resume.go            # verify model/backend/host in compatibility
internal/engine/compare.go           # NEW: verify-compare harness (frozen manifest → 2b only → comparison.json)
internal/cli/compare.go, bench.go    # NEW: `verify-compare`, `bench efficacy`
internal/benchmark/                  # NEW: Score(), Results, baseline/policy loading
internal/recognize/lang_go.go        # receiver inference for method routes; ambiguous certainty
internal/jobs/jobs.go, server/handlers.go, cli/run.go   # app_slug/app_name at creation; initial scan_meta at scan_start
internal/apps/aggregate.go           # slug grouping from scan_meta; ambiguous_mapping
skill/phases/phase2_shared.md        # deliverable v2: Handler dispositions section
skill/phases/phase2b_session.md      # NEW: verifier worked examples (hashed)
skill/phases/phase1t_threat_model.md # diagram subset rules aligned with the parser
vhlocal/web/index.html               # report viewer: model-driven summary/index/details, link rewriting, print scope;
                                     #   per-diagram render/fallback/retry/theme re-render; classic/legacy: table fallback
web-react/src/pages/Reports.tsx, components/Markdown.tsx, Mermaid.tsx, lib/api.ts, lib/types.ts
web-react/tests/browser/             # NEW: Playwright specs (operator-run)
testdata/replay-171/, diagrams/, grouping/, benchmark/{target,truth,baseline,POLICY.md}; coverage100 (v2 + real Get)
internal/*/…_test.go, tests/parity/  # scenarios 1–14; reference contracts unchanged
```

**Structure Decision**: extend the pipeline in place; every new capability is a stdlib package with a
persisted, versioned record consumed by existing surfaces. The report model is the one place counts are
computed; the citation package is the one place locations are parsed; the diagram package is the one place
Mermaid is validated. Workstream A is deliverable and testable without any Workstream B change.

## Complexity Tracking

No constitution violations to justify. The Mermaid subset parser is deliberately small (nodes, edges,
labels, subgraphs, comments) and refuses anything else as `unsupported`; the browser-side `mermaid.parse`
with the pinned renderer remains the authoritative check.
