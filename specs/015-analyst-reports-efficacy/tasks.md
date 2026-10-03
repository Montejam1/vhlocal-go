---

description: "Task list for feature 015: Actionable analysis reports and measured scan efficacy"
---

# Tasks: Actionable analysis reports and measured scan efficacy

**Input**: Design documents from `/specs/015-analyst-reports-efficacy/`

**Prerequisites**: plan.md, spec.md, research.md (R0–R10), data-model.md, contracts/report-and-diagrams.md (C-A), contracts/coverage-grouping-identity.md (C-B), contracts/citation-benchmark.md (C-C), quickstart.md (scenarios 1–14)

**Tests**: INCLUDED — the specification's acceptance evidence 1–13 and SC-001..014 are fixture-driven gates; constitution VII requires offline tests for every FR. Test tasks precede their implementation within each story and must FAIL first.

**Organization**: Grouped by user story. Workstream A (US1–US3) ships first and independently; Workstream B (US4, US5, US8, US6, US7) follows in dependency order (US8's citation/manifest changes precede the benchmark that scores them; US7 is the only P2). The feature is complete only when both workstreams pass.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: US1–US8 (Setup/Foundational/Polish carry no story label)
- Exact file paths included.

## Path Conventions

Single Go module `vhlocal` at repo root. Build: `export PATH=$PATH:/usr/local/go/bin`; `CGO_ENABLED=0 go build -o bin/vhlocal ./cmd/vhlocal`. Offline gate: `gofmt -l . && go vet ./... && go build ./... && go test ./...` plus `go test -race ./internal/engine/... ./internal/jobs/... ./internal/server/... ./internal/agent/... ./internal/apps/...`. React: `cd web-react && npm run typecheck` (offline; `npm run build` is operator-owned).

**Standing constraints (every task):** static-only (never execute target code, PoCs, exploit tests, or the benchmark target); offline only (fake/transcript providers — never a live model, never Ollama); **fully isolated storage** in every test (`internal/testisolate`; never touch `~/.vhlocal` or `~/vulnhunter-reports`); `../vhlocal` read-only; stdlib only (no new runtime dependency; Mermaid stays the embedded 11.17.2); all persisted changes additive and versioned; evidence rules never weakened; no model call during report build or regeneration; credentials and hidden reasoning never persisted; preserve features 012–014, dashboards, ledgers, human review decisions, SARIF semantics; never interrupt an in-flight scan; the live 171-candidate run is replayed from sanitized records, never re-run.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Empty homes for new packages and the shared offline fixtures every story uses.

- [X] T001 Create package-clause stubs with doc comments: `internal/consolidate/classify.go`, `internal/consolidate/groups.go`, `internal/report/model.go`, `internal/report/html.go`, `internal/threatmodel/threatmodel.go`, `internal/citation/citation.go`, `internal/benchmark/benchmark.go`, `internal/engine/dispositions.go`, `internal/engine/compare.go`, `internal/cli/compare.go`, `internal/cli/bench.go`.
- [X] T002 [P] Create `testdata/replay-171/` — sanitized records of the live baseline `843875fb0919` (no prompts, no operator paths): `scan_meta.json` (438 agent rows, phases, outcome), `findings.json` (171 non-duplicate candidates: 43 supported / 7 rejected / 121 unresolved incl. 8 explicit `unresolved` verdicts), `candidate_manifest.json`, `verification_decisions.json`, `verification_sessions.json`, `verification_reconciliation.json`, `review_units.json` (v1), `coverage_ledger.json`, `hunt_execution.json`, `artifact_manifest.json`, `threat_model.md` (the malformed lines 48–52 kept), plus `README.md` stating provenance and sanitization; the repo path inside records is `testdata/replay-171/target` (a minimal stub tree whose cited files/lines exist so evidence quotes byte-match).
- [X] T003 [P] Create `testdata/diagrams/` — the FR-014 corpus, one `NN-<case>.md` per case (missing node bracket `F["SQL DB (SQLAlchemy)"`, `" ]` gap, unterminated edge label `B -.->|HTTP request (untrusted) .-> E`, inline `%%` comments, quotes and parentheses in labels, Unicode `→ – ‑`, two diagrams in one file, `style`/`classDef`/`class`, quoted subgraph id `subgraph "Network"["Network"]`, malicious label `A["<img src=x onerror=alert(1)>"]`, valid reference diagram) and `expected.json` mapping each case to `{state, repairs[], errors[]}` per data-model DiagramArtifact.
- [X] T004 [P] Create `testdata/grouping/` — sanitized supported findings + decisions reproducing the live repeated pickle, XSS, XXE and NoSQL candidates (same sink anchor, several entry points) and negative controls (same endpoint, distinct sinks/preconditions/fixes; same CWE different files), with a stub source tree so anchors resolve.
- [X] T005 [P] Create `testdata/benchmark/` — `target/` seeded corpus (Python Flask/FastAPI, Go net/http, JS/TS Express; ≥ 2 seeded issues per language across ≥ 4 families incl. injection, path traversal, authorization, deserialization; one **safe control** beside each class), `truth/ground_truth.json` (version 2 per data-model: `id, language, cwe, family, expected: vulnerable|safe_control, anchor{file,function,lines}, root_cause, acceptable_matches, notes`), `POLICY.md` skeleton, and `README.md` stating that `truth/` is never inside `target/` and never in prompts.
- [X] T006 [P] Add offline doubles to `internal/engine/testdoubles_test.go`: `dispositionWriter` (reads spans, then writes a v2 deliverable with a `## Handler dispositions` section; modes: full-span-no-dispositions, 400-line-overlap, valid-per-handler, out-of-scope, fabricated-id, stale-revision, unresolved-checks), `citationRepairWriter` (writes an invalid `Location` first, rewrites on feedback), `amendingVerifier` (calls `amend_candidate` then verifies through the evidence contract), `mixedFailureVerifier` (invalid args → invalid submission → valid reads until turn limit), `identityRecordingProvider` (stamps a per-instance name into every response's `Provenance.RequestedModel`/`Backend`).
- [X] T007 Run `gofmt -w` on new files; confirm `go build ./...` and `go vet ./...` pass with the empty scaffolding and new fixtures.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: One classification, hashed prompts/schemas, and versioned loaders that every story's records and counts depend on.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T008 Implement `consolidate.Classify(f map[string]any) Class` in `internal/consolidate/classify.go` (`supported | rejected | unresolved_explicit | unresolved_failed | duplicate`) replacing `report.isSupported`/`isRejected`, `reports.Load`'s hypothesis rule and the intent of `index.html:_isSubstantiated`; `unresolved_explicit` ⇔ `verification_record.verdict == "unresolved"`; add `Doc.SeveritySupported` and `Doc.SeverityCandidates` in `internal/consolidate/consolidate.go` (`Counts` retained unchanged) with the invariant `Σ SeveritySupported == supported`; unit tests in `internal/consolidate/classify_test.go` covering every class and Unrated.
- [X] T009 [P] Add `prompt_hash`/`tool_schema_hash` plumbing: `internal/engine/prompts.go` computes sha256 of the phase system prompt text and of the phase's tool envelope JSON, stamps both on every `PromptRecord`, adds `candidate_id` (2b) and classifies 2b repair nudges as `kind: repair`; `internal/engine/record.go` gains `PromptHashes map[string]string`, `ToolSchemaHashes map[string]string`; test in `internal/engine/prompts_test.go`.
- [X] T010 [P] Versioned loaders: `internal/engine/review_units.go` `loadReviewUnits` returns `SemanticsVersion` (absent ⇒ 1) and a `Label()` ("read-overlap evidence (v1)"); `internal/inventory/inventory.go` `CoverageLedger` gains `SemanticsVersion` and `Counts["source_exposed"]`; `internal/reports/reports.go` exposes `CoverageSemantics` on `Report`; tests assert a 014-era file loads as v1 with the label.
- [X] T011 [P] Serve new records through existing surfaces: extend `internal/server/static.go` `listFiles` content types for `.jsonl`; `internal/server/status.go` `scanStatus` passes `report_model_present`, `diagram` state, `coverage_semantics` through additively; test in `internal/server/status_test.go`.
- [X] T012 Wire `Classify` into `internal/reports/reports.go` (`Findings`, `Hypotheses`, new `Supported`, `Rejected`, `Unresolved` counts) and confirm `internal/apps/aggregate.go` metrics and `internal/server/stats*_test.go` baselines are unchanged (extend `TestDashboardPreservationBaseline`).

**Checkpoint**: Foundation ready — one classification, hashed provenance, versioned records.

---

## Phase 3: User Story 1 - An executive summary before diagnostic detail (Priority: P1) 🎯 MVP

**Goal**: A persisted report model drives a ≤ 300-word / ≤ 5-item executive summary, supported-only severity totals and labelled counts, rendered first on every surface and byte-identical after regeneration.

**Independent Test**: Scenario 1 — `testdata/replay-171` → `report_model.json`, Markdown, HTML: summary first, ≤ 300 words, ≤ 5 leading, totals 43/7/121 visible before diagnostics, Σ severity = 43, identical after `Regenerate`.

### Tests for User Story 1 ⚠️ (write first, ensure they FAIL)

- [X] T013 [P] [US1] Model test in `internal/report/model_test.go`: build the model from `testdata/replay-171` records; assert `counts.supported == 43`, `rejected == 7`, `unresolved_explicit == 8`, `unresolved_failed == 113`, `total_candidates == 171`, `Σ severity_supported == 43`, `severity_candidates` present under its own key, `summary.words ≤ 300`, `len(summary.leading) ≤ 5`, every `leading[].ref` resolves to an index entry, `status.job_terminal` absent (C-A2, C-A3).
- [X] T014 [P] [US1] Rendering-order test in `internal/report/order_test.go`: Markdown and HTML section sequence equals C-A6; `## Executive summary` appears before any `CAND-` id, agent label or `verification_sessions` mention; the run-status warning is one line; the long failure explanation string appears exactly once (appendix) (FR-001, FR-004).
- [X] T015 [P] [US1] Honesty tests in `internal/report/summary_test.go`: fixture with zero supported + partial execution ⇒ narrative starts with the limitation sentence and never contains "clean"; job-terminated/partial fixture never renders "complete"/"finished successfully"; "supported by static reasoning" never rendered as executed (C-A4, FR-003).
- [X] T016 [P] [US1] Regeneration/consistency test in `internal/engine/report_model_test.go`: run a fake-provider scan, snapshot `report_model.json` + both reports, `Regenerate`, assert byte-identical; assert no provider `Chat` call occurred during finalize's report build or `Regenerate` (counting provider) (C-A1, C-A5, SC-014).

### Implementation for User Story 1

- [X] T017 [US1] Implement `ReportModel` in `internal/report/model.go` per data-model (`version 1`, `target`, `status` axes, `counts` incl. `source_review{completed, exposed, total, semantics_version}`, `severity_supported`, `severity_candidates`, `summary`, `index`, `findings` with every `verification_record.evidence[]{path,start,end,quote}`, `groups` (empty until US5), `appendix`, `refs`) + `BuildModel(in Input, doc consolidate.Doc, ru *ReviewUnits-view, groups, outcome)`; `Write` to `report_model.json`.
- [X] T018 [US1] Deterministic executive summary in `internal/report/summary.go`: leading ≤ 5 supported findings ordered by severity rank, then group size, then id; surfaces = distinct entry points/files; actions = fix text or "fix not provided"; limitations = outcome recovery steps + degraded reasons + disabled phases (deduplicated, one sentence each); word counter (narrative only, excludes metrics/index) enforcing ≤ 300 by truncating the limitations list with "… (N more in Coverage and limitations)".
- [X] T019 [US1] Refactor `internal/report/report.go` `RenderMarkdown` to render only from the model: new section order, `##` sections / `###` per finding, `## Executive summary` + `## Outcome metrics` (labelled counts, supported severity list with Unrated, candidate severity under "Candidates (all statuses)"), keep the 014 Completion/Review-coverage wording inside `## Coverage and limitations`; move `Input` fields (`Repo`, `GitCommit`, `ScanID`) additively.
- [X] T020 [US1] Split HTML into `internal/report/html.go` rendering the same model and order; severity tiles from `severity_supported`; candidate stats under an explicit "candidates" label; keep single-file/offline guarantees and existing `report_test.go` strings that remain valid (update those that encode the old order in T014's tests).
- [X] T021 [US1] Build the model in `internal/engine/engine.go` finalize (after outcome, review units, groups) and in `internal/engine/regenerate.go` (records only); pass `report.Input.Model` to `report.Write`; write `report_model.json` before the reports.
- [X] T022 [US1] Main UI `vhlocal/web/index.html`: `openReport` fetches `report_model.json` first; `healthPanelHTML` and the summary/counts render from the model (supported vs candidate severity separately labelled); fallback to the previous `findings.json` math only when absent with the visible note "counts from findings.json (pre-015 scan)" (C-A10).
- [X] T023 [P] [US1] React `web-react/src/lib/types.ts` (`ReportModel`), `lib/api.ts` (`reportModel(id)` via `reportFetch`), `pages/Reports.tsx` `ReportDetail`: render executive summary + outcome metrics from the model above the Markdown body; pre-015 fallback note; `npm run typecheck`.

**Checkpoint**: Reports open with an honest summary and correct totals on every surface.

---

## Phase 4: User Story 2 - A navigable remediation report with progressive detail (Priority: P1)

**Goal**: Findings index with search/filters/anchors/keyboard, structured finding details with captured code excerpts, separate candidate and execution appendices, working in-app links, consistent exports and print scope.

**Independent Test**: Scenario 2 — the 171 fixture: every evidence/artifact link resolves through the report file endpoint; index anchors, filters over all rows, export scope + filter disclosure; shipped-asset contract for both UIs.

### Tests for User Story 2 ⚠️ (write first, ensure they FAIL)

- [X] T024 [P] [US2] Index/detail test in `internal/report/index_test.go`: every index row has id, title, severity, surface, `evidence_status ∈ {evidence_captured, evidence_missing, not_verified}`, anchor `finding-<id>`; finding detail renders every evidence entry as escaped code with `path:start-end` caption, and the literal lines "Recommended fix: not provided" / "Captured evidence: none (not verified)" when absent; rejected/unresolved-explicit/unresolved-failed appear in Appendix A under their own headings with reason and action; per-agent rows are not in the main body (C-A7, C-A8, FR-007, FR-008).
- [X] T025 [P] [US2] HTML behavior test in `internal/report/html_test.go`: search input + severity/status filters exist and rows carry `data-sev`/`data-status` for **all** classes; rows `tabindex="0"`; filter banner and print header disclose active filter and export scope; `break-inside: avoid` rule present; `beforeprint` expands; no external requests; model-authored `<script>` in a title is escaped (C-A7, C-A11, FR-010).
- [X] T026 [P] [US2] Link contract test in `internal/server/report_links_test.go`: `SCAN_REPORT.md` and `report_model.json` reference only relative paths; shipped `index.html` `mdRender` rewrites relative hrefs to `/api/reports/{id}/file?path=`; React `Markdown.tsx` source contains `urlTransform` with the same base rule; only `http(s):`/`mailto:`/relative schemes allowed (C-A9).
- [X] T027 [P] [US2] Cross-surface consistency test in `internal/engine/report_surfaces_test.go`: counts and section order in Markdown, HTML, `report_model.json` and the React-consumed JSON agree for the 171 fixture (FR-009).

### Implementation for User Story 2

- [X] T028 [US2] Implement the findings index + finding detail sections in `internal/report/report.go` (Markdown: compact table with anchors, linked appendices) and `internal/report/html.go` (collapsed `<details>` per finding, evidence `<pre><code>` blocks, appendix sections, per-agent table behind a `<details>` "Execution diagnostics" loading from the model).
- [X] T029 [US2] HTML interactivity in `internal/report/html.go`: search box + severity/status filters over all rows, keyboard-focusable rows, `#finding-<id>` anchors, filter banner, export scope toggle (`summary` = sections 1–3, `full`), print CSS (page breaks, wrapping code, print header with scope/filter), `sessionStorage` reading-position restore keyed by scan id.
- [X] T030 [US2] Main UI `vhlocal/web/index.html`: `mdRender(base)` rewrites relative `href`/`src` to the owning report's file endpoint and validates schemes; `openReport` renders the model-driven findings index (search/filters/anchors/keyboard, collapsed details, evidence code blocks) and keeps `SCAN_REPORT.md` below; preserve reading position/selection across refresh and report switch with the 014 sequence guard; fix nested list/blockquote/code rendering in `mdRender`.
- [X] T031 [P] [US2] React `web-react/src/components/Markdown.tsx` (`urlTransform` to the report file endpoint, scheme validation, heading anchors), `pages/Reports.tsx` (findings index with filters/search/keyboard, evidence code blocks, appendices, reading position via search params, stale guard), `lib/api.ts`; `npm run typecheck`.
- [X] T032 [P] [US2] Classic/legacy `vhlocal/web/index.classic.html`, `index.legacy.html`: link rewriting in their `mdRender`, model-driven summary/counts block, no redesign.
- [X] T033 [US2] Shipped-asset contract test `internal/server/report_form_test.go` (`TestShippedReportContract`): embedded `index.html`/classic/legacy carry the link rewriting, model fetch, filter/search/keyboard markers, pre-015 fallback note; React source markers for `urlTransform` and the index (FR-010, SC-002 shipped-asset half).

**Checkpoint**: An engineer can work the findings index without scrolling past diagnostics; links and exports work.

---

## Phase 5: User Story 3 - Threat-model diagrams that render reliably (Priority: P1)

**Goal**: Diagrams are validated artifacts with structure, deterministic serialization, recorded bounded repairs, honest fallbacks, and isolated per-diagram rendering in both UIs.

**Independent Test**: Scenario 3 — `testdata/diagrams` corpus → `threat_model_diagram.json` states/repairs/errors match `expected.json`; serializer deterministic; audited edge invalid; UI contract markers present.

### Tests for User Story 3 ⚠️ (write first, ensure they FAIL)

- [X] T034 [P] [US3] Parser/repair tests in `internal/threatmodel/threatmodel_test.go`: every corpus case yields the expected `state/repairs/errors`; `Serialize(Parse(x))` is idempotent and deterministic (sorted nodes/edges, canonical quoting); repairs never add/remove a node or edge (structure equality before/after); the audited edge ⇒ `invalid` + `E_EDGE_LABEL_UNTERMINATED` with line 48; `style/classDef/class/click` ⇒ `R_STRIP_DIRECTIVE` or `unsupported`; the malicious label survives as escaped text in `structure.nodes[].label` (C-A12, C-A13).
- [X] T035 [P] [US3] Artifact/material tests in `internal/reports/material_test.go` + `internal/apps/selection_test.go`: `Material.Diagram{state, errors}` populated from `threat_model_diagram.json`; narrative available + diagram invalid are independent; application selection returns separate `threat_model{narrative, diagram}` selections and skips invalid diagrams for the diagram selection only (C-A14).
- [X] T036 [P] [US3] Engine test in `internal/engine/threatmodel_artifact_test.go`: a 1t run with a fake provider writing the corpus produces `threat_model_diagram.json`; regeneration reproduces it byte-identically; a run with `threat_model=false` writes none; the `internal/report` nav and model expose `refs.diagram`.
- [X] T037 [P] [US3] Shipped-UI contract in `internal/server/diagram_form_test.go`: `index.html` renders per diagram with `mermaid.parse(...suppressErrors)` before `render`, `securityLevel: 'strict'`, per-diagram error block with line/code, Retry and View-source controls, node/flow table fallback, theme-change re-render hook, SVG export control; React `Mermaid.tsx` resets `svg/failed` on `chart` change and exposes the same states; classic/legacy contain the node/flow table fallback sentence (C-A15, C-A16).

### Implementation for User Story 3

- [X] T038 [US3] Implement `internal/threatmodel`: `Parse(src) (Diagram, []Error)` for the flowchart subset (`flowchart|graph` + direction; nodes `id["…"]`/`id("…")`/`id{"…"}`/`id[…]`; edges `-->`, `-.->`, `==>` with optional `|label|`; `subgraph id["label"] … end`; `%%` comments; unsupported directives), `Repair(src) (string, []RepairRecord)` limited to `R_CLOSE_LABEL_QUOTE`, `R_QUOTE_GAP`, `R_QUOTE_LABEL`, `R_STRIP_DIRECTIVE`, `R_ASCII_LABEL`, `Serialize(Diagram) string` deterministic, `Validate(markdown) DiagramArtifact` over every ```` ```mermaid ```` fence with `renderer_version: "11.17.2"`.
- [X] T039 [US3] Write `threat_model_diagram.json` in `internal/engine/engine.go` after 1t (next to the SBOM) and in `internal/engine/regenerate.go`; add `refs.diagram` to the report model and a "Threat model diagram: valid | repaired (N rules) | invalid (line, code)" line to `## Coverage and limitations`.
- [X] T040 [US3] `internal/reports/material.go` `Material.Diagram` sub-state read from the artifact (absent artifact on a pre-015 run ⇒ `diagram.state: "unknown"`); `internal/reports/reports.go`, `internal/apps/selection.go` (`threat_model{narrative, diagram}` selections; `apps.AppArtifacts` additive), `internal/server/status.go` pass-through.
- [X] T041 [US3] Main UI `vhlocal/web/index.html`: replace batch `runMermaid` with per-element `renderDiagram(el)`: `mermaid.parse` with `suppressErrors` → `render` → on failure show narrative (already on page), node/flow table (from `threat_model_diagram.json` when available, else client-side subset parse), error `{line, code, message}`, Retry / View source; `securityLevel: 'strict'`; clear state when the host element is replaced and on theme toggle (re-render); SVG export via data URL; apply `_fixMermaid` only with the same enumerated rules and show "repaired: <rules>".
- [X] T042 [P] [US3] React `web-react/src/components/Mermaid.tsx`: reset `svg/failed/error` on `chart` change, `mermaid.parse` first, structured error + Retry + source, `securityLevel: "strict"`, theme re-render, SVG export; `Markdown.tsx` passes diagram index; `pages/Reports.tsx`/`Applications.tsx` show `diagram.state` from the API; `npm run typecheck`.
- [X] T043 [P] [US3] Classic/legacy `vhlocal/web/index.classic.html`, `index.legacy.html`: render the node/flow table + source for mermaid fences with the sentence "diagram rendering is available in the main UI".
- [X] T044 [P] [US3] Align `skill/phases/phase1t_threat_model.md` diagram rules with the parser subset (one `flowchart TD`, quoted labels, ASCII, no directives, edges outside subgraphs) — prompt text only; hashed by T009.

**Checkpoint**: Workstream A complete — reports and diagrams are analyst-ready; deliverable on its own.

---

## Phase 6: User Story 4 - Review coverage that measures completed analysis (Priority: P1)

**Goal**: `reviewed_no_issue` requires a validated structured per-handler disposition tied to what the unit read; reads count as source exposure; checks aggregate by applicability; semantics versioned; legacy labelled; lifecycle gated.

**Independent Test**: Scenarios 4–5 — disposition fixtures and the paired 100-vs-8 fixtures on `testdata/coverage100`; v1 regeneration keeps v1 label.

### Tests for User Story 4 ⚠️ (write first, ensure they FAIL)

- [X] T045 [P] [US4] Disposition validation tests in `internal/engine/dispositions_test.go`: parse the v2 section (all fields, `Checks` vocabulary `done|n/a(reason)|unresolved(reason)`); validation outcomes `scope: out_of_scope`, `revision: stale`, `evidence: not_read|outside_span`, `identity: fabricated`; a bare "reviewed everything" sentence yields no disposition (C-B2..B4).
- [X] T046 [P] [US4] Coverage v2 tests in `internal/engine/review_units_v2_test.go` on `testdata/coverage100` with `dispositionWriter`: 400-line overlapping read ⇒ 0 `reviewed_no_issue`, `source_exposed` > 0; full reads without dispositions ⇒ 0 completed; valid per-handler dispositions ⇒ exactly those handlers; sibling handlers, missing checks (⇒ `partial`), fabricated ids, stale revision, Go and JS examples; paired 100-vs-8 ⇒ 100 vs 8 completed with `source_exposed == 100`; `axes` never derived from each other (C-B5, C-B6, SC-004, SC-005).
- [X] T047 [P] [US4] Legacy/label tests in `internal/engine/review_units_v2_test.go`: a 014-era `review_units.json` regenerates with `semantics_version: 1`, identical counts and the label on `report_model.json`, `SCAN_REPORT.md`, scan status and application history (C-B1, FR-019).
- [X] T048 [P] [US4] Lifecycle gate test in `internal/engine/lifecycle_gate_test.go`: with an incomplete v2 ledger, a prior finding absent from the new scan is `unknown_incomparable`, never `fixed`/`not_observed`; complete ledger ⇒ existing behavior (C-B8).
- [X] T049 [P] [US4] Follow-up test extension in `internal/engine/review_units_v2_test.go`: gaps still trigger exactly one bounded follow-up per partition whose deliverable uses the v2 section; no additional scheduling; partial outcomes preserved (C-B7).

### Implementation for User Story 4

- [X] T050 [US4] Hunt deliverable contract v2 in `skill/phases/phase2_shared.md`: add the required `## Handler dispositions` section (block format per data-model) after the candidate list, with the applicability vocabulary and the rule that only THIS pass's class is expected `done`; update `buildHuntTask` in `internal/engine/hunt.go` to list the unit's assigned handlers (`file:line METHOD PATH`) so the model has the identities.
- [X] T051 [US4] Implement `internal/engine/dispositions.go`: parser for the v2 section, `validate(d, assignment, unitReads, revision, routes)` producing `validation{scope, revision, evidence, identity}` and structured `checks[]`; `hunt_execution.detail[]` gains `dispositions: {parsed, credited, rejected}`; missing section ⇒ unit flagged `no_dispositions` (v1-style exposure only).
- [X] T052 [US4] Coverage v2 in `internal/engine/review_units.go`: `semantics_version: 2`, `axes{discovered, supported_inventory, assigned, attempted, source_exposed, completed_review, verified}`, disposition credit rule (all planned classes `done`/`n_a` ⇒ `reviewed_no_issue`; any `unresolved` ⇒ `partial`; reads without disposition ⇒ source exposure), structured `dispositions[]` record, follow-up units parsed the same way; `ledgerEvidence` passes only credited dispositions.
- [X] T053 [US4] `internal/inventory/inventory.go`: `coverage_ledger.json` `semantics_version`, `counts.source_exposed`; `internal/engine/engine.go`: lifecycle gate (`cl.Complete` under v2 required for `fixed`/`not_observed`, else `unknown_incomparable` via `lifecycle.Suppressed`-style block naming the reason); report model `counts.source_review` and `## Coverage and limitations` axes table with the semantics label.
- [X] T054 [P] [US4] Surfaces: `internal/server/status.go` `review_units` gains `semantics_version`, `axes`; `internal/apps/aggregate.go` history rows carry `coverage_semantics`; main UI + React show the axes table and the v1 label (`vhlocal/web/index.html`, `web-react/src/pages/Scans.tsx`, `Applications.tsx`, `lib/types.ts`).

**Checkpoint**: "No issue" means a validated analytical conclusion; activity is reported as exposure.

---

## Phase 7: User Story 5 - Group remediation work without losing evidence (Priority: P1)

**Goal**: Equivalent supported findings form stable remediation groups with linked occurrences; distinct defects stay distinct; uncertain equivalence is only suggested; raw and grouped counts everywhere.

**Independent Test**: Scenario 6 — `testdata/grouping` → one group per repeated pickle/XSS/XXE/NoSQL defect; negative controls separate; regeneration stable; decision status derived.

### Tests for User Story 5 ⚠️ (write first, ensure they FAIL)

- [X] T055 [P] [US5] Grouping tests in `internal/consolidate/groups_test.go`: established vs suggested rules (same family ∧ anchor ∧ compatible fix; same file different function ⇒ suggested); CWE-only / title-only / overlapping-range-only / shared-route-only ⇒ not grouped; distinct sinks/preconditions on one endpoint ⇒ separate; `raw_supported == Σ members`; every supported finding in exactly one group; group ids stable when a non-primary member is removed (C-B9, C-B10, C-B12).
- [X] T056 [P] [US5] Evidence/decision tests in `internal/engine/groups_test.go`: grouping changes no bytes of `findings.json` findings, `verification_decisions.json` or the review store; `decision_status` derives from `internal/review` records of members; `members_changed_since` true when a member's stable id is absent from the newest decision's scan/revision; `Regenerate` yields identical `remediation_groups.json` (C-B11).
- [X] T057 [P] [US5] Report/surface test in `internal/report/groups_test.go`: model `groups[]`, index rows carry `group_id`, `## Findings index` shows raw vs grouped counts, group members listed under the primary with links; HTML/Markdown/React consistency.

### Implementation for User Story 5

- [X] T058 [US5] Implement `internal/consolidate/groups.go`: anchor resolution (file + enclosing function via `recognize.Scope` + sink statement text through the confined `source` reader), fix/precondition token normalization, `BuildGroups(findings, repo) Groups` with `established|suggested`, `RG-<16hex>` id from family + earliest member anchor, `members[].role`, `raw_supported`, `grouped`; write `remediation_groups.json` (version 1).
- [X] T059 [US5] `internal/engine/engine.go` finalize + `regenerate.go`: build groups after `FinalFindings`, compute `decision_status`/`members_changed_since` from `internal/review` store records of members (read-only), pass groups to the report model; `candidate_manifest.json` `candidates[].likely_group` (report-only; no verification work skipped).
- [X] T060 [US5] Report rendering in `internal/report/report.go` + `html.go`: group-first findings index (primary row + occurrence sub-rows), `group-<id>` anchors, raw/grouped counts in Outcome metrics and executive summary actions (one action per group).
- [X] T061 [P] [US5] Surfaces: `internal/server/status.go` + `internal/apps/aggregate.go` (`groups` count additive), main UI report index grouping (`vhlocal/web/index.html`), React `pages/Reports.tsx` + `lib/types.ts`; `npm run typecheck`.

**Checkpoint**: One fix list per defect, every occurrence and decision still visible.

---

## Phase 8: User Story 8 - Diagnose verifier failures before attributing them to the model (Priority: P1)

**Goal**: Citations validated at hunt ingestion with one correction turn; canonical facts and worked examples in the verifier session; structured feedback; bounded `amend_candidate` with explicit identity rules; per-call failure records with provenance; replayable diagnostics; operator-triggered comparison harness; Go recognizer receiver fix; attestation kept distinct.

**Independent Test**: Scenarios 10–13 — audit citation examples through real ingestion; mixed-failure session records; comparison routing with `identityRecordingProvider`; `url.Values.Get("q")` negative example.

### Tests for User Story 8 ⚠️ (write first, ensure they FAIL)

- [X] T062 [P] [US8] Citation tests in `internal/citation/citation_test.go`: grammar + normalizations with provenance for the three audited strings (`E_CITATION_AMBIGUOUS`; normalized `backend/app/security.py:40`; primary `49-55` + supplementary `62-64`); `E_CITATION_NO_LINE`, `E_PATH_ESCAPE` (symlink), `E_PATH_ABSOLUTE`, `E_FILE_NOT_FOUND`, `E_RANGE_OUT_OF_BOUNDS` with `aids.file_length`, `E_REVISION_STALE`; `Bind` resolves route guard + handler span for Python/Go/JS and reports `unsupported` honestly for non-HTTP; no clamping/shifting ever (C-C2, C-C4).
- [X] T063 [P] [US8] Ingestion tests in `internal/engine/citation_ingest_test.go`: `citationRepairWriter` deliverable → one correction turn with per-finding feedback → rewritten file accepted; `hunt_execution.detail[].citation{invalid, repaired, remaining, correction_turns}`; still-invalid findings enter the manifest as `invalid_citation`, are counted in `raw_count`, appear in the report appendix, and never get a verification session; older Markdown artifacts import through the same validator (C-C1, C-C3, SC-010).
- [X] T064 [P] [US8] Verification session tests in `internal/engine/verify_contract_test.go`: task text contains handler span, `METHOD PATH` identity separate from display label, file length, required evidence span and the worked-example block; structured feedback fields; identical repeated submission stops after the second with `E_REPEATED_SUBMISSION`; malformed JSON / wrong-typed args ⇒ `E_TOOL_ARGS_JSON`/`E_TOOL_ARGS_TYPE` and never coerced; a perfect verdict on an `invalid_citation` candidate is rejected; explicit `unresolved` counted as `unresolved_explicit` (C-C5, C-C6, C-C8).
- [X] T065 [P] [US8] Amendment tests in `internal/engine/amend_test.go` with `amendingVerifier`: same-anchor amendment keeps the id; different-anchor amendment creates `CAND-…` with `supersedes`, marks the old `superseded`, inherits no decision; second amendment in a session refused; resume replays amendments idempotently and rejects a revision mismatch; `Regenerate` never invokes the model or rewrites citations; the reference-contract parity tests still pass (C-C7, C-C9).
- [X] T066 [P] [US8] Failure-record tests in `internal/engine/verify_calls_test.go` with `mixedFailureVerifier`: `verification_calls.jsonl` has three distinct entries (args, submission, turn exhaustion) with their own class/code/message; `SessionOutcome.failures_by_class` counts each; aggregates report `occurrences_by_class`, `sessions_by_class`, `stop_reasons`, overlap note; the `tool_failure` summary events carry per-class operation/message, not the session's last; `diagnostics/<candidate>.json` replays the failure through `verification.Reconcile` offline; `truncated_fields[]` declared; no credentials (C-C10, C-C11, SC-011).
- [X] T067 [P] [US8] Comparison tests in `internal/engine/compare_test.go`: two `identityRecordingProvider`s → every 2b call's recorded provenance names the variant's provider; frozen manifest and revision reused; `comparison.json` decisions/missing/repair rate/evidence validity/cost/config diff; all-unresolved variant ⇒ `gate.efficacy_improved == false`, reason `all_unresolved`; unexecuted variant ⇒ `not_run: true`; resume compatibility invalidates on a changed verify model (C-C13, C-C14, SC-012).
- [X] T068 [P] [US8] Recognizer tests in `internal/recognize/lang_go_test.go`: `r.URL.Query().Get("q")`, `r.Header.Get("X")`, `w.Header().Get("Y")`, `values.Get("z")` produce no route beside Gin (`gin.Default()`), Chi (`chi.NewRouter()`, `Route` closure `chi.Router`), `http.NewServeMux()` and package-level `http.HandleFunc` registrations that remain recognized with handler refs; unknown receiver with `"/path"` ⇒ `Certainty: Ambiguous`; `TestGoRecognizerNegativeControls` count preserved; `testdata/coverage100` Go services restored to `r.URL.Query().Get("q")` and `coverageFixture` still enumerates exactly 100 (C-C15, SC-013).
- [X] T069 [P] [US8] Provenance/prompt tests in `internal/engine/prompts_test.go` + `internal/verification/sessions_test.go`: 2b prompt records carry `candidate_id`, `prompt_hash`, `tool_schema_hash`, nudges are `kind: repair`; `SessionOutcome.model` + per-call `provenance{backend, endpoint, requested_model, returned_model}`; 2b `AgentRecord` carries the candidate id (C-C12).

### Implementation for User Story 8

- [X] T070 [US8] Implement `internal/citation`: `Parse`, `Normalize` (rules: backticks, `line N`/`lines N-M`, trailing commentary after a valid range, en-dash; ambiguous ⇒ error), `Resolve(repo, revision)` via `internal/source` (confinement, symlinks, existence, bounds, file length), `Bind` (route guard from `internal/inventory`/`authz.go` + `recognize.Scope` handler span; `certainty`), `Error{code, field, received, expected, repairable, aids}` with the codes in data-model.
- [X] T071 [US8] Ingestion in `internal/engine/hunt.go` + `verify.go` `collectHuntCandidates`: validate every extracted finding; per-unit one bounded correction turn (feedback message listing `{finding, field, code, received, expected, aids}`) counted in `attempts`; `hunt_execution.detail[].citation`; manifest schema 2 in `internal/verification/verification.go` (`candidates[].citation{original, normalized, binding, status}`, `invalid_citation` never scheduled, `Reconcile` rejects any decision on an `invalid_citation` candidate with a clear error); the Markdown adapter path unchanged otherwise.
- [X] T072 [US8] Verifier session contract in `internal/engine/verify.go`: task text gains canonical facts (handler span, route identity vs display label, file length, required evidence span) from `citation.Bind`; load `skill/phases/phase2b_session.md` (NEW file with tested worked examples of canonical citations, handler identities, complete evidence, supported/rejected/unresolved decisions, correction after an error) into the system prompt; structured `submit_verification` feedback; repeated-identical-submission stop (`E_REPEATED_SUBMISSION`); strict argument decoding (`E_TOOL_ARGS_JSON`/`E_TOOL_ARGS_TYPE`, own class `invalid_tool_args` with field); explicit `unresolved` recorded as `explicit_unresolved`.
- [X] T073 [US8] `amend_candidate` tool in `internal/engine/verify.go` + `internal/verification/verification.go`: schema `{candidate_id, path, start_line, end_line, reason}`; one accepted amendment per session; must `Resolve`+`Bind`; identity rule (same resolved anchor ⇒ kept; else new id with `supersedes`/`superseded`, no inherited decision); `amendments[]` in the manifest; resume replay + revision check in `internal/engine/resume.go` (also add verify model/backend/host to `resumeCompatibility`); regeneration never invokes the model.
- [X] T074 [US8] Failure records in `internal/engine/verify.go` + `internal/verification/sessions.go`: `verification_calls.jsonl` writer (one line per call/attempt with `class/code/message/feedback/repaired_by_call`), `SessionOutcome{calls, model, provenance, explicit_unresolved, amended}`, aggregates (`occurrences_by_class`, `sessions_by_class`, `stop_reasons`, `overlap_note`) written into `verification_metrics.json`; per-class `tool_failure` events use per-class operation/message; capture `client.Provenance` on every 2b call; 2b `AgentRecord.CandidateID`.
- [X] T075 [US8] Diagnostic capture in `internal/engine/diagnostics.go`: `diagnostics/<candidate>.json` (complete failing submissions + exact feedback + hashes + source refs; `context: bounded|full`; `truncated_fields[]`; dedup by prompt hash; retention newest 200 / 5 MB, decisive fields never truncated); scan option `diagnostic_capture: bounded|full` added to `internal/config/scanopts.go`, `internal/cli/run.go`, `internal/server/server.go` and the 013 option contract tests; redaction via `internal/redact`; never credentials or hidden reasoning.
- [X] T076 [US8] Comparison harness `internal/engine/compare.go` + CLI `internal/cli/compare.go` (`vhlocal verify-compare --manifest <file> --repo <path> --revision <sha> --variant prompt=<file> | model=<name>[,backend=<b>,host=<h>] [--truth <file>] [--out <dir>]`): re-run only 2b over the frozen manifest into a new results dir per variant; record effective role config observed on every call; `comparison.json` per data-model with `config_diff` first; `gate` (all-unresolved rule); `not_run` for unexecuted variants; never sends source to a provider the operator did not name.
- [X] T077 [US8] Go recognizer receiver inference in `internal/recognize/lang_go.go`: resolve `sel.X` to a router declaration (`gin.Default/New`, `*gin.Engine`, `chi.NewRouter/NewMux`, `chi.Router`, `*chi.Mux`, `http.NewServeMux`, `echo.New`, incl. `Group`/`Route` closure params) before treating `Get/Post/…` as a route; unknown receiver + path-like arg ⇒ `Ambiguous` (excluded from denominator, disclosed); restore `testdata/coverage100/gosvc/*/routes.go` to `r.URL.Query().Get("q")`; update `internal/inventory` to exclude `Ambiguous` from `Total` and list them under `excluded_with_reason`.
- [X] T078 [P] [US8] Attestation record shape in `specs/015-analyst-reports-efficacy/quickstart.md` table (`kind: attested | machine_executed | not run`, browser/version or `unknown`) and a validation-report check in `internal/server/applications_form_test.go`-style test that the shipped UI contract tests are named as source-string checks, never "browser verified" (FR-031).
- [X] T079 [P] [US8] Surfaces: report appendix "Unresolved (session failed)" rows show `class/operation/code`; `## Coverage and limitations` shows occurrences vs sessions with the overlap note; scan detail (`internal/server/status.go`), main UI Prompts/Log panes label `truncated` records "stored preview (8 KB clamp); full text not stored" (`vhlocal/web/index.html`), React `Scans.tsx`; `npm run typecheck`.

**Checkpoint**: Every verifier failure is attributable, repairable through the interface, and replayable.

---

## Phase 9: User Story 6 - An efficacy benchmark that measures supported detections (Priority: P1)

**Goal**: Reproducible benchmark over seeded multi-language issues and safe controls; supported-only deduplicated precision/recall with explicit denominators; frozen baseline and versioned policy; live runs operator-triggered and labelled.

**Independent Test**: Scenario 7 — transcript-provider runs over `testdata/benchmark/target` scored offline; rejected/unresolved/duplicates never count; truth isolation; baseline config diff.

### Tests for User Story 6 ⚠️ (write first, ensure they FAIL)

- [X] T080 [P] [US6] Scorer tests in `internal/benchmark/benchmark_test.go`: only `supported ∧ non-duplicate` findings count; a truth id counts once across repeated hits; rejected/unresolved never count; unmatched supported ⇒ FP; safe-control hits ⇒ FP flagged by language/family; per-language/per-family tables; explicit denominators; `cost.usd == "unknown"` for an unpriced backend and `0` for ollama; candidate recall counts manifest candidates (C-C16).
- [X] T081 [P] [US6] Isolation/baseline tests in `tests/parity/benchmark_test.go`: scan `testdata/benchmark/target` with the transcript provider; assert no `prompts.jsonl` record contains any truth id or the string `ground_truth`; `Score` output matches a golden; baseline file records target revision, build, effective config, models, prompt/schema hashes, sampling, seeds, budgets; comparison output prints `config_diff` first and marks live variants `not_run` (C-C17, C-C18, SC-007).
- [X] T082 [P] [US6] CLI test in `internal/cli/bench_test.go`: `vhlocal bench efficacy --results <dir> --truth <file> [--baseline <file>] --json` prints `Results` and exits non-zero only on a policy regression; the legacy `testdata/score.go` prints a deprecation notice pointing to the new scorer.

### Implementation for User Story 6

- [X] T083 [US6] Implement `internal/benchmark`: `LoadTruth`, `Score(resultsDir, truth) Results` (matching by acceptable anchors resolved via `recognize.Scope`; supported-only; dedup by truth id; safe controls; verification stats from `verification_metrics.json`/sessions; coverage from `review_units.json` v2 axes; artifacts from `artifact_errors`; cost from `scan_meta.usage` + `internal/pricing`), `Compare(results, baseline, policy) []Regression`, `LoadBaseline`, `LoadPolicy`.
- [X] T084 [US6] CLI `internal/cli/bench.go`: `bench efficacy` subcommand (keep existing `bench` throughput as `bench throughput`), `--results/--truth/--baseline/--json`; `Makefile` target `bench-efficacy` (scores an existing results dir; never launches a scan); retire `testdata/score.go` behind a deprecation notice.
- [X] T085 [US6] Freeze the offline baseline: `testdata/benchmark/baseline/2026-09-29-offline.json` produced from the transcript-provider run (labelled `provider: transcript`, `live: false`), `testdata/benchmark/POLICY.md` (regression = supported precision/recall or safe-control FP worse than baseline − declared tolerance per language/family; no absolute threshold; live baselines must record run variation), and a `docs/engineering/2026-09-29-efficacy-baseline.md` note comparing the audited live run with the config-diff block first and every unexecuted live evaluation marked `not run`.

**Checkpoint**: Efficacy claims are measured against out-of-target truth with honest denominators.

---

## Phase 10: User Story 7 - Stable application identity while scans run (Priority: P2)

**Goal**: Canonical application identity persisted at scan creation; provisional and final artifacts share one history through running, completion, cancellation and restart; no merge by display name; ambiguous legacy mappings explicit.

**Independent Test**: Scenario 8 — lifecycle fixture under one slug across create → running → restart → complete/cancel; same-name repos distinct; `ambiguous_mapping` for legacy dirs.

### Tests for User Story 7 ⚠️ (write first, ensure they FAIL)

- [X] T086 [P] [US7] Identity lifecycle test in `internal/server/app_identity_test.go`: `POST /api/scans` persists `app_slug`/`app_name` in the job spec; with a delayed fake provider, `/api/applications/{slug}` lists the running scan (partial `scan_meta.json`) under the same slug as after completion; server restart (`interrupted`) keeps it; cancellation keeps it; no second application appears at any point (C-B13, C-B14, SC-008).
- [X] T087 [P] [US7] Mapping tests in `internal/apps/identity_test.go` + `internal/reports/reports_test.go`: two repositories with basename `shop` map to distinct slugs and separate histories; a results dir with no `scan_meta.json` is listed as `ambiguous_mapping` (never merged/hidden); existing names, reports, ledgers and review decisions unchanged (`preservation*_test.go` extended) (C-B15, C-B16).
- [X] T088 [P] [US7] CLI parity test in `internal/cli/run_test.go`: `vhlocal run` writes the initial partial `scan_meta.json` at scan start with `app_slug`.

### Implementation for User Story 7

- [X] T089 [US7] `internal/server/handlers.go` `handleCreateScan` + `internal/cli/run.go`: compute `app_slug = apps.SlugFor(repoAbs)` and persist `app_slug`/`app_name` in the job spec before submit; `internal/jobs/jobs.go` `Job.Public()` exposes them.
- [X] T090 [US7] `internal/engine/engine.go`: write the initial `scan_meta.json` (`schema: "partial"`, repo, app_slug, app_name, model, started_at, `status: running`, phases_requested) at `scan_start` (atomic temp+rename), register/name the application idempotently at start (`apps.Register`/`SetName`), final `rec.Write` replaces it; `internal/engine/regenerate.go` refuses to "complete" a partial record (explicit error).
- [X] T091 [US7] `internal/reports/reports.go` `Load` reads `app_slug` from partial records; `internal/apps/aggregate.go` `index()` groups only by slug from `scan_meta` and emits `ambiguous_mapping` entries for dirs with no `scan_meta.json`; `AppDetail` gains `ambiguous []` (additive); main UI + React show running scans in the application history with a "running" badge and the ambiguous list (`vhlocal/web/index.html`, `web-react/src/pages/Applications.tsx`).

**Checkpoint**: Workstream B complete.

---

## Phase 11: Polish & Cross-Cutting Concerns

- [X] T092 [P] Update `specs/015-analyst-reports-efficacy/contracts/*.md` status notes from the as-built code; disclose any contract wording changed to match behavior as a scope change (FR-031); update `CHANGELOG.md`, `README.md` (report layout, `bench efficacy`, `verify-compare`, `diagnostic_capture` option) and `docs/engineering/2026-09-29-scan-reliability-handoff.md` backlog items now delivered.
- [X] T093 [P] Playwright browser specs under `web-react/tests/browser/` (report opens summary-first; filters/search/keyboard/anchors; scan switching no stale content; diagram corpus renders or falls back; `/` and `/app`) + `make browser-test` target + `web-react/tests/browser/README.md` stating they are operator-run, need an installed browser runtime, and are recorded as `machine_executed` only when run.
- [X] T094 [P] Run feature 012/013/014 regression + parity suites (`tests/parity/...`, `internal/server/preservation*_test.go`, `internal/engine/outcome_test.go`, `verify_classes_test.go`, `review_units_test.go` adjusted to v2 where the spec changes semantics — document each changed assertion) and confirm dashboards, option contracts, ledgers, analyst decisions, SARIF and static-only boundaries unchanged (SC-009).
- [ ] T095 Run the full isolated offline gate (`gofmt -l .` excl. the pre-existing fixture, `go vet ./...`, `go build ./...`, static build, `go test ./...`, `-race` on engine/jobs/server/agent/apps) with the real-store fingerprint byte-identical before/after (SC-014); `npm run typecheck`.
- [X] T096 Execute `quickstart.md` scenarios 1–14 offline and prepare the operator report: build identity + tested URLs, browser rows `not run` until the operator runs T093, live efficacy `not run` until the operator runs `vhlocal run` + `bench efficacy`; state explicitly that passing fake-provider tests and a checked task list are not evidence of live-model detection efficacy (SC-007, SC-012, FR-023).

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)** → **Foundational (Phase 2)** → user stories.
- **Workstream A**: US1 (Phase 3) → US2 (Phase 4, needs the model) → US3 (Phase 5, independent of US2 except report refs; can start after US1).
- **Workstream B**: US4 (Phase 6) depends on Foundational only; US5 (Phase 7) depends on US1's model for rendering; US8 (Phase 8) depends on Foundational (hashes) and precedes US6; US6 (Phase 9) depends on US4 (coverage axes) and US8 (verification metrics, manifest schema 2); US7 (Phase 10) depends on Foundational only.
- **Polish (Phase 11)** after all stories.

### Within Each Story

- Tests first (must fail) → records/parsers → engine wiring → surfaces (report, server, main UI, React, classic/legacy) → story checkpoint.

### Parallel Opportunities

- Setup: T002–T006 in parallel. Foundational: T009–T011 in parallel after T008.
- Every story's `[P]` test tasks run together; surface tasks marked `[P]` (React/classic/legacy) run alongside the main UI task.
- After Foundational: US1 and US4 and US7 can proceed concurrently (different files); US3 can start once T017 exists; US8 can start after T009.

## Parallel Example: User Story 8 tests

```
T062 internal/citation/citation_test.go
T063 internal/engine/citation_ingest_test.go
T064 internal/engine/verify_contract_test.go
T065 internal/engine/amend_test.go
T066 internal/engine/verify_calls_test.go
T067 internal/engine/compare_test.go
T068 internal/recognize/lang_go_test.go
T069 internal/engine/prompts_test.go + internal/verification/sessions_test.go
```

## Implementation Strategy

### MVP First (US1)

Setup → Foundational → US1 delivers the report model and the honest executive summary on every surface; this alone fixes the buried summary and the 4× severity over-count and is byte-identical on regeneration.

### Incremental Delivery

1. US1 → US2 → US3: Workstream A shippable on its own (analyst-ready reports and diagrams).
2. US4 → US5: coverage means analysis; fix lists are grouped without evidence loss.
3. US8 → US6: verifier failures diagnosable/repairable, then measured against out-of-target truth with a frozen baseline.
4. US7 → Polish: identity, docs, browser specs, gates, honest operator report.

## Notes

- Tests (T013–T016, T024–T027, T034–T037, T045–T049, T055–T057, T062–T069, T080–T082, T086–T088) are written first and fail before implementation.
- Evidence rules (`validateEvidenceBacked`, byte-matching quotes, span coverage, entry-point identity, function evidence) are never loosened; the parity reference contracts remain the oracle.
- No task runs a live model, executes target code, sends source to a provider the operator did not name, or touches operator storage; the 171-candidate baseline is replayed from sanitized records.
- Live-model efficacy and browser workflows remain operator actions and are reported as `not run` until performed.

## Completion evidence — 2026-09-29

Resumed after the interrupted implementation. Remaining command stubs, benchmark
regressions/baseline, identity lifecycle, diagnostic redaction/full context,
report stale-response handling and documentation are delivered. See
`docs/engineering/2026-09-29-015-completion.md` for named checks and build identity.

T095 remains unchecked **only for the literal real-store before/after fingerprint
criterion**: the operator launched scan `c7514f55c559` during this session, so the
live log and results changed legitimately. The ordinary full/race gates passed;
the final gate also runs with the two real store paths shadowed by read-only bind
mounts in a separate mount namespace. This prevents test writes without stopping
the live scan. Do not claim byte identity for the concurrently changing stores.
Repeat that fingerprint comparison when the operator stores are quiescent.

Second attempt — 2026-09-30, after the stores had been quiescent ~6 h. The full
gate passed again (`GATE_EXIT=0`: gofmt, vet, build, static build, `go test ./...`,
`-race` on engine/jobs/server/agent/apps, `npm run typecheck`), but scan
`c7514f55c559` resumed mid-gate, so the fingerprint again differs. This time every
changed byte is positively attributed to that scan: 5 new files all inside its own
results directory, its `prompts.jsonl`, and the shared log — which was proven
append-only (the pre-gate bytes hash identically as a prefix) with all 12 appended
lines carrying its job id and model. The suite wrote nothing to the operator stores.
That is the substance of SC-014 but still not the literal byte-identity observation,
so the task stays unchecked. Evidence and the repeat procedure:
`validation-015/t095-attribution.md`.

Audit correction — 2026-09-30. A spot audit of the checked tasks found **T079
incomplete while marked done**, in two of its named deliverables: the report's
`## Coverage and limitations` never rendered occurrences vs sessions or the overlap
note (the aggregate existed only in `verification_metrics.json`), and the main UI
still labelled a clamped prompt record `content clamped` instead of the honest
"stored preview (8 KB clamp); full text not stored" — React alone carried the new
wording. Neither had test coverage, which is why the gap survived. Both are now
implemented (`internal/report/coverage.go` failure block wired into the Markdown and
HTML renderers, fed from the record by `failureAggregates` in
`internal/engine/outcome_build.go`; `vhlocal/web/index.html` relabelled) and both are
now asserted: `internal/report/failures_test.go` and
`TestShippedMainUILabelsStoredPreviewHonestly` in `internal/server/evidence_form_test.go`.
Tasks sampled and confirmed genuinely complete: T051, T053, T054, T061, T076, T077,
T078, T084, T085, T090, T091, T092.

T093 delivers browser specs; their execution is **not run** (runtime absent).
T096 delivers the offline scenario evidence and operator report; live efficacy
is **not run**. These labels are not converted into passes by checking tasks.

Implementation clarifications: diagnostic context is deduplicated by its full
sanitized content hash, retaining the prompt hash as provenance, because a system
prompt hash is shared across different candidates. The 5 MB limit drops context
previews first, never decisive failing submissions. `verify-compare` requires an
explicit fresh output directory and explicit providers. Lifecycle tests span the
engine, jobs, server and CLI packages rather than one monolithic test. No evidence
requirement was relaxed and no operator report was regenerated.
