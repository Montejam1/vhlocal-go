# Contract — Report model, rendering, exports, diagrams (Workstream A)

Behavior invariants for `internal/report`, `internal/consolidate`, `internal/threatmodel`, both viewers.
Offline-verified unless marked operator.

## Report model (FR-001..004)
- **C-A1**: `report_model.json` is written by finalize and by regeneration and is byte-identical between the
  two for the same records (as the 014 Completion block is).
- **C-A2**: `counts.supported == len(findings)` and `Σ severity_supported == counts.supported`;
  `counts.total_candidates == supported + rejected + unresolved_explicit + unresolved_failed` (duplicates
  excluded and reported separately).
- **C-A3**: `summary.words ≤ 300`, `len(leading) ≤ 5`, each `leading[].ref` resolves to an index anchor.
- **C-A4**: a run with `counts.supported == 0` and execution ≠ complete has `summary.narrative` beginning
  with the limitation sentence; the word "clean" never appears in the summary.
- **C-A5**: no model call, no inference cost, during finalize's report build or `vhlocal report`.

## Rendering order and surfaces (FR-005..010)
- **C-A6**: Markdown/HTML section order: `## Executive summary` → `## Outcome metrics` → `## Findings index`
  → `## Findings` (`### <id>` each) → `## Coverage and limitations` → `## Appendix A — Candidates`
  (`### Rejected`, `### Unresolved (explicit decision)`, `### Unresolved (session failed)`) →
  `## Appendix B — Execution` (per-phase table; agent rows linked, collapsed in HTML). The 014 Completion and
  Review-coverage blocks live inside "Coverage and limitations" unchanged in wording.
- **C-A7**: every index row has `id="finding-<id>"` (HTML) / `<a id>` anchor (Markdown); HTML rows are
  `tabindex="0"` and the filter/search operate over all rows with `data-sev`/`data-status`; an active filter
  is disclosed in the banner and in the print header; `beforeprint` expands details.
- **C-A8**: finding detail renders every `verification_record.evidence[]` as escaped code with a
  `path:start-end` caption; absent fix ⇒ literal "Recommended fix: not provided"; absent evidence ⇒
  "Captured evidence: none (not verified)".
- **C-A9**: in-app viewers rewrite relative links to `/api/reports/{id}/file?path=<rel>`; exports keep
  relative paths; only `http(s):`, `mailto:` and relative targets are allowed; model markup is escaped.
- **C-A10**: React `/app` and the main UI read `report_model.json` when present; when absent they fall back
  to their previous math and display "counts from findings.json (pre-015 scan)".
- **C-A11**: print/PDF: export scope selector (`summary` = sections 1–3; `full`), `break-inside: avoid` per
  finding, code blocks wrap; the print header names the scope and any active filter.

## Diagrams (FR-011..014)
- **C-A12**: `threat_model_diagram.json` exists whenever `threat_model.md` exists (post-015 runs and on
  regeneration); each fence has exactly one `state`; `invalid` diagrams carry ≥1 `errors[]` with a line.
- **C-A13**: repairs are limited to the enumerated rules; a repaired diagram's `structure` equals the
  structure of the original text with the rule applied (no edge/node added or removed); the audited edge
  `B -.->|HTTP request (untrusted) .-> E` is `invalid` with `E_EDGE_LABEL_UNTERMINATED`, never repaired.
- **C-A14**: `reports.Material` for `threat_model.md` gains `diagram{state, errors}`; narrative availability
  and diagram validity are separate fields on every surface (`/api/reports`, `/api/applications/{slug}`).
- **C-A15**: UI: one failed diagram never prevents the rendering of a sibling; a failed diagram shows the
  narrative, the node/flow table, `{line, code, message}` and Retry / View source; render/error state is
  cleared when the report, application or diagram changes and on theme change; labels render as text
  (`securityLevel: strict`); SVG export is user-initiated.
- **C-A16**: classic/legacy show the node/flow table + source and the sentence "diagram rendering is
  available in the main UI" (no Mermaid there).

## Operator-run browser evidence
- **C-A17**: `web-react/tests/browser/` specs cover: 171-candidate report opens with summary first;
  filter/search/keyboard/anchors; scan switching with no stale content; diagram corpus renders or falls
  back per C-A15; `/` and `/app`. Results are recorded as `machine_executed` only when run; otherwise the
  attestation table row says `not run`.

## As-built status (2026-09-29)

Model, Markdown, standalone HTML and both interactive viewers carry the report changes. Full body/diagnostics are collapsed after the structured interactive view. Both report viewers reject stale responses. Embedded JavaScript parses and React builds. Browser test specifications exist, but no browser runtime is installed here: browser rendering/interaction is NOT machine-verified. Diagram corpus tests exercise the static parser, not Mermaid layout in a browser.

See `docs/engineering/2026-09-29-015-completion.md` for executed evidence and remaining operator checks. The diagnostic content-addressing and explicit output-directory requirement are disclosed implementation clarifications; no evidence-validation or efficacy acceptance rule was relaxed.
