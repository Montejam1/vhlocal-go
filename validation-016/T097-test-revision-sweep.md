# T097 — test revision sweep (feature 016)

Date: 2026-10-03. Scope: every test assertion this feature changed, with the reason, and a
check that nothing about evidence, counts, provenance or status integrity was weakened
(C-C20).

## How the revisions were organised

The task list deliberately put each revision inside the story that broke it — T036 (US1),
T066 (US3), T096 (US5) — so the offline gate stayed usable as a checkpoint. T097 is the
final audit, not the repair.

Two renderers now exist. `renderMarkdownModel` / `renderHTMLModel` dispatch on
`m.Presentation`: a model carrying the projection renders the redesigned document, and a
model saved before this feature renders through `renderMarkdownLegacy` /
`renderHTMLLegacy`, which are the feature-015 bodies, unchanged. That is required by FR-026
and C-C7, and it is also what let most feature-015 tests keep their assertions verbatim:
they were retargeted at the legacy path they describe, rather than deleted.

## Revisions, file by file

Each file below carries the reason in a comment at the changed assertion.

| File | Change | Reason |
|---|---|---|
| `internal/report/order_test.go` | `TestRenderOrderSummaryFirst` → `TestLegacyRenderOrderSummaryFirst`, reading the legacy renderers; new `TestPresentationOrderKeepsSummaryFirst` added | the section names changed; the two properties worth keeping on the new path (no candidate id before the summary, one copy of each failure explanation) are now asserted there too |
| `internal/report/surfaces_test.go` | retargeted the count strings and the order markers to the new document, reading every count from the persisted projection | the "all surfaces agree" intent is unchanged; only the labels moved |
| `internal/report/us3_test.go` | banner assertions rewritten for the new note | the old banner presented 64 candidates as findings (FR-003, SC-002); the guarantee (an incomplete run is flagged, a clean one is not, reasons stay available) is asserted unchanged |
| `internal/report/report_useful_test.go` | `TestReportSupportedFirstWithDetail` reads the legacy renderer; `TestReportRenderingsAgree` split between the new label and the legacy review detail | the per-detection document is the legacy one; US2 brings the recorded review detail into the new document's five sections |
| `internal/report/index_test.go` | both tests read the legacy renderers | they describe the per-detection index and the "fix not provided" wording that FR-015 removes; the new document's rows, anchors and deep links are asserted in `anchors_test.go`, `index_columns_test.go` and `document_order_test.go` |
| `internal/report/html_test.go` | `TestHTMLFiltersPrintAndEscaping` reads the legacy renderer | it counts per-detection row classes and the status filter of the legacy index; the new page's filters, escaping and offline guarantees are asserted in `anchors_test.go`, `offline_selfcontained_test.go` and `print_test.go` |
| `internal/report/groups_test.go` | the rendering assertions read the legacy renderers | the ↳ occurrence marks and the "Supported findings (raw)" label are the legacy grouping presentation; the new unit's grouping is asserted in `grouping_corpus_test.go`, `same_route_groups_test.go` and `group_fallback_test.go`. The model-level assertions are untouched |
| `internal/report/coverage_axes_test.go` | reads the axes from `## Scan details` instead of `## Coverage and limitations` | the block moved; every axis assertion is unchanged |
| `internal/report/failures_test.go` | same section retarget | identical reason |
| `internal/report/report_test.go` | heading and label strings follow the new document | "Run status (three independent axes)", "Assessment method", "Issues to fix"; every honesty assertion kept |
| `internal/report/summary_test.go` | reads `## Summary` … `## Priority actions`; the static-method assertion now matches the new wording | the opening section was renamed and bounded; the guarantee (no all-clear, no implied completion, method named) is unchanged |
| `internal/engine/outcome_test.go` | reads the failure class from `### Unfinished verification sessions` | a verification failure class is scanner troubleshooting and moved under Scan details (FR-003); the assertion itself is unchanged |
| `internal/server/report_form_test.go` | nothing removed; a note records why, and two React symbols added | the strings belong to the feature-015 renderers, which still render pre-016 reports |

## Assertions narrowed, and why

Three checks I wrote during this feature were narrowed after they proved to be measuring the
wrong thing. Each is recorded here because narrowing a test is the easiest place to hide a
regression.

1. `scope_note_test.go`, exposure axis. The first version forbade the substring `90`
   anywhere in the document, which matched hex digests and line numbers. It now matches the
   renderings that actually read as a coverage figure (`90 of 100`, `90/100`, "90 entry
   points reviewed", "reviewed: 90") and requires the word "exposure" nearby. The projection
   assertion that completed and exposed stay separate fields is unchanged.
2. `scope_note_test.go`, unknown coverage. The first version forbade `of 100 entry points`
   anywhere; that fired on the feature-014 completion block, which is a recorded operator
   diagnostic the run itself wrote. FR-004 governs the READER-FACING figure, so the check now
   applies to the opening. Scan details may still carry the recorded tally.
3. `safety_test.go`, hostile strings. The first version forbade the substrings `onerror=`
   and `javascript:alert(1)`, which correct escaping leaves in the text. It now asserts that
   every element inside the rendered issue content is one the renderer emits (a tag
   allowlist) and that no live markup or `javascript:` URL exists. This is stronger.

One assertion was removed outright: a line-count reduction I had written into
`surface_parity_test.go`. SC-010 measures consolidation — one detail section per primary
issue, no per-detection duplicate, no appendix, nothing deleted — not document length. The
new document is in fact **longer** (3,293 lines against the 2,777-line baseline) because
every issue now carries real remediation guidance where the baseline said "fix not provided"
54 times, and because every relocated diagnostic stayed in the file. That is reported in
T100 rather than hidden. The replacement assertions are stronger: each detection is counted
exactly once, the detection total matches the records, and every recorded evidence excerpt is
still present.

## Weakening check

- Evidence: no evidence assertion was removed. `grouping_corpus_test.go`,
  `surface_parity_test.go`, `safety_test.go` and `regenerate016_test.go` each assert that
  recorded excerpts survive; `legacy_test.go` asserts the legacy path still renders them.
- Counts: every count assertion is now read from `baseline.json` or from the persisted
  projection rather than typed into the test, so a count cannot drift silently.
- Provenance: the backing detection ids, the recorded group id, the recorded severities and
  the guidance provenance are each asserted on both surfaces.
- Status integrity: the three axes are still asserted independently
  (`status_corpus_test.go`, `projection_determinism_test.go`), and the needs-review split is
  asserted never to enter a vulnerability or severity total.

## Residual search results

- `finding(s) were produced` appears only in `us3_test.go`, where it is asserted ABSENT.
- `Findings index` appears only in `order_test.go` and `legacy_test.go`, both describing the
  legacy document.
- `fix not provided` appears in `primary_test.go` and `guidance_resolution_test.go` as an
  absence assertion, in `index_test.go` as the legacy `IndexRow.Action` value, and in
  `report_form_test.go` as the legacy viewer's own string.
