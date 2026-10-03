# Quickstart — Validating feature 015 (offline first)

Everything below runs offline with fake providers and isolated storage (`internal/testisolate`). No live
model, no target execution, no `../vhlocal` execution. Live-model efficacy and browser workflows are
operator actions and are labelled as such.

## Prerequisites
- Go 1.23+ (`/usr/local/go/bin`), `CGO_ENABLED=0` static build; Node only for `npm run typecheck` /
  `npm run build` in `web-react/` (local `node_modules`, no network).
- Optional, operator: a browser + Playwright runtime for `make browser-test` (needs network to install; never
  vendored).

## Offline gate (must stay green)
```
export PATH=$PATH:/usr/local/go/bin
gofmt -l . | grep -v testdata/goapp/api/routes.go   # empty
go vet ./... && go build ./... && CGO_ENABLED=0 go build -o bin/vhlocal ./cmd/vhlocal
go test ./...
go test -race ./internal/engine/... ./internal/jobs/... ./internal/server/... ./internal/agent/... ./internal/apps/...
# real-store byte-identity (SC-014): fingerprint ~/.vhlocal + ~/vulnhunter-reports before/after `go test ./...`
```

## Validation scenarios → success criteria

| # | Scenario (offline, isolated) | Proves |
|---|---|---|
| 1 | Sanitized 171-candidate replay (43/7/121, 438 agent rows) → `report_model.json`, Markdown, HTML: summary ≤ 300 words / ≤ 5 leading, totals visible before diagnostics, severity Σ = 43, byte-identical after `Regenerate` | SC-001, C-A1..A6 |
| 2 | Same fixture: every candidate/evidence link resolves through `/api/reports/{id}/file`; index anchors/filters/search present in HTML; export scope + filter disclosure; shipped-asset contract test for both UIs | SC-002, C-A7..A11 |
| 3 | Diagram corpus (missing brackets, unterminated label incl. the audited edge, comments, quotes, parentheses, Unicode, multiple diagrams, malicious labels) → `threat_model_diagram.json` states/repairs/errors; serializer determinism; topology preserved | SC-003, C-A12..A14 |
| 4 | Disposition fixtures: 400-line overlapping read; full reads without dispositions; valid dispositions; sibling handlers; missing checks; fabricated ids; stale revision; Go/JS examples | SC-004, C-B2..B5 |
| 5 | Paired fixtures 100-vs-8 dispositions with all 100 read; v1 record regeneration keeps v1 label | SC-005, C-B6 |
| 6 | Grouping fixtures (pickle/XSS/XXE/NoSQL repeats; distinct defects on one endpoint); regeneration stability; decision status/members-changed | SC-006, C-B9..B12 |
| 7 | Benchmark corpus with transcript provider: rejected/unresolved/duplicates never count; safe-control FP; per-language/family; truth isolation; baseline config diff; `not_run` labelling | SC-007, C-C16..C18 |
| 8 | Lifecycle fixture: create → running (partial scan_meta) → restart → complete/cancel under one slug; same-name repos distinct; `ambiguous_mapping` for legacy dirs | SC-008, C-B13..B16 |
| 9 | Preservation suites (dashboards, options, ledgers, reviews, static-only) + embedded-asset tests on the built binary | SC-009 |
| 10 | Citation examples from the audit through the real ingestion path: normalization with provenance, ambiguous → feedback, one correction turn, invalid stays `invalid_citation`; amendment kept/superseded identity; perfect verdict cannot bypass | SC-010, C-C1..C-C8 |
| 11 | Mixed-failure session (args error → submission error → turn limit): three distinct call records; aggregates with overlap note; `diagnostics/*.json` replays the failure through `Reconcile` offline | SC-011, C-C10..C12 |
| 12 | Comparison fixtures: fake providers with per-call identity prove role routing; frozen manifest; denominators; all-unresolved gate; live variants `not_run` | SC-012, C-C13..C14 |
| 13 | Go recognizer: `url.Values.Get("q")` beside genuine registrations; `coverage100` on the real construct; attestation rows keep `attested` vs `machine_executed` | SC-013, C-C15 |
| 14 | Report build/regeneration with the fake provider absent: zero model calls; full-suite real-store fingerprint identical | SC-014, C-A5 |

## Fixtures & doubles
- `testdata/replay-171/` — sanitized records of the live baseline (no prompts): manifest, decisions,
  sessions, reconciliation, review units, hunt execution, artifact manifest, scan_meta. Drives scenarios 1–2.
- `testdata/diagrams/` — the FR-014 corpus, each case with expected state/repairs/errors.
- `testdata/coverage100/` — extended with v2 disposition deliverables (`readingWriter` gains a
  `dispositions` mode) and Go sources restored to `r.URL.Query().Get("q")`.
- `testdata/grouping/` — repeated pickle/XSS/XXE/NoSQL supported findings + negative controls.
- `testdata/benchmark/{target,truth,baseline,POLICY.md}` — seeded multi-language corpus and frozen baseline.
- Doubles: `citationRepairWriter` (invalid citation → reads feedback → rewrites), `amendingVerifier`
  (uses `amend_candidate` then verifies), `mixedFailureVerifier`, `identityRecordingProvider` (stamps its
  name into every response's provenance), transcript provider from `tests/parity`.

## Operator-owned (not in the offline gate)
- `npm run build` for `/app`; `make browser-test` (Playwright specs under `web-react/tests/browser/`)
  against the fresh binary — results recorded in the table below as `machine_executed`; anything not run
  stays `not run`.
- Live-model runs: `vhlocal run` on `testdata/benchmark/target` then `vhlocal bench efficacy`;
  `vhlocal verify-compare` variants. Reported with the config diff and run variation; never a side effect.

### Validation report template (SC-012 rule: source-only checks are not browser evidence)

| Field | Value |
|---|---|
| build (version / assets hash / built_at) | |
| tested URLs | `/` `#reports?open=<id>` · `/app/reports?open=<id>` · `#applications?app=<slug>` · `/app/apps?app=<slug>` |
| browser / version | (or `unknown`) |
| scenarios | id → `attested` \| `machine_executed` \| `not run`, with result and notes |
| live efficacy run | results dir, `bench efficacy` output, config diff vs baseline, or `not run` |

## Execution record — 2026-09-29

The implementation is built; the running operator server was not restarted.
Detailed build/hash/HTTP URLs and gate results are in
`docs/engineering/2026-09-29-015-completion.md`. Browser / version: **unknown**;
browser interaction and live model comparisons: **not run**.

| Scenario | Kind | Executed evidence |
|---|---|---|
| 1 | machine_executed | `TestReplayModelCountsAndSummaryBounds`, `TestRenderOrderSummaryFirst`, `TestReportModelRegeneratesByteIdentical` |
| 2 | machine_executed | report index/link/surface tests, shipped source-string checks; Node stale-response regression. Browser half not run. |
| 3 | machine_executed | `TestCorpusStatesRepairsAndErrors`, `TestAuditedEdgeIsNeverRepaired`, serializer tests. Mermaid browser layout not run. |
| 4 | machine_executed | `TestParseAndValidateDispositions`, `TestCoverageV2CreditRequiresValidatedDispositions` |
| 5 | machine_executed | `TestCoverage100AllReviewedWithEvidence`, `TestCoveragePaired8StaysHonest`, `TestLegacyReviewUnitsStayV1OnRegeneration` |
| 6 | machine_executed | consolidate grouping tests, `TestGroupsInReportSurfaces` |
| 7 | machine_executed | benchmark scorer/CLI tests, `TestBenchmarkTranscriptIsolationAndBaseline`; live quality not run |
| 8 | machine_executed | server lifecycle, jobs restart, engine scan-start and CLI identity tests; same-name and legacy mapping regression |
| 9 | machine_executed | full Go/parity/preservation suites and fresh-binary HTTP asset checks |
| 10 | machine_executed | citation ingestion/correction, amendment/replay, strict verifier contract and invalid-citation regressions |
| 11 | machine_executed | `TestVerificationCallsRecordEveryFailureDistinctly`, full capture/retention, nested-redaction and distinct-context regressions |
| 12 | machine_executed | `TestFrozenVerifierComparison`, CLI dry run; live verifier variants not run |
| 13 | machine_executed | `TestGoRecognizerReceiverInference`, negative controls, attestation/source-check label regression |
| 14 | machine_executed | regeneration without provider; protected offline/race gate. Literal real-store fingerprint is inconclusive while the operator scan writes; T095 remains open for that check. |

The two 015 coverage assertions intentionally distinguish completed dispositions
from read exposure; v1 historical counts retain their old meaning. Passing fake
provider tests does not establish live-model detection efficacy. No browser row
has been promoted from source-string checks to browser verification.
