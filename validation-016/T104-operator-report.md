# Feature 016 — operator report (T104)

Date: 2026-10-03. Prepared from the offline validation of
`specs/016-actionable-vulnerability-reports/quickstart.md`.

## What this report is, and is not

Scenarios 1 through 19 are offline and were executed. Scenarios 20 through 22 require human
observation and are **not run**.

**Passing offline tests and a checked task list are not evidence of reader comprehension,
browser quality, or print quality.** SC-001 (a reader identifies the application, the issue
count, the first action and whether review is incomplete within 60 seconds) and SC-008 (the
browser and print review) are unproven until an operator performs scenarios 20 through 22.
Nothing in this document should be read as establishing them.

## Build identity

| Field | Value |
|---|---|
| Repository | `/home/br0kan/Programs/vhlocal-go` |
| Git HEAD | `cc3c1f0` (worktree dirty — this feature's work is uncommitted) |
| Go toolchain | `go1.27.1 linux/amd64`, module target `go 1.23` |
| Binary | `vhlocal`, `Version = "dev"` (`assets.go`), stdlib only, no `go.sum` |
| Static build | `CGO_ENABLED=0 go build -ldflags="-s -w" ./cmd/vhlocal` → ELF 64-bit, **statically linked**, stripped |
| Presentation projection | `report.PresentationVersion = 1` |
| Guidance table | `internal/guidance`, 27 weakness families, compiled in, no model call |
| Acceptance corpus | `testdata/report016`, sanitized copy of the 2026-09-30 scan; all 9 source records re-verified against `SOURCE_FINGERPRINTS.txt` and **unchanged** |

## URLs the redesigned report reaches (not opened in a browser here)

These are the six surfaces FR-021 covers. Their source was checked; none was loaded in a
browser as part of this validation.

| Surface | Path | How it was checked |
|---|---|---|
| Default web report | `/` (`vhlocal/web/index.html`) | source-string contract, `internal/server/shipped_report_test.go` |
| Retained viewer | `/classic` (`vhlocal/web/index.classic.html`) | same |
| Retained viewer | `/legacy` (`vhlocal/web/index.legacy.html`) | same |
| React app | `/app/reports` (`web-react/src/…`) | source-string contract plus `tsc --noEmit` |
| Downloaded document | `SCAN_REPORT.md` | rendered and asserted from the frozen fixture |
| Downloaded document | `SCAN_REPORT.html` | rendered and asserted from the frozen fixture |

The local server was already running on `http://0.0.0.0:8421` throughout and was **not**
restarted, rebuilt or redeployed; the shipped assets are embedded, so the running process
still serves the previous build. Serving the new assets is an operator action.

## Offline gate

Run immediately before this report; full detail in `validation-016/T103-offline-gate.md`.

| Step | Result |
|---|---|
| `gofmt -l .` (excluding the pre-existing fixture) | clean |
| `go vet ./...` | clean |
| `go build ./...` | clean |
| static `CGO_ENABLED=0` build | statically linked, stripped |
| `go test ./... -count=1` | 39 packages ok, 0 failures |
| `go test -race` on report, engine, server, jobs, agent, apps, guidance, reports | all ok |
| `npm run typecheck` | clean |
| Real-store fingerprint before vs after | **identical** — 5,479 files, same metadata digest and same content digest, empty diff |

## Offline scenarios 1 through 19

All executed. Every row names the test that executes it, so the claim can be re-checked
rather than taken on trust.

| # | Result | Executed by |
|---|---|---|
| 1 | pass | `TestPersistedModelCarriesProjection`, `TestHeadlineCountsAreTheEstablishedDefects`, `TestReviewItemsExplainWhatIsUnresolved`, `TestDismissedCandidatesStayAvailableAndOutOfTotals` |
| 2 | pass | `TestScopeNoteShowsThreeFactsOnce`, `TestRenderedCountsCarryTheirLabels` |
| 3 | pass | `TestOpeningProseIsBounded`, `TestOpeningExcludesDiagnostics` — measured 90 projection words, 114 rendered words, bound 180, baseline 557 |
| 4 | pass | `TestIssueSectionsAreOrderedAndComplete`, `TestIssueSectionsDoNotRepeatParagraphs` |
| 5 | pass | `TestFamilyGuidanceIsMechanismAppropriate`, `TestNoUniversalFallbackAndNoSharedSteps`, `TestUnknownWeaknessTakesInvestigateBranch`, `TestGuidanceResolutionOrderAndProvenance` |
| 6 | pass | `TestPolicyDependentFamiliesNameTheMissingDecision`, `TestResolveCarriesTheMissingDecision` |
| 7 | pass | `TestGroupingCorpusAccountsForEverySupportedRecordOnce`, `TestTwoEstablishedGroupsAtOneRouteStaySeparate`, `TestRepeatedCitationsDoNotInflateLocationCount`, `TestNoMergeIsInferredWithoutAnEstablishedGroup` |
| 8 | pass | `TestDisplaySeverityMapping`, `TestGroupSeverityUsesHighestAndRetainsOriginals`, `TestDisplaySeverityCategoriesAreExact`, `TestFixture016GroupSeverityDistribution` |
| 9 | pass | `TestGeneratedArtifactsFabricateNothing`, `TestGeneratedArtifactsClaimNoExecution` |
| 10 | pass | `TestStatusCorpusRendersHonestly` (9 cases), `TestIncompleteScanOffersNoAllClear`, `TestZeroFindingsWithIncompleteReviewDistinguishesAbsenceFromIgnorance` |
| 11 | pass | `TestMarkdownAndHTMLAgreeOnEveryIssue`, `TestSurfacesAgreeOnCountsAndOrder`, `TestShippedViewersReadThePresentationProjection`, `TestShippedViewersRenderOneSummaryAndOneCandidateList` |
| 12 | pass | `TestScaleCorpusFiltersReachEveryIssue` (120 issues), `TestScaleCorpusHandlesVeryLongValues` |
| 13 | pass | `TestDefaultBodyHasOneSectionPerIssue` — 34 sections against the 49 baseline |
| 14 | pass | `TestTechnicalDiagnosticsArePresentAndSeparated`, `TestProvisionalSeverityStaysOutOfTotals`, `TestReviewItemsExplainWhatIsUnresolved`, `TestDismissedCandidatesStayAvailableAndOutOfTotals` |
| 15 | pass | `TestSavedReportWithoutProjectionRendersAsLegacy`, `TestSavedReportWithoutGroupsStillReportsEveryFinding`, `TestPresentationVersionIsHonouredAndNeverInvented` |
| 16 | pass | `TestRegenerate016IsDeterministicAndOffline`, `TestRegenerate016RefusesUnfinishedRecords` |
| 17 | pass | `TestHostileStringsAndMissingArtifactsRenderSafely`, `TestArtifactAvailabilityIsStated` |
| 18 | pass | `TestFixture016IsSanitized`, `TestProjectionIsDeterministic`, plus the source-scan fingerprint re-check and the before/after store fingerprint below |
| 19 | pass | `TestStandaloneReportIsSelfContained` |

Scenario 16 carries a scope note: the regeneration corpus is built from engine-written
verification records rather than `testdata/report016`, which is a report-rendering corpus with
no raw phase outputs. The frozen fixture's determinism is covered by
`TestProjectionIsDeterministic` instead. Recorded in the contract as-built notes.

## Human-observed scenarios 20 through 22

| # | Scenario | Status |
|---|---|---|
| 20 | Timed review, at least three intended readers who did not implement the feature | **not run** |
| 21 | Browser review at desktop width and at 375 CSS pixels | **not run** |
| 22 | Print a sample and check all five sections, no clipping, no dark page background, diagnostics omitted by default | **not run** |

What exists for them is preparation, not evidence: the print stylesheet forces collapsed
sections open and excludes the diagnostics by default, a "full + diagnostics" export scope is
available, the index is keyboard-activatable with a visible focus ring, severity is labelled
as text, and the stylesheets carry a 420px layout and anywhere-wrapping for long recorded
paths. Whether any of that reads well to a person is unestablished.

The operator-run Playwright specifications in `web-react/tests/browser/reports.spec.ts` were
updated for the redesigned report (T098) and are labelled operator-run. They were **not
executed**, so they must be recorded as `machine_executed: false` until an operator runs them.

## Two observations a reader should know about

Neither is a test failure; both are judgements worth stating rather than leaving to be found.

1. **Overlapping citations read as several locations.** Where the records cite
   `dispatch_operations.py:51-62`, `:52-62` and `:61-62` for one issue, the report shows three
   affected locations and the index says "3 locations". C-P15 collapses *identical* citations;
   merging overlapping-but-different ranges would mean deciding they are the same span, which
   the records do not say. A reader may reasonably see one location where the report says
   three.
2. **One long recorded paragraph in Needs review.** An inconclusive item's recorded reason is
   rendered inline, which makes that bullet long. FR-017 requires saying what is unresolved,
   and the text is the review's own; it is the one place in the document where a reader meets
   a wall of prose.

## Out of scope, and untouched

No live scan, no inference call, no server restart, no regeneration of an operator report, no
change to grouping quality or scan coverage, and no commit. The operator's
`~/.vhlocal` and `~/vulnhunter-reports` were read only for the fingerprint comparison.
