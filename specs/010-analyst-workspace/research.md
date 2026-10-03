# Phase 0 Research: Evidence-centered analyst workspace

Grounded in a full codebase inventory of `~/Programs/vhlocal-go` (HTTP API,
persistence, comparison, status, provenance, and both front-end surfaces). Each decision cites
what exists today so the plan reuses rather than duplicates, and names the real gaps.

## R1 — Primary surface, embedding, and the offline gate

**Decision**: Deliver the new workspace **backend-first**, with the **React SPA (`web-react/`)
as the primary design surface** and the **legacy UI (`vhlocal/web/index.html`) kept accessible
and unregressed**. The Go backend is the offline-tested increment gate; React build + browser
acceptance are operator-owned.

**Evidence**: `assets.go:26` embeds `all:vhlocal/web`; `internal/server/static.go:26-36` serves
the React SPA at `/app`, but `vhlocal/web/app/` is absent and git-ignored — it exists only
after `npm run build` (`Makefile:17-18` `npm ci && npm run build`), and `web-react/node_modules`
is absent so a build needs network. The committed served surface is `/` → `vhlocal/web/index.html`
(`static.go:18-19`). Neither surface has a Findings page or a source/evidence viewer today.

**Rationale**: The spec names React as the primary target *and* says to identify the actual
shipped entrypoints, preserve access from other entrypoints, and not require a second legacy
redesign. The standing constraint requires offline validation with the operator running live
testing. Backends are surface-agnostic and fully offline-testable (`go test ./...` + fake
provider), so putting the real behavior there satisfies both: the feature is verifiable offline
regardless of which UI an operator builds. This matches features 007–009, which shipped their
served behavior while treating the React build/typecheck as operator-owned.

**Alternatives considered**: (a) React-only — rejected: cannot be built/tested offline here, so
increments couldn't be gated. (b) Legacy-only full rebuild of a Findings workspace in
`index.html` — rejected: the spec designates React primary and forbids requiring a second legacy
redesign. (c) Embed a prebuilt `app/` in git — rejected: build output is intentionally
git-ignored and operator-owned.

**Consequence for acceptance**: SC-012 (validate against the actual built frontend) and SC-010/
SC-011 (browser a11y/perf) are **operator-owned browser steps**; the plan delivers deterministic
offline Go tests + fixtures for every backend behavior they exercise, and the quickstart splits
"automated offline gate" from "operator browser acceptance."

## R2 — Findings queue & cross-scan identity (new `internal/findings`)

**Decision**: Add `internal/findings` that builds a cross-scan finding index from existing
report data and serves a searchable/sortable/filterable queue, including scans that ran with
the ledger disabled. Reuse the existing stable-identity precedence to relate occurrences across
scans.

**Evidence**: `findings.json` (`consolidate.Doc`, `consolidate.go:38`) already holds `findings[]`
with `StableIdentity`/`RootCauseKey`/`ClusterID`/`CandidateKey` (`finding.go:55-58`) and
per-finding `VerificationStatus`/`VerificationReason`/`VerificationRecord`. `reports.Index`
enumerates report dirs. `lifecycle.Key` (`lifecycle.go:45`) defines cross-run identity precedence
(`source-v1:<stable_identity>` → root_cause_key → cwe+file). There is **no** `/api/findings`
endpoint today.

**Approach**: `findings.Index(reportsDir)` → per-occurrence rows {finding-occurrence id (scan id
+ stable identity), application/slug, scan, scanned revision, severity+basis, evidence assessment,
reproduction state, file/path, lifecycle status where comparison exists}. Query params for
application/scan/severity/evidence-assessment/human-review-state/file-path/new-regressed and a
free-text search; server-side sort. Ledger-disabled scans are included because findings come from
`findings.json`, not the ledger. Empty-search vs no-findings distinguished by an explicit result
shape.

**Rationale**: Findings already carry identity and assessment; the gap is an index + queue API.
Reusing `lifecycle.Key` keeps cross-scan relation consistent with the engine.

**Alternatives**: Deriving the queue from the membank ledger — rejected: excludes ledger-disabled
scans and loses per-scan occurrences (FR-001).

## R3 — Durable human review decisions + history + conflict (new `internal/review`)

**Decision**: Add `internal/review` — a durable, append-only human-decision store keyed by stable
finding identity, separate from scan evidence, with an inspectable history, supersede-not-erase,
and optimistic-version conflict detection. Expose submit/get endpoints.

**Evidence**: Today's `consolidate.ReviewRecord` is `json:"-"` (an engine input channel, not
output; `finding.go:90`) and `verification.Decision` is **model-produced** and **overwritten per
run** (`verification.go:66`, `WriteDecisions` replaces the file). The `DELETE
/api/ledgers/{slug}/finding` route is a **stub** (`handlers.go:506`). So there is **no** human
disposition store, no history, and no conflict handling.

**Approach**: Store under `~/.vhlocal/reviews/` (atomic temp+rename like `jobs.Store.persist`),
one record per stable finding identity containing an append-only list of decisions
{disposition ∈ needs-review/investigating/accepted-risk/dismissed/resolved, notes, rationale,
operator attribution + timestamp, decided-against scan id + revision, a monotonically increasing
version}. Rationale required for dismissal/accepted-risk/resolution (validated server-side).
Reads never mutate scan evidence or AI verdict. Conflict: submit carries the last-seen version
(If-Match style); a stale write is rejected with the current record so the newer decision is not
lost. A decision does **not** enable/recreate a ledger or cleared tracking (FR-022). Materially
changed evidence (detected via identity + evidence hash) surfaces "evidence changed" rather than
silently carrying a dismissal (FR-021).

**Rationale**: Satisfies FR-018..FR-022 and Principle I (separation) and VI (idempotent/atomic).

**Alternatives**: Writing dispositions into `findings.json` — rejected: that is scan evidence and
must not be overwritten. Storing in the membank ledger — rejected: ties review to ledger, which
FR-001/FR-022 forbid.

## R4 — Revision-bound evidence & source viewer (new `internal/evidence`)

**Decision**: Add `internal/evidence` serving source excerpts bound to the scan's captured source
or recorded revision, with an explicit "revision/source unavailable" state; never substitute the
working tree.

**Evidence**: `scan_meta.json` records `git_commit`/`git_branch`/`git_dirty` (`record.go`) and
`repo`/`results_dir`. Findings carry `location` (file:line). Path-confined file serving already
exists (`serveConfined`, `static.go:100`; `/api/reports/{id}/file`, `/api/scans/{id}/file`).
There is **no** source-excerpt-by-revision endpoint and **no** evidence viewer in either UI.

**Approach**: An evidence endpoint returns a source excerpt for a finding's location bound to the
captured source (if the scan captured it) or the recorded commit; if neither can be retrieved,
return an explicit unavailable state and keep other evidence (verification record, report)
reachable. Read-only, path-contained, static-only. Classify each citation observed/model-inferred/
syntactic/missing and mark unresolved ones invalid/unavailable (FR-015). Authorization/business-
logic findings are reviewable without a synthetic source-to-sink trace (FR-014) — the record's
entry-point/attacker-control/defenses fields drive the view.

**Rationale**: FR-011..FR-015 and Principle I/III. Reuses containment; adds only revision-aware
read.

**Alternatives**: Reading the current working tree — rejected outright by FR-012/Principle I.

## R5 — Reuse existing comparison; add explicit unknown/incomparable (US2/US4)

**Decision**: Surface baseline comparison from the **existing** `internal/lifecycle` (per-report
diff: new/persisting/regressed, `not_observed` supersedes fixed) and **membank** recall
(total_known/found/new/missed/recall). Add explicit unknown/incomparable states; no auto-rescan.

**Evidence**: `lifecycle.Reconcile`/`NoPrior` (`lifecycle.go`; wired via `engine.reconcileLifecycle`
`engine.go:650`) already labels new/persisting/regressed and lists fixed, with vocabulary
`not_observed`/`reappeared`. `membank.CoverageSummary` (`membank.go:274`) yields recall. Both feed
`findings.json`. There is no *interactive* baseline-selection surface.

**Approach**: The findings/queue and detail views read these existing blocks. Baseline = operator-
selected comparable scan; when identity/scope/coverage can't support a conclusion, show
unknown/incomparable (never auto-"fixed", FR-024). A finding absent in a partial scan stays
unknown. No expensive automatic rescans.

**Rationale**: FR-023/FR-024, SC-005. Reuses deterministic engine logic; avoids re-implementing
comparison.

**Alternatives**: New comparison engine — rejected: duplicates `lifecycle`/`membank`.

## R6 — Honest artifact manifest & status axes (extend `internal/reports` + reuse `status.go`)

**Decision**: Reuse the three status axes and phase outcomes; extend the artifact manifest to the
full state set where "available" means **validated material**, not a present filename.

**Evidence**: `consolidate.RunStatus` (execution/coverage/validation, `status.go:5`) +
`server/status.go` `scanStatus`/`enrichScan`/`phaseOutcomes` already carry axes distinct from the
queue `status`, and `reports/material.go` models threat/SBOM availability. Artifacts are listed via
`/api/scans/{id}/artifacts` and downloaded via `/api/reports/{id}/file` / `/api/scans/{id}/file`.
The manifest today does not distinguish pending/failed/missing/unreadable/malformed/unknown.

**Approach**: A manifest surface (reachable from scans, reports, application history) mapping each
expected artifact (findings report, threat model/report, SBOM, verification/reproduction material)
to not-requested/pending/available/failed/missing/unreadable/malformed/unknown, validating content
(parse/shape check) before calling it available (FR-028). View/download reuse existing file
endpoints; missing optional artifacts never hide others (FR-029). Partial/interrupted scans keep
usable outputs and explain unfinished work; resume/retry stays explicit and scoped (FR-030) —
reuse the existing `interrupted` job status and never auto-run on page load.

**Rationale**: FR-025..FR-030, SC-006, Principle II. Maximizes reuse; adds validation + state
breadth.

**Alternatives**: Treating filename presence as availability — rejected by FR-028/Principle I.

## R7 — Contextual AI for a finding (new `internal/assist`)

**Decision**: Add `internal/assist` providing on-demand, bounded, single-finding model actions
(explain flow, find mitigations, challenge, draft regression test, propose fix) via the existing
`client.Provider` + shell-free agent tools, with full provenance, explicit provider config, no
silent fallback, visible failure/cancel, and non-executed draft artifacts persisted per
finding+revision.

**Evidence**: `client.Provider.Chat` + `client.Provenance` (backend/endpoint/models/tokens,
`provider.go:67`) are captured on every response; `agent.Run` drives a tool loop limited to
`Read/Grep/Glob/Write` with **no shell** (`agent.go:116`); a fake provider exists
(`client/testsupport/fake.go`). But **all** model calls today happen inside the async scan worker
(`server.go:97` → `engine.Execute`); there is **no** on-demand per-finding endpoint.

**Approach**: New endpoint(s) run one bounded action scoped to the selected finding + scan
revision + supplied evidence, using the operator-configured provider (destination shown before
submission; no silent fallback — reuse Principle V behavior). Agent tools restricted to read-only
(`Read/Grep/Glob`); drafts (tests/fixes) are returned as reviewable diffs/artifacts that never
execute code, install deps, or touch the working tree, and never auto-update severity/disposition
(FR-043). Results persisted keyed to finding+revision+action, labeled distinct from scan evidence
(FR-040), retrievable, and not resubmitted on revisit; in-flight results are not misattached on
navigation (FR-042) — the client binds a request id to the finding+revision. Offline tests use the
fake provider for all five actions + failure + cancellation.

**Rationale**: FR-039..FR-045, Principles III/IV/V, SC-008. Reuses transport/provenance/agent;
adds an on-demand orchestration + result store.

**Alternatives**: Reusing the scan worker for interactive calls — rejected: it is batch/whole-scan
and not scoped to a finding; canned/disabled responses — rejected by FR-045.

## R8 — Dashboard preservation baseline + independent "Needs attention" (new `internal/attention`)

**Decision**: Baseline the current dashboard exactly, then add a separate "Needs attention" queue
computation that fails independently and never alters the existing population.

**Evidence**: `/api/stats` (`handleStats`, `handlers.go:122`) returns the feature-008 aggregates
(scans, findings, tokens+breakdown, averages incl. whole-number avg findings, times, `by_model`)
with missing-data handling. The dashboard renders these + the findings-per-scan chart + latest-scan
actions.

**Approach**: Record a preservation baseline (the exact metric/field set + relative order +
formatting, incl. whole-number average findings and 008 missing-data handling) as a regression
reference (FR-033/FR-034, SC-001). Add `internal/attention` computing the six queues (supported
Crit/High awaiting review; new supported Crit/High vs selected baseline with explicit no-baseline;
unresolved needing review/evidence; regressions from comparable history; incomplete/interrupted
scans + failed/missing artifacts; apps whose latest scan is older than an operator threshold,
default 7 days, editable). Each queue: scope+definition+count+link to its filtered destination,
honest unknown/unavailable (not zero), defined dedup so an item can't inflate a count (FR-036).
Served by a **separate** endpoint so a queue failure cannot blank the existing dashboard (FR-037);
queue filters never touch `/api/stats` population; new supported-only counts explicitly labeled
(FR-038). Time staleness ≠ incomplete coverage; scan-revision mismatch shown separately when known.

**Rationale**: FR-033..FR-038, SC-001/SC-007. Additive + isolated by construction.

**Alternatives**: Extending `/api/stats` with queues — rejected: couples queue failure to the
preserved dashboard (violates FR-037).

## R9 — Saved views, navigation, dialogs, theming, accessibility (React primary)

**Decision**: Add a saved-views store (`internal/views`) and modernize the React shell:
collapsible sidebar, a consistent in-app dialog primitive replacing native confirm/prompt, unified
light/dark theming, keyboard a11y, reduced-motion, responsive layout, and a real Settings page.
Preserve feature-009 Table/List choices and existing links/redirects.

**Evidence**: Both surfaces use a top-bar nav (no sidebar) and native `confirm()`/`prompt()`
(React: `Applications.tsx:63,147,156`, `Ledger.tsx:55,127,144`, `Reports.tsx:36`; legacy: six
sites incl. `index.html:4444` prompt). React `Settings` is a placeholder stub
(`App.tsx:25`, `Placeholder.tsx`). Theme keys differ (`vhlocal.theme` vs `vh-theme`).

**Approach**: Saved named views/filters persisted (`~/.vhlocal/views/`) and applied to the queue
(FR-006). React `Layout.tsx` gains a collapsible sidebar (Overview/Dashboard, Applications,
Findings, Scans prominent; Reports/Activity secondary; Docs/Settings discoverable) preserving
existing routes/redirects and app/scan context (FR-046). A shared dialog component preserves
confirmation semantics and restores focus (FR-049). Keyboard operability + visible focus +
accessible names + reduced-motion + responsive containers (FR-050/FR-051). Real Settings (no empty
placeholder, FR-047). Table/List preference preserved (FR-054). Scan setup uses user-facing labels
+ visible presets + pre-launch review (FR-052). The legacy UI keeps its existing dialogs/nav
working (no forced redesign); optional parity dialog upgrades are non-blocking.

**Rationale**: FR-046..FR-053, SC-010. React is the design target; legacy stays accessible.

**Alternatives**: Rebuilding legacy nav to match — rejected: spec forbids requiring a second
legacy redesign.

## R10 — Migration / compatibility

**Decision**: All new stores are additive; existing artifact/report/`findings.json`/ledger formats
are unchanged. Older records that lack fields map to explicit unknown/unknown-historical states.

**Evidence**: Reports are recognized by name or deliverable (`reports.go:79`); older dirs may lack
newer artifacts or revision metadata.

**Approach**: Readers tolerate missing fields and render unknown/unknown-historical rather than
guessing (FR-028, FR-056). Original evidence is never rewritten; compatibility is read-side only.

## R11 — Testing posture (offline)

**Decision**: Offline Go tests gate every backend increment; React typecheck/build and browser
scenarios are operator-owned; no live model, no Python.

**Approach**: Unit/integration Go tests for `findings`, `review` (incl. conflict + history +
rationale-required + no-ledger-recreation), `evidence` (revision-bound + unavailable), `attention`
(counts match filtered destinations, dedup, no-baseline, unavailable, staleness), artifact-manifest
state mapping, status axes, and `assist` (all five actions + failure + cancellation via the fake
provider). Extend `internal/server/testsupport/seed.go` with fixtures: ledger-disabled scan,
recorded/absent revisions, artifacts in each state, comparable/partial baselines, a 1,000-finding
set, and provider fixtures. `go test ./...`, `go vet ./...`, `gofmt -l` must stay clean. Browser
acceptance (SC-010/SC-011/SC-012) is operator-owned against an operator-built React app; the
quickstart records build provenance and any skipped checks explicitly (never counted as passed).

## Post-design constitution re-check

The design adds additive JSON stores (atomic, stable-identity-keyed, append-only history),
read-only revision-bound evidence access, a validated artifact manifest, an isolated "Needs
attention" endpoint, and a provenanced, shell-free, non-executing contextual-AI path — all within
Evidence Integrity, Orthogonal Status, Static-Only, Provenance, Explicit-Failure, Resumable, and
Offline-Testable. **Constitution Check remains PASS after design.**
