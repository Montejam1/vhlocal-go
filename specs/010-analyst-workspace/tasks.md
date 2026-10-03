---
description: "Task list for feature 010 — Evidence-centered analyst workspace"
---

# Tasks: Evidence-centered analyst workspace

**Input**: Design documents from `/specs/010-analyst-workspace/`

**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅ (R1–R11), data-model.md ✅,
contracts/api.md ✅, contracts/ui.md ✅, quickstart.md ✅

**Tests**: INCLUDED for the backend. The spec requires offline acceptance evidence including
negative/degraded cases (SC-008/SC-011/SC-012; quickstart "Automated offline gate"), and the
contextual-AI path is exercised via the in-repo fake provider. Go tests are the increment gate.
React `npm run typecheck`/build and browser scenarios (UI-* contracts, SC-010/SC-011/SC-012) are
**operator-owned** (no `node_modules` offline) and appear as explicit operator-acceptance tasks.

**Organization**: Backend-first, by user story. US1+US2 (both P1) are the MVP review flow. Go work
is offline-testable now; React work is authored in source and validated by the operator.

## Format: `[ID] [P?] [Story?] Description with file path`

- **[P]**: parallelizable (different files, no dependency on an incomplete task).
- Backend paths under `internal/…`; React under `web-react/src/…`; legacy `vhlocal/web/index.html`.
- Standing constraints: no live model (AI via fake provider), no Python, scan evidence never
  rewritten, new stores additive under `~/.vhlocal/`, dashboard preserved with queues strictly below.

## Path Conventions

- New Go packages: `internal/findings`, `internal/review`, `internal/views`, `internal/evidence`,
  `internal/assist`, `internal/attention`; extend `internal/reports`, `internal/server`.
- Reused (do not duplicate): `internal/consolidate` (+`status.go`), `internal/lifecycle`,
  `internal/membank`, `internal/apps`, `internal/verification`, `internal/client` (+`testsupport/
  fake.go`), `internal/agent`, `internal/jobs`.
- Server routes registered in `internal/server/handlers.go` `Handler()`.

---

## Phase 1: Setup (fixtures & preservation baseline)

**Purpose**: Establish the green baseline and the deterministic fixtures every story needs.

- [X] T001 Confirm baseline green: `export PATH=$PATH:/usr/local/go/bin && go build ./... && go test ./... -count=1 && go vet ./...` (record pre-change state).
- [ ] T002 Extend `internal/server/testsupport/seed.go` with the full fixture set: multiple applications; multiple scans of one application; **one ledger-disabled scan**; runs with recorded `git_commit` and with absent revision/captured source; artifacts in each state (valid/available, missing, unreadable, malformed, pending, failed, not-requested, unknown-historical); comparable and partial/incomparable baselines; a **1,000-finding** fixture; and fake-provider request/response fixtures. Add seed helpers per state so each test selects what it needs.
- [X] T003 Dashboard preservation baseline: add a golden test in `internal/server/stats_baseline_test.go` asserting `/api/stats` returns the exact feature-008 metric/field set and semantics (scans, findings, whole-number average findings, tokens + input/output breakdown, average tokens/scan, usage counts, total/average scan time, `by_model`) over the seeded history including zero-scans and missing usage/timing (FR-033/FR-034, SC-001). This is the regression reference before any dashboard change.

---

## Phase 2: Foundational (blocking prerequisites)

**Purpose**: Shared cross-scan identity + response-state conventions used by every story.

**⚠️ CRITICAL**: US1–US6 depend on these.

- [X] T004 Create `internal/findings/identity.go`: a cross-scan finding-identity resolver reusing the existing precedence `lifecycle.Key` (`source-v1:<stable_identity>` → `root_cause_key` → `cwe+file`) to map a finding occurrence (`<scan id>`+`<stable_identity>`) ↔ its stable id, plus an evidence fingerprint (hash of the evidence a decision is made against) for change detection. Unit test in `internal/findings/identity_test.go` (stable across scans; distinct findings distinct ids).
- [X] T005 Add response-state conventions in `internal/server/states.go`: helpers/shape so responses distinguish loading/empty/filtered-empty/refreshing/stale/disconnected/failed and so a failed detail is an explicit error, a failed refresh preserves prior data, and a failed mutation is never reported as success (FR-031/FR-032, API-X1). Unit test `internal/server/states_test.go`.

**Checkpoint**: identity + state conventions ready — user stories can begin.

---

## Phase 3: User Story 1 — Review a finding without losing context (Priority: P1) 🎯 MVP (part 1)

**Goal**: Findings as a primary destination with a searchable/sortable/filterable cross-scan queue
(incl. ledger-disabled scans), saved views, persistent context, and context-preserving navigation.

**Independent Test**: With the seeded history (incl. the ledger-disabled scan), query the queue with
filters/sort, open occurrences from each entry point, save/apply/reset a view, and confirm
filtered-empty ≠ no-findings; confirm stable occurrence ids round-trip.

### Tests (write first)

- [X] T006 [P] [US1] `internal/findings/index_test.go`: index over `reports.Index` yields occurrences from ALL scans including the **ledger-disabled** one (FR-001); filters (application/scan/severity/evidence/review/path/new-regressed) and free-text search work; filtered-empty is a distinct result shape from no-findings (FR-007).
- [X] T007 [P] [US1] `internal/views/store_test.go`: named saved views persist (atomic), reapply to reproduce the same population, and reset clears (FR-006).
- [X] T008 [P] [US1] `internal/server/findings_api_test.go`: `GET /api/findings` (filters/sort/paging, ledger-disabled inclusion) and `GET /api/findings/{occ}` (404 → useful missing-record shape, FR-010) per contracts API-F1/F2.

### Implementation

- [X] T009 [US1] `internal/findings/index.go`: build `FindingQueueRow[]` from `consolidate.Doc` across `reports.Index` (occurrence id, application/slug, scan, revision-where-recorded, severity+basis, evidence assessment, reproduction state, file/path, lifecycle status where comparison exists, head review disposition defaulting to `needs-review`). Query/sort/filter API (data-model FindingQueueRow).
- [X] T010 [US1] `internal/views/store.go`: SavedView store under `~/.vhlocal/views/` (atomic temp+rename like `jobs.Store.persist`); fields `id`, non-empty `name`, `filters`, `sort`, timestamps (data-model SavedView).
- [X] T011 [US1] Wire routes in `internal/server/handlers.go`: `GET /api/findings`, `GET /api/findings/{occ}`, `GET/POST /api/views`, `DELETE /api/views/{id}` (API-F1/F2, API-V1), using T005 state conventions and path containment.
- [ ] T012 [P] [US1] React: add `web-react/src/pages/Findings.tsx` (queue + persistent context header + three-pane shell with resizable/collapsible panes remembering sizes) and route it in `web-react/src/App.tsx`; add clients in `web-react/src/lib/api.ts` for findings + views (UI-F1/F2/F3).
- [ ] T013 [US1] React in `web-react/src/pages/Findings.tsx` (+ `web-react/src/lib/` URL/state hooks): preserve filters/sorting/selection/queue-position across navigation and browser back/forward and Table/List switch; implement stable finding links and a useful missing-record state (UI-F4, FR-008/010). Keep the feature-009 Table/List preference (FR-054).

**Checkpoint**: Findings queue + context usable and independently testable (Go green; React operator-built).

---

## Phase 4: User Story 2 — Inspect evidence & make a durable decision (Priority: P1) 🎯 MVP (part 2)

**Goal**: Revision-bound evidence viewer, the four dimensions, durable human decisions with history +
conflict handling, and honest baseline comparison.

**Independent Test**: With fixtures for present/absent revision, the four-dimension states, and
comparable/partial baselines: view revision-bound source (unavailable stated, working tree never
read), record a decision requiring rationale, reload+restart to confirm persistence + history +
supersede, force a stale conflict, and confirm absent-in-partial ≠ fixed.

### Tests (write first)

- [X] T014 [P] [US2] `internal/evidence/evidence_test.go`: excerpt bound to captured source or recorded `git_commit`; explicit `revision-unavailable`/`source-unavailable`; working tree is never read; citation classes observed/model-inferred/syntactic/missing (FR-011/012/015).
- [X] T015 [P] [US2] `internal/review/store_test.go`: rationale REQUIRED for `dismissed`/`accepted-risk`/`resolved` (FR-018); append-only `history` with monotonically increasing `version` and supersede-not-erase (FR-019); optimistic `base_version` conflict rejects a stale write and returns current head (FR-021); store never writes scan evidence and never recreates a ledger/cleared tracking (FR-020/022); evidence-fingerprint change surfaced (FR-021).
- [X] T016 [P] [US2] `internal/findings/comparison_test.go`: comparison projection reusing `lifecycle` + `membank` marks new/recurring/regressed/fixed and recall; absent-in-partial is unknown/incomparable, never auto-fixed; no auto-rescan (FR-023/024).
- [X] T017 [P] [US2] `internal/server/review_api_test.go`: `GET/POST /api/findings/{stable}/review` (rationale rule, 409 on stale `base_version` with current record) and `GET /api/findings/{occ}/evidence`, `GET /api/findings/{occ}/comparison?baseline=` per API-R1/R2, API-F3, API-C1.

### Implementation

- [X] T018 [US2] `internal/evidence/evidence.go`: EvidenceView from a finding occurrence — revision-bound excerpt (line numbers, highlighted location, surrounding context), entry-point/attacker-control/flow/defenses/impact/rationale/remediation from the verification record where present, citation classification, explicit unavailable states; read-only + path-contained (reuse `serveConfined`) (data-model EvidenceView).
- [X] T019 [US2] `internal/review/store.go`: ReviewDecisionRecord store under `~/.vhlocal/reviews/<stable-id>.json` (atomic), append-only `history` (version/disposition∈{needs-review,investigating,accepted-risk,dismissed,resolved}/rationale/notes/scan_id/revision/operator/decided_at), rationale-required validation, optimistic-version conflict, evidence-fingerprint (data-model ReviewDecisionRecord).
- [X] T020 [US2] `internal/findings/comparison.go`: ComparisonView reusing `lifecycle.Reconcile`/`NoPrior` + `membank.CoverageSummary`; operator-selected baseline; explicit unknown/incomparable (data-model ComparisonView).
- [X] T021 [US2] Wire routes in `internal/server/handlers.go`: `GET /api/findings/{occ}/evidence`, `GET/POST /api/findings/{stable}/review`, `GET /api/findings/{occ}/comparison` (API-F3/R1/R2/C1).
- [ ] T022 [P] [US2] React: evidence pane (syntax-highlighted source + highlighted location + citation classes + unavailable state), four-dimension display (none derived from another; no numeric confidence), and comparison view (UI-E1/E2/E4); extend `web-react/src/lib/api.ts`.
- [ ] T023 [US2] React: decision form + history in `Findings.tsx` — rationale required for dismissal/accepted-risk/resolution, persistence across reload/restart, supersede display, and a surfaced stale-conflict dialog (UI-E3, FR-018/019/021).

**Checkpoint (MVP)**: complete saved-finding review flow — queue → evidence → decision+history → artifact/return — works end to end (Go green; operator browser-validates React).

---

## Phase 5: User Story 3 — Scan completion & every available artifact (Priority: P1)

**Goal**: Honest three-axis status and a validated artifact manifest with view/download and correct
loading/empty/stale/failed states.

**Independent Test**: With complete/partial/failed/cancelled/interrupted/historical-unknown runs and
artifacts in every state, confirm axes are independent and never inferred from a completion label,
each artifact state is correct with `available` meaning validated, missing optional artifacts don't
hide others, and a failed detail leaves loading+retry while a late response doesn't corrupt the view.

### Tests (write first)

- [X] T024 [P] [US3] `internal/reports/manifest_test.go`: ArtifactManifestEntry state set (not-requested/pending/available/failed/missing/unreadable/malformed/unknown-historical) where `available` requires **validated content** (parse/shape), not a filename (FR-027/028); missing optional ≠ hides others (FR-029).
- [X] T025 [P] [US3] `internal/server/status_api_test.go`: `GET /api/scans/{id}/status` carries execution/coverage/validation (or marks unavailable) + requested stages/outcomes distinct from queue/job status (FR-025/026); `GET /api/scans/{id}/manifest` returns the state set (API-S1/S2).

### Implementation

- [X] T026 [US3] Extend `internal/reports` (e.g. `manifest.go`) to compute ArtifactManifestEntry[] with content validation, reusing `reports/material.go` for threat/SBOM (data-model ArtifactManifestEntry).
- [X] T027 [US3] Wire routes in `internal/server/handlers.go`: `GET /api/scans/{id}/status` (reuse `scanStatus`/`phaseOutcomes`) and `GET /api/scans/{id}/manifest` (also reachable per report/application); reuse existing `/api/reports/{id}/file` & `/api/scans/{id}/file` for view/download (API-S1/S2).
- [ ] T028 [P] [US3] React: status axes display + artifact manifest (view/download; missing optional doesn't hide others; partial/interrupted keep usable outputs + explain unfinished; resume/retry explicit and scoped) in `Scans.tsx`/`Applications.tsx`/`Reports.tsx` (UI-S1/S2, FR-030).
- [ ] T029 [US3] React: apply workspace-state conventions across `web-react/src/pages/*.tsx` (a shared hook in `web-react/src/lib/useAsyncState.ts`): initial-loading/empty/filtered-empty/refreshing/stale/disconnected/failed; failed-detail retry; stale-preserving refresh; late-response guard; failed-mutation not shown saved (UI-S3, FR-031/032).

**Checkpoint**: trustworthy status/artifact surfaces across the workspace.

---

## Phase 6: User Story 4 — Dashboard "Needs attention" queues (Priority: P2)

**Goal**: Six navigable queues appended **below** the fully-preserved dashboard, failing independently.

**Independent Test**: For a fixed history/baseline/scope/age-threshold, each queue count matches its
filtered destination (dedup, no-baseline, unavailable-not-zero); every existing metric/chart is
unchanged in value/order; a simulated queue-data failure leaves the dashboard usable.

### Tests (write first)

- [X] T030 [P] [US4] `internal/attention/attention_test.go`: the six queues (supported Crit/High awaiting review; new supported Crit/High vs selected baseline with explicit no-baseline; unresolved needing review/evidence; regressions from comparable history; incomplete/interrupted scans + failed/missing artifacts; apps whose latest scan older than `stale_days` default 7) — counts match the filtered destination, deduplicated (FR-036); unavailable shown honestly not zero; staleness ≠ incomplete coverage (FR-038).
- [X] T031 [P] [US4] `internal/server/attention_api_test.go`: `GET /api/attention?baseline=&stale_days=` served independently of `/api/stats`; a queue-computation failure does not fail `/api/stats` (FR-037, API-Q1). Re-assert the T003 baseline still holds.

### Implementation

- [X] T032 [US4] `internal/attention/attention.go`: compute the six AttentionQueue entries (key/scope/definition/count/link/honesty-flags) reusing `internal/findings`, comparison, status, and manifest; dedup; default `stale_days=7` editable (data-model AttentionQueue).
- [X] T033 [US4] Wire `GET /api/attention` in `internal/server/handlers.go`, isolated so its failure cannot blank `/api/stats` (FR-037).
- [ ] T034 [US4] React `Dashboard.tsx`: render "Needs attention" **below all existing sections** with per-queue scope/definition/count/link and honest unknown/unavailable; keep every existing metric/chart/model-breakdown/latest-scan action in prior order; new supported-only counts explicitly labeled; queue filters never change existing population (UI-D1/D2, FR-033..038).

**Checkpoint**: actionable queues added with the trusted dashboard fully intact.

---

## Phase 7: User Story 5 — Contextual AI on the selected finding (Priority: P2)

**Goal**: Five on-demand, finding-scoped actions with real provenance, explicit provider config, no
silent fallback, visible failure/cancel, and non-executed drafts.

**Independent Test**: Using fake-provider fixtures, run all five actions + failure + cancellation;
confirm binding to finding+revision+evidence, real provenance, drafts non-executed, no silent
fallback, no resubmit on revisit, and no misattach on navigation.

### Tests (write first)

- [X] T035 [P] [US5] `internal/assist/assist_test.go`: all five actions (explain-flow/find-mitigations/challenge/draft-test/propose-fix) via `client/testsupport/fake.go`; `client.Provenance` captured; agent tools limited to `Read/Grep/Glob` (no shell, no target write); drafts are non-executed reviewable artifacts; failure + cancellation surfaced; **no silent provider/model fallback** (FR-039..043, Principles III/IV/V).
- [X] T036 [P] [US5] `internal/server/assist_api_test.go`: `POST /api/findings/{occ}/assist`, `GET .../assist/{request_id}`, `POST .../assist/{request_id}/cancel` — result bound to finding+revision+action+request_id, persisted/retrievable, no resubmit on repeat GET (API-A1/A2/A3, FR-042).

### Implementation

- [X] T037 [US5] `internal/assist/assist.go`: orchestrate one bounded action via `client.Provider` + `agent.Run` (read-only tools), operator-configured provider/destination (from config), no silent fallback; persist AssistResult under `~/.vhlocal/assist/<stable-id>/<action>-<revision>.json` labeled distinct from scan evidence (data-model AssistResult).
- [X] T038 [US5] Wire routes in `internal/server/handlers.go`: `POST /api/findings/{occ}/assist`, `GET /api/findings/{occ}/assist/{request_id}`, `POST /api/findings/{occ}/assist/{request_id}/cancel` (API-A*).
- [ ] T039 [P] [US5] React: contextual-AI panel in `Findings.tsx` — show provider/destination before submit, run the five actions, display provenance + citations + generated-analysis label, visible failure/retry/cancel, request_id bound to finding+revision (no resubmit/misattach), drafts shown as reviewable diffs (UI-A1/A2).

**Checkpoint**: contextual assistance delivered with real behavior and provenance.

---

## Phase 8: User Story 6 — Navigation, configuration, interaction consistency (Priority: P2)

**Goal**: Collapsible sidebar, consistent in-app dialogs, unified theming, keyboard a11y, real
Settings, understandable scan setup, connected application details — React primary; legacy kept accessible.

**Independent Test**: Keyboard-only main flow in both themes at 1440/1024/390px + 200% zoom; sidebar
navigation preserves context; existing links resolve/redirect; dialogs replace native prompt/confirm
and restore focus; Settings is real; scan setup shows labels + pre-launch review.

### Implementation (React primary; operator-verified)

- [ ] T040 [P] [US6] React `components/Layout.tsx`: collapsible sidebar (Overview/Dashboard, Applications, Findings, Scans prominent; Reports/Activity secondary; Docs/Settings discoverable), preserving routes/redirects and app/scan context (UI-N1, FR-046).
- [ ] T041 [P] [US6] React: a shared in-app dialog primitive (`components/ui/dialog.tsx`) replacing native `confirm()`/`prompt()` across `Applications.tsx`, `Ledger.tsx`, `Reports.tsx`, `Findings.tsx`, preserving confirmation semantics + focus restore (UI-N2, FR-049).
- [ ] T042 [P] [US6] React in `web-react/src/components/Layout.tsx` + `web-react/src/index.css` (theme tokens): unify theming (light/dark) and text/icon cues; keyboard operability + visible focus + accessible names + tabs-with-panels + reduced-motion + responsive containers; preserve Table/List choice (UI-N3, FR-048/050/051/054).
- [ ] T043 [US6] React: add `web-react/src/pages/Settings.tsx` (replace the `Placeholder` route in `web-react/src/App.tsx`) — a real Settings page, no empty placeholders; expose existing role/model configuration; reject unsupported settings explicitly (FR-047, FR-052).
- [ ] T044 [US6] React: scan-setup review in `NewScan.tsx` — user-facing labels (not implementation terms), visible presets, no invented time/cost/coverage guarantees, pre-launch review of effective choices incl. inference destination (UI-N4, FR-052).
- [ ] T045 [US6] React in `web-react/src/pages/Applications.tsx`: application details connect scan history/findings/threat/SBOM; threat/component → related findings only where evidence supports it, else state no reliable mapping; reports stay readable/exportable from canonical data (UI-N5, FR-053).

**Checkpoint**: coherent, accessible workspace; legacy at `/` unregressed.

---

## Phase 9: Polish & Cross-Cutting Concerns

- [X] T046 Full offline gate: `export PATH=$PATH:/usr/local/go/bin && go build ./... && go test ./... -count=1 && go vet ./... && gofmt -l internal cmd` — all green (SC-012 offline portion).
- [X] T047 Verify legacy surface unregressed via `internal/server/preservation010_test.go` (and manual note): feature-009 Table/List + delete/forget on Applications/Ledger and reports/links reachable at `/` still served by `vhlocal/web/index.html` (UI-L1, FR-054, SC-009); browser check operator-owned.
- [X] T048 [P] Update user-facing docs for changed workflows (Findings/evidence/decisions/queues/assist) under `docs/` and the served Docs view.
- [X] T049 [P] Update `CHANGELOG.md` with the feature-010 entry (analyst workspace; backend-first; React primary/legacy preserved; dashboard preserved with queues below; no scanner/data changes; offline-tested, AI via fake provider).
- [ ] T050 Operator acceptance (owned by operator; record results, report skipped checks explicitly): `make ui` + `npm run typecheck` + build; run the `quickstart.md` browser acceptance (UI-F/E/S/D/A/N + legacy UI-L1) in both themes at 1440/1024/390px + 200% zoom; the SC-011 1,000-finding 2-second checks; record build provenance + console/network failures. Produce a completion matrix (delivered / verified / remaining).

---

## Dependencies & Execution Order

### Phase dependencies
- **Setup (P1)** → **Foundational (P2)** blocks all stories.
- **US1 (P3)** depends on Foundational; **US2 (P4)** depends on US1 (queue + identity). Together they are the MVP review flow.
- **US3 (P5)** depends on Foundational (independent of US1/US2 for status/artifacts, but shares fixtures).
- **US4 (P6)** depends on US1 (findings), US2 (comparison/review), US3 (status/manifest).
- **US5 (P7)** depends on US1/US2 (finding context + evidence).
- **US6 (P8)** depends on the pages existing (US1–US5) but its Go surface is minimal.
- **Polish (P9)** after the targeted stories.

### Within a story
Tests (where listed) → store/index → route wiring → React UI. Same-file tasks run sequentially.

### Parallel opportunities
- Test tasks marked [P] within a story run together (different files).
- Distinct new packages can be built in parallel across stories once Foundational is done
  (`findings` vs `evidence` vs `review` vs `attention` vs `assist` are different files), but route
  wiring in `internal/server/handlers.go` is a shared file → those wiring tasks (T011/T021/T027/
  T033/T038) are sequential.
- React page/component tasks in different files are [P]; edits to `Findings.tsx` are sequential
  (T012→T013→T023→T039).

---

## Implementation Strategy

### MVP first (US1 + US2)
1. Setup + Foundational.
2. US1 (findings queue + context) → US2 (evidence + durable decision + comparison).
3. **STOP and VALIDATE**: the complete saved-finding review flow, offline Go green; operator
   browser-validates the React workspace. This is the spec's prioritized first increment.

### Incremental delivery
US3 (trustworthy status/artifacts) → US4 (dashboard queues) → US5 (contextual AI) → US6
(nav/interaction/a11y) → Polish. Each increment ships with its offline acceptance evidence
(negative/degraded cases included) and marks remaining work explicitly.

---

## Notes
- Backend is the offline gate (`go test ./...`); React build/typecheck/browser is operator-owned.
- AI path uses `internal/client/testsupport/fake.go`; no live model, no Python.
- New stores are additive under `~/.vhlocal/`; scan evidence is never rewritten (Principle I).
- Preserve features 007–009: dashboard metrics + missing-data handling; Table/List + delete/forget;
  forget/clear keeps reports; review never recreates cleared tracking.
- Commit per story; validate each story independently before moving on.
