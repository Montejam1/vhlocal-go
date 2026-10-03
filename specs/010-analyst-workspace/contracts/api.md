# Contracts — HTTP API (new & changed)

New/changed endpoints on the loopback server (`internal/server/handlers.go` `Handler()`), Go 1.22
`method path` mux. All are read-only with respect to scan evidence; new writes touch only the
additive `~/.vhlocal/` stores. Existing endpoints (reports, applications, ledgers, scans, stats,
activity, config, models, profiles) are unchanged except where noted. IDs map to requirements/SCs
and to tasks.

## Findings queue & detail (US1)

- **API-F1 `GET /api/findings`** — cross-scan finding queue. Query: `application`, `scan`,
  `severity`, `evidence` (supported/rejected/unresolved/unknown), `review`
  (needs-review/investigating/accepted-risk/dismissed/resolved), `path`, `status`
  (new/recurring/regressed), `q` (free text), `sort`, `dir`, plus paging. Returns
  `FindingQueueRow[]` (data-model) including scans that ran with the ledger disabled (FR-001).
  Distinguishes filtered-empty from no-findings via an explicit result shape (FR-007). (SC-002/003)
- **API-F2 `GET /api/findings/{occ}`** — one occurrence's detail (identity, four dimensions,
  context: application/repo/revision/scan/baseline). `{occ}` = scan id + stable id. 404 → useful
  missing-record state (FR-010). (SC-003/004)
- **API-F3 `GET /api/findings/{occ}/evidence`** — revision-bound source excerpt(s) + citations +
  entry-point/flow/defenses/impact/remediation; explicit `revision-unavailable`/`source-unavailable`
  (FR-011..FR-015). Working tree never substituted. (SC-004)

## Human review decisions (US2)

- **API-R1 `GET /api/findings/{stable}/review`** — the ReviewDecisionRecord (head + history) for a
  stable id; empty ⇒ default `needs-review` (FR-016/FR-019).
- **API-R2 `POST /api/findings/{stable}/review`** — append a decision {disposition, rationale,
  notes, scan_id, revision, base_version}. Server requires rationale for
  dismissed/accepted-risk/resolved (FR-018); rejects a stale `base_version` with the current head
  (409 + current record) so the newer decision is not lost (FR-021). Never writes scan evidence,
  never enables/recreates a ledger or cleared tracking (FR-020/FR-022). Returns the new head
  version. (SC-002/005)

## Baseline comparison (US2/US4)

- **API-C1 `GET /api/findings/{occ}/comparison?baseline=<scan|none>`** — new/recurring/regressed/
  fixed + recall vs an operator-selected comparable baseline; explicit unknown/incomparable when
  identity/scope/coverage don't support a conclusion; absent-in-partial is never auto-fixed
  (FR-023/FR-024). Reuses `lifecycle` + `membank`. (SC-005)

## Scan status & artifacts (US3)

- **API-S1 `GET /api/scans/{id}/status`** — three axes (execution/coverage/validation) + requested
  stages and recorded stage outcomes, distinct from queue/job termination; axis may be marked
  unavailable (FR-025/FR-026). Reuses `scanStatus`/`phaseOutcomes`. (SC-006)
- **API-S2 `GET /api/scans/{id}/manifest`** (also reachable per report/application) — Artifact
  ManifestEntry[] with state ∈ not-requested/pending/available/failed/missing/unreadable/
  malformed/unknown; `available` requires validated content (FR-027/FR-028). Missing optional
  artifacts don't hide others (FR-029). View/download reuse existing `/api/reports/{id}/file` and
  `/api/scans/{id}/file` (unchanged). (SC-006)
- Existing `GET /api/scans/{id}/artifacts` and the `interrupted` job status are reused for
  partial/resume surfacing; resume/retry stays an explicit operator action (FR-030) — no auto-run.

## Dashboard queues (US4)

- **API-Q1 `GET /api/attention?baseline=<scan|none>&stale_days=<n>`** — the six "Needs attention"
  queues (each: key, scope, definition, count, link, honesty flags), deduplicated (FR-036), served
  **separately** from `/api/stats` so a failure here cannot blank the dashboard (FR-037). Default
  `stale_days=7`, editable (FR-035). Unknown/unavailable shown honestly, never as zero. (SC-007)
- **`GET /api/stats`** — **unchanged**: preserves every feature-008 metric, breakdown, average
  (incl. whole-number avg findings), and missing-data handling (FR-033/FR-034, SC-001). Queue
  filters MUST NOT alter its population (FR-037).

## Saved views (US1)

- **API-V1 `GET /api/views`**, **`POST /api/views`**, **`DELETE /api/views/{id}`** — named saved
  queue filters/sort (FR-006). Per-operator; applying one reproduces the same population.

## Contextual AI (US5)

- **API-A1 `POST /api/findings/{occ}/assist`** — run one action {action ∈ explain-flow/
  find-mitigations/challenge/draft-test/propose-fix, request_id, provider (operator-configured)}.
  Bound to finding+scan revision+evidence; destination shown before submission by the client from
  `/api/config`; **no silent fallback** (FR-041); returns a handle. Draft actions return
  non-executed reviewable diffs/artifacts (FR-043). (SC-008)
- **API-A2 `GET /api/findings/{occ}/assist/{request_id}`** — poll/stream status
  (running/succeeded/failed/cancelled), provenance, citations, output; retrievable later; revisiting
  does not resubmit (FR-042). **API-A3 `POST .../assist/{request_id}/cancel`** — visible cancel.
  Failures/bounded retries/cancellation are surfaced (FR-042); results carry engine-recorded
  provenance and a "generated analysis" label distinct from scan evidence (FR-040). Offline tests
  drive all five actions + failure + cancel via `client/testsupport/fake.go`. (SC-008)

## Cross-cutting invariants (all endpoints)

- **API-X1**: Loading, empty, filtered-empty, refreshing, stale, disconnected, and failed states
  are distinguishable in responses; a failed detail request is an explicit error (client leaves
  loading + retry), a failed refresh preserves prior data (stale), a failed mutation is not
  reported as success (FR-031/FR-032). Out-of-order handling is a client concern (below).
- **API-X2**: Path containment preserved for every file/source read (reuse `serveConfined`);
  static-only — no endpoint executes target code (Principle III, FR-055).
- **API-X3**: Untrusted repo/AI content is returned as data, never interpreted as tool/endpoint
  authorization (FR-044).
