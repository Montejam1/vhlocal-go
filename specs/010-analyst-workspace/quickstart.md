# Quickstart & Validation Guide: Evidence-centered analyst workspace

This feature is **backend-first**: all new behavior (findings queue, revision-bound evidence,
durable review decisions, honest artifacts/status, attention queues, contextual AI) is delivered as
Go endpoints + additive stores that are **fully validated offline**. The React SPA is the primary
UI and is **operator-built/browser-validated** (no `node_modules` offline). No live model, no
Python — the contextual-AI path is exercised with the in-repo fake provider.

## Prerequisites

- `export PATH=$PATH:/usr/local/go/bin`
- `go build -o bin/vhlocal ./cmd/vhlocal`
- A seeded reports dir (extend `internal/server/testsupport/seed.go`) containing: multiple
  applications; multiple scans of one application; **one ledger-disabled scan**; runs with recorded
  and with absent revisions; artifacts in each state (available/valid, missing, unreadable,
  malformed, pending, failed, not-requested, unknown-historical); comparable and partial baselines;
  a **1,000-finding** fixture; and provider fixtures for the fake AI provider.

## Automated offline gate (the increment gate)

```bash
export PATH=$PATH:/usr/local/go/bin
go build ./...
go test ./... -count=1     # every new package + endpoint must be green
go vet ./...
gofmt -l internal cmd      # clean
```

Offline Go coverage to add (maps to contracts/SCs):

- `internal/findings` — queue across scans incl. **ledger-disabled** (API-F1, SC-002);
  filtered-empty vs no-findings (FR-007); cross-scan identity via `lifecycle.Key`.
- `internal/review` — rationale required for dismissed/accepted-risk/resolved (FR-018); append-only
  history + supersede (FR-019); **optimistic-version conflict** rejects stale writes (FR-021);
  never writes scan evidence / never recreates a ledger (FR-020/022). (SC-002/005)
- `internal/evidence` — revision-bound excerpt; **revision/source unavailable** state; working tree
  never read (FR-012). (SC-004)
- comparison projection — reuses `lifecycle`+`membank`; absent-in-partial ≠ fixed; unknown/
  incomparable (FR-024). (SC-005)
- status + `internal/reports` manifest — three axes distinct from queue status (API-S1); artifact
  state set with **validated** availability (API-S2, FR-028); missing optional ≠ hides others.
  (SC-006)
- `internal/attention` — each queue count **matches its filtered destination** for a fixed history/
  baseline/scope/`stale_days`; dedup; no-baseline; unavailable-not-zero; independent failure
  (API-Q1, FR-036/037). (SC-007)
- `internal/assist` — all five actions + failure + cancellation via `client/testsupport/fake.go`;
  provenance captured; drafts are non-executed; no silent fallback (API-A*, FR-039..045). (SC-008)
- dashboard preservation — `/api/stats` byte-for-byte semantics unchanged for the same seeded
  history incl. zero-scans and missing usage/timing (FR-033/034). (SC-001)

## Dashboard preservation baseline (record BEFORE any UI change)

Capture the current `/api/stats` shape + the dashboard's rendered metric/chart/model-breakdown set
and relative order as a regression reference (a golden JSON test over the seeded history, plus a
noted screenshot inventory for the operator). Every later change is checked against this baseline
(FR-033/034, SC-001).

## Operator browser acceptance (React primary; owned by the operator)

```bash
make ui          # npm ci && npm run build  (network-dependent; operator machine)
go build -o bin/vhlocal ./cmd/vhlocal   # embeds vhlocal/web/app after the build
bin/vhlocal server --reports-dir <seeded-dir>
# React app at http://127.0.0.1:8420/app ; legacy at /
cd web-react && npm run typecheck        # operator-owned
```

Walk the UI contracts against the built app (record build provenance + any console/network
failures; report skipped checks explicitly, never as passed):

1. **Findings workspace** (UI-F1..F4): entry points, three panes + resize/collapse, saved views,
   context across back/forward, stable link. (SC-003)
2. **Evidence + decision** (UI-E1..E4): revision-bound source, four dimensions, decision + history
   across reload/restart, conflict surfaced, comparison honesty. (SC-002/004/005)
3. **Status + artifacts** (UI-S1..S3): axes, manifest states, view/download, workspace states +
   retry/stale/late-response. (SC-006)
4. **Dashboard** (UI-D1/D2): all existing metrics/charts preserved in order; "Needs attention"
   below; queue-failure isolation; counts match destinations. (SC-001/007)
5. **Contextual AI** (UI-A1/A2, fake provider fixtures): five actions bound + provenanced; failure/
   cancel; no resubmit/misattach; drafts non-executed. (SC-008)
6. **Nav/interaction/a11y** (UI-N1..N5): sidebar + links/redirects, in-app dialogs, keyboard-only in
   both themes at 1440/1024/390px + 200% zoom, real Settings, scan-setup labels/review. (SC-009/010)
7. **Legacy** (UI-L1): `/` still works — feature-009 Table/List + delete/forget, reports/links
   reachable, no regression. (SC-009)
8. **Responsiveness** (SC-011): with the 1,000-finding fixture, filter change / select / next each
   render within 2s (excluding live inference) on the recorded acceptance machine.

## Standing constraints honored

- No workloads sent to a live model; the AI path is offline via the fake provider.
- No Python executed; parity/behavior is judged against the Go source and the offline suite.
- Scan evidence is never rewritten; new stores are additive under `~/.vhlocal/`.

## Success-criteria coverage

SC-001↔dashboard-preservation gate + UI-D1/D2; SC-002↔findings/review offline + UI-E3; SC-003↔UI-F*;
SC-004↔evidence offline + UI-E1/E2; SC-005↔comparison offline + UI-E4; SC-006↔status/manifest offline
+ UI-S*; SC-007↔attention offline + UI-D2; SC-008↔assist offline (fake provider) + UI-A*; SC-009↔UI-N*/
UI-L1; SC-010↔UI-N3 (operator browser); SC-011↔operator perf run; SC-012↔operator build + provenance.
