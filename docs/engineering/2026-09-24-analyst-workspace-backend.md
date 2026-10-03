# Analyst workspace — backend (feature 010)

Prepared: 2026-09-24

This documents the backend delivered for the evidence-centered analyst workspace
(`specs/010-analyst-workspace`). All of it is offline-tested (`go test ./...`); the
React workspace UI that consumes these endpoints is built and browser-validated by
the operator. No scanner behavior changed, scan evidence is never rewritten, and
all new state lives additively under `~/.vhlocal/`.

## New HTTP endpoints

### Findings queue & detail (US1)
- `GET /api/findings` — cross-scan finding queue. Query params: `application` (slug),
  `scan`, `severity`, `severity_in` (comma list, e.g. `critical,high`), `evidence`
  (`supported|rejected|unresolved|unknown`), `review`
  (`needs-review|investigating|accepted-risk|dismissed|resolved`), `path`, `status`
  (`new|recurring|regressed`), `q` (free text), `sort`, `dir`. Includes findings from
  scans run with the ledger disabled. Response carries `rows`, `total`, `indexed`,
  `filtered_empty`, `no_findings`, and a normalized `state`
  (`ok|empty|filtered_empty`).
- `GET /api/findings/{occ}` — one occurrence's detail: `{finding, raw, review}`.
  `{occ}` is `<scan id>~<stable identity>`. 404 → useful missing-record state.

### Evidence & comparison (US2)
- `GET /api/findings/{occ}/evidence` — revision-bound source excerpt + narrative.
  Source is returned only when the repo is verifiably at the finding's recorded
  commit (HEAD read from `.git`, never executed; not dirty); otherwise
  `source.available=false` with `reason` `revision-unavailable` / `source-unavailable`
  / `no-location`. The working tree is never substituted.
- `GET /api/findings/{occ}/comparison?baseline=<scan|none>` — new/recurring/regressed
  vs a comparable baseline; an absent baseline finding is `fixed` only when current
  coverage is complete, else `unknown_incomparable`. `baseline=none` → `no-baseline`.

### Human review decisions (US2)
- `GET /api/findings/{stable}/review` — the append-only decision record (empty ⇒
  head defaults to `needs-review`).
- `POST /api/findings/{stable}/review` — append a decision
  `{disposition, rationale, notes, scan_id, revision, base_version}`. Rationale is
  required for `dismissed`/`accepted-risk`/`resolved`. A stale `base_version` returns
  `409` with the current record (optimistic concurrency — no silent overwrite). Never
  writes scan evidence or recreates a ledger.

### Saved views (US1)
- `GET /api/views`, `POST /api/views` (`{name, filters, sort}`), `DELETE /api/views/{id}`.

### Scan status & artifact manifest (US3)
- `GET /api/scans/{id}/status` — the three independent axes (execution / coverage /
  validation) + per-phase outcomes, distinct from the queue/job status.
- `GET /api/scans/{id}/manifest` — each expected artifact's validated state:
  `not_requested | available | missing | unreadable | malformed | generation_failed |
  unknown_historical`. "available" requires content-validated material.

### Dashboard "Needs attention" (US4)
- `GET /api/attention?stale_days=<n>` (default 7) — six queues, each with
  `key, label, definition, count, link, available, note`. Counts are deduplicated by
  stable identity. Served separately from `/api/stats` so a failure here never blanks
  the preserved dashboard, and queue filters never change the stats population.
- `GET /api/stats` — unchanged; preserves the feature-008 metric set (a golden test
  locks it as a regression baseline).

### Contextual AI (US5)
- `POST /api/findings/{occ}/assist` — run one action
  `{action, request_id, provider, host, model}` where `action` ∈
  `explain-flow|find-mitigations|challenge|draft-test|propose-fix`. Uses the
  operator-configured provider with no silent fallback (unknown provider → explicit
  error); runs with no tools (cannot execute code or touch the working tree); result
  carries provenance, is labeled `generated-analysis`, and draft actions are
  non-executed artifacts. Repeating with the same `request_id` returns the stored
  result (no resubmit).
- `GET /api/findings/{occ}/assist?action=<action>` — fetch a stored result.
- `POST /api/findings/{occ}/assist/cancel` — cancel a running action.

## New internal packages

- `internal/findings` — cross-scan index/queue, occurrence identity (reuses
  `internal/lifecycle` precedence), evidence fingerprint, and baseline comparison.
- `internal/review` — durable review-decision store (`~/.vhlocal/reviews/`), append-only
  history, optimistic-version conflict, rationale rule.
- `internal/views` — saved views (`~/.vhlocal/views/`).
- `internal/evidence` — revision-bound source excerpt + narrative (read-only, static).
- `internal/attention` — the six dashboard queues.
- `internal/assist` — contextual-AI orchestration + result store (`~/.vhlocal/assist/`),
  exercised offline via `internal/client/testsupport` fake provider.

## Constraints honored

Static-only (no target execution; contextual AI has no tools), three independent
status axes, engine-recorded provenance, explicit provider failure with no silent
fallback, additive/atomic stores keyed by stable identity, path containment on every
source read, and untrusted repo/AI text treated as data. Offline-tested end to end;
no live model and no Python are required for the backend acceptance.
