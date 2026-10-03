# Contract — Scan evidence API & applications cleanup

Behavior invariants for `internal/server` (+ `internal/jobs` resolver). Offline-verified. IDs map to FRs/SCs.

## One evidence-state resolver (FR-002)

Every evidence endpoint derives the job's state from store facts via ONE resolver:

| State | Condition | Artifacts | File / Prompts / Log |
|---|---|---|---|
| `unknown` | id not in store | **404** `{"error":"no such job"}` | 404 same |
| `not_started` | queued, or cancelled before `scan_start` | **202** `{"state":"not_started","files":[]}` | **202** `{"state":"not_started"}` (as built: uniform across every evidence endpoint — the plan's 409 was dropped so one state has one status) |
| `running_no_files` | bound at `scan_start`, dir exists, no files yet | 200 `{"state":"running_no_files","files":[]}` | 200 `{"state":"running_no_files", …}` (prompts/log report this evidence state while running and nothing is written yet) |
| `ready` | bound, files present | 200 `{"state":"ready","files":[...]}` | 200 content |
| `empty` | terminal, bound, dir exists, no files | 200 `{"state":"empty","files":[]}` | 200 `{"state":"no_records"}` / `{"state":"no_lines"}` |
| `unavailable` | bound but dir missing/unreadable | **503** `{"state":"unavailable","reason":"..."}` | 503 same |

**Status note (as built, T061)**: `state` values are the resolver's names verbatim (`running_no_files`, not
`running`). Prompts and log add their own terminal empties (`no_records`, `no_lines`) and the legacy
`not_recorded`; while a scan is running with nothing written yet they return the resolver's
`running_no_files` so the UI can say "nothing yet" rather than "none".

- **C-E1**: unknown ≠ not_started ≠ running_no_files ≠ empty ≠ unavailable — never the same body/status.
- **C-E2**: `results_dir` is bound on the engine's `scan_start` (FR-001), persisted, confined to allowed
  roots and owned by the job; File reads stay confined to that directory (constitution III).

## Bounds (FR-003/004/024 — pinned so "bounded" is testable, SC-003)

| Surface | Default | Max | Behavior past the bound |
|---|---|---|---|
| Artifacts page (`limit`) | 200 files | 1000 | `next_offset` returned; UI shows "show more" |
| Log window (`tail`) | 500 lines | 5000 | older lines reachable via `after` cursor paging |
| Prompt record content (`system`/`task`) | 8 KB each | — | clamped at write time with `truncated:true`; the full text is **not** stored (see records.md — the "expand fetches the full record" path was never built) |
| Prompts page (`limit`) | 100 records | 500 | `next_after` returned |
| Application list rendering | 100 rows/page | — | page / "show more"; detail opens without rendering the whole list |
| Scan-log line detail | 2 KB | — | clamped with a `…[truncated]` marker |

These are the values T014 (state contract), T027 (main UI), T029 (React), and T056 (applications) quote.

## `GET /api/scans/{id}/artifacts` — paged
`?offset=&limit=` (default/max per Bounds); returns `state`, `files[]`, `total`, `next_offset` (FR-003/004).

## `GET /api/scans/{id}/prompts` — new (FR-005/009)
`?after=<seq>&limit=` → `{"state": ready|no_records|not_recorded, "records":[PromptRecord…], "next_after"}`.
- **C-P1**: `not_recorded` when `scan_meta.prompt_capture_version` is absent (scan predates capture) — the UI
  shows "not recorded by this version", never "not captured yet".
- **C-P2**: records contain no credentials/authorization headers; hosts redacted; `redactions[]` labels masks.
- **C-P3**: every model call kind (`main|repair|canary|repartition`) for every role is present with `seq`
  order, `phase`, `label`, `role`, `model`, `ts`.

## `GET /api/scans/{id}/log` — new window (FR-006)
`?tail=<n>&after=<cursor>` → `{"state": ready|no_lines|running_no_files, "lines":[...], "cursor", "total"}`
(tail-bounded; the UI polls with `after` for follow). `no_lines` is a state, not a prose sentinel. Prompts
likewise return `total` alongside `next_after`.

## Scan detail (`GET /api/scans`, `GET /api/scans/{id}`) — additive fields (FR-016/021, as built)
`enrichScan` adds, next to — never inside — the queue `status`: `outcome` (the `run_status.outcome` block
verbatim from `findings.json`) and `review_units: {revision, counts, follow_up_ran, unreviewed:[{route_id,
reason}]}` from `review_units.json`. Both are absent for scans that predate feature 014 (never invented).
Application history rows (`/api/applications/{slug}.scan_history[]`) carry the same `outcome` per scan.

## Live-update contract (FR-003/004)
- **C-L1**: on a healthy local connection new artifacts/prompts/log lines are retrievable within 5 s of being
  written; the UI's open tab reflects them without navigation, and refreshes once more on terminal status.
- **C-L2**: the UI attaches a per-pane abort/sequence guard; a response for scan A never renders in scan B.
- **C-L3**: browser disconnect never affects the running job; reconnect re-reads from `after`/`cursor` without
  duplicates (FR-008).

## `GET /api/applications/{slug}` — artifact selection (FR-025/026)
Response gains `artifacts: { threat_model: Selection, sbom: Selection }` where Selection = `{scan_id,
created, revision, path, valid, older_than_latest, reason}` chosen as the newest **valid** from this
application's own history; `threat_model=false` on the latest scan → `reason:"threat model disabled for the
latest scan"`. Report-file endpoints keep **404 (absent) distinct from 5xx (error)**.

**As built**: `valid:false` selections carry `reason`; a malformed/empty/unreadable newest file is skipped and
named in the reason (`newest SBOM in <scan> is malformed; no valid SBOM in this application's history`). A
scan with `1t` requested but skipped (`threat_model=false`) classifies its material `not_requested` (never
`missing`) on every surface (`reports.Report.ThreatModelDisabled`). `report-file` reads: 404 only for
`ENOENT`/directory; stat or read failures are **500** with the OS error.

## `GET /api/applications/cleanup` · `POST /api/applications/cleanup` (FR-028)
- GET → `{candidates:[{slug, repo, reason}], preserved_count, preview_token}` (nothing changes). The token is
  a digest of the candidate slugs, so it is stable while the registry is unchanged and stale once it isn't.
- POST requires `{"confirm":"<preview_token>"}`; writes `applications.json.bak-<ts>` first; removes exactly
  the previewed ids; never touches reports/ledgers; returns `{removed, backup_path}`. A missing/incorrect
  token, or an empty preview → 400, nothing changes (no backup is written either). CLI parity:
  `vhlocal applications cleanup --preview | --apply --confirm <token>` (and `applications list`).
- The literal `/api/applications/cleanup` route takes precedence over `/api/applications/{slug}`.

## `GET /api/config` — build identity (SC-012)
Gains `build: { version, embedded_assets_hash, built_at, built_at_source }` — `embedded_assets_hash` is
sha256 over every embedded `vhlocal/web` file (path + content, sorted), computed once per process;
`built_at_source` is `ldflags` (stamped via `-X vhlocal.BuiltAt=`), `executable_mtime` (honest fallback) or
`unknown`.

## Intentional differences vs `../vhlocal` (read-only Python reference)
- The reference has no evidence-state resolver, prompt records, scan-tagged log window, review units,
  completion block, artifact selection, cleanup or build identity; all of the above are Go-only additions.
- Coverage: the reference's `BuildLedger` marks a route reviewed only via an in-span finding. The Go ledger
  adds `reviewed_no_issue` / `excluded_with_reason` from `review_units.json` evidence; parity's `dispatch`
  projection skips class `followup` units (`hunt:<slug>:followup`) because the reference never dispatches them
  (documented in `tests/parity/project.go`).
- When phase 2b ran, an `unresolved` candidate is not coverage evidence in Go (the reference counted any
  hunt finding); the 012 Go recognizer's `url.Values.Get("q")` false positive is a noted follow-up.
