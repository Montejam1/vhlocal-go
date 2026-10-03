# API Contracts — application/scan/report/material endpoints

These are the response contracts the shipped browser surfaces already expect (legacy `vhlocal/web/index.html` and `web-react`, whose `types.ts` mirrors the reference API). The server MUST satisfy them; field names are normative. Errors MUST be distinguishable from empty success (an error is an HTTP error status and/or an `error` field — never a `200` with an empty list).

## GET /api/applications

- No `repo` query → `{ "applications": AppSummary[] }`, sorted by `-last_scanned`, excluding hidden slugs.
- With `?repo=<path>` → `{ "slug": string, "application": AppSummary|null }` (form pre-fill).
- Each `AppSummary` MUST include every field in data-model §AppSummary. `open_findings`/`ledger_total` MUST be `null` (not `0`) when no ledger exists.
- Discovery MUST include applications whose scans ran with the ledger disabled and applications known only from on-disk reports.

**CA-1**: Given seeded state with (a) a registry app, (b) a ledger-disabled repo that has reports, (c) an app known only from an on-disk report, the list returns all three (minus any hidden), each with the full field set; a ledger-less app shows `open_findings=null`.

## GET /api/applications/{slug}

- `200` → `AppDetail` (AppSummary + `scan_history[]` + `has_ledger`); `404` for an unknown slug; `400` for an invalid slug (`^[A-Za-z0-9._-]+$`, no `..`).
- `scan_history` rows carry the data-model §ScanHistoryRow fields; `recall_pct` is `null` unless there were known open findings.

**CA-2**: A detail response for an app with ≥2 reports (including one created before this feature) lists both in `scan_history` newest-first with correct per-report outcome and availability flags.

## POST /api/applications/{slug} (rename) · DELETE /api/applications/{slug} (forget)

- Rename sets the name by slug (creating the entry if absent), preserving stable identity; **existing report files are never deleted**.
- Forget hides the slug (and clears its ledger) but **keeps reports on disk**; a later scan of the same repo un-hides it.

**CA-3**: Forgetting an app removes it from the list but preserves its report files; re-scanning the same repo makes it reappear with its history intact.

## GET /api/scans · GET /api/scans/{id}

- List → `{ "jobs": Job[], "busy": bool }`, newest first; history survives restart; dead in-flight jobs load as `interrupted`.
- Each `Job` MUST include the data-model §Scan/Job fields, with `prompt_tokens`/`completion_tokens`/`agent_index`/`agent_total` **populated during a run** (not fixed at 0), plus `phase_outcomes[]` and the three engine axes (`execution_status`, `coverage_status`, `validation_mode`) distinct from queue `status`.
- Detail additionally exposes `phase_outcomes` and status axes for the step tracker.

**CA-4**: A job for a partial run reports queue `status` distinctly from `execution_status=partial`; `phase_outcomes` marks the unfinished phases `completed=false` with a `reason`; token/agent progress fields are non-zero during the run.

## GET /api/reports · /api/reports/{id}/files · /api/reports/{id}/file?path=

- List → `{ "reports_dir": string, "reports": Report[] }` (data-model §Report fields), newest first, tolerant of custom output dirs and legacy shapes.
- Files listing is recursive, dotfiles skipped, paths relative; file read is path-escape guarded (resolved-prefix check) and serves `.html` as `text/html`, everything else as `text/plain` (no in-page execution).

**CA-5**: A report list built from mixed/legacy on-disk report dirs returns each with correct `findings`/`severities`/`coverage_status`/`has_threat_model`/`has_sbom`/`phases_present`; file reads outside the results dir are rejected.

## Threat model / SBOM availability

- The scan, report, and application views MUST expose each material's `MaterialAvailability` state (data-model), and, when `available`, a working open/download path — including for pre-existing on-disk files with no re-scan.
- Generation/parse/read failures MUST be represented (not swallowed); the discarded `sbom.Write` error becomes a visible `generation_failed`/`malformed` state.

**CA-6**: For fixtures covering each material state (not_requested / available / missing / malformed / generation_failed), the correct state is returned; an available SBOM (21 components) and threat model are openable/downloadable from all three view types without re-scanning.
