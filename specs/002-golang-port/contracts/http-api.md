# Contract: HTTP Engine API + SSE (parity)

The Go engine MUST reproduce these endpoints, methods, request bodies, response shapes, status codes, and error bodies exactly, because the bundled React UI and legacy HTML UIs (and any scripts) read them by key. Source of truth: current `vhlocal/server.py`, `jobs.py`, `apps.py`, `activity.py`, `profiles.py`, `membank.py`, `reports.py`.

## Conventions

- JSON responses: `Content-Type: application/json`, `Cache-Control: no-store`, body `json.dumps(obj)`.
- Error body is **always** `{"error": <message>}`; default status 400.
- Malformed/empty request bodies parse to `{}` (never 400 on bad JSON).
- Unmatched route → 404 `{"error":"not found"}`.
- Server identifies as `vhlocal`, HTTP/1.1, threaded (goroutine-per-request in Go). Binds `127.0.0.1:8420` by default; non-loopback bind refused without `--unsafe-bind`.

## Shared objects

### Job (`Job.public()`)
Fields: `id` (12-hex), `spec` (full ScanSpec dict; `spec.out` overwritten with resolved results dir at submit), `status` (`queued|running|done|failed|cancelled|interrupted`), `created_at` (unix float), `started_at` (num|null), `finished_at` (num|null), `results_dir` (str|null), `error` (str|null), `usage` (str|null — `Usage.summary()`), `phase` (str|null, `"{key} — {title}"`), `agent_label` (str|null), `agent_index` (int), `agent_total` (int), `prompt_tokens` (int), `completion_tokens` (int), `findings_count` (int), `findings_stage` (`""|confirmed|final`), `current_model` (str), `elapsed` (float, computed).
`usage` string format: `"{calls} calls | {prompt:,} prompt + {completion:,} completion tok | {seconds:.1f}s | {tps:.1f} tok/s | peak prompt {peak:,}"`.
`spec` = ScanSpec.to_dict() with all fields stringified where Path (full field list & defaults mirror the CLI `run` flags; see cli.md).

### Report (`Report.to_dict()`) — all fields always present
`id, path, name, repo, model, model_reported, created (mtime float), stamp, findings (int), hypotheses (int), severities (obj str→int), findings_summary, branch, audit_date, complete (bool), phases_present ([str] ⊆ 1,2,2b,3,3d,4), size (int bytes), has_report (bool), has_consolidated (bool), coverage_status, coverage_degraded (bool), recall_pct (int|null), ledger_slug, chains (int), sbom_total (int), has_sbom (bool), has_threat_model (bool), slug`.

## Endpoints

### Config / discovery
- **GET /api/config** → `{skill_dir, reports_dir, allow_roots:[str], phases:[{key,title}] (all 7 incl "1t"), defaults:{model:"gpt-oss:120b", num_ctx:131072, ollama_host, openai_host:"http://localhost:8080", openrouter_host:"https://openrouter.ai/api", openrouter_key_set:bool}}`.
- **GET /api/models?backend=&host=** → `{models:[...]}`. ollama items `{name:str|null,size:num|null,family:str|null}`; openai items `{name,size:null,family:null}`; openrouter items `{name,tier:"free|$|$$|$$$|$$$$",context:num|null}`. Transport failure → **502** `{"error":"cannot reach ..."}`.
- **GET /api/profiles** → `{profiles:[{name,description,overrides,builtin:bool}]}`. Built-ins first (`quick`,`thorough`,`share`,`benchmark` with the exact overrides in cli.md/profiles), then user JSON; `overrides` sanitized to the 18 allowed structural keys; never model/host/backend.
- **GET /api/stats** → `{scans,with_usage,prompt_tokens,completion_tokens,total_tokens,avg_tokens_per_scan,findings,avg_findings_per_scan,total_seconds,avg_seconds_per_scan,by_model:{<model>:{scans,tokens,findings}}}`. `by_model` key `"unknown"` when model empty.

### Scans
- **POST /api/scans** → validates body (see cli.md flag parity; `repo` required + allow-root check; `out` allow-root check; `num_ctx`/`max_partitions` positive; `phases` via select_phases; extra non-spec field `app_name`). Errors: `"repo is required"` 400, `"repo is not a directory: {repo}"` 400, allow-root violations **403**, phase error 400, positivity errors 400. Success **201** = Job.
- **GET /api/scans** → `{jobs:[Job], busy:bool}`, newest-first.
- **GET /api/scans/{id}** → Job; 404 `{"error":"no such job"}`.
- **GET /api/scans/{id}/events** → SSE (see below); 404 JSON if unknown.
- **GET /api/scans/{id}/log** → `text/plain`, that scan's central-log slice; empty → `"(no log lines for this scan)"`; 404 JSON if unknown.
- **GET /api/scans/{id}/artifacts** → `{files:[]}` if no results dir, else `{root, files:[{path,size}]}` (recursive, dotfiles excluded, sorted).
- **GET /api/scans/{id}/file?path=** → raw bytes; `text/html` for `.html` else `text/plain`; no results dir → 404 `{"error":"no results directory"}`; empty path → 400 `{"error":"path required"}`; escape → **403** `{"error":"path escapes results directory"}`; missing → 404 `{"error":"not found"}`. Requesting the consolidated HTML auto-refreshes if stale.
- **POST /api/scans/{id}/cancel** → 200 `{"cancelled":true}`; not cancellable → **409** `{"error":"job not cancellable"}`. Queued job cancelled immediately (emits `scan_done`); running job flagged for cooperative cancel (stops within one model turn).

### SSE (`/api/scans/{id}/events`)
Headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `Connection: keep-alive`. Frame: `data: <json>\n\n` (no `event:`/`id:` lines). Query `offset` (int, default 0) indexes the per-job event ring (bounded 4000; oldest trimmed); client passes the count it has received as next `offset`. Keepalive `: keepalive\n\n` every 15s of silence; after a keepalive, close if status terminal. Sending a `job_end` event closes the stream. Every event dict carries `ts` (unix float) + `type` + type-specific fields:

| type | fields |
|---|---|
| `queue` | `message` |
| `scan_start` | `repo, results_dir, model, verify_model(str|null), phases:[str], num_ctx` |
| `phase_start` | `key, title` |
| `phase_done` | `key, seconds, produced(bool)` |
| `phase_skip` | `key, reason` (`resume`|`zero_verified_candidates`) |
| `agent_start` | `label, model` (+ optional `index,total,partition,vuln_class`) |
| `agent_done` | `label, turns, stopped_reason` (+ optional `index,total,prompt_tokens,completion_tokens`) |
| `agent_skip` | `label, index, total` |
| `fanout_plan` | `partitions:[str], agents(int), partition_source, partition_fallback(bool), coverage_partitions_added:[str]` |
| `findings` | `count, stage` (`confirmed`|`final`) |
| `handoff` | `written(bool), file(str|null)` |
| `canary` | fail: `ok:false,kind,model`; ok: `ok:true,model` |
| `breaker_tripped` | `phase, transport_errors, message` |
| `budget_halted` | `spent_usd, cap_usd, message` |
| `log` | `level, message` |
| `error` | `message` |
| `scan_done` | `seconds, usage, cancelled(bool), aborted(str|null), results_dir, report(str|null)` (queued-cancel reduced form: `cancelled:true,seconds:0,usage:""`) |
| `job_end` | `status` (terminal); closes stream |

### Reports
- **GET /api/reports** → `{reports_dir, reports:[Report]}`, newest-first; includes explicit-`out` job dirs.
- **GET /api/reports/{id}/files** → `{root, files:[{path,size}]}`; 404 `{"error":"no such report"}`.
- **GET /api/reports/{id}/file?path=** → same as scans file endpoint; 404 `{"error":"no such report"}` if id unresolved. `GET /api/reports/{id}` with no `files`/`file` tail → 404 (no detail endpoint).
- **DELETE /api/reports/{id}** → 200 `{"deleted":id}`; unresolved 404; outside reports tree **403**; == reports root **403**; active scan **409**; rmtree failure **500**.

### Applications
- **GET /api/applications** (list) → `{applications:[AppSummary]}` sorted by `last_scanned` desc, hidden excluded. AppSummary: `slug,name,repo,named(bool),scans,last_scanned,latest_findings,latest_severities,latest_coverage,latest_report_id,open_findings(int|null),ledger_total(int|null),has_threat_model,has_sbom`.
- **GET /api/applications?repo=** (lookup) → `{slug, application:AppSummary|null}`.
- **GET /api/applications/{slug}** → AppSummary + `scan_history:[{id,created,model,findings,hypotheses,severities,coverage_status,coverage_degraded,has_report,has_threat_model,has_sbom,recall_pct(int|null),chains}]` + `has_ledger(bool)`. Bad slug 400 `{"error":"bad application id"}`; unknown 404 `{"error":"no such application"}`.
- **POST /api/applications/{slug}** body `{name}` → 200 registry entry `{slug,name,repo,created,updated}`; bad slug 400; blank name 400 `{"error":"name is required"}`; unknown 404; failure 400 `{"error":"could not name application"}`.
- **DELETE /api/applications/{slug}** → 200 `{"forgotten":slug}` (hides app + deletes ledger, keeps reports); bad slug 400.

### Ledgers
- **GET /api/ledgers** → `{ledgers:[{target,target_name,runs_recorded,total,open,fixed,regressed,reliable,by_severity,updated,slug}]}` sorted by `updated` desc.
- **GET /api/ledgers/{slug}** → full on-disk ledger + injected `summary` + `slug`; 404 `{"error":"no such ledger"}`. On-disk shape: `{target,updated,runs_recorded:[str],findings:[{key,canonical_cwe,family,title,location,severity,first_seen:{run,model,date},last_seen:{...},confirmed_in:[str],confirmed_count,cross_family(bool),status,confidence}],...}`.
- **DELETE /api/ledgers/{slug}** → 200 `{"cleared":slug}`; bad slug 400 `{"error":"bad ledger id"}`; not found 404.
- **DELETE /api/ledgers/{slug}/finding?key=** → 200 `{"removed":key}`; bad slug 400; missing key 400 `{"error":"finding key is required"}`; no such finding 404.

### Activity / log
- **GET /api/activity?limit=&type=&scan=** → `{events:[{ts,type,message,...}]}` newest-first, `limit` clamped [1,2000] default 200. Event types & fields per activity.py (`scan.started/completed/cancelled/failed/interrupted/ended`, `app.named/renamed/forgotten`, `report.deleted`, `threat_model.built`, `ledger.finding_removed`, `ledger.cleared`); null fields dropped.
- **GET /api/log?tail=&scan=&level=** → `{text}`; `tail` clamped [1,20000] default 500; `level` min-level filter (DEBUG<INFO<WARNING<ERROR<CRITICAL); lines oldest→newest joined by `\n`.

### Misc
- **POST /api/openrouter-key** body `{api_key}` → 200 `{"key_set":bool}`. In-memory only; never persisted, echoed, or logged.

## Static-file routes
Served from the embedded `web/` FS with no-cache headers; content-type by extension; path-escape guarded (must stay under root and be a file, else 404).
`/`,`/index.html`→`web/index.html`; `/legacy(.html)`→`web/index.legacy.html`; `/classic(.html)`→`web/index.classic.html`; `/static/<rest>`→`web/<rest>`; `/app` and `/app/<rel>`→ if `rel` starts `assets/` or last segment has a `.` → `web/app/<rel>`, else `web/app/index.html` (SPA deep-link fallback).

## Behavior invariants
- **Serialized scans**: single FIFO worker; `busy` reflects the one in-flight job.
- **Job persistence** at `~/.vhlocal/jobs.json`; on load, `running`/`queued` jobs rewritten to `interrupted` with `error="server restarted while job was active"` — never re-run.
- **Slug validation** `^[A-Za-z0-9._-]+$` and no `..`, applied on application POST/DELETE and ledger DELETE; GET routes match against enumerated dir listings (traversal structurally impossible). Trailing slashes stripped; slugs/ids unquoted.
- **Security**: allow-root checks on `repo` and `out`; artifact reads confined to the owning results/report dir resolved before prefix check; report ids matched against the enumerated set.

## Acceptance
The existing built React UI and the legacy/classic HTML UIs run unmodified against the Go engine; every endpoint returns the same path/method/JSON shape; SSE replays backlog then streams live with the same event vocabulary; cancel stops within one model turn (SC-002).
