---

description: "Task list for porting vhlocal to Go with interface parity"
---

# Tasks: Port vhlocal to Go with interface parity

**Input**: Design documents from `/specs/002-golang-port/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/ (cli.md, http-api.md, artifacts.md), quickstart.md

**Tests**: INCLUDED — the constitution (Principle VII) and spec FR-029 / SC-006 / SC-007 require an offline automated test suite. Test tasks appear within each story's phase.

**Organization**: Tasks grouped by user story (US1=P1 CLI scan parity, US2=P2 HTTP engine + UI, US3=P3 auxiliary tools). The reference Python source at `vhlocal/` is the parity oracle for differential tests.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependency on incomplete tasks)
- **[Story]**: US1 / US2 / US3 (Setup, Foundational, Polish carry no story label)
- Paths follow plan.md: `cmd/vhlocal/`, `internal/<pkg>/`, tests as `_test.go` beside each package.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Go module, build/release tooling, embed scaffold, test harness.

- [X] T001 Create Go module and directory skeleton (`go.mod` pinning Go 1.23+, module path; `cmd/vhlocal/main.go` subcommand dispatch stub; empty `internal/{cli,engine,phases,agent,tools,client,inventory,consolidate,lifecycle,report,sarif,sbom,manifest,verification,membank,apps,remediation,redact,profiles,server,jobs,activity,logsetup,knowledge,config,assets}` packages) per plan.md structure
- [X] T002 [P] Implement `go:embed` scaffold in `internal/assets/embed.go` embedding `skill/` (methodology) and `vhlocal/web/` (built React `app/` + legacy/classic HTML); document build ordering (npm build → go build) in a header comment
- [X] T003 [P] Add `Makefile` with `build` (single binary) and `release` (cross-compile matrix linux/amd64, linux/arm64, darwin/amd64, darwin/arm64; version via `-ldflags -X`; CGO_ENABLED=0) per research R12
- [X] T004 [P] Configure `gofmt`/`go vet` and a CI gate running `go test ./...` fully offline (no network, no live model) per research R11
- [X] T005 [P] Create test support in `internal/client/testsupport/`: a fake inference transport implementing the provider interface + `httptest` fixture server for Ollama `/api/chat`, OpenAI `/v1/chat/completions`, OpenRouter; copy/point at `testdata/vulnapp` + `testdata/ground_truth`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared primitives every scan/engine/server path needs. **No user-story work may begin until this phase is complete.**

- [X] T006 [P] Config + env resolution in `internal/config/config.go`: `VHLOCAL_OLLAMA_HOST`(`http://localhost:11434`), `VHLOCAL_OPENAI_HOST`(`http://localhost:8080`), `VHLOCAL_OPENAI_API_KEY`, `VHLOCAL_OPENROUTER_API_KEY`, `VHLOCAL_LEDGER_DIR`(`~/.vhlocal/ledger`), `VHLOCAL_PROFILES_DIR`(`~/.vhlocal/profiles`), `VHLOCAL_LOG_FILE`/`VHLOCAL_LOG_DIR`(`~/.vhlocal/vhlocal.log`), `VHLOCAL_ACTIVITY_FILE`; reports dir default `~/vulnhunter-reports`; openrouter fixed host `https://openrouter.ai/api`; **API keys resolvable from env OR in-memory, never persisted/logged** (FR-009a)
- [X] T007 [P] Central logging with per-scan line tagging in `internal/logsetup/` and activity feed in `internal/activity/` (event types and fields per contracts/http-api.md `/api/activity`; null fields dropped)
- [X] T008 [P] `normalize_text` punctuation map in `internal/phases/normalize.go` — exact map: hyphens `U+2010,2011,2012,2013,2014,2015,2212 → "-"`; spaces `U+00A0,2007,2009,202F → " "`; quotes `U+2018→', U+2019→', U+201C→", U+201D→"`; nothing else altered (data-model §normalize_text)
- [X] T009 [P] Phase specs + SKILL preamble extraction (`## Operating Principles`…`## Workflow`) + partition-table parsing + `Hunt targets` JSON parsing in `internal/phases/phases.go`; phase keys `1,1t,2,2b,3,3d,4` with exact titles, `reads`, `max_turns`, `fan_out`; class groups INJ/NAV/LOG + SINK + combined ALL (depends on T008)
- [X] T010 [P] Sandboxed tools Read/Grep/Glob/Write in `internal/tools/`: resolved-path prefix containment (read roots = target repo + skill dir + results dir; write root = results dir only), output caps (`MAX_READ_LINES=1200`, `MAX_LINE_CHARS=500`, `MAX_GREP_MATCHES=150`, `MAX_GLOB_RESULTS=400`, `MAX_RESULT_CHARS=60000`), SKIP_DIRS set, case-insensitive tool names + aliases (`glob`/`Glob`, `read_file`/`Read`), ripgrep-with-pure-Go-fallback (research R9). **No shell/exec tool** (Principle III)
- [X] T011 [P] Knowledge tables in `internal/knowledge/`: the full `_FAMILIES` table (family key, canonical name, canonical CWE, baseline severity, members — first-family-wins), `CWE_INFO`, severity tier order `Critical,High+,High,Medium,Low,Informational`, `_GATED` regex, `normalized_cwe`/`canonical_name`/`normalized_severity` (−1 tier on gated match, clamp to Informational), fixed `CVE-N/A` string (data-model honesty-critical tables)
- [X] T012 [P] Git provenance helper in `internal/client/provenance.go`: best-effort `git_commit`/`git_branch`/`git_dirty` via `os/exec`, empty when not a repo
- [X] T013 Inference clients in `internal/client/`: provider interface + `ollama.go` (`/api/chat`,`/api/tags`), `openai.go` (`/v1/chat/completions`,`/v1/models`), `openrouter.go` (fixed host, key from config, tier map `free/$/$$/$$$/$$$$`); always set `num_ctx`; capture provenance (backend, endpoint redacted, requested + returned model, sampling/ctx/limits); **explicit failure surfaced + recorded, no silent fallback, no local→paid fallback** (Principle V); bounded same-endpoint retry + fresh-context tool-call repair (2 attempts then graceful end) per research R4/R14 (depends on T006)
- [X] T014 Agent tool loop in `internal/agent/`: one isolated run with system preamble, tool dispatch to `internal/tools`, context pruning, `stopped_reason` tracking, graceful end on repeated failure (never crash the scan) (depends on T010, T013)
- [X] T015 [P] Deterministic entry-point inventory in `internal/inventory/` (research R16 — highest fidelity risk): recognize FastAPI (`@app.get`, `APIRouter`, `include_router` prefixes) + Flask (`@app.route`, blueprints) route registrations from Python source without CPython `ast`; build `CoverageLedger` (entries `{method,path,file,line,subsystem,disposition,evidence}`, dispositions `finding_emitted|reviewed_no_issue|covered_by_parent_analysis|excluded_with_reason|not_reviewed`, `complete = total>0 && not_reviewed==0`) and partition-fallback synthesis; non-Python entry points = documented limitation (depends on T010)

**Checkpoint**: Shared primitives ready — user story implementation can begin.

---

## Phase 3: User Story 1 - CLI scan produces the same result artifacts (Priority: P1) 🎯 MVP

**Goal**: `vhlocal run` executes the full phase pipeline and writes the byte-compatible artifact set (SCAN_REPORT.html/.md, findings.json, findings.sarif, scan_meta.json, coverage_ledger.json, run_manifest.json, README.md, per-phase outputs, SBOM/threat-model when enabled) with the same honesty guarantees.

**Independent Test**: Run against `testdata/vulnapp`; compare the results directory to a Python run on the same fixture/model — same filenames, same JSON field semantics, same deterministic labels; negative control never reported (SC-001, SC-004, SC-006).

### Tests for User Story 1 ⚠️ (write first; differential vs Python oracle)

- [X] T016 [P] [US1] Artifact-set + `findings.json` top-level-block presence test over `testdata/` in `internal/consolidate/consolidate_test.go` (assert `meta,attribution,run_status,coverage,counts,assessment,lifecycle,application_intelligence,findings`)
- [X] T017 [P] [US1] Knowledge/normalization table tests in `internal/knowledge/knowledge_test.go`: CWE→family/canonical/severity for a battery incl. multi-family CWEs, and `_GATED` −1-tier cases
- [X] T018 [P] [US1] `root_cause_key` fingerprint + dedup/cluster tests in `internal/consolidate/dedup_test.go`
- [X] T019 [P] [US1] Lifecycle reconciliation tests in `internal/lifecycle/lifecycle_test.go` (new/persisting/regressed/fixed, duplicate inheritance, `identity_schema_changed` guard)
- [X] T020 [P] [US1] Coverage/inventory tests in `internal/inventory/inventory_test.go` (route enumeration, dispositions, partition fallback) — parity oracle = Python output on fixtures
- [X] T021 [P] [US1] SBOM + SARIF golden tests in `internal/sbom/sbom_test.go`, `internal/sarif/sarif_test.go` (multi-ecosystem fixture; SARIF 2.1.0 rule/result/level/taxa mapping)
- [X] T022 [P] [US1] Resume/idempotency + degraded-path tests in `internal/engine/engine_test.go` (empty deliverable redone, unparseable partition table → visible fallback, budget halt, tool-call repair, no double-count on re-run)
- [X] T023 [P] [US1] Fixture scorer `testdata/score.go` (recall on the 5 planted bugs + negative-control check) per quickstart Scenario 3

### Implementation for User Story 1

- [X] T024 [US1] `RunRecord` (scan_meta.json) struct in `internal/engine/record.go` — all fields, order, and defaults from data-model §RunRecord (`quality_strictness` default `"balanced"`, `iac_lens` default `true`, `hunt_samples` default `1`, etc.); `agents[]` element `{label,phase,model,turns,stopped_reason}`; atomic write (temp + rename), `indent=2`
- [X] T025 [US1] `Finding` struct + `to_dict` (append `potential_severity`) + vocabulary constants in `internal/consolidate/finding.go` — full field set/defaults from data-model §Finding (`severity` default `"Unrated"`, `severity_rank` default `7`, `classification` default `"hypothesis"`, `cve` fixed `CVE-N/A`); keep model claims (`status`,`exploit_test`) distinct from harness-derived state (Principle I)
- [X] T026 [US1] Findings extraction in `internal/consolidate/extract.go`: parse hunt `results/*.md`, `phase2b_output.md`, `README.md`; tolerant header-aware table parsing (mixed heading/column styles, verdict-cell skipping); route ALL model-output regex through `normalize_text` (depends on T025, T008)
- [X] T027 [US1] Dedup + `root_cause_key` fingerprint + clustering in `internal/consolidate/dedup.go` (family:file:func:flowsig; degraded `family::title_signature`; empty disables dedup; duplicates flagged not merged) (depends on T025, T011)
- [X] T028 [US1] Normalized CWE/family/severity + knowledge enrichment (`description`/`exploitability`/`reference`/`cve`) in `internal/consolidate/normalize.go`; set `reported_severity` when normalized differs (depends on T011, T025)
- [X] T029 [P] [US1] Quality battery (strictness `lenient|balanced|strict`) in `internal/consolidate/quality.go` producing per-finding `quality_checks[]` and the statically-supported bar
- [X] T030 [US1] `compute_run_status` three orthogonal axes in `internal/consolidate/status.go`: `execution_status∈{aborted,cancelled,complete,partial,incomplete,unknown}`, `coverage_status∈{degraded,complete,partial}` + `coverage_degraded_reasons[]`, `validation_mode∈{static_reasoning,dynamic_execution}` (dynamic only if `bash_enabled`); no axis derived from another (Principle II) (depends on T031 for coverage inputs)
- [X] T031 [US1] Coverage-ledger assembly + shallow-run degradation signals (0 entry points over non-trivial repo; large repo single partition) in `internal/consolidate/coverage.go` writing `coverage_ledger.json` (depends on T015)
- [X] T032 [P] [US1] Lifecycle reconcile (Mode A) in `internal/lifecycle/lifecycle.go` — key precedence (stable_identity → family-normalized root_cause_key → cwefile → ""), prior-report lookup, canonical `not_observed`/`reappeared` + deprecated `fixed`/`regressed` aliases (depends on T025)
- [X] T033 [P] [US1] Verification set in `internal/verification/`: `candidate_manifest.json`, decisions contract validation, `verification_reconciliation.json`, `verification_metrics.json`, per-candidate files, `artifact_manifest.json` (JSON array); trailing `\n` + atomic writes
- [X] T034 [P] [US1] SBOM generator in `internal/sbom/` — CycloneDX 1.5, manifest parsers for pypi/npm/golang/maven/gem/cargo/composer, `_SKIP_DIRS`, deterministic ordering, `summary` for findings.json
- [X] T035 [P] [US1] SARIF 2.1.0 emitter in `internal/sarif/` (driver `vhlocal`, CWE taxonomy GUID, rule/result/level/kind/taxa/invocations mapping from artifacts.md) (depends on T025, T011)
- [X] T036 [P] [US1] `run_manifest.json` builder + `config.hash` (`sha256(sorted config subset)[:16]`) in `internal/manifest/`
- [X] T037 [P] [US1] membank ledger in `internal/membank/`: slug `<basename>-<sha1(resolved)[:8]>`, `ledger_key` rules, confidence tiers (reliable/confirmed/provisional), idempotent-by-run merge, `_coverage` recall summary
- [X] T038 [P] [US1] Applications registry in `internal/apps/` (`applications.json`; entry `{slug,name,repo,created,updated}` / hidden `{slug,hidden:true}`; valid-slug guard `^[A-Za-z0-9._-]+$` no `..`)
- [X] T039 [P] [US1] Redaction (`internal/redact/`) masking cards/SSNs/credentials in artifacts; remediation DTOs (`internal/remediation/`) writing `remediation/<VULN>/{remediate.json,summary.md}` + `index.json` (report-only)
- [X] T040 [US1] `write_consolidated` in `internal/consolidate/consolidate.go`: assemble `findings.json` with all top-level blocks + `counts`/`attribution`/`assessment` (depends on T024–T039)
- [X] T041 [US1] Profiles in `internal/profiles/` (JSON store; built-ins `quick/thorough/share/benchmark` with exact overrides; structural-only allow-list of 18 keys; never model/host/backend) per contracts/http-api.md
- [X] T042 [US1] Deterministic report rendering in `internal/report/`: `SCAN_REPORT.md` + self-contained `SCAN_REPORT.html` (no external requests, inline print CSS forcing light palette, severity glyph+word, KPI tiles, stacked severity meter, filter/expand JS, "Filtered view — N of M" banner, Save-as-PDF) rendered from findings.json/scan_meta.json only — no model call (FR-008, FR-014) (depends on T040)
- [X] T043 [US1] Engine `execute_scan` pipeline in `internal/engine/engine.go`: `select_phases`, resume via `.vhlocal_state.json`, per-phase run + deliverable validation, Phase-2 fan-out (split/combined × classes + sink + iac lens), Phase-1t threat-model partition augmentation, harness-enforced coverage, budget cap + hunt circuit-breaker, `prompts.jsonl`/`errors.jsonl`, agents record, results-dir naming (`<repo>_VULNHUNT_RESULTS_<model>_<stamp>`); one shared implementation for CLI + server (FR-012) (depends on T009, T014, T015, T024, T040, T042)
- [X] T044 [US1] `vhlocal run` subcommand in `internal/cli/run.go` + `cmd/vhlocal/main.go` dispatch: every flag from contracts/cli.md with default<profile<explicit precedence (explicit via `FlagSet.Visit`), `--flag`/`--flag=value` + repeatable `-v`, backend/host resolution, wire to `execute_scan`; exit 0/2 (depends on T043, T041)

**Checkpoint**: MVP — a CLI scan produces the full parity artifact set; deterministic layers match the Python oracle; fixture recall + negative control pass.

---

## Phase 4: User Story 2 - HTTP engine and browser UI work unchanged (Priority: P2)

**Goal**: `vhlocal server` serves the embedded UI and the full JSON API + SSE over the same shared engine, with the same security posture and serialized-queue behavior.

**Independent Test**: Start the engine, load the existing React/legacy UIs, exercise every screen and each endpoint; SSE replays then streams; cancel stops within one turn; security guards refuse bad binds/paths (SC-002, SC-009).

### Tests for User Story 2 ⚠️

- [X] T045 [P] [US2] API contract tests via `httptest` in `internal/server/api_test.go` — one per endpoint, asserting path/method/JSON shape from contracts/http-api.md
- [X] T046 [P] [US2] SSE test in `internal/server/sse_test.go` (offset backlog replay, `data:` frames, 15s keepalive, `job_end` close, cancel-within-one-turn)
- [X] T047 [P] [US2] Security tests in `internal/server/security_test.go` (loopback default; `--unsafe-bind` required for non-loopback; allow-root 403 on repo/out; `?path=../` 403; slug validation; report-id matched against enumerated set)
- [X] T048 [P] [US2] Jobs persistence test in `internal/jobs/jobs_test.go` (interrupted-on-restart, no re-run, FIFO serialization, busy state)

### Implementation for User Story 2

- [X] T049 [US2] Jobs FIFO queue + store in `internal/jobs/`: single worker goroutine draining a channel, persistence to `jobs.json`, `cancel` via `context.Context`, `queued/running/done/failed/cancelled/interrupted` FSM, interrupted-on-load (`error="server restarted while job was active"`), bounded per-job event ring (4000) with offset slicing (depends on T043)
- [X] T050 [US2] `Job.public()` + `ScanSpec.to_dict` + `Usage.summary` shapes in `internal/jobs/public.go` (fields/types from contracts/http-api.md; `elapsed` computed)
- [X] T051 [US2] net/http server + `ServeMux` (1.22 path patterns) + security layer in `internal/server/server.go`: loopback default, non-loopback needs `--unsafe-bind`, allow-root checks on `repo`+`out`, artifact reads confined to owning dir (resolve before prefix check), report ids matched to enumerated set; `_json`/`_err` helpers (error body `{"error":msg}`) (depends on T049)
- [X] T052 [US2] SSE handler in `internal/server/sse.go`: `text/event-stream`, `offset` replay, `data: <json>\n\n`, `: keepalive\n\n` every 15s + terminal close, close on `job_end`; every event carries `ts`+`type`+type-specific fields (full vocabulary in contracts/http-api.md)
- [X] T053 [US2] Static UI serving from embedded FS in `internal/server/static.go`: `/`,`/index.html`; `/legacy(.html)`; `/classic(.html)`; `/static/<rest>`; `/app`+`/app/<rel>` (assets/extension → file, else SPA `index.html`); no-cache headers; path-escape guard (depends on T002)
- [X] T054 [P] [US2] Config/models/profiles/stats endpoints in `internal/server/routes_meta.go` (`/api/config`, `/api/models` with 502 on unreachable, `/api/profiles`, `/api/stats`)
- [X] T055 [P] [US2] Scans endpoints in `internal/server/routes_scans.go`: POST create (full body validation + 400/403 error bodies, 201 Job), GET list/detail/artifacts/file/log, POST cancel (409 when not cancellable)
- [X] T056 [P] [US2] Reports endpoints in `internal/server/routes_reports.go`: index (`Report.to_dict`, all fields), files, file, guarded DELETE (403 outside tree/==root, 409 active scan, 500 on failure) + `internal/reports/` index builder
- [X] T057 [P] [US2] Applications endpoints in `internal/server/routes_apps.go` (list, `?repo=` lookup, detail with `scan_history`+`has_ledger`, POST rename, DELETE forget)
- [X] T058 [P] [US2] Ledgers endpoints in `internal/server/routes_ledgers.go` (list, detail with injected `summary`+`slug`, DELETE clear, DELETE finding by `key`)
- [X] T059 [P] [US2] Activity + log + openrouter-key endpoints in `internal/server/routes_misc.go` (`/api/activity` clamp [1,2000], `/api/log` clamp [1,20000], `POST /api/openrouter-key` in-memory only)
- [X] T060 [US2] `vhlocal server` subcommand in `internal/cli/server.go`: flags per contracts/cli.md (`--host`,`--port` 8420,`--state`,`--ollama-host`,`--reports-dir`,`--allow-root` repeatable default `$HOME`,`--unsafe-bind`,`--skill-dir`,`--log-file`,`-v`) + bind guard (depends on T051)

**Checkpoint**: The existing UI runs unmodified against the Go engine; all endpoints + SSE match; security posture and serialized queue verified.

---

## Phase 5: User Story 3 - Auxiliary command-line tools (Priority: P3)

**Goal**: The supporting subcommands behave identically to their Python module counterparts.

**Independent Test**: For each tool, run against a fixture and confirm same output artifact, exit behavior, and refusals (quickstart Scenario 9).

- [X] T061 [P] [US3] `vhlocal report` in `internal/cli/report.go`: regenerate `SCAN_REPORT.md/.html`+`findings.json` deterministically (reuse T040/T042), `--all` bulk, `--delete <dir>` `--yes` guarded (refuse outside reports dir / active scan)
- [X] T062 [P] [US3] `vhlocal logs` in `internal/cli/logs.go`: central-log read + scan-tag slice (`--tail`,`--level`,log path)
- [X] T063 [P] [US3] `vhlocal sbom` in `internal/cli/sbom.go`: `<repo>` → CycloneDX, `--out` default `./sbom.cdx.json` (reuse T034)
- [X] T064 [P] [US3] `vhlocal bench` in `internal/cli/bench.go`: prefill/generation throughput; `--backend`,`--host`,`--model`
- [X] T065 [P] [US3] `vhlocal batch` in `internal/cli/batch.go`: CSV `repo[,app_id]` rows, `--skill-dir` required, forwards scan flags to `execute_scan`
- [X] T066 [P] [US3] `vhlocal authz` / `vhlocal membank` / `vhlocal policy-bench` in `internal/cli/{authz,membank,policy_bench}.go` (parity with the Python maintenance/eval entry points)
- [X] T067 [P] [US3] Tests for auxiliary subcommands in `internal/cli/*_test.go` (report regen determinism, delete guards, logs slicing, sbom output, batch CSV parsing)

**Checkpoint**: All documented entry points present as subcommands with parity behavior.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [X] T068 Amend the constitution's *Safety & Technical Constraints › Runtime* clause (and Principle VII test-command wording) via `/speckit-constitution`, naming the accepted risk (research R15) — governance prerequisite for the review gate
- [X] T069 [P] Update `README.md`, `RUNBOOK.md`, `DEPLOY.md` with the binary-invocation migration note (`python3 -m vhlocal.X` → `vhlocal X`), with zero undocumented flag deltas (SC-003)
- [X] T070 [P] Differential parity CI suite in `tests/parity/` comparing Go vs Python artifacts over `testdata/` (filenames, JSON field semantics, deterministic labels) — the standing guard for FR-031
- [X] T071 Cross-platform release smoke test: `make release` then run `vhlocal -h` + a phase-1 scan on each produced binary (SC-011, SC-012)
- [X] T072 [P] Add a `CHANGELOG.md` entry for the Go port
- [X] T073 Run `quickstart.md` Scenarios 1–9 end-to-end and record results
- [X] T074 Retire/deprecate the Python tree (coexistence note → removal plan) once parity suite is green

---

## Dependencies & Execution Order

### Phase dependencies

- **Setup (Phase 1)**: no dependencies.
- **Foundational (Phase 2)**: after Setup; **blocks all user stories**.
- **US1 (Phase 3)**: after Foundational. The MVP.
- **US2 (Phase 4)**: after Foundational; reuses the US1 engine (`execute_scan`, consolidation, rendering) — start once T043 exists.
- **US3 (Phase 5)**: after Foundational; reuses US1 consolidation/SBOM/rendering — start once T040/T042/T034 exist.
- **Polish (Phase 6)**: after the targeted stories; T068 (amendment) should precede merge.

### Critical path within US1

T024 → T025 → {T026, T027, T028} → T029/T030/T031 → T040 → T042 → T043 → T044. Parallelizable satellites off T025/T011: T032, T033, T034, T035, T036, T037, T038, T039.

### Story independence notes

US1 is fully standalone (MVP). US2 and US3 deliberately build on the shared engine (constitution invariant: one engine for CLI + server), so they layer on US1 rather than duplicating it — each still independently *testable* via its own endpoints/subcommands.

### Parallel opportunities

- Setup: T002, T003, T004, T005 in parallel.
- Foundational: T006, T007, T008, T009, T010, T011, T012, T015 in parallel; T013 then T014 sequential.
- US1 tests T016–T023 all [P]. US1 satellites T032–T039 all [P].
- US2 endpoint tasks T054–T059 all [P] after T051/T052. US2 tests T045–T048 [P].
- US3 T061–T067 all [P].

---

## Parallel Example: User Story 1 satellites (after T025 + T011)

```bash
Task: "SBOM generator in internal/sbom/ (T034)"
Task: "SARIF 2.1.0 emitter in internal/sarif/ (T035)"
Task: "run_manifest builder in internal/manifest/ (T036)"
Task: "membank ledger in internal/membank/ (T037)"
Task: "Lifecycle reconcile in internal/lifecycle/ (T032)"
Task: "Verification set in internal/verification/ (T033)"
```

---

## Implementation Strategy

### MVP first (US1)

1. Phase 1 Setup → 2. Phase 2 Foundational → 3. Phase 3 US1 → **STOP & VALIDATE**: differential artifact parity + fixture recall/negative-control on `testdata/vulnapp`. This is a demoable, honest CLI scanner.

### Incremental delivery

Foundation → US1 (MVP, CLI parity) → US2 (server + existing UI) → US3 (auxiliary tools) → Polish (docs, amendment, parity CI, release, retire Python). Each story adds value without breaking the previous.

### Governance gate

T068 (constitution amendment) must land before merge, since the port carries one justified Constitution deviation (runtime language) that the review gate will otherwise block.

---

## Notes

- The reference Python source (`vhlocal/`) is the parity oracle; differential tests (T016–T023, T070) pin behavior against it.
- [P] = different files, no incomplete-task dependency. `[US#]` maps to spec user stories.
- Honesty-critical tables (normalize_text, `_FAMILIES`, severity `-1` rule, `root_cause_key`, lifecycle) must be behavior-identical to Python (Principle I/II) — do not paraphrase them.
- Commit per task or logical group; verify tests fail before implementing where TDD applies.
