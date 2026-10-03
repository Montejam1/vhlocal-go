---
description: "Task list for feature 012 — Multi-language scan coverage"
---

# Tasks: Multi-language scan coverage

**Input**: Design documents from `/specs/012-multilanguage-coverage/`

**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅ (R0–R10), data-model.md ✅,
contracts/recognizer.md ✅, contracts/artifacts.md ✅, quickstart.md ✅

**Tests**: INCLUDED. The spec makes per-language recognizer unit tests and per-language **end-to-end
offline scan fixtures** (vulnerable/defended/unresolved) explicit acceptance evidence (FR-016/040,
SC-001..012). All tests run offline: no live model, no network, **no target-language runtimes**, and
**`CGO_ENABLED=0`**.

**Organization**: Staged delivery (research R9). Foundational phase blocks all languages. Then Stage 1
(Python/Go/JS-TS), Stage 2 (Java/C#/Ruby/PHP), Stage 3 (Kotlin/C/C++/Rust), then surfacing + polish.
Each language is an independently testable increment (recognizer + verification adaptation + integration +
end-to-end fixture). **MVP = a complete non-Python scan-to-report flow** (Go or JS/TS, SC-005).

## Format: `[ID] [P?] [Story?] Description with file path`

- **[P]**: parallelizable (different files, no dependency on an incomplete task). Distinct language
  recognizers live in separate files (`internal/recognize/lang_*.go`) and are `[P]` once Foundational lands.
- **[Story]**: US1 census, US2 recognition, US3 staged/fixtures, US4 integration, US5 verification,
  US6 coverage, US7 disclosure.
- Backend paths under `internal/…`; fixtures under `testdata/` and `tests/parity/`.

## Path Conventions

- New package: `internal/recognize/` (interface, census, scope resolver, per-language `lang_*.go`, sinks).
- Refit/extend: `internal/inventory`, `internal/engine` (engine.go/helpers.go/hunt.go/sweep.go),
  `internal/phases/partition.go`, `internal/verification`, `internal/consolidate`, `internal/authz`,
  `internal/report`, `internal/reports`, `internal/server`, `internal/manifest`, `internal/sarif`.
- Fixtures: `testdata/<lang>app/`, `testdata/ground_truth/<name>.json`, `tests/parity/transcript/<name>.json`,
  `tests/parity/golden/<name>.json`; harness mirrors `tests/parity/full_pipeline_test.go`.
- Standing constraints: no live model, no target runtimes, no CGO, static-only (no target execution),
  additive artifacts, preserve features 008–011 + dashboards.

---

## Phase 1: Setup

- [X] T001 Baseline green + static build: `export PATH=$PATH:/usr/local/go/bin && CGO_ENABLED=0 go build ./... && go test ./... -count=1 && go vet ./...` (record pre-change state; the binary must build with CGO off — research R1).
- [X] T002 Create the `internal/recognize` package skeleton (`internal/recognize/recognize.go`): package doc stating static-only/offline/stdlib-first/no-CGO, and empty files `census.go`, `scope.go`, `sinks.go`, `matrix.go`, plus `lang_*.go` stubs for the 12 languages. No behavior yet; `go build` stays green.
- [ ] T003 Add a per-language fixture harness helper in `tests/parity/multilang_test.go` (or extend `full_pipeline_test.go` helpers) that, given `<name>`, runs `engine.Execute` over `testdata/<name>/` with a transcript provider and `Project`/`Compare` against `tests/parity/golden/<name>.json` — the reusable driver every language fixture will call (mirrors `TestFullPipelineArtifactsAndDeterministicPhases`).

---

## Phase 2: Foundational (blocking prerequisites — MUST complete before any language)

**⚠️ CRITICAL**: These are the cross-language foundations; no language recognizer can be integrated until they land.

- [X] T004 [P] Define the language-agnostic model in `internal/recognize/recognize.go`: `InvestigationUnit` (id, language, framework, module, application_type, surface_kind, location, handler_ref, surface_attrs, certainty ∈ {resolved,partial,unresolved}, inputs, sensitive_ops, evidence), `ExternalInput`, `SensitiveOp`, `Limitation`, `Module`, `SourceFile`, and the `Recognizer` interface (`Recognize`, `Language`, `AppTypes`, `Mechanism`) + a registry with deterministic dispatch (data-model; contracts C-R1/C-R3/C-U2).
- [X] T005 [P] Implement the whole-repo census in `internal/recognize/census.go`: enumerate first-party source by language/module/application-type with recorded exclusions (production/test/generated/dependency/unreadable/unsupported), consistent across census/discovery/assignment/coverage; excluded deps/generated never counted as reviewed; path/symlink confinement preserved (US1; FR-007/008/010; contracts C-U6).
- [X] T006 [P] Implement `EnclosingScope(language, source, line)` in `internal/recognize/scope.go`: Go via stdlib `go/ast`; brace-based scanner for JS/TS/Java/Kotlin/C#/C/C++/Rust/PHP; indentation for Python; def/end for Ruby. Returns containing function/method span + owner chain (US5; FR-028; contract C-S1).
- [ ] T007 [P] Create the per-language registry scaffolding in `internal/recognize/sinks.go`: CWE→sink tables, auth-idiom tables, and test-assertion forms keyed by language, seeded with the existing Python tables migrated verbatim from `internal/consolidate/corroborate.go` and `internal/authz/authz.go` (regression-preserving); expose lookups the verification layer will call (US5; FR-013/025; contract C-S3).
- [ ] T008 Refit `internal/inventory/inventory.go` to consume `internal/recognize`: `Route`/`LedgerEntry`/`CoverageLedger` gain `language`, `application_type`, `surface_kind`; keep emitting `coverage_ledger.json` for parity. Preserve Python route recognition via the Python recognizer (US7 compat; FR-034; contract C-A1).
- [ ] T009 Replace mention-based disposition with evidence-backed per-unit review: in `internal/inventory` (`disposition`/`BuildLedger`) and `internal/phases/partition.go` (`AugmentForCoverage`), require a `UnitReviewRecord` whose source refs resolve to the run for `reviewed_*`; a filename/identifier mention or a finding elsewhere in the file MUST NOT mark a sibling reviewed; validate referenced IDs belong to the run (US6; FR-025/026; contract C-C1; SC-006).
- [ ] T010 Implement the four distinct coverage axes in `internal/consolidate/status.go` + `internal/consolidate/consolidate.go`: census / inventory-support / assignment / review, each with explicit denominators/labels per language & application type; never blend differing unit kinds into one percentage; add language-scoped `coverage_degraded_reasons` and a `StatusInput` "languages unenumerated/unsupported" signal; keep execution/coverage/validation independent (US6; FR-020/024/027; contract C-C2; SC-007).
- [X] T011 Generalize source-size/degradation in `internal/engine/helpers.go` (`countPySource` → language-aware census counts) and `internal/engine/engine.go` (thresholds keyed off total recognized source, not `.py`) (US6; FR-024).
- [ ] T012 Feed discovered scope into hunt work in `internal/engine/engine.go` + `internal/engine/hunt.go` + `internal/phases/partition.go`: pass recognized units (language/framework/app-type/source context) into partition planning and `buildHuntTask` inputs; derive module/subsystem assignments from discovered non-Python scope when recon is missing/malformed; never collapse a mixed-language repo into one unqualified whole-repo assignment; expose effective work limits + assignment counts; preserve unassigned/unfinished scope with reasons (US4; FR-015/016/019/020/023; contract C-C3).
- [ ] T013 Ungate verification from Python in `internal/verification/verification.go` + `authz.go` + `artifacts.go`: `requireFunctionEvidence`, candidate-identity owner chain, `routeGuardFor` span, and PoC-assertion detection use `recognize.EnclosingScope` + `recognize` sink/auth/assertion tables for ALL languages; make `fileAndLine` tolerant of columns/drive letters; a class/construct with no applicable checker → **unresolved** (never refutation); preserve exact quotation/identity and supported/rejected/unresolved (US5; FR-026/027/028/029/030; contracts C-S2/C-S3).
- [ ] T014 Point `internal/consolidate/corroborate.go` and `internal/engine/sweep.go` at the `internal/recognize` sink registry (per-language patterns; Python behavior unchanged); sweep pairs its existing multi-language ext filter with per-language sinks (US5; FR-025; contract C-S3).

**Checkpoint**: language-agnostic model + census + scope + evidence-backed coverage + integration seams ready; Python still passes its existing tests.

---

## Phase 3: Stage 1 — Python (preserve) + Go + JavaScript/TypeScript (Priority: P1) 🎯 MVP

**Goal**: Python regression-preserved; Go and JS/TS fully recognized across their dedicated app types, integrated, verified, and each proven by an end-to-end offline fixture.

**Independent Test**: Each Stage-1 language passes its recognizer unit tests + an end-to-end scripted scan (vulnerable/defended/unresolved) reaching a published report; Python’s existing suite stays green; a non-Python repo does not use a Python-empty denominator.

- [ ] T015 [P] [US2] `internal/recognize/lang_python.go` + `lang_python_test.go`: house the Python recognizer (FastAPI/Flask/Django + argparse/click + Celery) behind the interface, migrated from `internal/inventory` regexes; assert existing Python route recognition is unchanged (regression) (FR-007).
- [X] T016 [P] [US2] `internal/recognize/lang_go.go` + `lang_go_test.go`: Go recognizer using stdlib `go/parser`/`go/ast` — `net/http`+ServeMux, Chi, Gin (web); `flag`/`main`, Cobra (cli); gRPC/`net/rpc` (rpc); with external inputs + sensitive ops (os/exec, database/sql, text/template, path/filepath). Authored expected inventory + negative controls (fake routes in strings, dead code) (FR-008/010/011/013; contracts C-U1..C-U5; SC-003/004).
- [ ] T017 [P] [US2] `internal/recognize/lang_js_ts.go` + `lang_js_ts_test.go`: JS/TS recognizer via a bounded structure-aware lexer — Express/Fastify/Koa/Next.js API (Pages+App Router, distinguish server API from browser pages)/Nest (web); Commander/yargs (cli); DOM sinks (browser); with inputs + sensitive ops (child_process, eval, SQL, fs, innerHTML). Authored expected inventory + negative controls; document recognized layouts/extensions/method-exports/dynamic segments (FR-009/011/013; contracts C-U1..C-U5; SC-003/004).
- [ ] T018 [US5] Add Go and JS/TS sink/auth/assertion tables to `internal/recognize/sinks.go` (+ tests) and confirm `internal/verification` produces supported/rejected/unresolved for Go and JS/TS candidates with real handler+guards via `EnclosingScope` (FR-025/026/027/030; contracts C-S2/C-S3).
- [X] T019 [US3] Go end-to-end fixture: `testdata/goapp/` (net/http or Gin app) + `testdata/ground_truth/goapp.json` + `tests/parity/transcript/goapp.json` + `tests/parity/golden/goapp.json` with a vulnerable (supported), a defended (rejected, real defense), and an unresolved example; wire into the T003 harness (FR-016; contract C-A11; SC-001/005). **This is the MVP proof.**
- [ ] T020 [US3] JS/TS end-to-end fixture: `testdata/jsapp/` (Express or Next.js API) + ground_truth + transcript + golden with vulnerable/defended/unresolved; wire into the harness (FR-016; contract C-A11; SC-001/005).
- [ ] T021 [US1] Census/app-type coverage for Stage 1 in `internal/recognize/census.go` (+ tests): confirm Go/JS-TS non-web app types (CLI, library/parser fallback, worker) are recognized or given scoped fallback with disclosed limits — coverage never derived solely from HTTP routes (FR-005/006; SC-002/006).

**Checkpoint (MVP)**: a complete non-Python (Go and JS/TS) scan-to-report flow works offline; Python unchanged.

---

## Phase 4: Stage 2 — Java, C#, Ruby, PHP (Priority: P2)

**Goal**: Common server/web + CLI + worker app types for Stage-2 languages, each recognizer + verification + end-to-end fixture.

**Independent Test**: Each Stage-2 language passes recognizer unit tests + its end-to-end fixture (vulnerable/defended/unresolved) to a published report; support-matrix cell backed by the passing fixture.

- [ ] T022 [P] [US2] `internal/recognize/lang_java_kotlin.go` + test (Java portion): Spring MVC/`@RestController`/JAX-RS/Servlets (web), picocli/`main` (cli), JMS listeners (consumer), gRPC (rpc); inputs + sensitive ops (Runtime.exec/ProcessBuilder, JDBC, ObjectInputStream, XML/XXE, reflection) (FR-008/010/011/013).
- [ ] T023 [P] [US2] `internal/recognize/lang_csharp.go` + test: ASP.NET Core controllers/minimal APIs/MVC (web), System.CommandLine/`Main` (cli), BackgroundService (worker); inputs + sensitive ops (Process.Start, SqlCommand, BinaryFormatter, XML/XXE, reflection) (FR-008/010/011/013).
- [ ] T024 [P] [US2] `internal/recognize/lang_ruby.go` + test: Rails routes/controllers/Sinatra (web), OptionParser/Thor (cli), Sidekiq (worker); inputs + sensitive ops (system/backticks/eval, ActiveRecord/SQL, YAML.load/Marshal, send, File) (FR-008/010/011/013).
- [ ] T025 [P] [US2] `internal/recognize/lang_php.go` + test: Laravel/Symfony/superglobals (web), argv (cli); inputs + sensitive ops (system/exec/shell_exec, eval, mysqli/PDO, unserialize, include/require, file ops) (FR-008/010/011/013).
- [ ] T026 [US5] Add Java/C#/Ruby/PHP sink/auth/assertion tables to `internal/recognize/sinks.go` (+ tests) and confirm verification supported/rejected/unresolved with real handler+guards for each (FR-025/026/027/030; contracts C-S2/C-S3).
- [ ] T027 [US3] End-to-end fixtures for Java, C#, Ruby, PHP: `testdata/{javaapp,csharpapp,rubyapp,phpapp}/` + ground_truth + transcript + golden, each with vulnerable/defended/unresolved; wire into the harness (FR-016; contract C-A11; SC-001).

**Checkpoint**: Stage-2 languages deliver full non-Python scan-to-report; Stage 1 unaffected.

---

## Phase 5: Stage 3 — Kotlin, C, C++, Rust (Priority: P3)

**Goal**: JVM/systems + CLI/parser/library app types for Stage-3 languages, each recognizer + verification + end-to-end fixture.

**Independent Test**: Each Stage-3 language passes recognizer unit tests + its end-to-end fixture; support-matrix cell backed by the passing fixture; C/C++/Rust library/parser/CLI repos are not "0% covered" for lacking routes.

- [ ] T028 [P] [US2] Kotlin recognizer in `internal/recognize/lang_java_kotlin.go` (Kotlin portion) + test: Spring/Ktor routing (web), `main`/args (cli); inputs + sensitive ops (ProcessBuilder, JDBC/Exposed, deserialization, reflection) (FR-008/010/011/013).
- [ ] T029 [P] [US2] `internal/recognize/lang_c_cpp.go` + test: C/C++ CLI/parser/file-processor/library — `main(argc,argv)`, stdio/file/socket inputs; sensitive ops (system/exec*, unsafe string/buffer ops, format strings, malloc/free, path handling) (FR-005/008/010/013; SC-002/006).
- [ ] T030 [P] [US2] `internal/recognize/lang_rust.go` + test: Actix/Axum/Rocket (web), clap (cli), library/parser fallback; inputs + sensitive ops (std::process::Command, unsafe blocks, sqlx/diesel, serde) (FR-008/010/011/013).
- [ ] T031 [US5] Add Kotlin/C/C++/Rust sink/auth/assertion tables to `internal/recognize/sinks.go` (+ tests) and confirm verification supported/rejected/unresolved (memory-safety classes for C/C++; unsafe for Rust) with real scope; checker-absence → unresolved (FR-025/027/030; contracts C-S2/C-S3).
- [ ] T032 [US3] End-to-end fixtures for Kotlin, C, C++, Rust: `testdata/{kotlinapp,capp,cppapp,rustapp}/` + ground_truth + transcript + golden, each with vulnerable/defended/unresolved (for C/C++ include a non-web CLI/parser target); wire into the harness (FR-016; contract C-A11; SC-001/002).

**Checkpoint**: all 12 baseline languages pass recognizer + end-to-end fixtures.

---

## Phase 6: Disclosure, support matrix & compatibility (US7, Priority: P1)

- [ ] T033 [US7] Emit `support_matrix.json` from `internal/recognize/matrix.go` (+ test): per (language, application-type) readability / deterministic recognition (dedicated|limited|unsupported) / verification checks / fallback review / known unsupported constructs / recognizer mechanism (stdlib|lexer|dependency:<name@version>) / acceptance status; a cell is "supported" only when its end-to-end fixture passes (FR-017/018; contract C-A4; SC-008).
- [ ] T034 [US7] Additive fields in `internal/consolidate/consolidate.go` (`Doc.ApplicationIntelligence` gains inventory+support_matrix+coverage_axes) and `internal/engine/record.go` (`RunRecord` gains languages_detected/enumerated/inventory_engine); populated in `internal/engine/engine.go` finalize (contracts C-A2/C-A3; FR-032).
- [ ] T035 [P] [US7] Render additive report section + Nav entry in `internal/report/report.go` (support matrix + multi-axis coverage; per-finding language/framework/module) and add `support_matrix.json` to `internal/reports/manifest.go` (contract C-A5; FR-029/030).
- [ ] T036 [P] [US7] Carry language-scoped coverage/degraded reasons in `internal/sarif/sarif.go` and `internal/manifest/manifest.go` (update `configHash` only if a new config key is added) (contract C-A7; FR-029/032).
- [ ] T037 [US7] Extend the API projection: `internal/server/status.go` `scanStatus` re-exposes coverage axes + support-matrix summary; `internal/reports/reports.go` `Report`/`Load` carry a languages/coverage summary — existing dashboard values/charts unchanged and additive-only (contract C-A6; FR-030/033; SC-010).
- [ ] T038 [US7] Wire the deterministic multi-language inventory into recon/hunt task inputs and reconcile `skill/phases/phase1_recon.md` so the model hunts the discovered denominator (not only Glob re-discovery) (contract C-A10; FR-015/016).
- [ ] T039 [US7] Legacy/compat handling: older reports lacking new evidence read as unknown/legacy (never retroactively complete); resume/regeneration must not accept stale inventory or invent review evidence or silently launch a scan; extend `tests/parity/reference/contracts.json` + `schema_test.go` + `reference_contract_test.go` for the new additive fields and keep them green (contracts C-A8/C-A9; FR-031/032/034/035; SC-009/010).

---

## Phase 7: Polish & Cross-Cutting Concerns

- [ ] T040 Determinism, failure & resume tests (offline) in `internal/recognize/determinism_test.go` and `internal/engine/multilang_resume_test.go`: repeated inventory over unchanged input → identical IDs/ordering/counts; malformed recon/parser failure/exhausted limits/interrupted scan preserve completed evidence + expose remaining work; resume neither duplicates work nor accepts stale discovery (FR-014/022/035; SC-008/009).
- [ ] T041 Static-only assertions (offline) in `internal/recognize/static_only_test.go`: confirm recognition performs no exec/process/network and requires no target-language runtime, and does not escape source boundaries or modify the target (FR-034/037/038; SC-011; contract C-R2).
- [ ] T042 No-regression check for features 008–011 via `internal/server/preservation012_test.go` (and keeping `tests/parity/*` green): existing dashboard metrics, application/ledger management, analyst review decisions, reports, and history open/behave unchanged (FR-036; SC-010).
- [ ] T043 Full offline gate: `export PATH=$PATH:/usr/local/go/bin && CGO_ENABLED=0 go build ./... && go test ./... -count=1 && go vet ./... && gofmt -l internal cmd` — all green with CGO off (SC-011).
- [ ] T044 [P] Publish the support matrix + update scan configuration/help and user docs under `docs/` and the served Docs view (FR-036).
- [ ] T045 [P] Update `CHANGELOG.md` with the feature-012 entry (12-language recognition beyond HTTP; evidence-backed coverage; staged delivery; additive surfacing; no execution/runtimes; no CGO).
- [ ] T046 Document the **scripted vs empirical** distinction + bounded empirical evaluation and the completion matrix in `docs/engineering/2026-09-26-multilanguage-coverage-evaluation.md` (results + limitations, reported separately, no unsolicited paid/long model scan; delivered/tested/remaining) (FR-040; SC-012).

---

## Dependencies & Execution Order

### Phase dependencies
- **Setup (P1)** → **Foundational (P2)** blocks all languages.
- **Stage 1 (P3)** depends on Foundational; is the **MVP** (Go/JS-TS e2e). **Stage 2 (P4)** and **Stage 3 (P5)** depend on Foundational (and reuse Stage-1 patterns) but are independent of each other per language.
- **Disclosure (P6)** depends on the coverage/support data produced by the language stages (can begin against Stage 1 and extend as languages land).
- **Polish (P7)** after the stages + disclosure.

### Within a language
recognizer (+census/unit tests) → sink/auth tables + verification adaptation → integration/coverage → end-to-end fixture. Each language is independently testable.

### Parallel opportunities
- Distinct `internal/recognize/lang_*.go` recognizers + their tests are `[P]` once Foundational (T004–T014) lands (different files). Fixtures in different `testdata/<name>/` dirs are `[P]`.
- Shared-file tasks are sequential: `internal/recognize/sinks.go` (T007/T018/T026/T031), `internal/verification/*` (T013 then per-stage confirmation), `internal/engine/*` and `internal/consolidate/*` (T008–T014), and the disclosure edits to shared report/consolidate/server files (T033–T039).
- Go gate tasks (T001, T043) are independent of edits.

---

## Implementation Strategy

### MVP first (Stage 1, a non-Python language)
1. Setup + Foundational (T001–T014).
2. Stage 1: Python regression (T015) + **Go recognizer + verification + end-to-end fixture (T016, T018, T019)** — the MVP proof (SC-005) — then JS/TS (T017, T020) and Stage-1 census (T021).
3. **STOP and VALIDATE**: the Go (and JS/TS) offline scan-to-report fixture passes end to end; Python unchanged.

### Incremental delivery
Stage 2 (Java/C#/Ruby/PHP) → Stage 3 (Kotlin/C/C++/Rust), each language shipping with its recognizer + verification + fixture + support-matrix cell → Disclosure (support matrix, additive surfacing, prompt/denominator reconciliation, compat) → Polish (determinism/failure/resume, static-only, no-regression, docs, completion matrix). The feature is complete only when **all 12** languages pass their acceptance (SC-008).

---

## Notes
- Every "supported" support-matrix cell MUST be backed by a passing end-to-end fixture (no listing-as-support).
- Recognition is stdlib-first, no CGO, no new runtime dependency by default; any per-language runtime parser dependency is a listed/justified budget item (material expansion → constitution amendment) — do not add one without recording it (research R1).
- Evidence-backed review replaces mention-based disposition; never mark a sibling unit reviewed from a mention or a finding elsewhere in the file.
- Static-only throughout: no target execution/import, no target runtimes, path/symlink confinement; no live model, no network; scan evidence and features 008–011 preserved; new data additive.
- Commit per language/stage; validate each language independently before moving on.

---

## Convergence Tasks (post-implement audit — 2026-09-26)

Added after a convergence audit of the shipped code against the spec. These do **not** replace the
existing unfinished tasks (T007–T046); they sequence and harden the path to real convergence and flag
the honesty gaps that shipped in the first increment. Scaffolding, a registered language, or a passing
build is NOT completion — a language is "supported" only when its end-to-end offline fixture passes
(FR-016/018, SC-001/008).

- [ ] T047 Wire `internal/recognize` into the live scan path (subsumes/depends on T008, T011, T012): `internal/recognize` is currently imported nowhere outside its own package, and `internal/inventory/inventory.go:104` + `internal/engine/helpers.go:366` are still `.py`-only. Replace the Python-only enumerator/denominator so recognized multi-language units drive partitions/hunt/coverage (FR-015/016/019/020; contract C-C3).
- [X] T048 **[honesty gap — shipped]** Replace the still-live mention-based disposition in `internal/inventory/inventory.go:266` (`disposition()` returns `reviewed_no_issue` on a substring `strings.Contains(analyzedText, r.File)`) with the evidence-backed per-unit review of T009: a `reviewed_*` disposition requires a `UnitReviewRecord` whose source refs resolve; a mention or a finding elsewhere in the file MUST NOT mark a sibling reviewed (FR-025/026; contract C-C1; SC-006).
- [ ] T049 **[QUEUED 2026-09-28 — deferred; not started]** **[honesty gap — shipped]** Ungate verification from Python (completes T013): `internal/verification/verification.go:113` and `:471`, and `internal/verification/artifacts.go:119` and `:206`, still branch on `strings.HasSuffix(..., ".py")`, so non-Python candidates get no containing-function evidence requirement. Route these through `recognize.EnclosingScope` + per-language tables for all languages; a checker-absent class → unresolved, never refutation (FR-026/027/028/030; contracts C-S2/C-S3).
- [ ] T050 **[QUEUED 2026-09-28 — deferred; not started]** Implement the Go recognizer's declared-but-missing sensitive-operation detection in `internal/recognize/lang_go.go`: the package/doc comment claims "representative sensitive operations (command execution)" and the model has `SensitiveOps`, but no unit populates it today (only web routes + Cobra + request inputs). Detect os/exec, database/sql, path/filepath, text/template sinks with source context; add tests (FR-013; contract C-U4).
- [ ] T051 Migrate Python route recognition into `internal/recognize/lang_python.go` behind the `Recognizer` interface and make it the live path (completes T015), asserting regression parity with the existing `internal/inventory` FastAPI/Flask behavior (FR-007).
- [X] T052 Add the Go end-to-end offline fixture (completes T019) — the MVP proof: `testdata/goapp/` + `testdata/ground_truth/goapp.json` + `tests/parity/transcript/goapp.json` + `tests/parity/golden/goapp.json` with a supported, a rejected (real defense), and an unresolved candidate flowing through `engine.Execute` to a published report (FR-016; contract C-A11; SC-001/005). Until this passes, Go is NOT "supported".
- [ ] T053 Support-matrix truthfulness gate in `internal/recognize/matrix.go` (+ test) (completes/guards T033/T018): assert no (language, application-type) cell is marked supported/dedicated unless a passing end-to-end fixture exists for it; a registered recognizer alone MUST NOT read as supported (FR-017/018; SC-008).
- [ ] T054 Complete the remaining baseline languages to real support (tracks existing T017/T020, T022–T032): JavaScript/TypeScript (Stage 1), then Java/C#/Ruby/PHP (Stage 2), then Kotlin/C/C++/Rust (Stage 3) — each with recognizer + verification adaptation + end-to-end fixture + a support-matrix cell backed by a passing fixture. The feature is complete only when all 12 pass (FR-001/015/016; SC-001/002/008).
