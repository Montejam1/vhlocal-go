# Implementation Plan: Port vhlocal to Go with interface parity

**Branch**: `002-golang-port` | **Date**: 2026-09-14 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/002-golang-port/spec.md`

## Summary

Re-implement the vhlocal vulnerability-assessment harness on the Go runtime while preserving its observable interfaces — the command surface, the HTTP/JSON API (and the existing browser UI it drives), the on-disk result artifacts and their formats, the configuration inputs, and the safety/honesty guarantees mandated by the constitution. The scanning methodology (the bundled `skill/` phase prompts) is data and is carried forward unchanged.

Technical approach: a single Go module producing one `vhlocal` binary with a subcommand per current entry point (`run`, `server`, `report`, `logs`, `sbom`, `bench`, `batch`, plus maintenance/eval commands). The engine is a library package (`internal/engine`) that both the `run` subcommand and the `server` subcommand call, so behavior cannot diverge. The bundled skill methodology and the built browser-UI assets are compiled into the binary with Go's `embed`, delivering the self-contained single-binary distribution; cross-compilation produces Linux/macOS binaries. The design leans on the Go standard library (`net/http`, `encoding/json`, `flag`, `os/exec`, `embed`, `testing`) to mirror the current project's stdlib-only minimalism, keeping third-party dependencies to a deliberately small, reviewed set.

## Technical Context

**Language/Version**: Go 1.23+ (generics-era stable toolchain; `embed`, `min`/`max` builtins, `slices`/`maps` stdlib available).

**Primary Dependencies**: Standard library first — `net/http` (server + backend clients + SSE), `encoding/json`, `flag` (subcommand + per-flag "was set" detection via `FlagSet.Visit` for the explicit>profile>default precedence), `embed` (bundle `skill/` + built UI), `os/exec` (optional `ripgrep`, `git`), `html/template`/`text/template` and manual builders (deterministic HTML/Markdown report rendering), `testing`/`net/http/httptest` (offline tests). Third-party additions, if any, are limited to build-time release tooling (e.g. a cross-compilation/release helper); a runtime third-party dependency requires explicit justification in Complexity Tracking and a constitution amendment (see Constitution Check). Decisions on CLI ergonomics (stdlib `flag` vs. a router library) and CycloneDX/SARIF emission (hand-rolled structs vs. a library) are resolved in [research.md](./research.md).

**Storage**: Filesystem only. Results directories under `~/vulnhunter-reports` (name format `<repo>_VULNHUNT_RESULTS_<model>_<timestamp>`); per-target ledgers and `applications.json` under `~/.vhlocal/ledger` (`$VHLOCAL_LEDGER_DIR`); job queue at `~/.vhlocal/jobs.json`; central log at `~/.vhlocal/vhlocal.log`; user profiles under `~/.vhlocal/profiles`. All artifacts are JSON/Markdown/HTML files matching the current schemas. No database.

**Testing**: Go `testing` (table-driven), `net/http/httptest` for the engine API, and fake in-process model transports + recorded fixtures for the backend clients — fully offline, no live model, no network, no paid services. The bundled `testdata/vulnapp` fixture (five planted bugs + one negative control) and a Go port of the scorer validate detection behavior. Target: the equivalent of today's `python3 -m unittest discover` gate, expressed as `go test ./...`.

**Target Platform**: Linux and macOS (amd64 + arm64), matching current docs; distributed as self-contained binaries via cross-compilation. Windows/other arches are non-goals for this release.

**Project Type**: CLI tool + long-lived HTTP engine serving a pre-built browser UI (single Go module, single binary, multiple subcommands). The React front end is a build-time-only asset, embedded and served unchanged.

**Performance Goals**: Parity, not speedup. Wall-clock is dominated by model inference (unchanged) and Phase 2 stays sequential this release. Non-inference work (report rendering, dedup, coverage computation, SBOM, reconciliation) should be at least as fast as today; the deterministic Phase 3d sweep stays sub-second. SSE latency and cancel-within-one-turn behavior must match.

**Constraints**: Static-only safety boundary (no shell/code-execution tool for agents; reads confined to target repo + skill + results dir; writes confined to results dir; never touch the user's working tree). No network egress beyond operator-configured inference endpoints; generated HTML reports make zero external requests. Server binds loopback by default; non-loopback requires an explicit unsafe opt-in; scan roots allow-listed; artifact reads confined to the owning results dir with traversal structurally prevented. Secrets (API keys) never written to disk, logs, or provenance. Offline-runnable test suite. Byte-compatible artifact/API field semantics (not byte-identical output — timings and model prose vary).

**Scale/Scope**: Port of ~40 Python modules (~10 CLI entry points, one HTTP engine with ~28 endpoints + SSE, ~7 phases, 3 inference backends, ~15 result-artifact types, deterministic consolidation/dedup/lifecycle/SBOM/SARIF layers). Targets range from small apps to large monorepos (thousands of source files, partitioned coverage). The front-end (React SPA + legacy HTML UIs) is reused, not ported.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

The constitution (v1.0.0) is evaluated principle by principle. **One gate fails and is escalated (Runtime constraint); all seven core principles are preserved by the port and are re-verified after design.**

| Principle | Status | How the port complies |
|---|---|---|
| I. Evidence Integrity (NON-NEGOTIABLE) | ✅ Preserved | Engine-observed facts (timings, phase status, agent counts, tokens, coverage) are written by Go engine code into `scan_meta.json`; model prose stays untrusted (`model_reported` only). Deterministic consolidation, not model judgment. Written-but-unrun exploit tests reported as not executed. Missing data labeled `unknown`/`degraded`/`not run`. FR-014, FR-021. |
| II. Orthogonal Status Reporting | ✅ Preserved | Execution / coverage / validation-mode axes emitted independently on every surface (report, API, SARIF, manifest, UI); no axis derived from another; degradation carries reasons. FR-020; verified by SC-005. |
| III. Static-Only Safety Boundary (NON-NEGOTIABLE) | ✅ Preserved | No shell/exec tool for agents; the Go tool loop offers only Read/Grep/Glob/Write, sandboxed with `filepath.Abs`+prefix containment resolved before checks; writes confined to results dir; user working tree untouched; no boundary-crossing capability added. FR-017–FR-019. |
| IV. AI Result Provenance | ✅ Preserved | Provenance (provider/backend, endpoint with secrets redacted, requested + returned model id, num_ctx/sampling/turn+token limits, tool envelope, phase/prompt identity, target git revision, per-phase attribution) captured by the engine at call time into records. Secrets never recorded. FR-022, FR-009a. |
| V. Explicit AI Failure, No Silent Fallback | ✅ Preserved | Backend failures surfaced, recorded, and reflected in status; no silent provider/endpoint/model switch; bounded same-endpoint retries + fresh-context tool-call repair recorded; paid backends never reached by fallback; failed agent ends gracefully as degraded coverage. FR-023, FR-005 edge cases. |
| VI. Resumable, Idempotent Operations | ✅ Preserved | Per-phase durable checkpoints; resume skips only present-and-valid deliverables; atomic writes (temp file + `os.Rename`); crash-interrupted jobs marked `interrupted`, never silently re-run; merges keyed by stable ids. FR-016; verified by SC-008. |
| VII. Testable Acceptance & Regression Coverage | ✅ Preserved (runner changes) | Concrete, checkable acceptance criteria (spec SC-001…SC-012); automated offline tests via fakes/fixtures; degraded paths tested; `testdata/` scoring incl. negative control. The test command changes from `python3 -m unittest` to `go test ./...` — a documented interface adjustment, not a weakening. FR-029; SC-006, SC-007. |

### Safety & Technical Constraints section

| Constraint | Status | Notes |
|---|---|---|
| **Runtime: Python 3.9+, standard library only** | ❌ **GATE FAILURE — escalated** | The feature's explicit purpose is to change the runtime to Go. This directly contradicts the "Runtime" clause. See Complexity Tracking and the amendment recommendation below. |
| Network: no egress beyond configured inference endpoints; reports make no external requests | ✅ Preserved | FR-026, SC-010. Embedded UI assets are self-contained (no CDN), preserving the offline guarantee. |
| Server posture: no auth, loopback default, non-loopback needs unsafe opt-in, allow-listed roots, confined reads | ✅ Preserved | FR-024, SC-009. |
| Untrusted inputs: normalize model text before parsing; degrade visibly; browser-served artifacts inert | ✅ Preserved | `normalize_text()` ported; parsers degrade with logged warnings; served artifacts non-executable. FR-025. |
| Determinism where possible: reports, status, dedup, ledger merges are code, not model | ✅ Preserved | FR-014. |

**Gate outcome**: The only failing gate is the Runtime language constraint, and it fails *by design* because changing the runtime is the sanctioned user request. Governance requires this be made knowingly: the plan records it in Complexity Tracking and **recommends amending the constitution's "Safety & Technical Constraints › Runtime" clause via `/speckit-constitution`** (a MINOR/MAJOR bump naming the accepted risk: loss of the "stock system Python, nothing to install" property in exchange for a self-contained binary; and defining the Go analog of "stdlib-only" as a small, reviewed dependency budget). Every other principle is upheld; proceeding to Phase 0 is safe with this deviation explicitly tracked.

### Post-Design Re-Check (after Phase 1)

Re-evaluated after `research.md`, `data-model.md`, `contracts/`, and `quickstart.md`:

- **No new gate failures introduced by the design.** The runtime deviation is unchanged; all other principles remain upheld by concrete design choices: stdlib-first zero-runtime-dep posture (R3), embedded self-contained assets preserving offline/no-egress (R5, R8), engine-authoritative records and deterministic consolidation tables reproduced exactly (data-model honesty-critical tables), `context`-based cancel and atomic-write resume (R10), and the offline `go test` gate with fakes/fixtures (R11).
- **One fidelity risk surfaced and bounded**: the Python-`ast`-based entry-point enumerator (the coverage denominator, Principle II) cannot reuse CPython's parser (R16). The design re-implements route recognition in Go and **pins it with differential tests against the current fixtures**, documenting any residual divergence as a stated limitation rather than hiding it — consistent with Principle II ("degrade visibly"). No boundary is widened.
- **Provenance/secret handling verified in the contracts**: run_manifest/attribution capture provenance; API keys are in-memory only and excluded from all artifacts, logs, and provenance (FR-009a, Principle IV).

Constitution Check re-confirmed: PASS with the single documented, justified Runtime deviation (Complexity Tracking) and the amendment action (R15). Ready for `/speckit-tasks`.

## Project Structure

### Documentation (this feature)

```text
specs/002-golang-port/
├── plan.md              # This file (/speckit-plan command output)
├── research.md          # Phase 0 output (/speckit-plan command)
├── data-model.md        # Phase 1 output (/speckit-plan command)
├── quickstart.md        # Phase 1 output (/speckit-plan command)
├── contracts/           # Phase 1 output (/speckit-plan command)
│   ├── cli.md           #   subcommand + flag contract (parity table)
│   ├── http-api.md      #   endpoint + SSE contract
│   └── artifacts.md     #   on-disk file schemas
└── tasks.md             # Phase 2 output (/speckit-tasks command - NOT created here)
```

### Source Code (repository root)

The Go implementation is added alongside the existing Python tree (which remains during migration, then is retired). The bundled `skill/`, `testdata/`, `web-react/`, and docs are reused in place; the built UI bundle is embedded from `vhlocal/web/`.

```text
go.mod                       # module: github.com/<owner>/vhlocal (or local module path)
cmd/
└── vhlocal/
    └── main.go              # subcommand dispatch → run/server/report/logs/sbom/bench/batch/...

internal/
├── cli/                     # flag sets per subcommand; explicit>profile>default precedence
│   ├── run.go  server.go  report.go  logs.go  sbom.go  bench.go  batch.go
├── engine/                  # execute_scan() pipeline as a library call (CLI + server share this)
│   ├── engine.go  select_phases.go  resume.go  coverage.go  state.go
├── phases/                  # phase specs, SKILL preamble extraction, partition parsing, normalize_text
├── agent/                   # the tool loop: one isolated agent run, context pruning, tool-call repair
├── tools/                   # Read / Grep / Glob / Write, sandboxed (path containment)
├── client/                  # inference transports
│   ├── ollama.go  openai.go  openrouter.go  provider.go  provenance.go
├── inventory/               # deterministic entry-point enumeration + coverage ledger
├── consolidate/             # deterministic findings consolidation, dedup, CWE/severity normalization
├── lifecycle/               # cross-run new/persisting/regressed/fixed reconciliation
├── report/                  # SCAN_REPORT.html + .md + findings.json rendering (deterministic)
├── sarif/                   # findings.sarif (SARIF 2.1.0)
├── sbom/                    # CycloneDX SBOM (manifest parsers per ecosystem)
├── manifest/  verification/ # run/artifact/verification manifests + records
├── membank/                 # per-target vulnerability ledger; applications registry
├── remediation/  redact/    # opt-in per-finding remediation DTOs; artifact redaction
├── profiles/                # JSON profiles, built-ins, structural-only allow-list
├── server/                  # net/http engine: REST + SSE + static UI; loopback/allow-root guards
│   ├── server.go  routes.go  sse.go  static.go  security.go
├── jobs/                    # FIFO queue, job store, persistence, cancellation
├── activity/  logsetup/     # activity feed; central logging with per-scan tagging
└── assets/                  # go:embed of skill/ methodology + built web/ UI bundle
    └── embed.go

tests/                       # Go tests mirror internal/ packages; offline fakes + fixtures
└── (per-package _test.go files preferred; cross-cutting integration tests here)

# Reused unchanged:
skill/                       # bundled methodology (data) — embedded
web-react/                   # React source; built to vhlocal/web/app (build-time), embedded
vhlocal/web/                 # built UI bundle + legacy/classic single-file HTML — embedded
testdata/                    # vulnapp fixture + ground truth + scorer (scorer ported to Go)
```

**Structure Decision**: Single Go module, single binary (`cmd/vhlocal`) with subcommands, and an `internal/` package layout that mirrors the current Python module boundaries one-to-one (engine, phases, agent, tools, client, inventory, consolidate, report, sarif, sbom, manifest, verification, membank, server, jobs, activity, logsetup, profiles, remediation, redact). This keeps the port reviewable module-by-module against its Python counterpart, preserves the "one engine implementation shared by CLI and server" invariant, and uses `go:embed` so the bundled skill and UI ship inside the binary (FR-032). The front end is not restructured.

## Complexity Tracking

> Filled because the Constitution Check has one gate failure that must be justified.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| **Runtime changed from "Python 3.9+, stdlib only" to Go** (violates Safety & Technical Constraints › Runtime) | This IS the feature. The user explicitly requested converting the project to Go; the Runtime clause cannot be satisfied while delivering the request. Go additionally enables the requested single-binary, no-prerequisite distribution and cross-platform release. | "Keep Python" rejected — it does not deliver the requested port at all. "Port but forbid all third-party Go deps to honor stdlib-only spirit" is largely adopted (stdlib-first design), but a hard zero-dependency rule may be impractical for release tooling and possibly SARIF/CycloneDX correctness; the dependency budget is therefore made explicit and small rather than absolute. Requires a constitution amendment (recommended via `/speckit-constitution`) that names the accepted risk: loss of "stock system Python, nothing to install" in exchange for a self-contained binary. |
| **Test runner changed** from `python3 -m unittest discover` to `go test ./...` (touches Principle VII's stated command) | Principle VII names a Python-specific command; the Go port must use the Go test runner. The *substance* of VII (offline, fake/fixture-driven, degraded-path coverage, `testdata/` scoring) is fully preserved. | Keeping the Python command is impossible for Go code. This is a mechanical adjustment folded into the same amendment. |
