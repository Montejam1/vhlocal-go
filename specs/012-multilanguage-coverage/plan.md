# Implementation Plan: Multi-language scan coverage

**Branch**: `012-multilanguage-coverage` | **Date**: 2026-09-26 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/012-multilanguage-coverage/spec.md`

## Summary

Make a 12-language baseline (Python, Go, JavaScript, TypeScript, Java, Kotlin, C#, C, C++, Rust, Ruby,
PHP) first-class for source-code vulnerability analysis, across eight application types (web, CLI,
library, parser/file processor, background worker, message consumer, RPC service, browser-side code),
with per-language deterministic recognition of investigation units + external inputs + security-sensitive
operations, real integration into hunt/verification/reporting, honest multi-axis coverage, a published
support matrix, and a per-language end-to-end offline fixture — while preserving Python, existing
history, dashboard metrics, and features 008–011.

**Current state (from a full inventory this planning pass):** the deterministic recognizer that owns the
coverage denominator is **Python-only and HTTP-route-centric** — `internal/inventory/inventory.go`
enumerates `.py` files for FastAPI/Flask decorators into an HTTP `Route`/`CoverageLedger`, and its
"reviewed" disposition is **mention-based substring containment** (`disposition()` /
`phases.AugmentForCoverage`), which is exactly the false-completion the spec forbids. Downstream,
`engine.countPySource` (`.py`) drives degradation thresholds; `verification.functionSpans`/
`requireFunctionEvidence` are Python `def`/indentation and **gated to `.py`** (so non-Python candidates
get *no* function-coverage requirement today); `consolidate/corroborate.go`'s entire CWE→sink table +
veto battery + `corsDanger` are Python/Flask/FastAPI/Django idioms; `authz/authz.go`'s auth regex is
Python/Flask; `engine/sweep.go` already filters by a multi-language extension map but sweeps Python-only
patterns. The recon **prompts are already multi-language** (`skill/phases/phase1_recon.md` globs many
languages), so the core mismatch is prompt breadth vs. a Python-only deterministic denominator.

**Central architecture decisions (detailed in research.md):**
1. Introduce a **language-agnostic investigation-unit model** (surface kinds beyond HTTP routes) and a
   pluggable **`Recognizer` interface** with one implementation per (language, application-type),
   replacing the HTTP-`Route`-only core while keeping `coverage_ledger.json` emitted for compatibility.
2. **Stdlib-first recognition within the zero-baseline dependency budget**: Go via the standard library
   `go/parser`/`go/ast` (zero-dep, real AST); Python keeps/refines its existing recognizer (regression);
   other languages via bounded, structure-aware lexers. **No CGO** (preserve `CGO_ENABLED=0` static
   binary), so tree-sitter/CGO grammars are rejected as the default; any per-language runtime parser
   dependency is a **separately justified, listed budget item**, and a material expansion triggers a
   constitution amendment (a hard gate in the plan).
3. Replace **mention-based disposition** with **evidence-backed per-unit review** (a unit is "reviewed"
   only with a unit-specific analysis record whose source references resolve) — the honesty core.
4. Add a **per-language enclosing-scope resolver** (Go: go/ast; brace-based for C-family/JS/TS/Java/
   Kotlin/C#/Rust/PHP; indentation for Python; block heuristics for Ruby) and **per-language sink/auth/
   assertion tables**, ungating verification from `.py`.
5. **Feed the deterministic inventory into hunt tasks** and coverage; surface inventory/coverage/support
   matrix **additively** in findings.json, scan_meta, reports, exports, and the API projection; label
   legacy data unknown/legacy.
6. **Deliver in stages**, each language proven by an offline end-to-end fixture (transcript + golden),
   reusing the existing `tests/parity` full-pipeline harness.

## Technical Context

**Language/Version**: Go 1.23+ (module `vhlocal`), single self-contained binary, `CGO_ENABLED=0`.
Front-end surfaces (served `index.html`, React `web-react`) are touched only for additive disclosure.

**Primary Dependencies**: Standard library first (`go/parser`, `go/ast`, `go/token` for Go recognition;
`regexp`, `bufio`, hand-written lexers for others). **Baseline: zero new third-party runtime
dependencies.** Any per-language parser/grammar dependency must be individually justified and listed in
research (R1); the default plan adds **none**. Build/release tooling is out of the runtime budget.

**Storage**: Files only. New evidence is **additive** to existing artifacts: `coverage_ledger.json`
(extended with language/app-type + per-unit evidence-backed disposition), `findings.json`
(`application_intelligence` gains an inventory/support-matrix block; `run_status` gains language-scoped
degraded reasons), `scan_meta.json` (`RunRecord` additive language/inventory fields), plus a new
`support_matrix.json` artifact. No schema-version field exists; compatibility is additive-only + graceful
read + parity contracts (see research R7).

**Testing**: Offline Go suite (`go test ./...`, `go vet`, `gofmt`) as the gate. Per-language recognizer
unit tests against authored fixtures; per-language **end-to-end** scan-to-report tests via the existing
`tests/parity` transcript+golden harness (`engine.Execute` + transcript/fake providers, `Project`/
`Compare`). No live inference, no network, **no target-language runtimes**, no CGO. A separate bounded
**empirical** evaluation on real repos is documented (not run in CI) and kept distinct from scripted
validation.

**Target Platform**: loopback single-binary server + CLI; browser UI for additive disclosure.

**Project Type**: static-analysis engine (Go) with web/CLI surfaces; backend-heavy feature.

**Performance Goals**: Deterministic recognition over a repository stays practical (seconds to low
minutes for large repos); recognition is single-pass per file, streaming, and bounded. Determinism is a
hard requirement (same input → identical IDs/ordering/counts).

**Constraints**: Static-only — **never execute/import target code, install deps, start services, or run
build scripts, and never require the target's language toolchains/runtimes** to discover source/units
(FR-037). Path/symlink confinement preserved. Zero-baseline dependency budget (any addition justified +
listed; material expansion → amendment). Evidence integrity — no mention-based "reviewed", no accepting
candidates to raise numbers, no checker-absence-as-refutation, exact quotation preserved. Preserve
features 008–011, dashboard metrics/charts, history; additive surfacing, no broad UI redesign; legacy
data labeled unknown/legacy.

**Scale/Scope**: 12 languages × up to 8 application types, delivered in 3 stages; ~one recognizer set +
one end-to-end fixture per language; touches inventory/engine/phases/verification/consolidate/authz/
report/server + prompts + fixtures (blast radius enumerated in research R0).

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after Phase 1. Constitution v1.1.0.*

- **I. Evidence Integrity** — Strongly advanced: replaces mention-based disposition with evidence-backed
  per-unit review (FR-025/026), forbids checker-absence-as-refutation and coverage-inflating acceptance
  (FR-030/031), preserves exact quotation/identity, and keeps unknown/legacy honest. PASS.
- **II. Orthogonal Status Reporting** — Execution/coverage/validation stay independent; multi-axis
  coverage (census/inventory-support/assignment/review) and language-scoped degraded reasons are added
  without collapsing axes (FR-024/027). PASS.
- **III. Static-Only Safety Boundary (NON-NEGOTIABLE)** — Recognition is pure static read; no target
  execution/import, no target runtimes, path/symlink confinement preserved (FR-037/038). **No CGO** keeps
  the static posture. PASS.
- **IV. Provenance / V. Explicit Failure** — Discovery provenance persisted; parser/recognition failures
  are explicit and per-file (a bad file never fails the scan), not silent (FR-009/014). PASS.
- **VI. Resumable/Idempotent** — Recognition is deterministic (identical IDs/ordering/counts on
  unchanged input); resume/regeneration must not accept stale inventory or invent evidence
  (FR-035, SC-009). PASS.
- **VII. Testable offline** — Per-language recognizer + end-to-end fixtures run offline with no live
  model/network/target runtime; scripted validation kept distinct from empirical accuracy (FR-040,
  SC-011/012). PASS.
- **Safety & Technical Constraints — Runtime / dependency budget** — This is the **gating** clause.
  Baseline zero third-party runtime deps; the plan defaults to **stdlib-only** recognition (go/parser for
  Go; hand-written lexers/regex for others) and adds no runtime dependency. Should any language require a
  runtime parser dependency to meet its fixture accuracy, it MUST be individually justified and listed,
  and a **material** expansion of the budget requires a constitution amendment before that language is
  delivered. Recognizers are self-contained/offline; no CDN/egress. **PASS given the stdlib-first
  default; per-language dependency additions are gated (research R1).**

**Gate result: PASS** (with the dependency-budget gate recorded). No unjustified violations →
Complexity Tracking omitted. Re-check after Phase 1: still PASS (design keeps recognition stdlib-first,
static-only, additive, and evidence-backed).

## Project Structure

### Documentation (this feature)

```text
specs/012-multilanguage-coverage/
├── plan.md          # this file
├── research.md      # Phase 0 (R0 blast radius; R1 dependency budget/parser; R2..R10)
├── data-model.md    # Phase 1 (investigation-unit + coverage + support-matrix + compat)
├── quickstart.md    # Phase 1 (offline gate + per-language fixture pattern + staged validation)
├── contracts/       # Phase 1 (recognizer interface + artifact/JSON contracts)
└── tasks.md         # /speckit-tasks (not created here)
```

### Source Code (repository root)

```text
internal/
├── recognize/               # NEW: language-agnostic recognition
│   ├── recognize.go         #   Recognizer interface, Unit/Input/SensitiveOp model, registry, dispatch
│   ├── census.go            #   whole-repo source/module/app-type census + exclusions (reasons)
│   ├── scope.go             #   per-language EnclosingScope resolver (Go: go/ast; brace; indentation)
│   ├── lang_go.go           #   Go recognizer (stdlib go/parser): net/http+ServeMux, Chi, Gin, flag/Cobra, gRPC
│   ├── lang_python.go       #   Python recognizer (refit of internal/inventory regexes; FastAPI/Flask/Django/argparse/Celery)
│   ├── lang_js_ts.go        #   JS/TS recognizer (bounded lexer): Express/Fastify/Koa/Next.js API/Nest, Commander, DOM sinks
│   ├── lang_java_kotlin.go  #   Java/Kotlin (Spring/JAX-RS/Servlet/Ktor, picocli, JMS)
│   ├── lang_csharp.go       #   C# (ASP.NET Core/MVC, System.CommandLine, BackgroundService)
│   ├── lang_c_cpp.go        #   C/C++ (main/argv, stdio/socket, unsafe ops)
│   ├── lang_rust.go         #   Rust (Actix/Axum/Rocket, clap, unsafe)
│   ├── lang_ruby.go         #   Ruby (Rails/Sinatra, OptionParser/Thor, Sidekiq)
│   ├── lang_php.go          #   PHP (Laravel/Symfony/superglobals)
│   ├── sinks.go             #   per-language CWE→sink + auth + assertion tables (generalizes corroborate)
│   └── matrix.go            #   support-matrix assembly (dedicated/limited/unsupported per lang×app-type)
├── inventory/               # EXTEND: Route→Unit compatibility; CoverageLedger gains language/app-type +
│                            #         EVIDENCE-BACKED disposition (replaces substring containment)
├── engine/                  # EXTEND: engine.go wires recognize.* (not .py-only); helpers.go countPySource
│                            #         → language-aware census; hunt.go feeds units into tasks; degradation
│                            #         thresholds generalized; sweep.go pairs multi-lang filter with per-lang sinks
├── phases/partition.go      # EXTEND: assignment from units (not substring containment); app-type aware
├── verification/            # EXTEND: ungate .py; per-language scope via recognize.scope; per-language
│                            #         sink/auth via recognize.sinks; robust fileAndLine; identity owners
├── consolidate/             # EXTEND: corroborate.go delegates to recognize.sinks; status.go coverage axes
├── authz/                   # EXTEND: per-language/per-handler auth via recognize
├── report/, reports/, server/, manifest/, sarif/  # EXTEND: additive inventory/coverage/support-matrix surfacing
└── ...

skill/phases/phase1_recon.md # EXTEND: wire the deterministic multi-language inventory into tasks (reconcile with prompts)

testdata/<lang>app/          # NEW per language: fixture repo + testdata/ground_truth/<name>.json
tests/parity/                # NEW per language: transcript/<name>.json + golden/<name>.json; extend contracts/schema tests
```

**Structure Decision**: A new `internal/recognize` package owns the language-agnostic model, the
`Recognizer` registry, the enclosing-scope resolver, and the per-language sink/auth tables; the existing
`internal/inventory` is refit to consume it and keep emitting a (now language-tagged, evidence-backed)
`coverage_ledger.json` for compatibility. Verification/consolidate/authz delegate their language-specific
pieces to `internal/recognize` instead of hardcoding Python. Surfacing is additive across the existing
report/export/API types. This isolates the multi-language logic, keeps recognition stdlib-first and
static, and lets each language ship + be tested independently behind its recognizer + fixture.

## Complexity Tracking

No constitution violations to justify. The one gated item — a per-language runtime parser dependency —
is deferred to research R1 with explicit criteria; the default design adds none, so no Complexity
Tracking row is required now. If a specific language later needs a runtime dependency, it will be added
here with its justification and the amendment status.
