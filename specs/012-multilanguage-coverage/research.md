# Phase 0 Research: Multi-language scan coverage

Grounded in a full inventory of the current Python-only recognition/verification/surfacing code this
planning pass. Each decision cites what exists today so the plan reuses and refits rather than rewrites,
and names the constitution gates it must satisfy.

## R0 — Current-state blast radius (what is Python-specific today)

**Recognition / planning:**
- `internal/inventory/inventory.go` — `.py`-only walk (`strings.HasSuffix(p,".py")`, :104); FastAPI/Flask
  decorator regexes (`reMethodDecorator`/`reRouteDecorator`/`reWSDecorator`/`rePrefixAssign`, :74-88);
  HTTP-centric `Route{Method,Path,File,Line,Subsystem}` (no Language/Framework); `CoverageLedger`
  denominator; **`disposition()` is mention-based substring containment** (:266); `FallbackPartitions`.
- `internal/engine/helpers.go:366` `countPySource` (`.py`-only) drives degradation thresholds (20/150,
  engine.go:411-465). `engine.go` wires `inventory.EnumerateRoutes`→partitions→`resolveHuntPartitions`/
  `runHunt`; `buildHuntTask` scope is the partition **description** string; prompts re-discover via
  Glob (the enumerated units are not passed as a task input).
- `internal/phases/partition.go` — `RouteRef{File,Desc}` HTTP-shaped; `AugmentForCoverage` is **substring
  containment** of filename in free-text descriptions (:196).

**Verification / evidence:**
- `internal/verification/verification.go` — `candidateIdentity` anchor is language-agnostic
  (`location|source|sourceID` + CWE hash) with a **`.py`-only owner-chain enhancement** (:113);
  `functionSpans`/`reDef` are Python `def`/indentation (:414-454); `requireFunctionEvidence` is **gated
  to `.py`** (:471) — non-Python candidates get *no* containing-function coverage requirement today;
  `fileAndLine` single-colon split (:174, fragile for `C:\`/columns).
- `internal/verification/authz.go` `routeGuardFor` uses the Python inventory + `functionSpans`.
- `internal/verification/artifacts.go` — `.py`-only assertion requirement (:119/206).
- `internal/consolidate/corroborate.go` — entire CWE→sink table (:33-52), per-class veto battery
  (:169-177), and `corsDanger` (`.py` walk, :293) are Python/Flask/FastAPI/Django idioms.
- `internal/authz/authz.go` — `reAuthCheck` Python/Flask idioms, whole-file grep.
- `internal/engine/sweep.go` — `sweepLanguage(ext)` **already multi-language for filtering** (js/ts/py/
  go/rb/php/java) but sweeps **Python-only** sink patterns; Python `common` builtin set.

**Surfacing / fixtures:**
- findings.json `Doc`/`CoverageInfo`/`AppIntel`/`RunStatus` (`internal/consolidate`); `RunRecord`
  (`internal/engine/record.go`, additive-only); `reports.Report`/`Load`; `report.go` RenderMarkdown +
  `reportNav`; `sarif.go`; `manifest.go` (+`configHash`); server `status.go` `scanStatus` projection.
- Recon prompts (`skill/phases/phase1_recon.md`) already glob many languages — the mismatch is
  prompt breadth vs. a Python-only deterministic denominator.
- Offline end-to-end pattern exists: `tests/parity/full_pipeline_test.go`
  `TestFullPipelineArtifactsAndDeterministicPhases` — transcript JSON + `testdata/vulnapp` +
  `engine.Execute` with transcript/fake providers + `Project`/`Compare` vs `tests/parity/golden`.
  No schema-version field; compatibility = additive-only + graceful read + parity contracts
  (`tests/parity/reference/contracts.json`, `schema_test.go`, `reference_contract_test.go`).

## R1 — Recognition approach & the dependency budget (the gating decision)

**Decision**: A pluggable **`Recognizer` per (language, application-type)**, implemented **stdlib-first
with zero new runtime dependencies by default**, and **no CGO**. Go uses the standard library
`go/parser`/`go/ast`/`go/token` (real AST, zero-dep). Python keeps its existing regex recognizer
(regression-preserved), refit behind the interface. JavaScript/TypeScript and the remaining languages use
**bounded, hand-written, structure-aware lexers** (brace/bracket/string/comment-aware scanners) rather
than full parsers. Any per-language **runtime** parser dependency is a **separately justified, listed**
budget item; a **material** budget expansion requires a constitution amendment **before** that language
ships.

**Rationale**: The constitution's Runtime clause sets a **baseline of zero third-party runtime
dependencies**, each addition justified and listed, material expansion → amendment; and the binary is
built `CGO_ENABLED=0` as a static cross-platform artifact. The obvious "12 real parsers" answer —
tree-sitter grammars — is **CGO-based** (breaks the static build) and constitutes a large dependency
expansion; it is therefore rejected as the default. Go's stdlib gives a first-class AST for free.
Structure-aware lexers (not regex piles) can meet the **exact-fixture** accuracy the spec measures
(recognizing declared framework patterns), which is explicitly "supported discovery patterns, not
universal recall". This keeps the gate PASS without an amendment while still beating the
"growing collection of untested regexes" the spec forbids (each recognizer is lexer-structured and
fixture-backed, with recorded boundaries).

**Alternatives considered**:
- **tree-sitter + 12 grammars (CGO)** — most accurate, but breaks `CGO_ENABLED=0`, adds a large runtime
  dependency surface, and needs a constitution amendment. Rejected as default; may be revisited per
  language only with explicit justification + amendment if a language cannot meet its fixtures otherwise.
- **Pure-Go parser libraries per language** — evaluated case-by-case; only considered where a single
  small, permissively licensed, reviewed pure-Go library decisively beats a lexer for that language's
  fixtures, and then added as a listed budget item. Default plan adds none.
- **Regex-only** — rejected: the spec explicitly rejects untested regex accumulation as a completeness
  argument; lexers give bracket/string/comment awareness that regexes cannot.

**Consequence**: research/tasks record, per language, whether recognition is stdlib/lexer (no dep) or
needs a listed dependency; the support matrix records the chosen mechanism and its limits. The default,
and the target for all 12 baseline languages, is **no new runtime dependency**.

## R2 — Language-agnostic investigation-unit model (de-HTTP the core)

**Decision**: Introduce an **investigation unit** as the core recognized element, superseding the
HTTP-only `Route`. A unit carries: stable id, source location, language, framework, module, **application
type**, **surface kind** (web-route | cli-command | library-api | parser-entry | worker-handler |
consumer-handler | rpc-method | browser-sink | fallback), function/handler reference, resolution
certainty (resolved/partial/unresolved), and attached **external inputs** and **security-sensitive
operations**. HTTP method/path become surface-kind-specific attributes, not the model's spine.

**Rationale**: FR-003/005/006 forbid equating language support with HTTP routes; most baseline app types
have no routes. `internal/inventory.Route` has no Language/Framework field and is HTTP-shaped; a
language-agnostic unit is required. `coverage_ledger.json` continues to be emitted (units projected to
ledger entries with language/app-type tags) for compatibility (R7).

**Alternatives considered**: extend `Route` with optional fields — rejected: bakes HTTP assumptions into
CLI/library/worker units and keeps the misleading route-count denominator.

## R3 — Evidence-backed per-unit review (replace mention-based disposition)

**Decision**: A unit is "reviewed" only when a **unit-specific analysis record** exists whose source
references resolve to the run and whose outcome is recorded (reviewed-with-finding / reviewed-without-
finding). Replace `inventory.disposition()` substring containment and `phases.AugmentForCoverage`
filename-in-description matching with explicit per-unit records; a filename/identifier mention, or a
finding elsewhere in the same file, never marks a sibling unit reviewed; referenced IDs are validated to
belong to the run.

**Rationale**: FR-025/026 and SC-006/007; the current substring approach is precisely the false
completion the spec prohibits (a two-unit file with evidence for one must leave the other unreviewed).
Aligns with feature-010's evidence-backed review vocabulary, applied at the coverage layer.

**Alternatives considered**: keep containment as a heuristic with a warning — rejected: it produces false
"reviewed" counts, an evidence-integrity violation.

## R4 — Per-language enclosing-scope resolver (ungate verification)

**Decision**: Add `recognize.EnclosingScope(language, source, line)` returning the containing function/
method span + owner chain. Go uses `go/ast`; brace-delimited languages (JS/TS, Java, Kotlin, C#, C, C++,
Rust, PHP) use a bracket-matching scanner; Python keeps indentation scanning; Ruby uses def/end block
matching. Verification's `requireFunctionEvidence`, identity owner-chain, and `routeGuardFor` span
recovery consume this resolver **for all languages** — removing the `.py` gate so non-Python candidates
get the same containing-function evidence requirement.

**Rationale**: `functionSpans`/`requireFunctionEvidence` are Python-only and `.py`-gated today, so
non-Python verification is weaker (FR-028/029). A shared scope resolver restores parity of rigor without
applying Python rules to other languages.

**Alternatives considered**: leave non-Python ungated — rejected: weakens evidence for exactly the
languages this feature adds.

## R5 — Per-language sink / auth / assertion tables

**Decision**: Generalize `consolidate/corroborate.go`'s Python CWE→sink table, per-class veto battery,
and `corsDanger`, plus `authz.reAuthCheck` and `artifacts` assertion detection, into **per-language
registries** in `internal/recognize/sinks.go`. Python tables are preserved as-is (regression); each new
language gets its own sink patterns, auth idioms, and test-assertion forms, validated by fixtures.
`corroborate.go` delegates to the registry; `sweep.go` pairs its existing multi-language filter with
per-language sink patterns; a class/construct with no applicable checker for a language reports
**unresolved** (never refutation).

**Rationale**: FR-013/025/027/030; today every sink/auth check is Python/Flask idiom. Delegation keeps
Python behavior intact while adding languages.

**Alternatives considered**: one universal sink regex set — rejected: false positives/negatives across
languages; the spec requires language-appropriate operations.

## R6 — Feed the deterministic inventory into hunt work

**Decision**: Pass recognized units (with language/framework/app-type/source context) into partition
planning and **hunt task inputs**, and derive module/subsystem assignments from discovered non-Python
scope when model recon is missing/malformed; never collapse a large mixed-language repo into one
unqualified whole-repo assignment. Cross-module/shared code stays available (partition is not a hard
read boundary). Effective work limits and assignment counts are exposed; bounded/stopped work preserves
unassigned scope with reasons.

**Rationale**: FR-015/019/020/023; today the enumerated list is not fed to the model (prompts
re-discover), and a non-Python repo collapses to `whole-repo`. Reconciles prompt breadth with the
deterministic denominator (R0).

## R7 — Additive multi-axis coverage, support matrix & compatibility

**Decision**: Add four distinct coverage axes (census, inventory support, assignment, review) per
language and application type, with explicit denominators/labels; never combine differing unit kinds into
one percentage. Surface **additively**: extend `coverage_ledger.json` (language/app-type + evidence-backed
disposition), add an inventory/support-matrix block under `findings.json.application_intelligence`, add
additive `RunRecord` fields, emit a new `support_matrix.json`, and project all of it through
`reports.Report`/`Load`, `report.go` (new report section + Nav entry), `sarif.go`, `manifest.go`, and the
server `status.go` projection. There is **no schema-version field**; rely on the existing **additive-only
discipline + graceful read + parity contracts** — older reports lacking the new evidence read as
**unknown/legacy**, never retroactively complete. Extend `tests/parity/reference/contracts.json` +
`schema_test.go` for the new fields.

**Rationale**: FR-020/024/027/029/032-034, SC-007/010; matches the codebase's established
additive/graceful/parity compatibility model (no version field exists).

**Alternatives considered**: introduce a schema-version field — deferred: the repo's convention is
additive-only + contracts; adding versioning is a larger change than this feature needs.

## R8 — Per-language offline end-to-end fixtures

**Decision**: For each baseline language, add `testdata/<lang>app/` (a small target app),
`testdata/ground_truth/<name>.json`, `tests/parity/transcript/<name>.json`, and
`tests/parity/golden/<name>.json`, each fixture containing a **vulnerable (supported)**, a **defended
(rejected with a real defense)**, and an **unresolved** example, and driven end-to-end by
`engine.Execute` + transcript/fake providers + `Project`/`Compare`, exactly like
`TestFullPipelineArtifactsAndDeterministicPhases`. Recognizer unit tests use authored expected
inventories independent of the implementation, with negative controls.

**Rationale**: FR-016, SC-001/003/005; reuses the proven offline harness; "supported discovery patterns,
not universal recall".

## R9 — Staged delivery & MVP

**Decision**: Stage 1 (Python preserved + Go + JS/TS), Stage 2 (Java, C#, Ruby, PHP), Stage 3 (Kotlin,
C, C++, Rust). Each stage's languages require their recognizer, verification adaptation, end-to-end
fixture, and support-matrix acceptance before "done". The **MVP** is a complete **non-Python**
scan-to-report flow (Go **or** JS/TS) proven by its end-to-end fixture (SC-005) — not an inventory-only
demo. Delivery order within the engine: (a) census + language-agnostic unit model + evidence-backed
coverage records + compatibility projection; (b) Stage-1 recognizers + hunt/verification integration +
fixtures; (c) Stages 2–3; (d) CLI/fallback breadth per language; (e) surfacing + regression validation.

**Rationale**: FR-015, spec staging; keeps Go/JS-TS as early milestones without treating them as
completion.

## R10 — Testing posture (offline, static, no target runtime, no CGO)

**Decision**: All acceptance is offline: recognizer unit tests + per-language end-to-end scripted scans
(controlled model responses), `go test ./...`/`go vet`/`gofmt` green, `CGO_ENABLED=0` build.
**Scripted-pipeline validation is reported separately from a bounded empirical evaluation** on real
repositories (documented as limitations + results, not run in CI, no unsolicited paid/long model scan).
Tests assert discovery does not execute code, install deps, require target runtimes, escape source
boundaries, or modify the target.

**Rationale**: FR-040, SC-011/012, and the standing project constraint (no live model, no target
runtimes).

## Post-design constitution re-check

The design keeps recognition stdlib-first (zero new runtime deps by default, no CGO), static-only (no
target execution/runtime), and additive; it strengthens evidence integrity (evidence-backed review,
ungated per-language verification, no checker-absence-as-refutation), preserves orthogonal status and
prior work, and is fully offline-testable. The single gated item — a per-language runtime parser
dependency — is avoided by default and, if ever needed, is listed/justified with amendment status.
**Constitution Check remains PASS after design.**
