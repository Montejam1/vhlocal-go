# Phase 1 Data Model: Multi-language scan coverage

New model is **additive** and language-agnostic; existing artifacts keep emitting (compatibility) with
new fields appended. Cited existing types are refit, not replaced. No schema-version field is introduced
(additive-only + graceful read + parity contracts — research R7).

## Core recognized model (new — `internal/recognize`)

### InvestigationUnit
The central recognized element, superseding the HTTP-only `inventory.Route` (R2).

| Field | Type | Rule |
|---|---|---|
| `id` | string | stable within a run; deterministic from language+module+surface+location+identity (same input → same id) |
| `language` | enum | one of the 12 baseline languages |
| `framework` | string | recognized framework/API (or "" when none) |
| `module` | string | module/package path |
| `application_type` | enum | web \| cli \| library \| parser \| worker \| consumer \| rpc \| browser |
| `surface_kind` | enum | web-route \| cli-command \| library-api \| parser-entry \| worker-handler \| consumer-handler \| rpc-method \| browser-sink \| fallback |
| `location` | string | `file:line` (resolver tolerant of columns/drive letters — R0 fixes `fileAndLine`) |
| `handler_ref` | string | function/method reference (declaration vs implementation distinguished) |
| `surface_attrs` | object | surface-specific (e.g. web: `method`,`path`; cli: `command`; consumer: `topic`; rpc: `method`) |
| `certainty` | enum | resolved \| partial \| unresolved (partial retains explicit uncertainty + assignment) |
| `inputs` | []ExternalInput | representative external inputs attributed to the unit |
| `sensitive_ops` | []SensitiveOp | representative security-sensitive operations located in/around the unit |
| `evidence` | []Detection | detection evidence (matched construct + source span) for auditability |

Rules: statically knowable prefixes/constants resolved; dynamic expressions never fabricated (→
`certainty=partial/unresolved`); distinct exposed surfaces sharing a handler stay distinct; identical
identifiers in different apps stay distinct; one malformed file never drops other files' units.

### ExternalInput / SensitiveOp
- **ExternalInput**: `{kind (request-field|argv|env|message|file|stream|dom|other), name, location}` — honest
  per app type (CLI/library/worker inputs not forced into HTTP shapes).
- **SensitiveOp**: `{cwe_class, operation, location, context_excerpt}` — command exec, SQL, deserialization,
  unsafe memory/string ops, template/HTML sink, file/path op, reflection, etc., per the per-language table.

### Recognizer (interface, not persisted)
`Recognizer` per (language, application-type): `Recognize(module, files) ([]InvestigationUnit, []Limitation)`.
Registry dispatches by detected language/app-type; a missing recognizer yields a **FallbackUnit** with
disclosed limits (never dropped). Go impl uses `go/ast`; others use bounded lexers (research R1).

### Limitation
`{scope (file|module|language|construct), reason, kind (unsupported|parse-error|dynamic-unresolved)}` — kept
visible; parse-error distinguished from "supported module, no matching units".

## Census & support (new)

### SourceCensusEntry
`{path, language, module, application_type, classification (production|test|generated|dependency|unreadable|unsupported), evidence}`.
Exclusions applied consistently across census/discovery/assignment/coverage with recorded reasons;
excluded dependencies/generated code never counted as reviewed production source.

### SupportMatrixEntry  (emitted as `support_matrix.json`)
Per (language, application-type): `{readability, deterministic_recognition (dedicated|limited|unsupported),
verification_checks, fallback_review, known_unsupported_constructs[], recognizer_mechanism (stdlib|lexer|
dependency:<name@version>), parser_versions, acceptance_status}`. A cell is "dedicated"/"supported" only
when backed by a passing end-to-end fixture (FR-017/018).

## Coverage records (refit of `internal/inventory` + `internal/consolidate`)

### CoverageDisposition (per unit) — replaces mention-based `disposition()`
Exactly one of: `assigned | reviewed_with_finding | reviewed_without_finding | unresolved_incomplete |
excluded_with_reason | not_reviewed`. `reviewed_*` REQUIRES a `UnitReviewRecord` (below). A filename/
identifier mention or a finding elsewhere in the file MUST NOT set `reviewed_*` (R3).

### UnitReviewRecord
`{unit_id, outcome (finding|no_finding), source_refs[] (must resolve to the run), analysis_ref}` — the
evidence a `reviewed_*` disposition requires. Referenced IDs validated to belong to the run.

### CoverageAxes (the four distinct facts — never one blended %)
`{census: {counts by language/app-type}, inventory_support: {dedicated/limited/unsupported per lang×app-type},
assignment: {assigned/unassigned/deferred}, review: {per-disposition counts}}`, each with explicit
denominator labels. Completeness qualified by support+scope; zero units ≠ "clean"; empty vs non-web/non-
service vs discovery-failure distinguished.

## Extensions to existing persisted artifacts (additive; cited)

- **`inventory.Route` → language-tagged** and **`CoverageLedger`/`LedgerEntry`** gain `language`,
  `application_type`, `surface_kind`, and the evidence-backed `CoverageDisposition`; ledger keeps emitting
  for parity (`internal/inventory/inventory.go`).
- **`consolidate.Doc.ApplicationIntelligence`** (`application_intelligence`) gains an `inventory` +
  `support_matrix` + `coverage_axes` block; **`consolidate.CoverageInfo`** gains per-language/app-type
  breakdown; **`consolidate.RunStatus.CoverageDegradedReasons`** gains language-scoped reasons and
  `StatusInput` a "languages unenumerated/unsupported" signal (`internal/consolidate`).
- **`engine.RunRecord`** (`scan_meta.json`) gains additive `languages_detected`, `languages_enumerated`,
  `inventory_engine`, and generalized (non-`.py`) source-size fields; degradation thresholds language-aware
  (`internal/engine/record.go`, `engine.go`, `helpers.go`).
- **`reports.Report`** gains a languages/coverage summary populated in `Load`; **`report.go` `Input`** +
  RenderMarkdown/HTML gain a support-matrix/coverage section and a Nav entry; **`sarif.go`**/**`manifest.go`**
  carry language-scoped coverage/reasons (`configHash` updated if a new config key is added).
- **Server projection** `internal/server/status.go` `scanStatus` re-exposes the new coverage/support fields
  to the UI; `support_matrix.json` reachable as a raw artifact and added to `reports.Manifest`.

## Compatibility & legacy

- No schema-version field: additive-only fields + graceful read (missing → unknown/legacy, never
  retroactively complete); resume/regeneration must not accept stale inventory or invent review evidence
  (FR-031/032/034/035). Parity contracts (`tests/parity/reference/contracts.json`, `schema_test.go`)
  extended for the new fields.

## Fixtures (new test data)

- **LanguageFixture**: per language — `testdata/<lang>app/` (target) + `testdata/ground_truth/<name>.json`
  (independently authored expected inventory) + `tests/parity/transcript/<name>.json` (scripted model) +
  `tests/parity/golden/<name>.json` (expected projection), each with vulnerable/defended/unresolved
  examples (R8).

## Relationships

- A `SourceCensusEntry` belongs to a module; a module yields `InvestigationUnit`s (or a `FallbackUnit`);
  each unit has inputs + sensitive ops, an `Assignment`, and a `CoverageDisposition` (with a
  `UnitReviewRecord` when reviewed). `CoverageAxes` aggregate units per language/app-type; the
  `SupportMatrixEntry` for a (language, app-type) is "supported" only when its end-to-end fixture passes.
- Verification consumes a unit's handler span (via `recognize.EnclosingScope`) and per-language sink/auth
  tables; outcomes stay supported/rejected/unresolved with exact quotation + stable identity.
