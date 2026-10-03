# Contracts — Recognizer interface & recognition behavior

Internal contracts for the new `internal/recognize` package and the behavior every language recognizer
must satisfy. These are Go-internal interfaces + behavioral invariants (verified by offline unit tests +
per-language fixtures), not HTTP endpoints. IDs are referenced by tasks and map to requirements/SCs.

## Recognizer interface

- **C-R1 (interface)**: A `Recognizer` for a (language, application-type) exposes
  `Recognize(module Module, files []SourceFile) ([]InvestigationUnit, []Limitation)` and pure metadata
  (`Language()`, `AppTypes()`, `Mechanism()` ∈ {stdlib, lexer, dependency:<name@version>}). Registration is
  in a registry dispatched by detected language/app-type (FR-002/005).
- **C-R2 (static & offline)**: `Recognize` MUST be pure static analysis — it MUST NOT execute/import target
  code, spawn processes, require a target-language runtime/toolchain, perform network I/O, or write outside
  the results dir; reads are path/symlink-confined to the target (FR-034/037/038, Principle III). Go's
  recognizer uses stdlib `go/parser`; others use bounded lexers; **no CGO** (FR-039, dependency budget).
- **C-R3 (determinism)**: For unchanged input, `Recognize` MUST return identical units, ids, and ordering
  (FR-022, SC-009). Unit ids are derived deterministically from language+module+surface+location+identity.
- **C-R4 (dependency budget)**: A recognizer's `Mechanism()` MUST be `stdlib` or `lexer` unless a listed,
  justified runtime dependency has been approved (material expansion → constitution amendment); the chosen
  mechanism is recorded in the support matrix (FR-039).

## Recognition behavior (per language, within declared boundary)

- **C-U1 (units beyond HTTP)**: Recognizers MUST produce `InvestigationUnit`s for the language's dedicated
  application types (web routes AND cli-commands, library-apis, parser-entries, worker/consumer-handlers,
  rpc-methods, browser-sinks as applicable) — recognition MUST NOT be limited to HTTP routes (FR-003/005/006).
- **C-U2 (identity & fields)**: Each unit carries id, language, framework, module, application_type,
  surface_kind, location, handler_ref, surface_attrs, certainty, inputs, sensitive_ops, evidence (data-model
  InvestigationUnit) (FR-010/011).
- **C-U3 (robust code)**: Recognizers MUST handle multiline declarations, aliases, comments/strings
  containing fake routes/commands (no spurious units), nested groups/mounting/prefixes, multiple methods,
  shared handlers, and duplicate identifiers in separate apps; MUST distinguish declaration vs implementation
  locations; MUST resolve statically knowable prefixes/constants; and MUST NOT fabricate values for dynamic
  expressions (→ `certainty=partial/unresolved` + assignment) (FR-011/012, SC-003/004).
- **C-U4 (inputs & sensitive ops)**: Recognizers MUST attribute representative external inputs to units and
  locate representative security-sensitive operations with source context, per the language's table
  (FR-013).
- **C-U5 (failure isolation)**: A malformed/unsupported file MUST yield a `Limitation` (parse-error or
  unsupported), NEVER drop other files' units or fail the scan; parse-error is distinguished from
  "supported module, no matching units" (FR-014, SC-004).
- **C-U6 (fallback)**: A surface/module with no dedicated recognizer MUST yield a `FallbackUnit` with
  disclosed limits, distinct from verified units; not every exported function/component is an external entry
  point (FR-006, SC-006).

## Enclosing scope & verification adaptation

- **C-S1 (scope resolver)**: `EnclosingScope(language, source, line)` MUST return the containing
  function/method span + owner chain per language (Go: go/ast; brace-based; Python indentation; Ruby
  def/end) (FR-028).
- **C-S2 (ungated function evidence)**: Verification's containing-function evidence requirement MUST apply to
  ALL supported languages (remove the `.py` gate), using C-S1; exact source quotation, revision attribution,
  and stable candidate identity are preserved (FR-026/029).
- **C-S3 (per-language checks)**: Sink/class corroboration, auth mapping, and PoC-assertion detection MUST
  use per-language tables; a class/construct with no applicable checker for a language yields **unresolved**
  and MUST NOT be represented as source evidence refuting the candidate; injection-style sinks MUST NOT be
  imposed on authorization/business-logic findings; candidates MUST NOT be accepted merely to raise coverage
  (FR-025/027/028/030/031).

## Coverage & disposition

- **C-C1 (evidence-backed review)**: A unit's disposition is `reviewed_with_finding`/`reviewed_without_finding`
  ONLY with a `UnitReviewRecord` whose source refs resolve to the run; a filename/identifier mention or a
  finding elsewhere in the same file MUST NOT mark a sibling reviewed; referenced IDs are validated (FR-025/026,
  SC-006).
- **C-C2 (four axes)**: Census, inventory-support, assignment, and review are reported as distinct axes with
  explicit denominators; differing unit kinds MUST NOT be blended into one percentage; completeness is
  qualified by support+scope; zero units ≠ "clean" (FR-020/023/024, SC-007).
- **C-C3 (assignment)**: Every in-scope unit/fallback unit gets a persisted assignment or an explicit
  unassigned/deferred reason; discovered scope is fed to hunt tasks; a mixed-language repo is not collapsed
  into one unqualified whole-repo assignment (FR-015/016/019/020).
