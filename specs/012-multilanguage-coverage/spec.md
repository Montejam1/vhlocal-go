# Feature Specification: Multi-language scan coverage

**Feature Branch**: `012-multilanguage-coverage`

**Created**: 2026-09-25

**Status**: Draft (revised in place — broadened language baseline & application types)

**Input**: User description: "Broaden vhlocal to first-class, source-code vulnerability analysis
across a 12-language baseline (Python, Go, JavaScript, TypeScript, Java, Kotlin, C#, C, C++, Rust,
Ruby, PHP), including applications that are not HTTP services. For each language, define explicit,
independently testable support (source/module discovery; functions/methods/context/boundaries;
representative external inputs and security-sensitive operations; assignment to real hunt work;
candidate extraction + evidence-backed verification; honest coverage and published findings). Cover
web apps, CLI tools, libraries, parsers/file processors, background workers, message consumers, RPC
services, and browser-side code. Language support must not mean file extensions, a language listing,
or a whole-repo generic fallback, and must not be equated with enumerating HTTP routes. Require a
concrete end-to-end offline scan fixture per language (vulnerable/defended/unresolved); distinguish
scripted-pipeline validation from empirical detection accuracy. Preserve Go and JS/TS work as early
milestones (not completion); define staged delivery and a per-language support matrix with acceptance
criteria. Preserve evidence-integrity, static-only operation, offline/self-contained delivery,
historical data, dashboard metrics, and current behavior; do not execute target code or require
target-language runtimes for discovery."

## Overview

vhlocal's model agents can read many languages, but the **deterministic inventory that actually drives
scan work is Python-only** (it enumerates `.py` files for selected web-route patterns), and downstream
coverage/verification helpers assume Python. Broad model reading is not measured, end-to-end language
support, and **language support is not the same as enumerating HTTP routes** — most security-relevant
code (CLIs, libraries, parsers, workers, consumers, RPC services, browser code) has no HTTP routes at
all.

This feature makes a **12-language baseline** — Python, Go, JavaScript, TypeScript, Java, Kotlin, C#,
C, C++, Rust, Ruby, PHP — first-class for source-code vulnerability analysis. For each language, "support"
means concrete, independently testable capability across six dimensions:

1. **Source & module discovery** — first-party source and modules found and classified.
2. **Investigation units** — functions/methods, relevant source context, and investigation boundaries.
3. **Attack surface** — representative **external inputs** and **security-sensitive operations**
   appropriate to that language and application type (not just HTTP routes).
4. **Assignment** — every in-scope unit reaches real hunt work or gets an explicit unassigned/deferred
   reason.
5. **Verification** — candidate extraction and evidence-backed, supported/rejected/unresolved
   verification compatible with the language.
6. **Coverage & findings** — honest multi-axis coverage accounting and published findings.

Support is defined across **application types**: web apps, CLI tools, libraries, parsers/file
processors, background workers, message consumers, RPC services, and browser-side code. The spec
documents which **language/application-type combinations have dedicated recognition** and which remain
**limited** (scoped model-guided fallback with disclosed limits). Language support must **never** mean
merely recognizing a file extension, listing a language, or assigning the whole repository to a generic
fallback agent.

Delivery is **staged**, and Go and JavaScript/TypeScript (alongside preserved Python) are the **early
milestones — not the completion** of the feature. Every required language ships with an **end-to-end
offline scan fixture** containing vulnerable, defended, and unresolved examples, and a **per-language
support matrix** carries explicit acceptance criteria. Accuracy of tested recognition boundaries is
preferred over a long unsupported list; scripted-pipeline validation is kept distinct from empirical
detection accuracy; and no language claim is made from readability alone.

### Language baseline & representative patterns (product coverage scope)

The named languages/frameworks/APIs are **target code the scanner must recognize**, not vhlocal's own
implementation stack and never executed. For each baseline language the spec fixes a **representative**
(not exhaustive) set of application types with **dedicated** recognition, framework/API patterns,
external inputs, and security-sensitive operations. Everything outside a language's dedicated set gets
scoped fallback with disclosed limits.

| Language | Dedicated application types | Representative frameworks / APIs | Representative external inputs | Representative security-sensitive operations |
|---|---|---|---|---|
| Python | web, CLI, worker, library/parser (fallback) | FastAPI, Flask, Django URLconf/views; argparse/click; Celery tasks | request params/body, argv, env, file/stdin, deserialized data | `subprocess`/`os.system`, `eval`/`exec`, SQL (DB-API/ORM), `pickle`/`yaml.load`, path joins, template rendering |
| Go | web, CLI, RPC, worker (fallback) | `net/http`+ServeMux, Chi, Gin; `flag`/`main`, Cobra; gRPC/`net/rpc` handlers | `*http.Request`, flag/args, env, stdin, RPC request messages | `os/exec`, `database/sql`, `text/template` vs `html/template`, `path/filepath`, `encoding/gob` |
| JavaScript | web, CLI, browser-side, worker/consumer (fallback) | Express, Fastify, Koa, Next.js API routes; Commander/yargs; DOM event handlers | `req.body/query/params`, `process.argv`, message payloads, DOM/`location` | `child_process`, `eval`, SQL query builders, `fs`, `innerHTML`, deserialization |
| TypeScript | web, CLI, browser-side, worker/consumer (fallback) | same as JavaScript (typed) incl. NestJS controllers | same as JavaScript (typed DTOs) | same as JavaScript |
| Java | web, RPC, CLI, worker/consumer | Spring MVC/`@RestController`, JAX-RS, Servlets; picocli/`main`; JMS listeners; gRPC | `HttpServletRequest`, `@RequestParam`/`@PathVariable`/`@RequestBody`, args, message bodies | `Runtime.exec`/`ProcessBuilder`, JDBC/`Statement`, `ObjectInputStream`, reflection, XML parsers (XXE), file IO |
| Kotlin | web, CLI, worker (fallback) | Spring, Ktor routing; `main`/args | Ktor/Spring request bindings, args | `ProcessBuilder`, JDBC/exposed, deserialization, reflection, file IO |
| C# | web, CLI, worker/consumer, RPC (fallback) | ASP.NET Core controllers/minimal APIs/MVC; `Main`/System.CommandLine; `BackgroundService` | `HttpRequest`, `[FromBody]`/`[FromQuery]`/route, args, message payloads | `Process.Start`, `SqlCommand`, `BinaryFormatter`/deserialization, reflection, XML (XXE), file IO |
| C | CLI, parser/file processor, library | `main(argc,argv)`, stdio/file APIs, socket recv | argv, stdin, file contents, env, network buffers | `system`/`exec*`, unsafe string ops (`strcpy`/`sprintf`/`memcpy`), format strings, `malloc`/`free`, path handling |
| C++ | CLI, service, parser/file processor, library | `main`, iostreams, common socket/service loops | argv, streams, network input, file contents | `system`, unsafe string/buffer ops, deserialization, `new`/`delete` lifetime, path handling |
| Rust | web, CLI, library/parser (fallback) | Actix, Axum, Rocket; clap | request extractors, clap args, stdin/files | `std::process::Command`, `unsafe` blocks, `sqlx`/`diesel`, `serde` deserialization, path handling |
| Ruby | web, CLI, worker | Rails routes/controllers, Sinatra; OptionParser/Thor; Sidekiq | `params`, `ARGV`, job args | `system`/backticks/`eval`, ActiveRecord/SQL, `YAML.load`/`Marshal`, `send`, `File` |
| PHP | web, CLI, library (fallback) | Laravel routes/controllers, Symfony, plain superglobals | `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`, `php://input`, argv | `system`/`exec`/`shell_exec`, `eval`, mysqli/PDO, `unserialize`, `include`/`require`, file ops |

Exact recognized constructs, framework versions, and known-unsupported constructs per (language,
application-type) are finalized in planning and published in the support matrix (FR-SM). The table above
is the representative baseline the fixtures and acceptance criteria are authored against.

### Staged delivery (all stages required to complete the feature)

Staging orders delivery; it does **not** make any baseline language optional. Every stage's languages
require their end-to-end fixture and support-matrix acceptance before that stage is "done", and the
feature is complete only when **all** baseline languages meet their acceptance criteria.

- **Stage 1 (P1, early milestones)**: Python (preserved + regression-tested), **Go**, **JavaScript**,
  **TypeScript** — full six-dimension support for their dedicated application types + scoped fallback.
- **Stage 2 (P2)**: **Java**, **C#**, **Ruby**, **PHP** — common server/web + CLI + worker app types.
- **Stage 3 (P3)**: **Kotlin**, **C**, **C++**, **Rust** — JVM/systems + CLI/parser/library app types.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Whole-repository, multi-language census & support disclosure (Priority: P1)

Before relying on any recognizer, an operator's scan inventories first-party source across the baseline
languages by language, module/package, application type, and recognizable framework signals, and
discloses per module what is deterministically supported vs limited. Production source, tests, generated
code, dependencies, unreadable files, and unsupported formats are distinguished with recorded reasons;
unsupported or dynamically unresolved surfaces are shown as unknown/unresolved, never as an absence of
attack surface. Language support is never reduced to a file-extension listing or a whole-repo generic
fallback.

**Why this priority**: Every downstream capability depends on an honest, application-type-aware census
and per-module support disclosure; without it, non-Python and non-web code is invisible or silently
assumed clean. Foundation of the MVP.

**Independent Test**: Run inventory over a mixed-language monorepo (multiple baseline languages and
application types) and over a frontend-only project, an unsupported-language library, and a background
worker; confirm each module reports language, application type, framework signals, deterministic-support
status, recognized surface kinds, limitations/errors, and whether scoped fallback was assigned; confirm
excluded tests/dependencies are not counted as reviewed production source and that zero recognized
routes/units is never reported as "clean/covered".

**Acceptance Scenarios**:

1. **Given** a monorepo containing several baseline languages and several application types, **When**
   inventory runs, **Then** it produces separate, accurate per-module census entries (language, module,
   application type, framework signals) with detection evidence retained and ambiguous cases visible.
2. **Given** tests, generated code, dependencies, unreadable files, and unsupported formats, **When**
   inventory runs, **Then** each is distinguished and excluded consistently across census/discovery/
   assignment/coverage with a recorded reason; excluded dependencies are not counted as reviewed source.
3. **Given** a module whose application type is not HTTP-web (library, parser/file processor, background
   worker, message consumer, RPC service, browser-side code), **When** inventory runs, **Then** it is
   not dropped for lacking HTTP routes: it is recognized by application type and either gets dedicated
   recognition or a scoped fallback unit with disclosed limits — and not every exported function or
   component is treated as an external entry point.
4. **Given** an unsupported (language, application-type) combination or a dynamically unresolved surface,
   **When** inventory reports it, **Then** it is shown as unknown/unresolved/limited, never as an absence
   of attack surface; containment and symlink rules are preserved.

---

### User Story 2 - Per-language recognition of investigation units, inputs & sensitive operations (Priority: P1)

For each supported (language, application-type) combination, an operator gets source-grounded
investigation units — functions/methods with relevant source context and investigation boundaries —
together with the representative **external inputs** and **security-sensitive operations** appropriate to
that language and application type (per the baseline table), not merely HTTP routes. Web entry points are
one surface kind among many (routes, CLI commands, exported library APIs, parser/deserialization entry
points, worker/consumer message handlers, RPC methods, browser DOM sinks).

**Why this priority**: Concrete, trustworthy units + attack-surface facts for each language are the core
of first-class coverage and the input to real hunt work.

**Independent Test**: Against an authored fixture corpus per language and application type, confirm every
expected unit, external input, and sensitive operation matches with source location and boundary, and
negative controls (fake routes/commands in strings/comments, dead code) yield no spurious recognitions;
confirm a single malformed file does not prevent recognition in other files/modules.

**Acceptance Scenarios**:

1. **Given** the representative frameworks/APIs for a language (baseline table), **When** recognition
   runs, **Then** the documented entry points/units are recognized with identity, source location,
   language/framework, module, application type, surface kind, handler/function reference, and
   protocol/dispatch details where applicable (e.g., HTTP method+path for web; command identity for CLI;
   message/topic for consumers; method for RPC), within the declared boundary.
2. **Given** representative external inputs for a language/application type, **When** recognition runs,
   **Then** those inputs are identified and attributed to their unit, and CLI/library/worker inputs are
   modeled honestly (not forced into fake HTTP methods/paths).
3. **Given** representative security-sensitive operations for a language (e.g., command execution, SQL,
   deserialization, unsafe memory/string ops, template/HTML sinks, file/path operations), **When**
   recognition runs, **Then** they are located with source context so hunting/verification can reason
   about them.
4. **Given** aliases, multiline declarations, nested groups/mounting/prefixes, multiple methods, shared
   handlers, duplicate identifiers across modules/apps, and separately defined handlers, **When**
   recognition runs, **Then** registration/declaration locations are distinguished from implementation
   locations, distinct exposed surfaces sharing a handler are preserved, identical identifiers in
   different apps are kept distinct, and statically knowable prefixes/constants are resolved without
   fabricating values for dynamic expressions.
5. **Given** a recognizable declaration whose method/path/command/handler/binding cannot be resolved,
   **When** recognition runs, **Then** a partial record is retained with explicit uncertainty and an
   investigation assignment; a parser failure is distinguished from a supported module with no matching
   units; and one unsupported file does not prevent recognition elsewhere.

---

### User Story 3 - Staged delivery with per-language end-to-end fixtures & support matrix (Priority: P1)

An operator (and reviewer) can see the feature delivered in stages, each language proven by a complete
**offline end-to-end scan fixture** (vulnerable, defended, and unresolved examples) that flows from
discovery through hunt assignment, verification, and a published report — with a per-language **support
matrix** stating exactly what is dedicated, limited, and unsupported. Go and JS/TS (with preserved
Python) are the first milestone but do not complete the feature; every baseline language has its own
acceptance criteria.

**Why this priority**: This is what prevents "language support" from meaning a listing or a regex pile:
each language must pass a real scan-to-report fixture, and completion requires all stages.

**Independent Test**: For each baseline language, run its offline scripted end-to-end fixture and confirm
a supported candidate, a rejected candidate (with a real defense), and an unresolved candidate each reach
the published report; confirm the support matrix entry matches observed behavior; confirm delivering only
Stage 1 does not mark the feature complete.

**Acceptance Scenarios**:

1. **Given** any baseline language, **When** its end-to-end offline fixture runs (controlled model
   responses, no live inference/network/runtime), **Then** discovered units reach real hunt assignments,
   candidate verification, and a published report — merely listing the language or finding identifier
   strings does not pass.
2. **Given** each language fixture, **When** it runs, **Then** it includes at least one vulnerable
   (supported), one defended (rejected with a real defense), and one unresolved example, and each is
   represented correctly end-to-end.
3. **Given** the delivery stages, **When** Stage 1 (Python/Go/JS/TS) is complete, **Then** the feature is
   NOT declared complete; Stages 2 and 3 languages remain required with their own fixtures and acceptance.
4. **Given** the published support matrix, **When** compared to observed behavior for each language, **Then**
   it accurately separates language readability, deterministic recognition (per application type),
   verification checks, fallback review, and known unsupported constructs, with recorded framework/parser
   versions and limits where relevant.

---

### User Story 4 - Feed discovered multi-language scope into real hunt work (Priority: P1)

An operator's scan integrates discovered multi-language scope into recon inputs, partition planning,
class-specific hunting, the sink-driven pass, and optional threat-model augmentation. Every in-scope
recognized unit (of any language/application type) and every fallback unit receives a persisted
assignment or an explicit unassigned/deferred reason, and a large mixed-language repository is never
silently collapsed into one unqualified whole-repository assignment.

**Why this priority**: Discovery only improves scan quality if it drives hunting and verification; this
turns breadth into findings. Part of the MVP scan-to-report flow.

**Independent Test**: On a mixed repository, confirm discovered non-Python units reach real hunt
assignments; when model recon is missing/malformed, confirm useful module/subsystem assignments are
derived from discovered scope; confirm the effective work plan (partition limits, augmentation, sampling,
assignment counts) is exposed and any bounded/stopped work preserves unassigned/unfinished scope with
reasons.

**Acceptance Scenarios**:

1. **Given** discovered units and fallback units across languages, **When** the scan plans work, **Then**
   each receives a persisted assignment or an explicit unassigned/deferred reason; nothing in scope is
   silently dropped.
2. **Given** missing or malformed model recon, **When** the scan plans work, **Then** it derives useful
   module/subsystem assignments from discovered scope rather than collapsing into a single unqualified
   whole-repository assignment.
3. **Given** a partitioned scan, **When** hunt agents work, **Then** cross-module calls and shared code
   remain available (a partition is not a hard source-read boundary), and language/framework/source
   context is available to the agents.
4. **Given** identities produced during a run, **When** artifacts are written, **Then** inventory,
   assignment, and finding identities are stable within the run and traceable across artifacts; shared
   handlers do not erase distinct exposed surfaces.
5. **Given** work limits, **When** the scan runs, **Then** effective limits and resulting assignment
   counts are exposed; bounded/stopped work preserves unassigned/unfinished scope with reasons; existing
   explicit threat-model settings are respected and broad discovery does not depend on the optional
   threat-model phase.

---

### User Story 5 - Evidence-backed verification compatibility per language (Priority: P1)

When a candidate in any supported language is verified, the actual function/handler and relevant
surrounding guards/context are available, exact source quotation and revision attribution are preserved,
candidate identity is stable, and the outcome is supported/rejected/unresolved — without applying
Python-only rules to other languages. If a construct or class cannot be checked, that limitation is
reported; the absence of an applicable checker is never presented as source evidence refuting a candidate.

**Why this priority**: Expanding discovery without preserving verification integrity produces
untrustworthy findings; this keeps evidence honest for every language. Part of the MVP.

**Independent Test**: For supported patterns per language, confirm verification sees the real
function/handler + guards, preserves exact quotation/revision/identity and supported/rejected/unresolved
outcomes; confirm a missing applicable checker yields unresolved/limitation, not a refutation; confirm
authorization/business-logic findings are reviewable without an injection-style sink.

**Acceptance Scenarios**:

1. **Given** Python-specific assumptions in candidate identity, source-location parsing,
   containing-function evidence, route/handler matching, authorization mapping, sink/class corroboration,
   and instance sweeping, **When** other languages are verified, **Then** the necessary pieces are adapted
   per language and Python-only rules are not applied to non-Python code.
2. **Given** a supported candidate in any baseline language, **When** it is verified, **Then** the actual
   function/handler and relevant guards/context are available, and exact source quotation, revision
   attribution, and stable candidate identity are preserved.
3. **Given** a construct or vulnerability class with no applicable checker for a language, **When**
   verification runs, **Then** the limitation is reported (unresolved) and is not represented as source
   evidence refuting the candidate; applicable explicit contradiction checks are preserved.
4. **Given** the goal of raising coverage numbers, **When** candidates are verified, **Then** candidates
   are not accepted merely to improve numbers, and injection-style sinks are not imposed on authorization
   or business-logic findings.

---

### User Story 6 - Honest multi-axis coverage & published findings across languages (Priority: P1)

An operator reading coverage can distinguish the **source census**, **inventory support/completeness**,
**assignment coverage**, and **review completion** — per language and per application type — and sees
published findings tied to real units. A "reviewed" disposition requires a real unit-specific analysis
record with resolving source references; completeness is always qualified by support and scope; and
counts that mix source files, routes, CLI commands, and fallback units into one misleading percentage
are prohibited.

**Why this priority**: Honest, non-misleading coverage is the difference between trustworthy breadth and
a false sense of safety; core evidence integrity.

**Independent Test**: With a two-unit file where only one unit has evidence, confirm the other stays
unreviewed; confirm mention-only outputs, malformed dispositions, missing IDs, missing source references,
failed agents, and truncated assignments cannot create false completed coverage; with a supported module
beside an unsupported one, confirm scoped progress plus unresolved whole-repository completeness, with
counts consistent across inventory, assignments, review records, API, scan details, and reports, and
explicit denominator labels.

**Acceptance Scenarios**:

1. **Given** discovery output, **When** coverage is computed, **Then** source census, inventory
   support/completeness, assignment coverage, and review completion are distinct axes and are not combined
   into one misleading percentage across differing unit kinds.
2. **Given** any recognized unit or fallback unit, **When** it is tracked, **Then** its state is one of:
   assigned, reviewed-with-finding, reviewed-without-finding, unresolved/incomplete, excluded (with reason),
   or not reviewed; a "reviewed" state requires an explicit unit-specific analysis record with resolving
   source references and an outcome.
3. **Given** a file with two units and evidence for only one, **When** coverage is computed, **Then** the
   second is not marked reviewed; a filename/identifier mention or a finding elsewhere in the file does not
   mark sibling units reviewed; referenced IDs are validated to belong to the run and source references
   resolve (no invented dispositions).
4. **Given** a supported module alongside an unsupported/unresolved one, **When** coverage is reported,
   **Then** completeness is qualified per language/application type; zero discovered units is not "clean";
   empty and legitimately non-web/non-service repositories are explained distinctly from discovery
   failures; execution/coverage/validation remain independent axes with equivalent degradation reporting
   across languages.

---

### User Story 7 - Consistent disclosure, support matrix & preservation of prior work (Priority: P1)

An operator sees understandable language, framework, module, application-type, and unresolved-scope
information in scan details and reports, with equivalent semantics in machine-readable outputs/exports,
and a published support matrix — all additive, with no broad UI redesign and no disturbance to existing
dashboard values/charts. Historical reports open without a forced rescan or rewritten evidence, older
records are labeled legacy/unknown, and resume/regeneration never accepts stale inventory as valid
completion or invents historical review evidence.

**Why this priority**: The expansion must be visible and trustworthy while strictly preserving prior work
and the operator's metrics; regressions to features 008–011 are unacceptable.

**Independent Test**: Confirm discovery provenance, support limitations, inventories, assignments, review
dispositions, coverage summaries, and the support matrix persist and appear in scan details, reports, and
machine-readable outputs with consistent semantics; open existing history and confirm no forced rescan,
no rewritten evidence, legacy labeling, and that existing dashboard metrics, application/ledger
management, and analyst review decisions do not regress.

**Acceptance Scenarios**:

1. **Given** a completed multi-language scan, **When** results are viewed, **Then** discovery provenance,
   support limitations, inventories, assignments, review dispositions, coverage summaries, and the support
   matrix are persisted and shown in scan details and reports, with equivalent semantics in
   machine-readable outputs/exports.
2. **Given** the existing dashboard, **When** coverage information is added, **Then** it is additive and
   clearly scoped; existing dashboard values and charts are maintained; no broad UI redesign occurs.
3. **Given** historical reports and existing route consumers, **When** the feature ships, **Then** they
   continue to open/work via documented compatibility/version handling; older records without the new
   evidence are labeled unknown/legacy rather than retroactively declared complete.
4. **Given** a resumed or regenerated scan, **When** it runs, **Then** it does not reuse incompatible or
   stale inventory/work as valid completion, does not invent historical review evidence, and does not
   silently launch a scan.

---

### Edge Cases

- A single unsupported or malformed file must not prevent recognition in other files/modules, nor reject
  the whole scan.
- A frontend-only project, an unsupported-language library, a parser/file processor, a background worker,
  a message consumer, and an RPC service each get explicit discovery limits and scoped fallback work —
  none reported clean/fully covered because zero HTTP routes were found.
- Empty repositories and legitimately non-web/non-service repositories are explained distinctly from
  discovery failures; a library or CLI-only repo is not "0% covered" for lacking routes.
- Fake routes/commands in strings/comments, unreachable/dead code, and dynamic expressions do not produce
  spurious or fabricated recognitions.
- Shared handlers/functions across distinct surfaces, and identical identifiers in different apps, are kept
  distinct.
- Malformed recon, discovery/parser failure, exhausted work limits, and interrupted scans preserve
  completed evidence and expose remaining work; repeated inventory over unchanged input is deterministic
  (same IDs, ordering, counts).
- Escaping symlinks and path-escape attempts are contained; excluded tests/dependencies never count as
  reviewed production source.
- A language present only via generated code or vendored dependencies is not counted as first-party
  supported coverage.

## Requirements *(mandatory)*

### Functional Requirements

**Language baseline & per-language support (cross-language)**

- **FR-001**: The system MUST support the baseline languages — Python, Go, JavaScript, TypeScript, Java,
  Kotlin, C#, C, C++, Rust, Ruby, PHP — as first-class targets for source-code vulnerability analysis;
  none is optional to complete the feature.
- **FR-002**: For each baseline language, the system MUST provide, as independently testable capabilities,
  all six support dimensions: (a) source & module discovery; (b) investigation units (functions/methods,
  relevant source context, investigation boundaries); (c) representative external inputs and
  security-sensitive operations appropriate to the language and application type; (d) assignment to real
  hunt work; (e) candidate extraction and evidence-backed verification compatibility; (f) honest coverage
  accounting and published findings. Each (language × dimension × dedicated application-type) is a
  distinct, checkable support-matrix cell.
- **FR-003**: Language support MUST NOT be claimed from recognizing a file extension, listing a language,
  or assigning the whole repository to a generic fallback agent; and MUST NOT be equated with enumerating
  HTTP routes. Each supported language MUST demonstrate concrete recognition of its representative units,
  inputs, and sensitive operations.
- **FR-004**: The system MUST document representative framework/API patterns, external inputs, and
  security-sensitive operations per baseline language (the baseline table), and MUST make recognition
  boundaries and known-unsupported constructs explicit; it MUST NOT promise exhaustive framework support,
  complete call graphs, or universal vulnerability detection.

**Application-type coverage (beyond HTTP)**

- **FR-005**: The system MUST recognize and account for the application types web app, CLI tool, library,
  parser/file processor, background worker, message consumer, RPC service, and browser-side code, and MUST
  define per (language, application-type) whether recognition is dedicated or limited (scoped fallback).
- **FR-006**: Non-web surfaces MUST NOT be dropped for lacking HTTP routes; each MUST receive dedicated
  recognition or a scoped fallback investigation unit with disclosed limits, kept distinct from verified
  registrations. The system MUST NOT treat every exported function or UI component as an external entry
  point, and MUST model CLI/library/worker/consumer/RPC inputs honestly (no fake HTTP methods/paths).

**Whole-repository census & support disclosure (US1)**

- **FR-007**: The scan MUST inventory first-party source by language, module/package, application type, and
  recognizable framework signals before relying on recognizers, retaining detection evidence and marking
  ambiguous cases visibly.
- **FR-008**: The inventory MUST distinguish production source, tests, generated code, dependencies,
  unreadable files, and unsupported formats, apply exclusions consistently across census/discovery/
  assignment/coverage, record a reason per exclusion, and MUST NOT count excluded dependencies or generated
  code as reviewed first-party production source.
- **FR-009**: For each module the inventory MUST expose separately: detected language/framework/application
  type, deterministic recognition support, recognized surface kinds, limitations/errors, and whether scoped
  fallback review was assigned; unsupported or dynamically unresolved surfaces MUST be reported as
  unknown/unresolved/limited, never as an absence of attack surface.
- **FR-010**: Repository/result path confinement and symlink rules MUST be preserved during inventory.

**Recognition of units, inputs & sensitive operations (US2)**

- **FR-011**: Each recognized unit MUST carry a source-grounded identity, source location,
  language/framework, module, application type, surface kind, function/handler reference, and
  surface-specific details where applicable (HTTP method+effective path for web; command/dispatch identity
  for CLI; message/topic for consumers; method for RPC; exported API/parse entry for libraries/parsers; DOM
  sink for browser code).
- **FR-012**: Recognizers MUST handle multiline declarations, comments/strings containing fake
  routes/commands, aliases, separately defined/imported handlers, nested groups/mounting/prefixes, multiple
  methods, and parameterized paths within each language's declared boundary; MUST distinguish
  declaration/registration locations from implementation locations; MUST preserve distinct exposed surfaces
  sharing a handler and identical identifiers in different applications; and MUST resolve statically knowable
  prefixes/constants without fabricating values for dynamic expressions or custom wrappers.
- **FR-013**: The system MUST identify representative external inputs and attribute them to their unit, and
  MUST locate representative security-sensitive operations with source context sufficient for
  hunting/verification.
- **FR-014**: When a declaration is recognizable but its method/path/command/handler/binding cannot be
  resolved, the system MUST retain a partial record with explicit uncertainty and an investigation
  assignment; a parser failure MUST be distinguished from a supported module with no matching units; and a
  single unsupported file MUST NOT prevent recognition in other files or modules.

**Staged delivery, fixtures & support matrix (US3)**

- **FR-015**: Delivery MUST be staged (Stage 1: Python/Go/JavaScript/TypeScript; Stage 2: Java/C#/Ruby/PHP;
  Stage 3: Kotlin/C/C++/Rust); Go and JavaScript/TypeScript MUST be preserved/delivered as early milestones
  but MUST NOT be treated as completion of the feature. The feature is complete only when every baseline
  language meets its acceptance criteria.
- **FR-016**: Every baseline language MUST have a concrete, offline, end-to-end scan fixture that flows from
  discovery through hunt assignment, verification, and a published report, and MUST include at least one
  vulnerable (supported), one defended (rejected with a real defense), and one unresolved example.
- **FR-017**: The system MUST publish a per-language **support matrix** separating language readability,
  deterministic recognition (per application type), verification checks, fallback review, and known
  unsupported constructs, with recorded framework/parser versions and limits where relevant; the matrix MUST
  match observed behavior and carry acceptance criteria per language.
- **FR-018 (SM)**: The specification, plan, tasks, and delivered support matrix MUST remain consistent about
  which (language, application-type) combinations are dedicated, limited, or unsupported; a language MUST NOT
  be marked supported without its passing end-to-end fixture.

**Integration into scan work (US4)**

- **FR-019**: Discovered scope MUST be integrated with recon inputs, partition planning, class-specific
  hunting, the sink-driven pass, and optional threat-model augmentation — an inventory used only for display
  is insufficient.
- **FR-020**: Every in-scope recognized unit and fallback unit (any language/application type) MUST receive
  a persisted assignment or an explicit unassigned/deferred reason; when model recon is missing or
  malformed, the system MUST derive useful module/subsystem assignments from discovered scope and MUST NOT
  silently collapse a large mixed-language repository into one unqualified whole-repository assignment.
- **FR-021**: Cross-module calls and shared code MUST remain available for investigation (a partition is not
  a hard source-read boundary), and language/framework/source context MUST be available to hunt agents.
- **FR-022**: Inventory, assignment, and finding identities MUST be stable within a run and traceable across
  artifacts; shared handlers MUST NOT erase distinct exposed surfaces.
- **FR-023**: The system MUST define and expose effective work limits (partition limits, augmentation,
  sampling, resulting assignment counts); bounded/stopped work MUST preserve unassigned/unfinished scope with
  reasons and MUST NOT silently omit scope or expand work without recording the effective plan. Existing
  explicit threat-model settings MUST be respected, and broad source discovery MUST NOT depend on enabling
  the optional threat-model phase.

**Coverage accounting (US6)**

- **FR-024**: The system MUST distinguish source census, inventory support/completeness, assignment
  coverage, and review completion (per language and application type) and MUST NOT combine differing unit
  kinds (source files, routes, commands, fallback units) into a single misleading percentage.
- **FR-025**: Each unit MUST be tracked through exactly one of: assigned, reviewed-with-finding,
  reviewed-without-finding, unresolved/incomplete, excluded (with reason), or not reviewed. A "reviewed"
  disposition MUST require an explicit unit-specific analysis record with resolving source references and an
  outcome.
- **FR-026**: A filename/identifier mention, or a finding elsewhere in the same file, MUST NOT mark sibling
  units reviewed; referenced IDs MUST be validated to belong to the run and source references MUST resolve;
  the system MUST NOT invent a completed disposition when the agent omitted it.
- **FR-027**: Completeness MUST be qualified by support and scope: full review of one supported module MUST
  NOT establish whole-repository coverage while unsupported/unresolved scope remains; zero discovered units
  MUST NOT be "clean/100% covered"; empty and legitimately non-web/non-service repositories MUST be explained
  distinctly from discovery failures; execution status, coverage status, and validation mode MUST remain
  independent axes with degradation reporting equivalent across languages.

**Verification integrity (US5)**

- **FR-028**: Python-specific assumptions in candidate identity, source-location parsing, containing-function
  evidence, route/handler matching, authorization mapping, sink/class corroboration, and instance sweeping
  MUST be adapted per language and MUST NOT be applied to non-Python code.
- **FR-029**: For supported patterns, verification MUST have the actual function/handler and relevant guards/
  context available, and MUST preserve exact source quotation, revision attribution, stable candidate
  identity, and supported/rejected/unresolved outcomes.
- **FR-030**: If a construct or vulnerability class cannot be checked for a language, the system MUST report
  that limitation (unresolved) and MUST NOT represent the lack of a checker as source evidence refuting the
  candidate; applicable explicit contradiction checks MUST be preserved.
- **FR-031**: The system MUST NOT accept a candidate merely to improve language-coverage numbers, and MUST
  NOT impose injection-style sinks on authorization or business-logic findings. This feature does not promise
  comprehensive taint analysis, equal detection accuracy across languages, or execution-based exploit
  confirmation; reproduction remains authored-only unless the operator separately invokes an existing
  authorized execution capability.

**Disclosure & historical preservation (US7)**

- **FR-032**: Discovery provenance, support limitations, inventories, assignments, review dispositions,
  coverage summaries, and the support matrix MUST be persisted and shown in scan details and reports, with
  equivalent semantics in machine-readable outputs and exports.
- **FR-033**: New coverage/support information MUST be additive and clearly scoped; existing dashboard values
  and charts MUST be maintained and no broad UI redesign MUST be required.
- **FR-034**: Historical reports and existing route/report consumers MUST continue to work via documented
  compatibility/version handling; older records without the new evidence MUST be labeled unknown/legacy
  rather than retroactively declared complete.
- **FR-035**: Resume MUST NOT reuse incompatible or stale inventory/work as valid completion; regeneration
  MUST NOT invent historical review evidence or silently launch a scan.

**Preservation of prior work & safety (cross-cutting)**

- **FR-036**: The feature MUST preserve in-progress work and existing scan history, application names, review
  decisions, ledgers, reports, and the operator's dashboard metrics/charts, and MUST NOT change unrelated UI
  management behavior from features 008–011.
- **FR-037**: The scanner MUST NOT execute or import target code, install its dependencies, start its
  services, or invoke its build scripts to discover source/units; inventory and recognition MUST NOT require
  the target's language toolchains/runtimes (Python, Node, Go, JVM, .NET, Rust, Ruby, PHP, C/C++ compilers);
  the shipped application MUST remain self-contained/offline-capable.
- **FR-038**: Repository/result path confinement, secret handling, explicit inference destinations, and
  existing scan safety defaults MUST be preserved.
- **FR-039**: Added parsing/recognition dependencies MUST be justified against the constitution's dependency
  budget, MUST prefer accurate syntax-aware recognition over untested regex accumulation, and MUST record
  parser/framework versions and recognition limits; a growing collection of untested regexes is not an
  acceptable completeness argument.

**Validation (cross-cutting)**

- **FR-040**: All acceptance tests MUST run without live inference, network access, or target-language
  runtimes; discovery MUST be verified not to execute code, install dependencies, escape source boundaries,
  or modify the target. Scripted-pipeline validation (controlled model responses proving the flow) MUST be
  kept distinct from empirical detection accuracy; a separate bounded manual evaluation on representative
  real repositories MUST be planned and reported as limitations + empirical results without requiring an
  unsolicited paid or long-running model scan.

### Key Entities *(include if feature involves data)*

- **Source census entry**: A first-party source unit's record — language, module/package, application type,
  framework signals, classification (production/test/generated/dependency/unreadable/unsupported), and
  detection evidence.
- **Module/unit**: A module/package with detected language/framework/application type, deterministic-support
  status, recognized surface kinds, limitations/errors, and fallback-assignment flag.
- **Investigation unit**: A recognized function/method/entry with source context and investigation boundary,
  surface kind (web route, CLI command, library API, parser/deserialization entry, worker/consumer handler,
  RPC method, browser DOM sink), identity, and resolution certainty (resolved/partial/unresolved).
- **External input**: A representative untrusted input attributed to a unit (request field, argv, env,
  message payload, file/stream, DOM/location), with source location.
- **Security-sensitive operation**: A representative dangerous operation located in source (command exec,
  SQL, deserialization, unsafe memory/string ops, template/HTML sink, file/path op, reflection), with context.
- **Fallback investigation unit**: A scoped analysis unit for a surface with no tested recognizer, distinct
  from verified recognitions and labeled with limits.
- **Assignment**: Mapping of a unit/fallback unit to hunt work, with persisted status or explicit
  unassigned/deferred reason; carries the effective work plan/limits.
- **Coverage record**: Per-unit disposition (assigned / reviewed-with-finding / reviewed-without-finding /
  unresolved-incomplete / excluded-with-reason / not-reviewed) plus the four distinct coverage axes (census,
  inventory support, assignment, review) with explicit denominators/labels, per language and application type.
- **Verification record (per language)**: The candidate's function/handler + guards/context, exact quotation,
  revision, stable identity, outcome (supported/rejected/unresolved), and checker-limitation notes.
- **Support matrix entry**: Per (language, application-type) — readability, deterministic recognition,
  verification checks, fallback review, known unsupported constructs, framework/parser versions/limits, and
  acceptance status (tied to a passing end-to-end fixture).
- **Language fixture**: An offline end-to-end scan fixture for a language with vulnerable/defended/unresolved
  examples and its independently authored expected inventory/coverage.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001 (Per-language end-to-end flow)**: Each of the 12 baseline languages passes its offline scripted
  end-to-end fixture (controlled model responses; no live inference/network/runtime): discovered units reach
  real hunt assignments, candidate verification, and a published report, including a supported, a rejected
  (real defense), and an unresolved example. Merely listing a language or finding identifier strings does not
  pass.
- **SC-002 (Beyond HTTP)**: For each language, at least its dedicated non-web application types from the
  baseline table (e.g., CLI, library/parser, worker/consumer, RPC, browser-side as applicable) are recognized
  with units, external inputs, and sensitive operations — coverage is never derived solely from HTTP routes,
  and a CLI-only or library-only repository is not reported "0% covered" for lacking routes.
- **SC-003 (Exact-fixture recognition)**: A manually authored fixture corpus covers every required
  (language, application-type) recognizer with expected inventories authored independently of the
  implementation; for documented supported patterns, 100% of expected units, input/operation identities, and
  source locations match, and negative controls (fake routes/commands in strings, dead code) yield zero
  spurious recognitions.
- **SC-004 (Realistic-code robustness)**: Fixtures include aliases, multiline declarations, nested/mounted
  groups, multiple methods, shared handlers, duplicate identifiers in separate apps, dynamic expressions,
  malformed files, unreachable/commented examples, excluded tests/dependencies, generated code, and escaping
  symlinks — each handled per the requirements (no spurious, fabricated, or whole-scan-dropping results).
- **SC-005 (Mixed-language inventories)**: A mixed monorepo spanning multiple baseline languages/application
  types yields separate accurate inventories, assignments, and coverage; a non-Python repository never uses a
  Python-empty inventory as its whole-repository denominator; Python behavior remains covered by its own
  tests and independent fixtures.
- **SC-006 (Fallback honesty)**: A frontend-only project, an unsupported-language library, a parser/file
  processor, a background worker, a message consumer, and an RPC service each receive explicit discovery
  limits and scoped fallback work, and none is reported clean/fully covered merely because zero HTTP routes
  were found.
- **SC-007 (No false completion & consistent counts)**: A two-unit file with evidence for only one unit
  leaves the other unreviewed; mention-only outputs, malformed dispositions, missing IDs, missing source
  references, failed agents, and truncated assignments cannot create false completed coverage; counts remain
  consistent across persisted inventory, assignments, review records, API, scan details, and reports, with
  explicit denominator labels.
- **SC-008 (Staged delivery & support matrix)**: Delivering Stage 1 (Python/Go/JS/TS) does not mark the
  feature complete; the published per-language support matrix matches observed behavior for every language and
  each "supported" mark is backed by a passing end-to-end fixture; Stages 2 and 3 languages have their own
  fixtures and acceptance.
- **SC-009 (Failure & determinism)**: Malformed recon, discovery/parser failure, exhausted work limits, and
  interrupted scans preserve completed evidence and expose remaining work; repeated inventory over unchanged
  input produces identical IDs, ordering, and counts; resume neither duplicates work nor accepts stale
  discovery as current evidence.
- **SC-010 (No regression to prior work)**: Existing history opens without a forced rescan or rewritten
  evidence, legacy coverage is labeled appropriately, and existing dashboard metrics, application/ledger
  management, and analyst review decisions do not regress.
- **SC-011 (Offline, non-executing acceptance)**: All acceptance tests run without live inference, network, or
  target-language runtimes installed; discovery is verified not to execute code, install dependencies, escape
  source boundaries, or modify the target; the relevant existing tests and the full offline suite pass before
  completion, with actual results and skipped checks recorded honestly.
- **SC-012 (Scripted vs empirical)**: Scripted-pipeline validation (proving the flow with controlled model
  responses) is reported separately from a bounded manual empirical evaluation on representative real
  repositories; empirical results and limitations are documented without an unsolicited paid or long-running
  model scan, and scripted passes are never presented as empirical detection-accuracy claims.

## Assumptions

- **Baseline language set is fixed and all required**: Python, Go, JavaScript, TypeScript, Java, Kotlin, C#,
  C, C++, Rust, Ruby, PHP. Delivery is staged (Stage 1 Python/Go/JS/TS as early milestones; Stage 2
  Java/C#/Ruby/PHP; Stage 3 Kotlin/C/C++/Rust), but no baseline language is optional for completion. The
  stage grouping is a documented planning assumption chosen to sequence work; it may be re-ordered in the plan
  provided every language keeps its fixture and acceptance criteria.
- **Representative, not exhaustive, patterns**: the baseline table fixes the representative frameworks/APIs,
  external inputs, and security-sensitive operations per language that fixtures and acceptance are authored
  against. Exact recognized constructs and known-unsupported constructs per (language, application-type) are
  finalized in the plan and published in the support matrix. No exhaustive framework support, complete call
  graphs, or universal vulnerability detection is promised.
- **Named languages/frameworks are target code to analyze**, not vhlocal's implementation stack, and are never
  executed. The scanner never runs target code or requires target-language toolchains/runtimes to discover
  source/units (FR-037).
- **Support means concrete capability, not listing**: a language is "supported" only when it passes its
  end-to-end offline fixture and its support-matrix cells are backed by tests. File readability, a language
  listing, or a whole-repo generic fallback is not support; HTTP-route enumeration is not a proxy for language
  support.
- **Application-type breadth**: web, CLI, library, parser/file processor, background worker, message consumer,
  RPC service, and browser-side code are all in scope; each (language, application-type) is declared dedicated
  or limited (scoped fallback). General model-guided review of unsupported languages/combinations remains
  available; one unsupported module never rejects the scan.
- **Recognition approach & dependency budget**: syntax-aware recognition is preferred over untested regex
  accumulation; any added parsing dependency is justified against the constitution's dependency budget with
  recorded versions/limits (decided in the plan).
- **Independent expectations**: the original Python application can inform expected behavior, but each new
  language requires independently authored expectations and fixtures; mirroring the old implementation's
  limitations is not acceptance.
- **Validation is offline and honest**: fixtures + scripted scans with controlled model responses prove the
  flow with no live inference/network/target runtimes; a separate bounded manual empirical evaluation on real
  repositories is planned and reported as limitations + results, without an unsolicited paid or long-running
  model scan. Consistent with prior features and the standing project constraint, no workloads are sent to a
  live model.
- **Preservation**: features 008–011 behavior (dashboard metrics/charts, application/ledger management,
  analyst review decisions, reports, ledgers, history) is preserved; new information is additive with no broad
  UI redesign; historical data is labeled legacy/unknown, never retroactively completed.

### Explicit Exclusions / Non-Goals

- Full compiler-grade call graphs, comprehensive taint analysis, and unrestricted dynamic-registration
  resolution.
- Automatic CVE lookups, dependency-vulnerability scanning, and license/SBOM-based vulnerability claims (SBOM
  remains a separate existing capability).
- New dynamic execution of target code, execution-based exploit confirmation, and any requirement to install
  or run target-language toolchains/runtimes for discovery.
- Equal detection accuracy across languages, universal vulnerability detection, and exhaustive framework
  feature support (e.g., every Next.js feature, every Spring annotation, every framework middleware).
- Languages/frameworks beyond the fixed baseline (additional adapters may be proposed separately after this
  scope passes); appearance in a language list or file-extension presence does not constitute support.
- A broad UI redesign; changes to unrelated feature 008–011 management behavior.
