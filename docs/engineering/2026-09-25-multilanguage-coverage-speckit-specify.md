# Claude Spec Kit handoff: Expand scan coverage breadth

Prepared: 2026-09-25

## What is being expanded

vhlocal-go is not restricted to analyzing Python source: its model agents can
read multiple languages, and its reconnaissance instructions explicitly cover
them. The implemented deterministic entry-point inventory, however, scans
Python files for selected web-route patterns. Several downstream coverage and
verification helpers also assume Python. Broad model reading capability does
not establish measured, end-to-end language support.

This handoff requests a specification, not immediate application edits. It
does not create a feature branch or change the active Spec Kit feature.

## Start in Claude

From the repository, paste:

```text
/speckit-specify Expand vhlocal-go's scan coverage breadth beyond its Python-oriented automatic inventory. Read docs/engineering/2026-09-25-multilanguage-coverage-speckit-specify.md and use the entire "Specification input" section as the feature description. Create one feature specification and its requirements quality checklist. Prioritize working Go and JavaScript/TypeScript coverage alongside preserved Python support, including end-to-end hunt assignment, verification compatibility, honest coverage accounting, and offline regression fixtures. Do not begin implementation in the specify step.
```

If that slash command is unrecognized, use the same instruction starting with
`Use the repository's speckit-specify skill to` instead of `/speckit-specify`.
After reviewing the generated specification, proceed through `speckit-plan`,
`speckit-tasks`, `speckit-analyze`, and `speckit-implement`.

## Specification input

Create a feature specification named "Multi-language scan coverage" for
vhlocal-go. The operator wants to improve scan quality by expanding coverage
breadth immediately. The desired outcome is that supported non-Python code is
discovered, assigned for investigation, and represented accurately in scan
coverage and findings, rather than depending entirely on model reconnaissance
or collapsing into an unexplained whole-repository pass.

Read `.specify/memory/constitution.md` and relevant existing scan, parity, and
analyst-workspace specifications first. Inspect current behavior rather than
assuming comments, prompts, or prior specifications prove support. Preserve
in-progress work, existing scan history, application names, review decisions,
ledgers, reports, and the user's existing dashboard metrics and charts. Do not
change unrelated UI management behavior from features 008–011.

### Scope and delivery priorities

The following initial scope is an explicit planning assumption selected to
deliver useful breadth promptly. It is not a claim that these stacks already
have complete support. Treat the named frameworks as target code to analyze,
not a mandated implementation stack or a requirement to execute them.

| Priority | Target | Required initial recognition |
|---|---|---|
| P1 | Python | Preserve and regression-test supported FastAPI and Flask HTTP/WebSocket patterns; expose remaining limitations |
| P1 | Go | Standard `net/http` registrations and method/path ServeMux patterns, Chi routing, Gin routing |
| P1 | JavaScript and TypeScript | Express routers, Fastify routes, Next.js server API routes in Pages Router and App Router layouts |
| P2 | CLI entry points | Python argparse dispatch, Go standard flag/main and Cobra command handlers, JavaScript/TypeScript Commander handlers |
| P1 | Mixed-language and other repositories | Source/language census, support disclosure, scoped fallback investigation units, and explicit unsupported/unresolved coverage |

Go and JavaScript/TypeScript are equally required delivery targets; do not
declare the feature complete after delivering only one. P2 CLI support remains
part of this feature and must have concrete tests. Other framework adapters
can be proposed separately after this scope works. In particular, do not claim
complete support for Java, C#, Rust, C/C++, Ruby, PHP, or every Python framework
merely because their files are readable or appear in a language list.

General review of unsupported languages must remain available. Do not reject
an entire scan because one module lacks deterministic discovery support.

### P1: Inventory the whole repository and disclose support

Before relying on route discovery, inventory first-party source by language,
module/package, and recognizable framework signals. Keep detection evidence
and ambiguous cases visible. File extensions alone may identify source
language but do not establish a framework or a complete attack surface.

Handle mixed-language monorepos and multiple applications/modules explicitly.
Distinguish production source, tests, generated code, dependencies, unreadable
files, and unsupported formats. Apply exclusions consistently across census,
discovery, hunt assignments, and coverage. Preserve containment and symlink
rules. Record why files or units are excluded; do not count excluded dependencies
as reviewed production source.

For each module, expose separately: detected language/framework, deterministic
discovery support, recognized surface kinds, limitations/errors, and whether
model-guided fallback review was assigned. Unsupported or dynamically unresolved
surface discovery must not be reported as an absence of attack surface.

Frontend/browser code, shared libraries, parsers, background workers, RPC,
message consumers, and serverless modules must not vanish merely because they
have no HTTP route declarations. Use scoped fallback investigation units for
these surfaces unless a tested recognizer exists. Do not count every exported
function or React component as an external entry point. Keep fallback analysis
units distinct from verified entry-point registrations and label their limits.

### P1: Recognize concrete entry points across the initial web stacks

Produce an inventory with source-grounded entry-point identities, source
locations, language/framework, module, surface kind, handler references, and
protocol-specific details such as HTTP method and effective route path.

Handle ordinary multiline declarations, comments and strings containing fake
routes, import aliases, separately defined/imported handlers, nested route
groups, router mounting, prefixes, multiple methods, and parameterized paths
within each supported framework's declared recognition boundary. Distinguish
route registration locations from handler implementation locations. Preserve
different effective routes that share a handler and identical route strings in
different applications. Resolve statically knowable prefixes and constants;
do not fabricate values for dynamic expressions or custom runtime wrappers.

When a registration is recognizable but its method, path, handler, or binding
cannot be resolved, retain a partial record with explicit uncertainty and an
investigation assignment. Parser failure is different from a supported module
with no matching entry points. A single unsupported file must not prevent
discovery in other files or modules.

For Next.js, distinguish server API handlers from browser pages/components.
Document which layouts, extensions, method exports, and dynamic segments are
recognized. Do not imply that API-route support includes every framework
feature, such as middleware or server actions.

### P2: Include bounded non-HTTP recognition

Recognize the CLI dispatch patterns in the scope table with command name or
dispatch identity, handler/source location, and declared inputs where statically
available. Model CLI input and local trust/preconditions honestly; do not force
commands into fake HTTP methods or route paths.

Recognized CLI units participate in hunt assignment, coverage, and verification
like web entry points. A standalone command must not receive zero scope simply
because no web framework was detected. Dynamic command registration remains
explicitly unresolved. Other non-HTTP surfaces receive the scoped fallback
behavior above, without claims of exhaustive discovery.

### P1: Feed discovered scope into real scan work

Integrate the inventory with recon inputs, partition planning, class-specific
hunting, the sink-driven pass, and optional threat-model augmentation. An
inventory used only for display is insufficient.

Every in-scope recognized entry point and fallback investigation unit must
receive a persisted assignment or an explicit unassigned/deferred reason.
When model recon is missing or malformed, derive useful module/subsystem
assignments from discovered non-Python scope. Do not silently collapse a large
mixed-language repository into one unqualified whole-repository assignment.

Keep cross-module calls and shared code available for investigation rather
than treating a partition as a hard source-read boundary. Make framework and
source-location context available to hunt agents. Inventory, assignment, and
finding identities must be stable within a run and traceable across its
artifacts; shared handlers must not erase distinct exposed routes.

Define and expose the effective work limits, including initial partition
limits, augmentation, sampling, and resulting assignment counts. If work is
bounded or stopped, preserve the unassigned or unfinished scope with reasons.
Do not silently omit scope or expand work without recording the effective plan.
Existing explicit threat-model settings remain respected; broad source
discovery must not depend on enabling the optional threat-model phase.

### P1: Make coverage meaningful across languages

Distinguish source census, inventory support/completeness, assignment coverage,
and review completion. Finding an entry point, creating an assignment, and
finishing its review are different facts. Do not combine source-file counts,
HTTP route counts, and fallback module counts into a misleading percentage.

Track each entry point or fallback unit through assigned, reviewed with a
finding, reviewed without a finding, unresolved/incomplete, excluded with a
reason, or not reviewed. A reviewed disposition requires an explicit
unit-specific analysis record with source references and its outcome. A bare
mention of a filename/route, or a finding elsewhere in the same file, must not
mark sibling entry points reviewed. Validate that referenced IDs belong to the
run and that source references resolve; do not invent a completed disposition
when the agent omitted it.

Completeness must be qualified by support and scope. Reviewing all recognized
Express routes does not establish whole-repository coverage when an adjacent
unsupported module or unresolved registration remains. Zero discovered routes
must not mean "clean" or "100% covered". Empty repositories and legitimately
non-web repositories need distinct explanations from discovery failures.

Report scoped progress even when whole-repository completeness is unknown.
Preserve execution status, coverage status, and validation mode as independent
axes. Generalize Python-only source-size and collapsed-partition warnings so
equivalent non-Python scans receive equivalent degradation reporting.

### P1: Preserve verification integrity for the added languages

Trace Python-specific assumptions in candidate identity, source location
parsing, containing-function evidence, route/handler matching, authorization
mapping, sink/class corroboration, and instance sweeping. Adapt the pieces
necessary to handle the new stacks without applying Python-only rules to them.

For supported initial patterns, make the actual handler and relevant surrounding
guards/context available to verification. Preserve exact source quotation,
revision attribution, stable candidate identity, and supported/rejected/unresolved
outcomes. If a language construct or class cannot be checked, report that
limitation; lack of an applicable checker must not be represented as source
evidence refuting the candidate. Preserve explicit contradiction checks where
they are applicable. Do not accept every candidate merely to improve language
coverage numbers, and do not impose injection-style sinks on authorization or
business-logic findings.

This feature expands coverage and necessary verification compatibility; it
does not promise comprehensive taint analysis, equal detection accuracy across
languages, or execution-based exploit confirmation. Reproduction remains
authored-only unless the operator separately invokes an existing authorized
execution capability.

### P1: Expose results consistently and preserve historical data

Persist discovery provenance, support limitations, inventories, assignments,
review dispositions, and coverage summaries. Show understandable language,
framework, module, and unresolved-scope information in scan details and reports,
with equivalent semantics in machine-readable outputs and exports that carry
coverage/status information. Avoid a broad UI redesign.

Maintain existing dashboard values and charts; any new coverage information is
additive and clearly scoped. Preserve historical reports and existing route
consumers through documented compatibility/version handling. Older records
without the new evidence remain unknown/legacy rather than being retroactively
declared complete. Resume must not reuse incompatible or stale inventory/work
as valid completion; regeneration must not invent historical review evidence
or silently launch a scan.

### Constraints and non-goals

- Keep the shipped application self-contained and offline-capable. Do not
  require the target's Python, Node, Go, or other language toolchain merely to
  inventory source. Do not execute/import target code, install its dependencies,
  start its services, or invoke its build scripts to discover routes.
- Preserve repository/result path confinement, secret handling, explicit
  inference destinations, and existing scan safety defaults.
- Prefer accurate, tested recognition boundaries over a long unsupported
  language list. Record parser/framework versions and limits where relevant.
  The plan must justify added dependencies against the constitution and
  evaluate syntax-aware approaches; a growing collection of untested regexes
  is not an acceptable completeness argument.
- Full compiler-grade call graphs, unrestricted dynamic registration
  resolution, automatic CVE lookups, dependency-vulnerability scanning, new
  dynamic execution, and all-language parity are outside this feature.
- The original Python application can inform expected behavior, but new
  language support requires independent expectations and fixtures. Mirroring
  the old implementation's limitations is not acceptance for the expansion.

### Acceptance and quality evidence

Translate the following into numbered requirements, prioritized user stories,
Given/When/Then scenarios, and measurable success criteria:

1. A manually specified fixture corpus covers every required initial web
   recognizer and CLI pattern. Expected inventories are authored independently
   of the discovery implementation. For the documented supported patterns,
   every expected entry point, method/path or command identity, and handler
   location matches; negative controls yield no spurious registrations.
2. Fixtures include aliases, multiline declarations, mounted/nested routers,
   multiple methods, shared handlers, duplicate paths in separate apps, dynamic
   expressions, malformed files, unreachable/commented examples, fake routes
   inside strings, excluded tests/dependencies, and escaping symlinks.
3. A mixed Python/Go/TypeScript repository yields separate accurate inventories
   and assignments. A non-Python-only repository does not use a Python-empty
   inventory as its whole-repository coverage denominator. Python behavior
   remains covered by its existing tests and independent expected fixtures.
4. A frontend-only project, an unsupported-language library, and a background
   worker each receive explicit discovery limits and scoped fallback work.
   None is reported clean/fully covered merely because zero routes were found.
5. An offline scripted public scan workflow with controlled model responses
   proves discovered Go and JavaScript/TypeScript entries reach actual hunt
   assignments, candidate verification, and published reports. Include a
   supported candidate, a rejected candidate with a real defense, and an
   unresolved candidate. Merely listing languages or finding route strings
   does not pass this scenario.
6. A two-handler file with evidence for only one handler leaves the other
   unreviewed. Mention-only outputs, malformed dispositions, missing IDs,
   missing source references, failed agents, and truncated assignments cannot
   create false completed coverage.
7. A known supported module alongside an unsupported module shows scoped
   progress plus unresolved whole-repository completeness. Counts remain
   consistent across persisted inventory, assignments, review records, API,
   scan details, and reports, with explicit denominator labels.
8. Malformed recon, discovery/parser failure, exhausted work limits, and
   interrupted scans preserve completed evidence and expose the remaining
   work. Repeated inventory runs over unchanged input produce the same IDs,
   ordering, and counts. Resume does not duplicate work or accept stale
   discovery results as current evidence.
9. Existing history opens without a forced rescan or rewritten evidence.
   Legacy coverage is labeled appropriately. Existing dashboard metrics,
   application/ledger management, and analyst review decisions do not regress.
10. Tests run without live inference, network access, or target-language
    runtimes installed. Verify discovery does not execute code, install
    dependencies, escape source boundaries, or modify the target. Run relevant
    existing tests and the full offline suite before declaring implementation
    complete; record actual results and skipped checks honestly.

The exact-fixture inventory criteria measure supported discovery patterns,
not universal recall or real-world vulnerability accuracy. Include a separate
bounded manual evaluation on representative real repositories in the plan;
report limitations and empirical results without requiring an unsolicited
paid or long-running model scan.

### Deliverables and implementation order

Create one new specification and separate requirements quality checklist;
document the initial stack selection as an assumption. Keep implementation
design and dependency choices in the plan. Target languages/frameworks are
product coverage requirements and must remain explicit in the specification.

Plan delivery in this order: source/support inventory and compatible coverage
records; Go and JavaScript/TypeScript discovery; real hunt/verification/report
integration; CLI and fallback-surface handling; UI disclosure and regression
validation. Define the first usable increment as a complete non-Python
scan-to-report flow, not an inventory-only demo. Complete all required stacks
and acceptance cases before claiming the feature finished.

Publish a support matrix separating language readability, deterministic
entry-point recognition, verification checks, fallback review, and known
unsupported constructs. Update scan configuration/help and user documentation.
Provide an evidence-based completion matrix identifying implemented, tested,
and remaining behavior. Do not describe prompt changes or passing parser
tests alone as proven scan-quality parity.

## Investigation pointers for the subsequent plan

These are implementation locations observed during review, not substitutes for
the user-facing requirements above. Recheck their current state when planning.

- `internal/inventory/inventory.go`: `.py`-only enumeration, HTTP-shaped route
  records, exclusions, deduplication, and mention-based review dispositions.
- `internal/engine/engine.go`, `helpers.go`, and `hunt.go`: initial inventory,
  Python source counts, partition fallback/augmentation, hunt inputs, coverage
  finalization, and degradation reporting.
- `internal/phases/partition.go`: HTTP-shaped route references and
  description-based assignment augmentation.
- `internal/verification/verification.go` and `authz.go`: candidate identities,
  function-context checks, and route/handler matching.
- `internal/consolidate/corroborate.go`, `internal/authz/`, and
  `internal/engine/sweep.go`: language-specific evidence checks and helpers.
- `skill/phases/phase1_recon.md` and Phase 2 prompts: preserve broad discovery
  instructions while wiring the deterministic inventory into actual tasks.
- Server/report types, exports, the React scan/report surfaces, and existing
  offline parity fixtures: compatibility and end-to-end acceptance.
