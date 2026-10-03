<!--
Sync Impact Report  (temporary review scratch — remove before committing)
==================
Version change: 1.0.0 → 1.1.0
Bump rationale: MINOR — materially changed guidance in the "Safety & Technical Constraints"
section (Runtime clause) and a clarifying wording change to Principle VII. No Core Principle
(I–VII) was removed or redefined in intent, so this is not MAJOR; the Runtime change is an
expansion/redefinition of a technical constraint (allowing Go), which is more than a PATCH.

Modified principles / sections:
  Safety & Technical Constraints › Runtime — was "Python 3.9+, standard library only";
    now Go (1.23+) as a self-contained single binary, Python allowed only during migration,
    the stdlib-only rule reframed as a small, reviewed runtime dependency budget, and the
    accepted risk named (loss of "stock Python, nothing to install" for a self-contained
    binary). Web-UI-self-contained/offline requirement retained (now embedded).
  VII. Testable Acceptance & Regression Coverage — offline test runner made runtime-agnostic:
    `go test ./...` (and `python3 -m unittest discover -s tests` while Python remains).
    All other VII requirements (offline, no live model/network/paid, fakes/fixtures, degraded
    paths, testdata negative controls) unchanged.

Added sections: none.  Removed sections: none.

Rationale for amendment: enables specs/002-golang-port (port to Go), which the prior Runtime
clause forbade. Documented as a justified deviation in that feature's plan.md (Complexity
Tracking + research R15); this amendment is the sanctioned governance step for it.

Templates reviewed (not modified — they read the constitution at runtime):
  ✅ .specify/templates/plan-template.md  — "Constitution Check" gate still picks up I–VII
  ✅ .specify/templates/spec-template.md  — acceptance scenarios align with Principle VII
  ✅ .specify/templates/tasks-template.md — test tasks align with Principle VII

Deferred TODOs: none. Ratification date unchanged (2026-09-13); Last Amended 2026-09-14.
-->

# vhlocal Constitution

## Core Principles

### I. Evidence Integrity (NON-NEGOTIABLE)

vhlocal MUST NOT fabricate evidence, and MUST NOT claim that something ran or succeeded
unless the engine saw it happen.

- Run facts (models, timings, phase status, agent counts, token usage, coverage) MUST come
  from engine-written records such as `scan_meta.json`. Model output describing its own run
  is untrusted. It MAY be kept for comparison (e.g. `model_reported`), but MUST NOT be
  presented as fact.
- A phase counts as complete only when it produced a valid, non-empty deliverable that
  passes its contract checks. An exit code, a missing error, or an engine "done" flag alone
  is not proof of success.
- Findings confirmed by reasoning MUST NOT be described as confirmed by execution. Exploit
  tests that were written but never run MUST be reported as not executed.
- Aggregate or hand-waved results ("all candidates confirmed") MUST NOT stand in for
  per-item evidence. Quoted evidence MUST be traceable to a real source location.
- When data is missing, unknown, or degraded, the output MUST say so (`unknown`, `degraded`,
  `not run`). It MUST NOT fill in a plausible default.

**Rationale:** A scanner that reports fluent, wrong findings is worse than no scanner. This
project has already seen a model write `Model: claude-opus-4-8` into a report produced by
`gpt-oss:120b`. Every downstream consumer relies on vhlocal's claims being true.

### II. Orthogonal Status Reporting

Every run MUST report three independent status axes. They MUST NOT be collapsed into a
single label:

- **Execution status**: did the requested phases run to completion and produce valid
  deliverables? (`complete`, `partial`, `incomplete`, `cancelled`, `aborted`, `unknown`)
- **Coverage status**: did the run actually reach the whole in-scope attack surface, or was
  it degraded (partition fallback, agents stopped on `max_turns`, skipped phases, unreviewed
  entry points)? Degradation MUST come with its reasons.
- **Validation mode**: were findings validated statically (by reasoning) or dynamically (by
  execution)?

Every report, API response, SARIF export, manifest, and UI surface that shows run status
MUST carry all three axes, or clearly mark an axis as unavailable. No surface MAY derive one
axis from another. For example, `execution=complete` MUST NOT imply `coverage=complete`.

**Rationale:** A run can finish every phase and still cover one partition of the codebase.
Merging these axes into "Completed" is exactly how a narrow run comes to look thorough.

### III. Static-Only Safety Boundary (NON-NEGOTIABLE)

By default, vhlocal MUST analyze target code without executing it or changing it.

- Agents MUST NOT have a shell or code-execution tool. The target's code, install hooks,
  build scripts, dependency installation, and exploit tests MUST NOT be run.
- Reads MUST be confined to the target repository, the skill directory, and the results
  directory. Writes MUST be confined to the results directory. Paths MUST be resolved before
  containment checks.
- The user's working tree MUST NOT be modified. Reports and generated PoCs MUST be written
  outside the scanned repository.
- Any capability that crosses this boundary (dynamic validation, fix-apply, patch
  application, dependency install) requires **explicit authorization**:
  - an operator-supplied opt-in per run or per invocation (CLI flag or API field), never a
    default;
  - it MUST NOT be inferred from model output, target repository content, or configuration
    carried over from a previous run;
  - it MUST be confined to an isolated copy of the target, never the user's working tree;
  - it MUST be recorded in run metadata and reflected in the validation mode (Principle II).
- Changing the *default* boundary requires a constitution amendment.

**Rationale:** The scan target is untrusted code, and its findings describe how to exploit
it. Execution trades a safety guarantee for fidelity. That trade belongs to the operator,
must be made knowingly, and must be visible afterwards.

### IV. AI Result Provenance

Every AI-generated result MUST carry engine-recorded provenance that is sufficient to
reproduce or audit how it was produced:

- **Provider/backend** (e.g. `ollama`, `openai`-compatible, `openrouter`).
- **Endpoint** (host/base URL, with credentials and secrets redacted).
- **Model** as requested, plus the model identifier the provider actually returned, when
  the provider returns one.
- **Relevant configuration**: context window (`num_ctx`), sampling parameters, turn and
  token limits, tool envelope, phase/prompt identity (skill version or content hash), and
  the target's git revision where available.
- Per-phase attribution whenever phases use different models or endpoints (e.g.
  `--verify-model` / `--verify-host` for Phase 2b).

Provenance MUST be captured by the engine at call time. It MUST NOT be reconstructed from
model prose. API keys, tokens, and other secrets MUST NOT be written into provenance
records, logs, or reports.

**Rationale:** Findings from different models, endpoints, and context sizes differ in
quality. Without provenance, a result cannot be trusted, compared, or reproduced, and
cost cannot be attributed.

### V. Explicit AI Failure, No Silent Fallback

Failures of external AI services MUST be explicit.

- When a provider, endpoint, or model fails (unreachable, auth error, rate limit exhausted,
  malformed response, context overflow, stall), the failure MUST be surfaced to the
  operator. It MUST be recorded in run metadata and logs, and reflected in execution and/or
  coverage status.
- vhlocal MUST NOT silently switch to a different provider, endpoint, or model. Any
  alternate MUST be explicitly configured by the operator beforehand, and its use MUST be
  recorded in provenance (Principle IV) and flagged in the report.
- Bounded retries against the *same* provider, endpoint, and model (backoff, fresh-context
  tool-call repair) are permitted. Retry counts and final outcomes MUST be recorded.
- Paid or cloud backends MUST never be reached by fallback from a local one. Traffic that
  leaves the machine or incurs cost MUST be an explicit operator choice.
- A failed agent MAY end gracefully without crashing the scan. Its unfinished work MUST
  still count as degraded coverage and MUST NOT be reported as clean.

**Rationale:** A silent fallback turns "model X found nothing" into "some unknown model
maybe looked". That breaks provenance and cost control, and can send private source code to
a service the operator never approved.

### VI. Resumable, Idempotent Operations

Long-running operations (scans, phases, batch runs, ledger bootstraps, report regeneration)
MUST be resumable and idempotent wherever practical.

- Progress MUST be persisted to durable, on-disk state at meaningful checkpoints, at least
  per phase. Resume MUST skip only work whose deliverable is present *and valid*
  (Principle I). Invalid or empty deliverables MUST be redone.
- Re-running a completed operation with the same inputs MUST NOT duplicate results, double
  count ledger entries, or corrupt existing artifacts. Merges MUST be keyed by stable
  identifiers (e.g. run id, results directory).
- Work interrupted by a crash or restart MUST be marked `interrupted`. It MUST NOT be
  silently re-run, because re-running is expensive and writes to disk. Resuming is an
  explicit operator action.
- Writes to persisted state SHOULD be atomic (write to a temporary file, then rename) so an
  interruption cannot leave a half-written record.
- Where resumability or idempotency is impractical, the plan MUST state why, and the
  operation MUST fail loudly rather than produce partial state that looks complete.

**Rationale:** A local-model scan can run for hours and die at any point. Losing completed
work wastes GPU time. Silently redoing it, or merging it twice, corrupts the record the
project exists to produce.

### VII. Testable Acceptance & Regression Coverage

- Every feature MUST define acceptance criteria that are concrete and checkable by a
  test or a scripted verification step, with observable inputs and expected outputs.
  Criteria such as "works well" or "is robust" are not acceptable.
- Every feature MUST ship with automated tests covering those criteria. Every bug fix MUST
  add a regression test that fails without the fix.
- Tests MUST be runnable offline with the runtime's standard test runner — `go test ./...`
  for the Go implementation (and `python3 -m unittest discover -s tests` for the Python code
  while it remains during migration). They MUST NOT require a live model, network access, or
  paid services. Model and transport behavior MUST be exercised through fakes or recorded
  fixtures.
- Behavior governed by Principles I–VI (honest status, safety confinement, provenance,
  explicit failure, resume/idempotency) MUST have direct tests. Degraded paths MUST be tested,
  not only happy paths.
- Detection-quality changes SHOULD be checked against `testdata/` fixtures, including the
  negative controls, which MUST NOT be reported.

**Rationale:** Many of this project's failures have been silent: a parser matching nothing,
a partitioner collapsing to one pass, a status label overstating coverage. Only tests that
pin behavior stop those failures from coming back unnoticed.

## Safety & Technical Constraints

- **Runtime:** Go (currently targeting Go 1.23+) is the implementation runtime, distributed
  as a self-contained single binary with no interpreter prerequisite. During the migration
  from the original Python 3.9 implementation the two runtimes MAY coexist, but the delivered
  product is the Go binary. The Go analog of the former "standard library only" rule is a
  **small, explicitly enumerated, reviewed runtime dependency budget**: the standard library
  is the default, the baseline is zero third-party *runtime* dependencies, and each runtime
  dependency added MUST be justified in the plan and listed. A material expansion of that
  budget requires a constitution amendment; build- and release-time tooling (cross-compilers,
  release helpers) is not part of the runtime budget. The web UI MUST remain self-contained
  (no CDN, works offline) and is embedded in the binary.
  - **Accepted risk (recorded per Governance):** adopting Go trades away the prior "stock
    system Python, nothing to install" property in exchange for a self-contained,
    cross-platform binary. The mitigations are the dependency budget above and the preserved
    offline/no-egress guarantees; the auditability the stdlib-only rule protected is carried
    forward by keeping the runtime dependency set small and reviewed.
- **Network:** No egress beyond operator-configured inference endpoints. Generated reports
  MUST make no external requests.
- **Server posture:** The engine server has no authentication. It MUST bind loopback by
  default, with a non-loopback bind requiring an explicit unsafe opt-in. Scan roots MUST be
  allow-listed, and artifact reads MUST be confined to the owning results directory.
- **Untrusted inputs:** Model output and target repository content are untrusted. Parsers
  over model output MUST normalize text (e.g. `phases.normalize_text()`) and MUST degrade
  *visibly*, never silently. Artifacts served to the browser MUST NOT be able to execute in
  the page context.
- **Determinism where possible:** Consolidated reports, status computation, deduplication,
  and ledger merges MUST be deterministic code, not model judgment.

## Development Workflow & Quality Gates

- **Specification:** Feature specs MUST state acceptance criteria (Principle VII). They MUST
  also state the feature's impact on the safety boundary (III), status axes (II), provenance
  (IV), and failure handling (V), or state explicitly that there is no impact.
- **Planning:** Every `/speckit-plan` MUST pass a Constitution Check against Principles
  I–VII before design and again after it. Deviations MUST be justified in the plan's
  Complexity Tracking section, together with the simpler alternative that was rejected.
- **Implementation gate:** A change is not done until the full offline test suite passes
  and new or changed behavior has tests. Test results MUST be reported as they actually
  were. Failing or skipped tests MUST NOT be described as passing.
- **Review gate:** Reviews MUST confirm that no new code path:
  - fabricates or infers success;
  - collapses status axes;
  - widens the static-only boundary without explicit opt-in;
  - drops provenance;
  - adds a silent provider or model fallback;
  - breaks resume or idempotency.
- **Documentation:** User-visible behavior changes MUST update `README.md`, `RUNBOOK.md`, or
  `CHANGELOG.md` as appropriate.

## Governance

- This constitution supersedes conflicting practices, conventions, and prior guidance for
  vhlocal. `README.md` and `RUNBOOK.md` provide runtime and operational guidance and MUST
  NOT contradict it.
- **Amendments** are made by changing `.specify/memory/constitution.md` in a reviewed commit
  that states the version bump and its rationale. Changes that alter safety defaults
  (Principle III) or AI fallback policy (Principle V) MUST name the risk being accepted.
  Dependent Spec Kit artifacts in flight MUST be re-checked against the amended text.
- **Versioning** follows semantic versioning:
  - MAJOR: a principle is removed or redefined in a backward-incompatible way.
  - MINOR: a principle or section is added, or guidance is materially expanded.
  - PATCH: clarifications and wording changes with no semantic change.
- **Compliance:** Every plan's Constitution Check and every code review MUST verify
  compliance. Unjustified violations block merge. Existing code found to violate a principle
  MUST be tracked as a defect, not grandfathered silently.

**Version**: 1.1.0 | **Ratified**: 2026-09-13 | **Last Amended**: 2026-09-14
