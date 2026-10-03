# Feature Specification: Port vhlocal to Go with interface parity

**Feature Branch**: `002-golang-port`

**Created**: 2026-09-14

**Status**: Draft

**Input**: User description: "You are in a folder with an application named vhlocal, a vulnerability assessment harness. I would like to convert this project to Golang while leaving the interface intact, though obviously the interface will need to be adjusted to match updated functionality and capabilities."

## Clarifications

### Session 2026-09-14

- Q: How should the current `python3 -m vhlocal.<module>` entry points map onto the compiled binary's command surface? → A: A single `vhlocal` binary with subcommands (`vhlocal run`, `vhlocal server`, `vhlocal report`, `vhlocal logs`, `vhlocal sbom`, …), each keeping the same flags and semantics.
- Q: Beyond preserving parity, which new capabilities should the first release introduce? → A: Parity-first, plus two explicit new deliverables — self-contained single-binary distribution with no runtime prerequisite, and cross-platform release binaries. True concurrent Phase 2 across endpoints is deferred to a later feature (not in scope now).

## Overview

vhlocal is a local vulnerability-assessment harness: it runs VulnHunter's phase-based scanning methodology against a locally-hosted or operator-configured inference model, entirely without network egress beyond that model. It ships as a command-line tool and as a long-lived HTTP engine with a browser UI, and it produces a fixed set of on-disk result artifacts (styled report, machine-readable findings, SARIF, coverage ledger, engine metadata, SBOM, threat model).

This feature re-implements vhlocal on a new runtime (Go) while keeping its **observable interfaces** — the command surface, the HTTP/JSON API, the result artifacts and their formats, the configuration inputs, and the safety and honesty guarantees — behaviorally equivalent to the current implementation, so that existing users, scripts, saved reports, and the browser UI continue to work. Where the runtime change forces an interface adjustment (for example, how the tool is invoked once it is a compiled binary rather than a Python module), the adjustment is minimal, documented, and preserves the same capabilities and outputs.

The scanning **methodology** (the bundled `skill/` phase prompts) is model-agnostic markdown data and is carried forward unchanged; only the runtime that loads it, dispatches agents, runs the tool loop, and writes artifacts is re-implemented.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A CLI scan produces the same result artifacts (Priority: P1)

An operator runs a scan from the command line against a target repository, pointing at their inference endpoint, and receives a results directory containing the same set of artifacts — the styled HTML report, the markdown report, machine-readable findings, SARIF, coverage ledger, and engine metadata — with the same file names, the same directory location convention, and the same field-level content semantics as the current tool. Their existing invocation habits and any wrapper scripts continue to work with only the documented change to how the tool is launched.

**Why this priority**: The core purpose of vhlocal is to run a scan and produce trustworthy artifacts. Everything else (the server, the UI, the auxiliary tools) exists to launch, monitor, or present that output. If a CLI scan produces the same artifacts with the same honesty guarantees, the product is fundamentally intact; this is the smallest slice that delivers real value on its own.

**Independent Test**: Run a scan of the bundled `testdata/vulnapp` fixture with the new implementation and with the current one against the same model/fixture, and compare the produced results directories: the same files exist, each machine-readable artifact validates against the same schema and carries the same fields, and the engine-recorded facts (timings aside) match.

**Acceptance Scenarios**:

1. **Given** a target repository and a reachable inference endpoint, **When** the operator launches a full scan, **Then** the results directory is created under the same default location (`~/vulnhunter-reports/<name>_..._<timestamp>/`, overridable), and contains `SCAN_REPORT.html`, `SCAN_REPORT.md`, `findings.json`, `findings.sarif`, `scan_meta.json`, `coverage_ledger.json`, `README.md`, and the per-phase artifacts, using the same file names as today.
2. **Given** a completed scan, **When** the operator opens `findings.json`, **Then** it carries the same top-level blocks (findings with per-finding validation state and normalized CWE/family/severity, `run_status`, `attribution`, `lifecycle`, `application_intelligence`) that the current tool writes, readable by the same downstream tooling.
3. **Given** the same scan flags the current CLI accepts (target, output location, model/host/backend, per-phase model routing, phase subset, partition caps, concurrency, sampling, budget caps, strictness, sweep mode, threat model, ledger, redaction, remediation, resume, verbosity, profile), **When** the operator passes them to the new CLI, **Then** each flag is accepted with the same name and semantics (adjusted only for the launch mechanism), or the change is explicitly documented.
4. **Given** a scan interrupted partway, **When** the operator re-runs with resume, **Then** only phases whose deliverable is present and valid are skipped and the remainder are redone, exactly as today.
5. **Given** a scan whose engine facts differ from what the model claimed about itself, **When** the report is generated, **Then** engine-observed facts are authoritative and any model-claimed value is kept only for comparison, never presented as fact.

---

### User Story 2 - The HTTP engine and browser UI work unchanged (Priority: P2)

An operator runs vhlocal as a long-lived HTTP engine and opens the existing browser UI. They start scans, watch the live tool-by-tool feed, cancel a running scan, browse reports and artifacts, view application intelligence (SBOM, threat model), inspect the vulnerability ledger, read activity and logs, and see engine stats — all through the same UI, served from the same process, backed by the same JSON API the current server exposes.

**Why this priority**: The server and its API are the second major interface. Because the browser UI is a pre-built static asset that talks to the engine only over the JSON API, re-implementing the engine to serve the same static bundle and the same API endpoints preserves the entire UI without changing it. This slice makes the tool usable for the browser-first operator and keeps every scripted API consumer working.

**Independent Test**: Start the new engine, load the existing built UI against it, and exercise each screen (scans, new scan, reports, application intelligence, ledger, activity, log, stats, settings); every screen populates and every action succeeds because each API endpoint the UI calls returns the same response shape as today.

**Acceptance Scenarios**:

1. **Given** the engine is started, **When** a client requests each documented endpoint (`GET /api/config`, `GET /api/models`, `GET /api/profiles`, `GET /api/stats`, `POST /api/scans`, `GET /api/scans`, `GET /api/scans/{id}`, `GET /api/scans/{id}/events`, `GET /api/scans/{id}/log`, `GET /api/scans/{id}/artifacts`, `GET /api/scans/{id}/file`, `POST /api/scans/{id}/cancel`, `POST /api/openrouter-key`, `GET /api/reports`, `GET /api/reports/{id}/files`, `GET /api/reports/{id}/file`, `DELETE /api/reports/{id}`, `GET /api/applications`, `GET /api/applications/{slug}`, `POST /api/applications/{slug}`, `DELETE /api/applications/{slug}`, `GET /api/ledgers`, `GET /api/ledgers/{slug}`, `DELETE /api/ledgers/{slug}`, `DELETE /api/ledgers/{slug}/finding`, `GET /api/activity`, `GET /api/log`), **Then** the response uses the same path, method, and JSON shape (fields and their meanings) as the current server, and the existing UI renders it without modification.
2. **Given** the engine is started, **When** a browser opens the UI, **Then** the same static front ends are served at the same paths — the React application under `/app`, the current single-file HTML UI at `/`, and the legacy/classic single-file UIs at their existing paths — plus the static asset routes they load.
3. **Given** a submitted scan, **When** the client subscribes to the scan's event stream, **Then** it receives the backlog of prior events followed by live events (server-sent events) using the same event-type vocabulary (queue, scan/phase/agent lifecycle, fan-out plan, findings, handoff, budget/breaker signals, log, error, done), with periodic keepalives, and cancellation stops the scan within one model turn — the same live behavior as today.
4. **Given** the default configuration, **When** the engine starts, **Then** it binds loopback only, refuses a non-loopback bind without an explicit unsafe opt-in, allow-lists scan roots, and confines artifact reads to a job's own results directory with traversal structurally prevented — the same security posture as today.
5. **Given** the engine is running, **When** two scans are submitted, **Then** they are serialized through a single FIFO worker and the busy state is reported, exactly as today.
6. **Given** the process is restarted with jobs that were mid-flight, **When** the queue reloads, **Then** those jobs are marked interrupted and never silently re-run.
7. **Given** a reports directory, ledger directory, and job store populated by the previous (Python) implementation, **When** the new engine indexes them, **Then** every existing report is listed and openable and existing ledgers, applications, and job state are read without loss.

---

### User Story 3 - Auxiliary command-line tools retain their behavior (Priority: P3)

An operator uses the supporting command-line tools around the core scan — regenerating a consolidated report from an existing results directory (including bulk regeneration and guarded deletion), reading the central log or slicing it to one scan, generating a CycloneDX SBOM for a repository, benchmarking inference throughput, running a batch of scans from a CSV, and the remaining maintenance/evaluation utilities — and each behaves the same as today.

**Why this priority**: These tools are used less often than a scan or the UI, but they are part of the documented interface and several are referenced by the RUNBOOK and DEPLOY guides. They can be delivered after the core scan and engine without blocking primary value.

**Independent Test**: For each auxiliary tool, run it against a fixture (an existing results directory, a repo, a CSV, an inference endpoint) with the new implementation and confirm it produces the same output artifact, exit behavior, and console/log output shape as the current tool.

**Acceptance Scenarios**:

1. **Given** an existing results directory, **When** the operator regenerates the consolidated report, **Then** `SCAN_REPORT.md` and `findings.json` (and the styled HTML) are rebuilt deterministically from engine records with no model call, and bulk mode regenerates every report under the reports directory.
2. **Given** the central log, **When** the operator reads it or slices it to a scan tag, **Then** the output matches today's, and every entry point (CLI, server, worker) writes to the same central log tagged by scan id.
3. **Given** a repository, **When** the operator generates an SBOM, **Then** a CycloneDX document is produced deterministically from the same set of supported manifest ecosystems, with the same default output path.
4. **Given** the report deletion tool, **When** the operator deletes a results directory, **Then** deletion is confirmed (or forced with an explicit flag), refuses to touch anything outside the reports directory, and refuses to delete a scan that is still running.

---

### Edge Cases

- **Inference endpoint failure** (unreachable, auth error, rate limit, malformed response, context overflow, stall): the failure is surfaced to the operator, recorded in run metadata and the central log, and reflected in execution and/or coverage status. The tool never silently switches provider, endpoint, or model.
- **Malformed tool-call output from the model**: the same bounded repair-in-fresh-context behavior applies (limited attempts against the same endpoint), and a still-failing agent ends gracefully — counting as degraded coverage — without crashing the scan.
- **Unparseable phase-1 partition table** (including typographic punctuation such as non-breaking hyphens in model output): text is normalized before parsing, and if parsing still fails the run degrades visibly (falls back and logs a warning) rather than silently collapsing coverage.
- **A phase that runs but produces an empty or invalid deliverable**: it is not counted complete; resume redoes it.
- **A shallow run** (no entry points enumerated over a non-trivial codebase, or a large codebase hunted in a single partition): coverage is reported as degraded with reasons, never as complete.
- **Artifacts produced by the previous implementation** that omit newer fields: they are read tolerantly, each field degrading to a documented fallback rather than dropping the report/finding.
- **A request to read an artifact by a traversal path or a report id outside the enumerated set**: it is refused; report ids are matched against the enumerated set rather than joined to a path.
- **A paid/cloud backend and a budget cap**: the run halts before exceeding the cap; paid backends are only ever reached by explicit operator choice, never by fallback from a local one.

## Requirements *(mandatory)*

### Functional Requirements

#### Interface parity

- **FR-001**: The system MUST provide the same command-line capabilities as the current implementation — running a scan, running the HTTP engine, regenerating reports, reading logs, generating SBOMs, benchmarking throughput, and batch scanning — with the same option names and semantics, adjusted only for how the compiled tool is launched (see FR-030) and with any adjustment documented.
- **FR-002**: A scan invoked from the command line MUST accept the current set of scan options with unchanged names and meaning: target repository; exact output directory and reports directory; model, host, and backend; per-role model/host/backend routing for recon, verify, and reproduce phases; phase subset; context window; partition cap; phase-2 mode; concurrency; reasoning effort; output-token cap; budget cap; hunt sample count; sweep mode; quality strictness; seed-routes; seed-prior; coverage enforcement toggle; IaC lens toggle; remediate; redact; ledger; threat model; resume; profile; and verbosity.
- **FR-003**: The system MUST support the same inference backends — a native local backend, an OpenAI-compatible backend, and a paid cloud gateway backend — selectable by the same option values, with the same host/key configuration inputs.
- **FR-004**: The HTTP engine MUST expose the same JSON API — same paths, methods, request bodies, and response shapes — that the current server exposes and that the bundled browser UI depends on, including the live event stream, so that the existing built UI runs unmodified against the new engine.
- **FR-005**: The HTTP engine MUST serve the existing browser UI from the same process, and MUST accept a scan-submission body that mirrors the CLI scan options.
- **FR-006**: The system MUST write the same result artifacts, by the same file names, into the results directory: the styled self-contained HTML report and the markdown report; machine-readable findings and SARIF; the engine metadata record; the coverage ledger; the run manifest, artifact manifest, and the verification/candidate manifest and records set; the authorization map; the captured prompts and error logs; the resume-state file; the scanner's own README report; the per-phase outputs and the raw per-agent hunt outputs; and — when enabled — the threat model, the SBOM, and the per-finding remediation set.
- **FR-006a**: The results directory MUST follow the same naming convention (`<repo-name>_VULNHUNT_RESULTS_<model-tag>_<timestamp>`) that external tooling globs and that the reports index parses back, with the same override precedence (exact output path > reports directory > default reports directory).
- **FR-007**: Each machine-readable artifact MUST conform to the same format and carry the same fields and semantics as today (findings JSON structure with its per-finding fields, SARIF 2.1.0 with driver identity `vhlocal`, CycloneDX SBOM, engine metadata record, coverage ledger, run/verification manifests, and the per-target vulnerability ledger and applications registry), so existing consumers and saved reports remain valid.
- **FR-008**: The styled HTML report MUST remain a single self-contained file with no external network requests, printable to PDF via the browser, forcing the light palette and expanding collapsed sections on print, and MUST show a "filtered view" banner when exported under an active filter.
- **FR-009**: The system MUST honor the same configuration inputs with the same names and defaults — the per-backend inference-host environment variables (local, OpenAI-compatible), the per-backend API-key environment variables (OpenAI-compatible, paid gateway), the central-log path environment variables and flag, the ledger/applications directory, the user-profiles directory, the activity-feed store, the reports directory, the skill directory, the allow-listed scan roots, and the job-state location.
- **FR-009a**: The paid-gateway API key MUST be resolvable from its environment variable or set in-memory at runtime, and MUST NOT be persisted to disk or written into any artifact, log, or provenance record.
- **FR-010**: The system MUST apply configuration profiles with the same precedence (built-in default < profile < explicit option), the same built-in profiles, and the same structural-only allow-list — a profile MUST NOT pin model, host, or backend — read from the same profile store format.

#### Behavioral / pipeline parity

- **FR-011**: The system MUST execute the same phase pipeline, keyed by the same phase identifiers (`1` recon; `1t` optional PASTA threat model; `2` hunt fan-out by vulnerability class and partition; `2b` falsification/verify; `3` reproduce/test/fix; `3d` deterministic root-cause sweep; `4` report), producing the same per-phase artifacts, and MUST allow running an arbitrary subset by those identifiers.
- **FR-012**: The CLI and the HTTP engine MUST drive one and the same scan implementation, so behavior cannot diverge between them.
- **FR-013**: The system MUST enumerate entry points deterministically and compute route coverage deterministically (non-overlapping partitions that do not re-scan already-covered files), with coverage enforcement on by default and disable-able by the same option.
- **FR-014**: The consolidated report, run-status computation, deduplication, normalized CWE/family/severity labeling, duplicate flagging, and ledger merges MUST be produced by deterministic logic, not by model judgment, and MUST be reproducible from the engine-recorded artifacts.
- **FR-015**: The system MUST perform deterministic cross-run finding lifecycle reconciliation (new / persisting / regressed / fixed) against the most recent prior report of the same target, without calling the model, preserving run independence.
- **FR-016**: The system MUST support the same resumability and idempotency guarantees: durable per-phase checkpointing, resume that skips only present-and-valid deliverables, no duplication or double-counting on re-run of a completed operation, marking crash-interrupted work as interrupted, and atomic writes to persisted state.

#### Safety, status, provenance, failure (constitution-aligned)

- **FR-017**: The system MUST preserve the static-only safety boundary by default: no shell or code-execution tool is available to agents; the target's code, install hooks, build scripts, dependency installation, and exploit tests are never run.
- **FR-018**: The system MUST confine reads to the target repository, the skill directory, and the results directory, and confine writes to the results directory, resolving paths before containment checks so traversal is caught; and MUST never modify the user's working tree — reports and generated PoCs are written outside the scanned repository.
- **FR-019**: Any capability that would cross the static-only boundary MUST require explicit per-run operator authorization, never inferred from model output or configuration, and MUST be recorded in run metadata and reflected in validation mode. (No such capability is added by this feature.)
- **FR-020**: Every run MUST report the three independent status axes — execution status, coverage status (with reasons when degraded), and validation mode (static vs. dynamic) — on every surface that shows run status (reports, API responses, SARIF, manifest, UI), without collapsing them or deriving one axis from another.
- **FR-021**: The system MUST NOT fabricate evidence or claim that something ran or succeeded unless the engine observed it. Findings confirmed by reasoning MUST NOT be described as confirmed by execution; exploit tests written but not run MUST be reported as not executed; missing/unknown/degraded data MUST be labeled as such rather than filled with a plausible default.
- **FR-022**: Every AI-generated result MUST carry engine-recorded provenance sufficient to reproduce or audit it — provider/backend, endpoint (with secrets redacted), requested model and the model identifier the provider actually returned, relevant configuration (context window, sampling, turn/token limits, tool envelope, phase/prompt identity, target revision where available), and per-phase attribution when phases use different models or endpoints — captured at call time, never reconstructed from model prose, and never containing secrets.
- **FR-023**: External AI failures MUST be explicit and surfaced, recorded, and reflected in status; the system MUST NOT silently fall back to a different provider, endpoint, or model; bounded same-endpoint retries are permitted and their counts and outcomes recorded; paid/cloud backends MUST never be reached by fallback from a local one.
- **FR-024**: The system MUST enforce the same server security posture: no authentication, loopback bind by default with non-loopback requiring an explicit unsafe opt-in, allow-listed scan roots checked for both the target and the output path, and artifact reads confined to the owning results directory with report ids matched against the enumerated set rather than joined to a path.
- **FR-025**: The system MUST treat model output and target repository content as untrusted: text is normalized before any regex parsing over model output, parsers degrade visibly rather than silently, and artifacts served to the browser cannot execute in the page context.
- **FR-026**: The system MUST make no network egress beyond the operator-configured inference endpoint(s); generated reports MUST make no external requests.

#### Provenance of this feature / migration

- **FR-027**: The bundled scanning methodology (skill and phase prompts) MUST be carried forward as data without change in meaning, and the skill directory MUST remain overridable by the same option.
- **FR-028**: The system MUST read result artifacts, ledgers, and job state produced by the previous implementation without loss, so existing scans on disk remain browsable and existing ledgers continue to accumulate.
- **FR-029**: The system MUST ship with automated tests that run offline (no live model, no network, no paid services), exercising model and transport behavior through fakes or recorded fixtures, and covering the safety, status, provenance, failure, and resume behaviors above, including degraded paths; and MUST support scoring against the bundled `testdata/` fixture including its negative control, which MUST NOT be reported.
- **FR-030**: The launch mechanism MUST be adjusted from a runtime-module invocation (`python3 -m vhlocal.<module>`) to a single compiled binary named `vhlocal` with a subcommand per current entry point (`vhlocal run`, `vhlocal server`, `vhlocal report`, `vhlocal logs`, `vhlocal sbom`, `vhlocal bench`, `vhlocal batch`, and the remaining maintenance/evaluation commands). Each subcommand MUST preserve every option name and semantic of its current module, and the mapping MUST be documented in the user-facing guides (README, RUNBOOK, DEPLOY).
- **FR-031**: Aside from the launch mechanism (FR-030), the feature MUST NOT drop or silently alter any existing command, option, endpoint, artifact, or field; any other observable change MUST preserve outputs and be documented. The first release is parity-only for behavior and does NOT add true concurrent Phase-2 execution across endpoints (deferred to a later feature).
- **FR-032**: The system MUST be distributable as a self-contained single binary with no runtime prerequisite (no interpreter install), carrying the bundled skill methodology and the built browser UI assets so that a fresh install runs a scan and serves the UI without additional setup, preserving the current "nothing to install" experience.
- **FR-033**: The system MUST be buildable and released as cross-platform binaries for at least Linux and macOS (the platforms the current guides target), produced as a first-class, tested output of the port.

### Key Entities

- **Scan run**: One execution of the pipeline against one target at one revision. Carries its spec (all options), engine-observed facts (timings, phases, agents, token usage, partition source), the three status axes, provenance, and a results directory. Represented on disk by the engine metadata record and resume state.
- **Finding**: A candidate or confirmed vulnerability. Carries model-reported and normalized CWE/family/severity, location and data-flow signature, per-finding validation state, root-cause key, and lifecycle status across runs.
- **Result artifacts**: The fixed set of files a scan writes (styled HTML report, markdown report, findings JSON, SARIF, coverage ledger, engine metadata, artifact manifest, scanner README, per-phase outputs, raw hunt outputs, threat model, SBOM).
- **Job**: A server-side unit of queued/running/finished scan work, with status, current phase/agent progress, token counters, findings count, results directory, and its scan spec; persisted to the job store and drained by a single FIFO worker.
- **Application**: A target repository grouped across its scans, with latest findings/severities/coverage, badges (threat model, SBOM), open findings, and ledger totals.
- **Ledger (memory bank)**: Per-application cross-run memory of findings, with tracked/open/fixed/regressed/reliable counts, severity breakdown, and per-finding history (first/last seen, confirmation count, cross-family marker, status, confidence).
- **Inference backend/endpoint**: The provider (native local, OpenAI-compatible, or paid cloud gateway), its endpoint, and its per-role routing and configuration.
- **Skill / methodology**: The bundled phase prompts and preamble that define the scanning method; data, carried forward unchanged.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For a scan of the bundled fixture, the new implementation produces a results directory containing 100% of the artifact file names the current implementation produces, with no extra or missing required artifacts.
- **SC-002**: 100% of the JSON API endpoints the bundled browser UI calls return the same response shape as the current server, such that the existing built UI runs unmodified — every screen populates and every action succeeds — with zero UI code changes.
- **SC-003**: 100% of documented command-line options are accepted with the same name and meaning; any option whose spelling or form changes is enumerated in a published migration note, and the count of undocumented changes is zero.
- **SC-004**: Every machine-readable artifact (findings JSON, SARIF, SBOM, engine metadata, coverage ledger) validates against the same schema/consumer that accepts the current tool's output; existing saved reports on disk remain 100% browsable in the new engine.
- **SC-005**: Every run reports all three status axes on every status-bearing surface; an automated check finds zero surfaces that omit an axis or derive one axis from another.
- **SC-006**: On the bundled fixture with its negative control, the tool never reports the negative control as a finding across repeated runs, and recall on the planted bugs is within the same band the current implementation achieves against the same model.
- **SC-007**: The offline test suite runs to completion with no live model, no network access, and no paid-service calls, and covers the safety-boundary, status-honesty, provenance, explicit-failure, and resume/idempotency behaviors including at least one degraded-path case each.
- **SC-008**: A scan interrupted and resumed redoes zero already-valid phases and re-does 100% of invalid/empty deliverables; re-running a completed scan produces no duplicated or double-counted results.
- **SC-009**: With the default configuration, the engine binds loopback only and refuses a non-loopback bind without the explicit unsafe opt-in in 100% of attempts; no artifact read escapes its owning results directory under traversal attempts.
- **SC-010**: The tool makes zero network connections other than to operator-configured inference endpoints during a scan, and generated HTML reports issue zero external requests when opened offline.
- **SC-011**: A fresh install on a supported platform runs a scan and serves the browser UI using only the single distributed binary, with zero additional runtime installation steps.
- **SC-012**: The release produces working, tested binaries for each supported platform (at minimum Linux and macOS), each exposing the full subcommand surface.

## Assumptions

- **Target runtime is Go**, as explicitly requested; this replaces the current Python 3.9 stdlib-only runtime. Because the current constitution names "Python 3.9+, standard library only" as a runtime constraint, adopting Go is expected to require a constitution amendment; that governance step is handled during planning, not by this specification.
- **The browser UI is reused as a static asset.** The existing React front end communicates with the engine only over the JSON API; it is built with its existing toolchain and the resulting bundle (together with the committed single-file legacy/classic HTML UIs) is served unchanged by the new engine. Only the backend and API are ported; re-implementing or redesigning the front end is out of scope unless the API contract itself must change. The front-end build tooling is a build-time dependency, not a runtime one.
- **The bundled `skill/` methodology is data, not code**, and is carried forward verbatim; this port does not change scanning prompts or their meaning.
- **Backward compatibility is one-directional**: the new implementation reads artifacts, ledgers, and job state written by the previous implementation. It is not required that the old implementation read artifacts written by the new one.
- **Timing-dependent and model-dependent values are not expected to match byte-for-byte** between implementations (durations, token counts, and the model's free-text prose vary per run and per host); parity is defined over interface shape, artifact set, field semantics, deterministic computations, and honesty guarantees — not over model output content.
- **Standard defaults are preserved**: reports directory `~/vulnhunter-reports`, central log `~/.vhlocal/vhlocal.log`, job state `~/.vhlocal/jobs.json`, server port and loopback bind, default model and context window, and the default inference host resolution from the environment.
- **The port replaces the shipped implementation.** The two implementations may coexist during migration, but the delivered product is the Go implementation; there is no requirement to keep both runnable indefinitely.
- **`ripgrep` remains an optional accelerator** with a built-in fallback scanner, as today.
- **No new capability crosses the static-only safety boundary.** Any dynamic-validation, fix-apply, or dependency-install capability remains out of scope and, if ever added, is a separate explicitly-authorized feature.
- **True concurrent Phase 2 is deferred.** The first release preserves the current sequential Phase-2 behavior; parallel hunt execution across multiple inference endpoints is a later feature, not part of this port.
- **Supported platforms are Linux and macOS** for the first release, matching the current documentation; other platforms (e.g. Windows, arm64 variants) may follow but are not required acceptance criteria here.
