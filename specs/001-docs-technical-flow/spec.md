# Feature Specification: Docs page matches vhlocal's technical functions & flow

**Feature Branch**: `001-docs-technical-flow`

**Created**: 2026-09-13

**Status**: Draft

**Input**: User description: "Please update the documentation page to match the technical functions and flow of vhlocal"

## Clarifications

### Session 2026-09-13

- Q: How comprehensive should the updated Docs page be? → A: Fuller technical reference — correct the flow AND add per-step model/backend routing, scan-config options, output formats, and safety/status concepts (but not an exhaustive per-flag/per-module reference).
- Q: How should pipeline steps be named, given the engine/CLI use phase IDs (1, 2, 2b, 3, 3d, 4) and artifact filenames? → A: Keep friendly names (Recon, Hunt, Verify…) and show the engine phase identifier and the real artifact filenames alongside each step.
- Q: Should the page explicitly explain Static-Only validation and Orthogonal Status Reporting (execution/coverage/validation-mode axes)? → A: Yes — explain both explicitly.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The pipeline description matches what actually runs (Priority: P1)

An operator opens the in-app documentation page ("How it works") to understand what a scan
does. They read a step-by-step account of the pipeline and expect it to match the run they
just kicked off — the same steps, in the same order, each reading and writing the same
artifacts that show up in their results directory, and an honest statement of the safety
boundary (does it run my code? does it touch the network?).

**Why this priority**: This is the core purpose of the page and of the request. If the
described flow does not match the real flow, the page misleads the very users who rely on it
to trust and interpret a scan. Every other improvement is secondary to the flow being correct.

**Independent Test**: Read the documentation page and, step by step, cross-check each named
step, its stated order, and its stated inputs/outputs against the engine's actual phases and
the files a real scan produces. The page passes if every described step corresponds to a real
step and every stated read/write corresponds to a real artifact, with nothing missing and
nothing invented.

**Acceptance Scenarios**:

1. **Given** the documentation page, **When** a reader lists the steps it describes in order,
   **Then** the list matches the steps the engine actually executes, by name and order.
2. **Given** a completed scan's results directory, **When** a reader checks each step's stated
   "reads"/"writes" against the files present, **Then** every stated artifact name matches a
   real artifact the engine reads or writes.
3. **Given** the page's safety-boundary statement, **When** compared to the engine's actual
   behavior, **Then** it correctly states that the target's code is never executed and that no
   network egress occurs except to the configured model server.
4. **Given** a step that does not always run (the threat-model step, or a selected subset of
   phases), **When** a reader reads its description, **Then** the page labels it as optional or
   selectable rather than as always-on.

---

### User Story 2 - Configurable technical functions are described accurately (Priority: P2)

Before launching a scan, an operator wants to understand the knobs that change how the scan
runs — routing different steps to different models/backends, choosing a profile, multi-sample
hunting, hunt-splitting, sweep mode, strictness, and cost caps — so they can configure a run
knowledgeably from the page's description.

**Why this priority**: These functions materially change cost, runtime, recall and precision.
Users configure scans based on this understanding; describing options that don't exist, or
omitting ones that do, leads to misconfigured or mistrusted runs. It ranks below P1 because a
correct flow is prerequisite to correct configuration.

**Independent Test**: For each configurable function the page describes, confirm a
corresponding real capability exists; for each real capability a user selects at scan time,
confirm the page accounts for it. Passes when the page's configurable-function set matches the
implemented set with no fabricated and no material missing items.

**Acceptance Scenarios**:

1. **Given** the page's description of model routing, **When** compared to the engine, **Then**
   it correctly states that individual steps (recon, hunt, verify, reproduce) can each run on a
   different model, and that both a local inference server and an OpenAI-compatible server are
   supported — without implying a single fixed model or a single backend.
2. **Given** the page's description of scan options, **When** a reader cross-checks it, **Then**
   every described option (e.g., profiles, multi-sample voting, hunt split/combined, sweep
   mode, strictness, budget cap) maps to a real, selectable capability.
3. **Given** an option the page does NOT need to expose in full, **When** it is summarized,
   **Then** the summary is still accurate and does not contradict the implemented behavior.

---

### User Story 3 - Post-pipeline and cross-run capabilities are represented (Priority: P3)

An operator wants to know what they get beyond the raw findings — application intelligence
(SBOM, threat model, data-flow diagram), a cross-run vulnerability ledger, honest coverage
labeling, exploit-chain analysis, and the report/output formats produced — and where those
outputs live.

**Why this priority**: These capabilities are differentiators and affect how a user consumes
results over time, but a reader can still run and interpret a single scan without them, so they
rank below the core flow and configuration.

**Independent Test**: For each post-pipeline capability the page describes, confirm it exists in
the implementation and that its described output/location is correct. Passes when the described
set matches the implemented set with no fabricated capabilities.

**Acceptance Scenarios**:

1. **Given** the page's "beyond the steps" content, **When** compared to the implementation,
   **Then** each described capability (application intelligence, cross-run ledger, honest/
   degraded coverage, exploit chains, output formats, redaction, remediation) exists.
2. **Given** a described capability, **When** a reader looks for where its output appears,
   **Then** the page's stated location matches reality (e.g., which tab surfaces it, or which
   artifact carries it).

---

### Edge Cases

- **A described feature was removed or renamed in code.** The page must not continue to
  describe a step, artifact, option, or capability that no longer exists under that name.
- **A run executes only a subset of phases.** The page must convey that phases are
  selectable, so a reader isn't surprised when a partial run omits described steps.
- **The threat-model step is opt-in.** The page must present it as optional, not as an
  always-on step.
- **A non-default backend or a stronger verification model is used.** The page must not imply
  a single hardcoded model or a single inference backend.
- **A run is marked degraded (shallow coverage).** The page's honesty claim must match the
  engine's actual coverage-labeling behavior, not overstate completeness.
- **Stated per-step turn/parallelism characteristics.** Any run characteristic the page cites
  (e.g., that the hunt is the fan-out step, or how it behaves on a single accelerator) must
  match the engine's real behavior rather than an idealized one.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The documentation page MUST describe every pipeline step the engine can execute,
  presented in actual execution order. Each step MUST show its readable name (e.g., Recon, Hunt,
  Verify) together with the engine's phase identifier (e.g., Phase 1, Phase 2, Phase 2b).
- **FR-002**: For each step, the page MUST state the inputs it reads and the outputs it writes,
  identifying them by the real artifact filenames the engine consumes and produces (e.g.,
  `phase1_output.md`, `results/`), so a reader can map each step to files in a results directory.
- **FR-003**: The page MUST correctly distinguish steps that always run from steps that are
  optional or individually selectable (including the optional threat-model step and the ability
  to run a subset of phases).
- **FR-004**: The page MUST accurately state the safety boundary: the target's code is never
  executed (no shell), and there is no network egress except communication with the configured
  model server.
- **FR-005**: The page MUST accurately describe per-step model and inference-backend routing as
  implemented — that recon, hunt, verify, and reproduce can each be pointed at a different
  model/host, and that more than one inference backend is supported.
- **FR-006**: The page MUST describe the scan-configuration functions that exist (such as named
  profiles, multi-sample hunt voting, split-vs-combined hunting, sweep mode, quality strictness,
  coverage enforcement, budget cap, and infrastructure-as-code lens) accurately, without
  describing options that are not implemented.
- **FR-007**: The page MUST describe the post-pipeline and cross-run capabilities that exist —
  application intelligence (SBOM, threat model, data-flow diagram), the cross-run vulnerability
  ledger, honest/degraded coverage labeling, exploit-chain analysis, redaction, remediation, and
  the report/output formats produced — and where each capability's output appears.
- **FR-008**: The page MUST NOT describe any step, artifact, option, or capability that does not
  exist in the current implementation.
- **FR-009**: Any run characteristic or metric the page cites (e.g., which step fans out, how the
  hunt behaves on a single accelerator, coverage honesty) MUST reflect the engine's real
  behavior and constraints.
- **FR-010**: Terminology and artifact names on the page MUST match those the engine and app use,
  so a reader can map page content directly to files in a results directory and to tabs in the app.
- **FR-011**: The documentation page MUST remain reachable from the application navigation and
  render without errors after the update.
- **FR-012**: The page MUST explain the static-only validation mode — that findings are confirmed
  by reasoning (static data-flow analysis), not by executing the target, and that exploit tests
  are written but not run — so a reader understands what "confirmed" does and does not mean.
- **FR-013**: The page MUST explain the three orthogonal status axes a run reports — execution
  status, coverage status, and validation mode — as independent signals that are not collapsed
  into one label, consistent with how the engine reports them (including that a fully executed
  run can still be coverage-degraded).
- **FR-014**: The page MUST describe the report and export formats the engine produces (the
  human-readable report, and the machine-readable finding/export outputs), so a reader knows what
  deliverables a completed scan yields and where they are found.
- **FR-015**: The page MUST be a technical reference covering the pipeline flow, the configurable
  functions, the outputs, and the safety/status concepts — but it is NOT required to enumerate
  every individual CLI flag, API field, or internal module.

### Key Entities *(include if feature involves data)*

- **Documentation page**: The single user-facing "how it works" page in the application. Its
  content is the subject of this feature.
- **Pipeline step**: A stage of a scan, with a name, an execution position, a purpose, the
  artifacts it reads, the artifacts it writes, and whether it always runs or is optional/selectable.
- **Configurable function**: A knob the operator can set for a run (model/backend routing per
  step, profile, multi-sample voting, hunt mode, sweep mode, strictness, budget cap, IaC lens,
  and similar), with a user-facing meaning and effect.
- **Post-pipeline capability**: A feature that operates on or across completed scans
  (application intelligence, cross-run ledger, coverage labeling, exploit chains, output formats,
  redaction, remediation), with an output and a location where the user finds it.
- **Run status & validation mode**: The way a run reports what happened — three independent axes
  (execution status, coverage status, validation mode) plus the static-only meaning of a
  "confirmed" finding — which the page must convey rather than collapse into a single label.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of the steps the engine can execute are represented on the page, in correct
  execution order.
- **SC-002**: Every step's stated inputs and outputs match real engine artifacts — zero
  mismatched or non-existent artifact names.
- **SC-003**: The page describes zero steps, options, or capabilities that do not exist in the
  current implementation.
- **SC-004**: A reader can locate the results-directory artifact for each described step's
  outputs using only the page's terminology, with zero artifacts unfindable.
- **SC-005**: Every item whose behavior is optional, selectable, or backend/model-dependent is
  labeled as such — zero items mislabeled as always-on (or vice versa).
- **SC-006**: In a short comprehension check, at least 90% of first-time readers correctly answer
  what each step does and whether the tool executes the scanned code.
- **SC-007**: The page loads from the app navigation and renders with zero errors.
- **SC-008**: Each described step shows both its readable name and its engine phase identifier —
  100% of steps carry both, with zero name/phase-ID mismatches against the engine.
- **SC-009**: A reader can correctly state, from the page alone, that the tool does not execute
  the scanned code and that a "confirmed" finding is confirmed by reasoning rather than execution.
- **SC-010**: The page presents execution status, coverage status, and validation mode as three
  distinct signals — a reader can name all three and does not conflate "finished" with "fully
  covered".

## Assumptions

- "The documentation page" refers to the in-app "How it works" docs page reached from the app's
  navigation. The project ships **two** UI surfaces that each carry this page, and per the plan-time
  decision (2026-09-13) **both** are in scope: (1) the default served UI's docs page — the
  `docsHTML()` view in `vhlocal/web/index.html`, served at `/` today; and (2) the React UI's docs
  page — `web-react/src/pages/Docs.tsx`, served at `/app`. Both MUST end up consistent with each
  other and with the engine. Project README files and the internal design-language pages are out of
  scope.
- The page's existing visual language (per-step cards plus a "beyond the steps" section) is the
  starting point and is retained, but the update MAY add or reorganize sections where new content
  (configurable functions, output formats, safety/status concepts) requires it. This feature is a
  content/completeness update, not a visual redesign.
- Per the Session 2026-09-13 clarification, "match the technical functions and flow" means a
  fuller technical reference — the pipeline flow, the configurable functions, the outputs, and the
  safety/status concepts — but NOT an exhaustive per-flag, per-API-field, or per-module reference.
- The source of truth for accuracy is the current vhlocal implementation (the scan engine, its
  CLI and server entry points, and the bundled phase methodology) at the current commit; where
  the page and the code disagree, the code is authoritative.
- The audience is operators and security engineers running vhlocal, reading the page in the app.
