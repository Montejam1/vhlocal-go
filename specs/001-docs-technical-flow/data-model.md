# Phase 1 Data Model: documentation content entities

This feature has no runtime data model (the pages are static). The "entities" are the content
structures each docs surface must present, and the rules each must satisfy. They map directly to the
spec's Key Entities and Functional Requirements, and are what the drift-guard test verifies.

## Entity: DocSurface

One of the two UI pages carrying the docs content.

| Field | Value |
|---|---|
| id | `default` or `react` |
| file | `vhlocal/web/index.html` (`docsHTML()`/`wireDocs()` + doc CSS) · `web-react/src/pages/Docs.tsx` |
| route | `/` · `/app/docs` |

**Rule**: Both surfaces MUST present the same DocStep set, the same artifact names, and the same
concept coverage (mutual consistency). Visual treatment may differ; substance may not.

## Entity: DocStep

A pipeline step as shown on the page. Sourced from `vhlocal.phases.PHASES`.

| Field | Source | Rule |
|---|---|---|
| readable_name | reviewed (Recon, Threat model, Hunt, Verify, Reproduce, Sweep, Report) | MUST appear |
| phase_id | derived from `PhaseSpec.key` (Phase 1, 1t, 2, 2b, 3, 3d, 4) | MUST appear alongside the name (FR-001) |
| optional | `1t` is optional; others always run (subset selectable) | optional/selectable MUST be labeled (FR-003, SC-005) |
| reads | `PhaseSpec.reads` | filenames MUST match the registry (FR-002) |
| writes | `PhaseSpec.output_file` | filenames MUST match the registry (FR-002) |
| purpose | reviewed prose | MUST describe what the step does |

**Rule**: No DocStep may reference a `phaseN*`-style artifact absent from the registry (FR-008).
Steps appear in execution order (SC-001).

## Entity: HuntClass

The three Phase-2 vulnerability classes. Sourced from `vhlocal.phases.CLASS_GROUPS`.

| Field | Value | Rule |
|---|---|---|
| code | `INJ`, `NAV`, `LOG` | all three MUST appear |
| label | injection · navigation & access control · logic & crypto | MUST match the registry description |

## Entity: ConfigFunction

An operator-facing knob the page describes (R3). Fields: name, what it does, effect on
cost/recall/precision. **Rule**: every ConfigFunction described MUST correspond to a real CLI
flag / scan-spec field / profile (FR-006); none may be invented (FR-008). Required coverage:
per-step model+backend routing, backends (Ollama + OpenAI-compatible), profiles, multi-sample
voting, split/combined hunt, sweep mode, quality strictness, budget cap, IaC lens, redaction,
remediation, ledger, threat-model.

## Entity: OutputArtifact

A deliverable a completed scan yields (R4). Fields: name, format, human/machine, location.
**Rule**: every OutputArtifact described MUST be one the engine actually produces (FR-014):
`SCAN_REPORT.html`, `SCAN_REPORT.md`, `findings.json`, `scan_meta.json`, SARIF export,
`sbom.cdx.json` (when threat-model ran), `poc/`, `exploit_tests/`. The page MUST state report
metadata is engine-observed (deterministic), not model prose.

## Entity: PostPipelineCapability

A feature operating on/across completed scans (R5). Fields: name, output, location (tab/artifact).
**Rule**: every capability described MUST exist (FR-007): Application Intelligence (Apps tab),
Vulnerability Ledger (Ledger tab, cross-run open/fixed/regressed + recall), honest/degraded
coverage, exploit-chain analysis, redaction, remediation.

## Entity: StatusAxis

One of the three independent run-status axes the page must explain (FR-013, SC-010).

| axis | meaning |
|---|---|
| execution status | did the requested phases run to completion and produce valid deliverables? |
| coverage status | did the run reach the whole in-scope surface, or was it degraded (with reasons)? |
| validation mode | were findings validated statically (reasoning) or dynamically (execution)? |

**Rule**: The page MUST present these as three distinct signals and MUST NOT imply one determines
another (e.g., "finished" ≠ "fully covered"). It MUST state the default validation mode is static —
findings confirmed by reasoning; exploit tests written but not run unless bash mode is enabled
(FR-012, SC-009).

## Concept coverage checklist (verified by the test)

Each surface MUST contain: all 7 DocStep names + phase IDs; all step artifact filenames; the 3
HuntClass codes; the static-only / "not executed" statement; the three StatusAxis terms
(execution, coverage, validation mode). No unregistered `phaseN*` artifact name may appear.
