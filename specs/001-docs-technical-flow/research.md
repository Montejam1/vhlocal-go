# Phase 0 Research: Docs page ↔ vhlocal technical accuracy

All unknowns from Technical Context are resolved below. Each item is a Decision / Rationale /
Alternatives triple.

## R1. Which surface(s) carry "the documentation page"?

**Decision**: Update **both** in-app docs surfaces and keep them mutually consistent:
1. `docsHTML()` (and its `wireDocs()` + doc CSS) inside `vhlocal/web/index.html` — served at `/`.
2. `web-react/src/pages/Docs.tsx` — the React SPA, served at `/app/docs`.

**Rationale**: `server.py` serves `web/index.html` at `/` (the page a running engine shows today)
and the React build at `/app` (built by `npm run build` → `vhlocal/web/app/`, which is **not
currently present**, and the `web-react/` tree is untracked in git). The two pages are the same
"How it works" view in two UIs. The operator confirmed both are in scope (plan-time decision
2026-09-13); the spec's Assumptions were updated to match.

**Alternatives considered**: (a) React page only — rejected: not built/served today, would not reach
users; (b) default page only — rejected: leaves the successor UI stale and inconsistent.

## R2. Source of truth for the pipeline flow and artifacts

**Decision**: Use the engine as authoritative, sourced from code — primarily
`vhlocal/phases.py`: the `PHASES` list of `PhaseSpec(key, title, prompt_file, output_file, reads, …)`
and `CLASS_GROUPS` (`INJ`, `NAV`, `LOG`). Where code and the current page disagree, code wins.

**Rationale**: `PHASES` is the single registry the engine actually runs from, so it is the correct
ground truth and a stable anchor for an automated test (R6). Canonical phase/artifact set:

| Phase ID | Readable name | key | Writes (`output_file`) | Reads |
|---|---|---|---|---|
| Phase 1 | Recon | `1` | `phase1_output.md` | (target repo) |
| Phase 1t (optional) | Threat model — PASTA | `1t` | `threat_model.md` (+ `sbom.cdx.json`) | `phase1_output.md` |
| Phase 2 | Hunt | `2` | `results/` (one file per agent) | `phase1_output.md` |
| Phase 2b | Verify | `2b` | `phase2b_output.md` (+ `phase2b_handoff.md`) | `results/` |
| Phase 3 | Reproduce | `3` | `phase3_output.md` (+ `poc/`, `exploit_tests/`) | `phase2b_handoff.md` |
| Phase 3d | Sweep | `3d` | `phase3d_output.md` | `phase3_output.md` |
| Phase 4 | Report | `4` | `README.md` | phase1 + 2b + 3 + 3d outputs |

Hunt classes: `INJ` (injection), `NAV` (navigation & access control), `LOG` (logic & crypto).

**Alternatives considered**: hand-maintained fact list in the spec — rejected: it would drift from
code exactly like the docs do; anchoring the test to `PHASES` prevents that.

## R3. Configurable functions to document (from `run.py` / `profiles.py`)

**Decision**: Document these operator-facing functions (grouped), which all exist as CLI flags /
scan-spec fields / profiles:

- **Per-step model + backend routing**: `--model`/`--host` (hunt/default) plus role overrides
  `--recon-*`, `--verify-*`, `--reproduce-*` (model/host/backend each). Backends: Ollama and
  OpenAI-compatible servers (`--backend openai`). → FR-005.
- **Profiles**: `quick`, `thorough`, `share` (structural presets; never pin a model/host). → FR-006.
- **Hunt breadth/robustness**: `--hunt-samples` (multi-sample voting), `--phase2-mode`
  split/combined, `--max-partitions`. → FR-006.
- **Precision/economy knobs**: `--sweep-mode` deterministic/model, `--quality-strictness`,
  `--max-budget-usd`, `--num-ctx`, `--reasoning-effort`. → FR-006.
- **Optional lenses/outputs**: `--threat-model` (PASTA), `--iac-lens`, `--remediate`, `--redact`,
  `--ledger`, `--seed-routes`, `--seed-prior`, coverage enforcement (`--no-enforce-coverage`).

**Rationale**: These are the functions the request's "technical functions" phrase refers to and the
knobs that change cost/recall/precision. The page describes them at a user-facing level (what they
do), not as an exhaustive flag reference (FR-015).

**Alternatives considered**: enumerate every flag/field — rejected by the Session 2026-09-13
clarification (fuller reference, not exhaustive).

## R4. Outputs / export formats to document

**Decision**: Document the deliverables a completed scan yields: the human report
(`SCAN_REPORT.html` + `SCAN_REPORT.md`), machine outputs (`findings.json`, `scan_meta.json`), the
SARIF export, the CycloneDX SBOM (`sbom.cdx.json`, when threat-model ran), and the per-finding
`poc/` + `exploit_tests/` artifacts. → FR-014. Deterministic (no model) generation is a key point
(constitution I/II): metadata comes from `scan_meta.json`, not model prose.

**Rationale**: `consolidate.py` / `render_html.py` render the reports and `findings.json` from
`scan_meta.json`; `sarif.py` emits SARIF. The current default page mentions these only in a trailing
note; they deserve a first-class "What you get" section.

## R5. Post-pipeline / cross-run capabilities to document

**Decision**: Document Application Intelligence (SBOM + threat model + data-flow diagram, in the Apps
tab), the cross-run Vulnerability Ledger (open/fixed/regressed + recall, `lifecycle.py`), honest/
degraded coverage labeling, and **exploit-chain analysis** (`chains.py`, currently undocumented),
plus redaction and remediation as optional passes. → FR-007.

**Rationale**: These exist as modules (`apps.py`, `lifecycle.py`, `chains.py`, `redact.py`,
`remediation.py`) and are user-visible. Exploit chains and the redaction/remediation passes are the
notable omissions on the current page.

## R6. How to test docs↔engine consistency offline

**Decision**: Add `tests/test_docs_consistency.py` — a deterministic `unittest` that:
1. imports `vhlocal.phases.PHASES` and `CLASS_GROUPS` (ground truth);
2. reads both surfaces as text (`vhlocal/web/index.html` and `web-react/src/pages/Docs.tsx`);
3. asserts every phase `output_file`/`reads` filename and every phase readable-name + phase-ID pair
   appears in **each** surface; asserts the three class codes appear;
4. asserts no `phaseN*.md`-style artifact name appears on a page that is **not** in the registry
   (catches invented/renamed artifacts — FR-008);
5. asserts required concept strings are present on each surface: static-only / "not executed",
   the three status-axis terms (execution, coverage, validation mode);
6. asserts the two surfaces agree on the phase/artifact set (mutual consistency).

**Rationale**: Runs offline with no model/network (constitution VII), sources truth from code so it
fails loudly on drift (the exact silent-failure class the constitution targets), and is stdlib-only.

**Alternatives considered**: (a) browser/render test (Playwright) — rejected: needs a browser and
network, violates the offline test rule and adds a dependency; visual render is a manual quickstart
step instead. (b) Snapshot of rendered HTML — rejected: brittle, not anchored to engine truth.

## R7. Drift audit of the current default page (`docsHTML()`)

**Accurate today** (keep): the six-step flow + optional threat model, per-step reads/writes with
real filenames, the hunt classes + gates, the Verify falsification checklist, deterministic sweep,
"one row per exploit-test PASS", per-step model routing, App Intel, Ledger, honest coverage.

**Gaps / fixes to apply on both surfaces**:
- **G1 (Principle I)**: Reword the exploit-test "PASS" language so it does not imply execution in the
  default static-only mode — findings are confirmed by reasoning; exploit tests are written but not
  run unless bash mode is explicitly enabled. (validation mode) → FR-012.
- **G2 (Principle II)**: Add an explicit **three status axes** explanation (execution / coverage /
  validation mode), not just "coverage status". → FR-013.
- **G3**: Add the configurable-functions coverage from R3 (profiles, multi-sample voting, strictness,
  budget cap, IaC lens, redaction, remediation) — currently only split/combined + per-step models. → FR-006.
- **G4**: Add exploit-chain analysis and a first-class outputs/export section (R4/R5). → FR-007/FR-014.
- **G5**: Note both backends (Ollama + OpenAI-compatible), not just a generic "model server". → FR-005.

**React `Docs.tsx`** additionally needs to reach parity with the default page's depth (it currently
has only short step leads and a 4-item "beyond" grid) before the G1–G5 additions.
