---
description: "Task list for Docs page ↔ vhlocal technical accuracy"
---

# Tasks: Docs page matches vhlocal's technical functions & flow

**Input**: Design documents from `specs/001-docs-technical-flow/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/docs-consistency.md, quickstart.md

**Tests**: INCLUDED — the constitution (Principle VII) mandates offline automated tests, and the plan
specifies a deterministic drift-guard test (`tests/test_docs_consistency.py`) anchored to
`vhlocal.phases`. Test tasks are therefore required, not optional, for this feature.

**Organization**: Tasks are grouped by user story (from spec.md). Note the two edited surfaces are
shared files (`vhlocal/web/index.html`, `web-react/src/pages/Docs.tsx`), so stories are independently
*testable* but not fully independently *parallelizable* — see Dependencies.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: US1 / US2 / US3 (maps to spec.md user stories)
- Exact file paths are included in every task

## Path Conventions

- Default UI surface: `vhlocal/web/index.html` (the `docsHTML()` / `wireDocs()` region + doc CSS)
- React UI surface: `web-react/src/pages/Docs.tsx`
- Ground truth (read-only): `vhlocal/phases.py` (`PHASES`, `PHASES_BY_KEY`, `CLASS_GROUPS`)
- Test: `tests/test_docs_consistency.py`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Make both surfaces editable and buildable before content work.

- [ ] T001 [P] Ensure the React docs surface is under version control: `git add` the untracked files
  in `web-react/` (at minimum `web-react/src/pages/Docs.tsx` and anything it imports) so the change is
  captured. Confirm with `git status` that `web-react/src/pages/Docs.tsx` is tracked.
- [ ] T002 [P] Verify the React build path per quickstart §3: `cd web-react && npm install && npm run
  build` emits `vhlocal/web/app/`. Fix any build break now; do not edit content until the build is green.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Stand up the drift-guard test harness and the cross-cutting invariants every story validates against.

**⚠️ CRITICAL**: No story-content task should be marked done until the harness exists and its invariants run.

- [ ] T003 Create `tests/test_docs_consistency.py` harness per `contracts/docs-consistency.md` §C2:
  import `vhlocal.phases.PHASES`, `PHASES_BY_KEY`, `CLASS_GROUPS`; read both surfaces
  (`vhlocal/web/index.html`, `web-react/src/pages/Docs.tsx`) as UTF-8 text; add helpers
  `_present(surface_text, term)` (case-insensitive) and `_registry_artifacts()` returning the set of
  `output_file`/`reads` names from `PHASES`. Stdlib + `unittest` only; no network, no model.
- [ ] T004 In `tests/test_docs_consistency.py`, add the two cross-cutting invariants: (a) **no invented
  artifacts** — every token matching `phase\d\w*(\.md|_output|_handoff)?|results/` found on either
  surface MUST be in `_registry_artifacts()` (FR-008); (b) **mutual consistency** — the set of registry
  artifact names present is identical across both surfaces. Run `python3 -m unittest
  tests.test_docs_consistency` — it MUST currently FAIL (content not yet updated).

**Checkpoint**: Harness present and failing — content work can begin.

---

## Phase 3: User Story 1 - Pipeline flow matches what runs (Priority: P1) 🎯 MVP

**Goal**: Both surfaces present the 7 steps (readable name + engine phase ID, in execution order) with
correct `reads`/`writes` filenames, mark the threat-model step optional, and honestly explain the
static-only validation mode and the three orthogonal status axes.

**Independent Test**: `python3 -m unittest tests.test_docs_consistency` passes the US1 assertions
(T005), and quickstart §2–3 confirms both pages show the correct steps/artifacts, the validation-mode
statement, and the three status axes.

### Tests for User Story 1 ⚠️ (write first; must fail before T006–T010)

- [ ] T005 [US1] Extend `tests/test_docs_consistency.py`: for **each** surface assert — every
  `PhaseSpec.output_file` and every `reads` entry (skip the bare-repo read) is present; every phase-ID
  label from `PHASES_BY_KEY` (`Phase 1`, `Phase 1t`, `Phase 2`, `Phase 2b`, `Phase 3`, `Phase 3d`,
  `Phase 4`) is present; the 7 readable names (Recon, Threat model, Hunt, Verify, Reproduce, Sweep,
  Report) are present; the three `CLASS_GROUPS` codes (INJ, NAV, LOG) are present; and the required
  concept terms are present — static-only / "not executed", and the three axis terms `execution`,
  `coverage`, `validation mode`. (FR-001/002/003/004/012/013; SC-001/002/004/005/008/009/010)

### Implementation for User Story 1

- [ ] T006 [US1] In `vhlocal/web/index.html` (`docsHTML()`): verify/correct all 7 step sections — each
  shows readable name **and** phase-ID badge, in execution order, with `reads`/`writes` matching
  `PHASES` exactly (`phase1_output.md`, `threat_model.md`+`sbom.cdx.json`, `results/`,
  `phase2b_output.md`+`phase2b_handoff.md`, `phase3_output.md`+`poc/`+`exploit_tests/`,
  `phase3d_output.md`, `README.md`); keep the threat-model step labeled **Optional**.
- [ ] T007 [US1] In `vhlocal/web/index.html` (`docsHTML()`): apply the validation-mode honesty fix
  (research G1) — reword the Phase 3 / Report "exploit-test PASS" language so the default static-only
  mode states exploit tests are **written but not run**, and findings are confirmed by reasoning, not
  execution; note bash mode as the explicit opt-in that runs them. (FR-012; Constitution I)
- [ ] T008 [US1] In `vhlocal/web/index.html`: add an explicit **"Three status axes"** block (execution
  status · coverage status · validation mode) stating they are independent and that "finished" ≠ "fully
  covered"; add any needed anchor/nav wiring in `wireDocs()` and doc CSS. (FR-013; Constitution II)
- [ ] T009 [P] [US1] In `web-react/src/pages/Docs.tsx`: expand the `STEPS` data + rendering so all 7
  steps show readable name + phase ID + correct `reads`/`writes` (parity with T006), preserving the
  optional marker for the threat-model step. (different file from T006–T008 → parallel)
- [ ] T010 [US1] In `web-react/src/pages/Docs.tsx`: add the validation-mode honesty statement (G1) and a
  three-status-axes section (mirror T007–T008 substance). (depends on T009 — same file)

**Checkpoint**: T005 passes on both surfaces; MVP is a correct, honest pipeline description on the live
and React pages.

---

## Phase 4: User Story 2 - Configurable functions documented accurately (Priority: P2)

**Goal**: Both surfaces document the real operator-facing functions (research R3) without inventing any.

**Independent Test**: T011 passes and quickstart §2–3 shows the configurable-functions content on both pages.

### Tests for User Story 2 ⚠️

- [ ] T011 [US2] Extend `tests/test_docs_consistency.py`: for each surface assert the config-function
  terms are present — `OpenAI` (backend), `profile`, `multi-sample`/`voting`, `combined` (hunt mode),
  `sweep`, `strictness`, `budget`, `IaC`/`infrastructure-as-code`, `redact`, `remediat`. (Reviewed term
  list per research R3; comment the source in the test.) (FR-005/006; SC-003/005)

### Implementation for User Story 2

- [ ] T012 [US2] In `vhlocal/web/index.html` (`docsHTML()`): add/extend a **"Configurable functions"**
  section covering per-step model + backend routing (Ollama **and** OpenAI-compatible), profiles
  (quick/thorough/share), multi-sample hunt voting, split/combined hunt, sweep mode
  (deterministic/model), quality strictness, budget cap, IaC lens, redaction, remediation, ledger — each
  described by what it does, none invented. (FR-005/006)
- [ ] T013 [P] [US2] In `web-react/src/pages/Docs.tsx`: add the same configurable-functions content
  (parity with T012). (different file from T012 → parallel)

**Checkpoint**: US1 + US2 content present and verified on both surfaces.

---

## Phase 5: User Story 3 - Post-pipeline capabilities & outputs (Priority: P3)

**Goal**: Both surfaces document the post-pipeline/cross-run capabilities (research R5) and a first-class
outputs section (research R4), with correct locations; report metadata is engine-observed.

**Independent Test**: T014 passes and quickstart §2–3 shows the capabilities + outputs content on both pages.

### Tests for User Story 3 ⚠️

- [ ] T014 [US3] Extend `tests/test_docs_consistency.py`: for each surface assert the post-pipeline +
  output terms are present — `exploit chain`/`chain`, `Application Intelligence`/`App Intel`, `ledger`,
  `SBOM`/`sbom.cdx.json`, `SARIF`, `SCAN_REPORT`, `findings.json`, `scan_meta.json`, `remediat`,
  `redact`. (FR-007/014; SC-003)

### Implementation for User Story 3

- [ ] T015 [US3] In `vhlocal/web/index.html` (`docsHTML()`): add **exploit-chain analysis** to "Beyond
  the steps" (research G4) and add/expand a **"What you get" / Outputs** section listing
  `SCAN_REPORT.html`+`SCAN_REPORT.md`, `findings.json`, `scan_meta.json`, SARIF export, `sbom.cdx.json`
  (when threat-model ran), `poc/`, `exploit_tests/`, with locations and a note that report metadata is
  engine-observed (deterministic), not model prose. Keep App Intel / Ledger / honest-coverage items.
  (FR-007/014; Constitution I/II)
- [ ] T016 [P] [US3] In `web-react/src/pages/Docs.tsx`: add the same post-pipeline + outputs content
  (parity with T015), updating the `BEYOND` grid. (different file from T015 → parallel)

**Checkpoint**: All three stories present and verified on both surfaces.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [ ] T017 [P] Add a `CHANGELOG.md` entry (newest-first) describing the docs-page update (both
  surfaces) — required by the constitution's Documentation gate.
- [ ] T018 Run the full offline suite `python3 -m unittest discover -s tests`; confirm
  `test_docs_consistency` passes and no prior test regressed. Report results as they actually are.
- [ ] T019 Run quickstart.md validation end-to-end: default page at `/` and React page at `/app`
  render without console errors, make **no external requests** (offline/no CDN), and a short
  comprehension check confirms a reader can state the six steps, the safety boundary, and the three
  status axes (SC-006/007/009/010).
- [ ] T020 [P] Final mutual-consistency pass: read `docsHTML()` and `Docs.tsx` side by side and
  reconcile any wording drift so the substance matches (spec Assumptions; enforced by T004(b)).

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies — start immediately. T001 unblocks all React edits; T002 unblocks React visual validation.
- **Foundational (Phase 2)**: depends on Setup. T003 → T004. BLOCKS all story test tasks.
- **User Stories (Phase 3–5)**: each depends on Foundational. Ordered P1 → P2 → P3.
- **Polish (Phase 6)**: depends on all desired stories being complete.

### User Story Dependencies & the shared-file caveat

- Stories are independently **testable** (each has its own assertions T005/T011/T014 and its own content).
- They are **not** independently **parallelizable across developers**: US1/US2/US3 each edit the same
  two files (`vhlocal/web/index.html`, `web-react/src/pages/Docs.tsx`) and the same test file. Do them
  in priority order to avoid merge conflicts. Within a story, the default-surface and React-surface
  tasks touch different files and can run in parallel.

### Within Each Story

- Test task (write first, fails) → default-surface content → React-surface content.
- Same-file tasks are sequential; cross-file tasks are `[P]`.

### Parallel Opportunities

- T001 ∥ T002 (Setup).
- Within US1: T009 (Docs.tsx) ∥ T006–T008 (index.html). T010 after T009 (same file).
- Within US2: T013 (Docs.tsx) ∥ T012 (index.html).
- Within US3: T016 (Docs.tsx) ∥ T015 (index.html).
- Polish: T017 ∥ T020.

---

## Parallel Example: User Story 1

```bash
# After T005 (US1 test written and failing), edit the two surfaces in parallel:
Task: "T006–T008 update the 7 steps + validation-mode fix + status-axes block in vhlocal/web/index.html"
Task: "T009 expand STEPS (name + phase ID + reads/writes) in web-react/src/pages/Docs.tsx"
# Then T010 (Docs.tsx status-axes + validation mode) after T009, and re-run T005 until green.
```

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. Phase 1 Setup → Phase 2 Foundational (test harness failing).
2. Phase 3 US1 → the live and React pages carry a correct, honest pipeline description with real phase
   IDs/artifacts, validation mode, and three status axes.
3. **STOP and VALIDATE**: `python3 -m unittest tests.test_docs_consistency` + quickstart §2–3.
4. This alone is a shippable correctness/honesty win (fixes the exploit-test "PASS" drift).

### Incremental Delivery

1. Setup + Foundational → harness ready.
2. US1 → correct flow (MVP). 3. US2 → configurable functions. 4. US3 → capabilities + outputs.
5. Polish → CHANGELOG, full suite, quickstart, final consistency pass.

---

## Notes

- [P] = different files, no incomplete-task dependency.
- The drift-guard test is the acceptance spine — keep it green after each story; it fails loudly if the
  engine's `PHASES`/`CLASS_GROUPS` change but the docs don't (the silent-drift class the constitution targets).
- No new Python or npm dependencies. Both surfaces stay self-contained/offline (no CDN).
- Commit after each task or logical group. Do not report a task done if its assertions/tests are not actually passing.
