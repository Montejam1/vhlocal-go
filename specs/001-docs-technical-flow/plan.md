# Implementation Plan: Docs page matches vhlocal's technical functions & flow

**Branch**: `001-docs-technical-flow` | **Date**: 2026-09-13 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-docs-technical-flow/spec.md`

## Summary

Bring the in-app "How VulnHunter works" documentation page into faithful agreement with what
vhlocal actually does — the pipeline flow, the configurable functions, the outputs, and the
safety/status concepts — across **both** UI surfaces that carry it: the default served UI's docs
view (`docsHTML()` in `vhlocal/web/index.html`) and the React UI's docs page
(`web-react/src/pages/Docs.tsx`). Each step is presented by its readable name plus its engine
phase identifier and real artifact filenames; the page explains the static-only validation mode
and the three orthogonal status axes; and it documents the configurable functions and post-pipeline
capabilities without inventing any that do not exist. A deterministic, offline unit test anchored to
the engine's phase registry pins the docs to the code so the two cannot silently drift apart.

## Technical Context

**Language/Version**: TypeScript + React 19 (the `web-react` SPA, Vite 6 build); vanilla
JS/HTML/CSS inside the stdlib-served `vhlocal/web/index.html`; Python 3.9+ (stdlib only) for the
consistency test and the server that serves both surfaces.

**Primary Dependencies**: No new dependencies. The React page reuses existing local components
(`@/components/ui/card`, `badge`, etc.); the default page is hand-written HTML/CSS/JS in one
self-contained file. The test uses only the Python standard library and imports `vhlocal.phases`.

**Storage**: N/A — the docs pages are static content; no persisted state.

**Testing**: `python3 -m unittest discover -s tests` (offline, no model, no network). A new
deterministic drift-guard test cross-checks both docs surfaces against `vhlocal.phases.PHASES`
and `CLASS_GROUPS`. Plus a manual visual render check of both surfaces (quickstart.md).

**Target Platform**: Browser, served by the stdlib engine server — the default UI at `/`
(`web/index.html`) and the React build at `/app` (`web/app/`, produced by `npm run build`).

**Project Type**: Web application (a documentation page within a larger local security tool).

**Performance Goals**: N/A for a content page. Hard requirement inherited from the constitution:
both surfaces stay **self-contained and offline** — no CDN, no external requests at runtime.

**Constraints**: Content must match the engine at the current commit; no new Python or npm runtime
dependencies; no change to the static-only safety boundary or to how the engine computes status;
the two surfaces must be mutually consistent.

**Scale/Scope**: Two files carry the page content — `vhlocal/web/index.html` (the `docsHTML()` /
`wireDocs()` region, ~lines 1773–2135, plus its CSS) and `web-react/src/pages/Docs.tsx` (~120
lines, to be expanded) — plus one new test file under `tests/`.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Per-principle impact (the spec must state impact on the safety boundary, status axes, provenance,
and failure handling — Development Workflow gate):

- **I. Evidence Integrity** — *Directly served.* The feature forbids describing features that do
  not exist (FR-008) and corrects a standing honesty gap: the default page implies an exploit-test
  "PASS" even though the static-only harness writes exploit tests but never runs them. The page will
  state that findings are confirmed by reasoning, not execution (FR-012). The drift-guard test
  enforces docs↔engine agreement. **PASS.**
- **II. Orthogonal Status Reporting** — *Directly served.* The page will present execution status,
  coverage status, and validation mode as three independent axes and must not collapse them
  (FR-013). No change to how the engine computes them. **PASS.**
- **III. Static-Only Safety Boundary** — *No change.* Documentation-only; the page describes the
  boundary (FR-004/FR-012). No code is executed, no tool gains a shell, no default changes. **PASS.**
- **IV. AI Result Provenance** — *No impact.* The feature produces no AI results. The page will
  describe per-step model/backend routing accurately (FR-005). **PASS.**
- **V. Explicit AI Failure, No Silent Fallback** — *No impact.* No provider/model selection logic
  is touched. **PASS.**
- **VI. Resumable, Idempotent Operations** — *No impact.* Static content; the test is deterministic
  and repeatable. **PASS.**
- **VII. Testable Acceptance & Regression Coverage** — *Directly served.* Ships an offline,
  deterministic `unittest` anchored to `vhlocal.phases.PHASES` / `CLASS_GROUPS` that fails loudly
  when the engine's phase/artifact set changes but the docs do not — pinning exactly the silent-drift
  class of failure the constitution names. **PASS.**

Technical constraints: stdlib-only test, **no new Python or npm runtime dependencies**, both
surfaces remain self-contained/offline. Documentation gate: `CHANGELOG.md` gets an entry
(user-visible change). Review gate: no new code path fabricates success, collapses status axes,
widens the safety boundary, drops provenance, adds a silent fallback, or breaks resume/idempotency.

**Result: PASS — no violations. Complexity Tracking not required.**

**Post-design re-check (after Phase 1)**: Still PASS. The design (research.md, data-model.md,
contracts/docs-consistency.md, quickstart.md) adds only static page content and one stdlib-only,
offline `unittest` anchored to `vhlocal.phases`. No new Python/npm dependency, no server change, no
safety-boundary change, no status-axis collapse (the design *adds* the three-axis explanation), and
provenance/failure/resume are untouched. The drift-guard test directly satisfies Principle VII.

## Project Structure

### Documentation (this feature)

```text
specs/001-docs-technical-flow/
├── plan.md              # This file
├── research.md          # Phase 0 output — decisions, ground-truth source, drift audit
├── data-model.md        # Phase 1 output — content entities + canonical fact table
├── quickstart.md        # Phase 1 output — how to validate both surfaces
├── contracts/
│   └── docs-consistency.md   # The docs-content contract + drift-guard test contract
└── tasks.md             # /speckit-tasks output (NOT created here)
```

### Source Code (repository root)

```text
vhlocal/
├── web/
│   └── index.html            # Default served UI (/). Edit docsHTML() + wireDocs() + doc CSS.
│                             # React build lands in web/app/ (git-ignored, built by npm).
├── phases.py                 # Ground truth: PHASES registry, CLASS_GROUPS (read-only here)
├── server.py                 # Serves / (index.html) and /app (React build) — unchanged
└── consolidate.py / sarif.py / render_html.py / chains.py / lifecycle.py / apps.py
                              # Source of truth for outputs & post-pipeline capabilities (read-only)

web-react/
└── src/pages/Docs.tsx        # React UI docs page (served at /app/docs). Expand for parity + additions.

tests/
└── test_docs_consistency.py  # NEW: deterministic offline drift-guard test (both surfaces vs engine)
```

**Structure Decision**: This is a content update to two existing UI surfaces plus one new test.
No new modules, no new dependencies, no server changes. The default page (`docsHTML()`) is already
a strong, mostly-accurate baseline; the React page must be expanded to parity and both must gain the
clarified additions (status axes, validation-mode honesty, configurable functions, outputs, chains).

## Complexity Tracking

No constitution violations — section intentionally empty.
