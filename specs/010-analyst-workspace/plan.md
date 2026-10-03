# Implementation Plan: Evidence-centered analyst workspace

**Branch**: `010-analyst-workspace` | **Date**: 2026-09-22 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/010-analyst-workspace/spec.md`

## Summary

Deliver an evidence-centered analyst workspace: a Findings destination with a
searchable/sortable queue, a source/evidence viewer bound to the scanned revision, durable
human review decisions with inspectable history and conflict handling, honest scan-status
and artifact surfaces, a "Needs attention" set of dashboard queues appended **below** the
preserved dashboard, contextual AI scoped to a finding, and a modernized navigation/
interaction layer — all while preserving features 007–009 and the constitution's boundaries.

**Central architecture decision (from the codebase inventory):** the primary NEW behavior is
**backend-first**. Every trustworthy capability the spec demands — a cross-scan findings
queue (including ledger-disabled scans), revision-bound evidence access, a durable human
review-decision store with history and conflict detection, honest artifact/status surfacing,
and on-demand contextual AI with real provenance — requires new Go endpoints and persistence
that **do not exist today**. That backend is surface-agnostic and fully offline-testable with
`go test ./...` (plus the existing fake provider for AI), which is the increment gate under
the standing "validate offline; operator runs live testing" constraint.

The **React SPA (`web-react/`) is the primary design surface** for the new workspace (sidebar
nav, Findings page, evidence viewer, dashboard queues, contextual AI panel, consistent
dialogs, theming/a11y). It is served at `/app` **only after an operator `npm run build`**
(there is no `node_modules`; `npm ci` needs network), so React build + browser acceptance are
**operator-owned**, exactly as in features 007–009. The committed, self-contained legacy UI
(`vhlocal/web/index.html`, served at `/`) stays accessible and keeps working; this feature
does **not** require a second full redesign of it. Reports and existing links from any
supported entrypoint remain reachable.

Wherever possible the feature **reuses** existing engine capabilities instead of duplicating
them: cross-scan comparison (`internal/lifecycle` + `internal/membank` recall), the three
status axes (`internal/consolidate/status.go` + `internal/server/status.go`), artifact
material states (`internal/reports/material.go`), stable finding identity
(`consolidate.Finding.StableIdentity` / `lifecycle.Key`), and provider provenance
(`client.Provenance`) with the shell-free agent tool loop (`Read/Grep/Glob` only).

## Technical Context

**Language/Version**: Go 1.23+ backend (module `vhlocal`; toolchain at `/usr/local/go`).
Front-end: the served self-contained legacy UI (`vhlocal/web/index.html`, vanilla JS/CSS, no
build step, embedded) and the React 19 + React-Router 7 + Vite 6 + Tailwind 4 SPA under
`web-react/` (TypeScript 5.7).

**Primary Dependencies**: Backend — standard library `net/http` (Go 1.22 `method path` mux),
existing internal packages (`consolidate`, `lifecycle`, `membank`, `reports`, `apps`,
`verification`, `engine`, `client`, `agent`, `jobs`, `server`). No new third-party Go
dependency is anticipated; any addition follows the constitution's reviewed dependency
budget. Front-end — no new runtime dependency; React uses libraries already declared in
`web-react/package.json` (no CDN; self-contained build).

**Storage**: Files under `~/vulnhunter-reports/<scan dir>/` (scan evidence, artifacts —
never rewritten) and `~/.vhlocal/` (ledger, applications registry, jobs, logs, activity). New
persistence added additively under `~/.vhlocal/` for **human review decisions + history**,
**saved views/filters**, and **contextual-AI results** — each keyed by stable finding
identity, separate from and non-overwriting of scan evidence. No database; JSON files with
atomic temp+rename (mirroring `jobs.Store.persist`), resumable and idempotent.

**Testing**: Offline Go suite (`go test ./...`, `go vet`, `gofmt -l`) for every new endpoint,
store, comparison surface, status/artifact mapping, and the contextual-AI path (via the
existing `internal/client/testsupport/fake.go`). Deterministic fixtures extend
`internal/server/testsupport/seed.go`. React `npm run typecheck`/`build` and browser
acceptance are **operator-owned** (no `node_modules` offline). No live model calls; no Python.

**Target Platform**: Loopback single-binary HTTP server + browser UI (legacy served at `/`;
React served at `/app` when built).

**Project Type**: Web service with two front-end surfaces (backend-heavy feature).

**Performance Goals**: Local finding operations (filter change, select finding, next finding)
return within 2 seconds against a documented 1,000-finding fixture, excluding live inference
(SC-011). Queue/aggregate endpoints stay responsive by reading indexed report data, not
rescanning.

**Constraints**: Static-only (no target execution; contextual-AI tools stay `Read/Grep/Glob`,
no shell, no target writes); three independent status axes never collapsed; engine-recorded
provenance; explicit provider failure with no silent fallback; resumable/idempotent stores;
self-contained/offline UI (no CDN, no unconfigured egress); untrusted repo/AI content never
executed and never treated as tool-authorizing instructions; repository/artifact path
containment; all pre-existing dashboard numbers/charts/order preserved; feature-009 Table/List
+ persistence + delete/forget semantics preserved; forget/clear keeps reports; review never
recreates cleared tracking.

**Scale/Scope**: One large feature in dependency-ordered increments (US1→US6). Data scale:
dozens of applications, hundreds of scans, ~1,000 findings per fixture; single local operator.

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after Phase 1. Constitution v1.1.0.*

- **I. Evidence Integrity** — Human decisions are stored **separately** and never overwrite
  scan evidence or the AI verdict (FR-020); evidence citations must resolve or be marked
  unavailable/invalid (FR-015); missing revision/source is stated, working tree never
  substituted (FR-012); no unsupported numeric confidence; authored-only ≠ executed (FR-017);
  unknown/incomparable states used honestly (FR-024, FR-028, FR-036). **PASS.**
- **II. Orthogonal Status Reporting** — All three axes carried on every run-status surface or
  marked unavailable; coverage/validation never inferred from completion (FR-025/FR-026).
  Reuses `ComputeRunStatus`/`scanStatus`. **PASS.**
- **III. Static-Only Safety Boundary** — No target execution added. Evidence viewer and
  contextual AI are read-only; AI tools remain `Read/Grep/Glob`; drafts are non-executed
  artifacts that never touch the working tree or install deps (FR-043); path containment
  preserved (FR-055); existing authorized isolated execution keeps its safeguards. **PASS.**
- **IV. AI Result Provenance** — Contextual-AI results carry engine-recorded
  `client.Provenance` (backend/endpoint/models/tokens) captured at call time, labeled distinct
  from scan evidence (FR-040). Secrets never persisted (existing behavior). **PASS.**
- **V. Explicit AI Failure, No Silent Fallback** — Contextual-AI failures/retries/cancellation
  are surfaced; provider/destination shown before submission; no silent provider/model switch
  (FR-041/FR-042). **PASS.**
- **VI. Resumable / Idempotent** — New JSON stores use atomic writes and stable-identity keys;
  decisions are append-only with supersede-not-erase; reads tolerate partial/old records;
  contextual-AI results keyed by finding+revision are idempotently addressable. No auto-rescan
  (FR-024, FR-030). **PASS.**
- **VII. Testable offline** — Every new backend surface has offline Go tests; the AI path uses
  the fake provider; fixtures are deterministic; React/browser is operator-owned as in prior
  UI work. **PASS (front-end acceptance recorded as operator-owned).**
- **Safety & Technical Constraints (Runtime/dependency budget, self-contained UI)** — No CDN,
  no unconfigured network; new Go deps avoided (budget-reviewed if unavoidable); dev/test
  tooling kept distinct from delivered-app deps. **PASS.**

**Gate result: PASS.** No violations → Complexity Tracking omitted. Re-check after Phase 1:
still PASS (design introduces additive stores + read-only surfaces + provenanced AI, all
within the boundaries above).

## Project Structure

### Documentation (this feature)

```text
specs/010-analyst-workspace/
├── plan.md          # this file
├── research.md      # Phase 0 output (decisions R1–R11)
├── data-model.md    # Phase 1 output (new stores + reused entities)
├── quickstart.md    # Phase 1 output (offline gate + operator browser acceptance)
├── contracts/       # Phase 1 output (new/changed HTTP + UI behavior contracts)
└── tasks.md         # /speckit-tasks (not created here)
```

### Source Code (repository root)

```text
internal/
├── findings/                # NEW: cross-scan finding index + queue (reads reports/consolidate),
│                            #      stable-identity resolution across scans (reuses lifecycle.Key)
├── review/                  # NEW: durable human review-decision store + append-only history
│                            #      + optimistic-version conflict handling (~/.vhlocal/reviews/)
├── views/                   # NEW: named saved views/filters store (~/.vhlocal/views/)
├── evidence/                # NEW: revision-bound source/excerpt access (captured source or
│                            #      recorded git_commit), explicit "revision unavailable" state
├── assist/                  # NEW: contextual-AI orchestration for one finding (bounded call
│                            #      via client.Provider + agent Read/Grep/Glob), result store
├── attention/              # NEW: "Needs attention" queue computation (reuses findings + lifecycle
│                            #      + status + artifacts), independent-failure isolation
├── reports/                 # EXTEND: artifact manifest state set (add pending/failed/missing/
│                            #         unreadable/malformed/unknown; "available"=validated)
├── consolidate/, lifecycle/, membank/, apps/, verification/, engine/  # REUSED, minimal/no change
├── client/, agent/          # REUSED by internal/assist (provider + shell-free tools + provenance)
└── server/
    ├── handlers.go          # EXTEND: register new routes (findings, evidence, reviews, views,
    │                        #         attention/queues, assist, artifact manifest)
    ├── status.go            # REUSED/EXTEND: status axes + artifact manifest surfacing
    └── testsupport/seed.go  # EXTEND: fixtures (ledger-disabled scan, revisions, artifact states,
                             #         comparable baselines, 1,000-finding set, provider fixtures)

web-react/src/               # PRIMARY design surface (operator-built/served at /app)
├── pages/Findings.tsx       # NEW: queue + evidence + review + assist workspace
├── pages/Dashboard.tsx      # EXTEND: preserve all metrics/charts; add "Needs attention" below
├── pages/Scans.tsx, Applications.tsx, Reports.tsx, Ledger.tsx, Settings  # EXTEND: status/artifact,
│                            #   real Settings (not placeholder), context preservation
├── components/Layout.tsx    # EXTEND: collapsible sidebar; consistent dialog primitive; theming
└── lib/api.ts               # EXTEND: clients for the new endpoints

vhlocal/web/index.html       # LEGACY served surface: kept accessible + unregressed; reports/links
                             # remain reachable. No full redesign; targeted reuse only where it
                             # keeps parity for existing views (per spec scope).
```

**Structure Decision**: Backend-first, additive. New internal packages (`findings`, `review`,
`views`, `evidence`, `assist`, `attention`) provide the real behavior and carry the offline
test surface; `reports`/`server`/`status` are extended; `consolidate`/`lifecycle`/`membank`/
`verification`/`client`/`agent` are reused as-is. The React SPA is the primary UI for the new
workspace (operator-built); the legacy UI stays accessible and unregressed. This keeps the
constitution's offline-testability gate on the Go side while honoring "React is the primary
design target" and "don't rewrite the legacy UI."

## Complexity Tracking

No constitution violations — section intentionally omitted. (The multiple new internal
packages are cohesion boundaries, not gratuitous projects: each owns one persistence concern
with its own offline tests, which is simpler to verify than folding review/assist/views state
into existing packages.)
