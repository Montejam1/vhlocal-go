# Feature 007 — UI surface decision & operator validation plan

Prepared 2026-09-22. Companion to `specs/007-application-completeness/`.

## `/app` (React) surface decision (T048)

**Finding (research I-1):** the served operator surface is the legacy self-contained
`vhlocal/web/index.html` (routes `/`, `/legacy`, `/classic`). The React app under
`web-react/` is **not embedded** — `vhlocal/web/app/` does not exist, so `GET /app`
returns 404. The React `web-react/src/lib/types.ts` already declares the enriched
`AppSummary`/`AppDetail`/`Job` shapes this feature's API now returns.

**Decision:** for this feature, **the legacy `index.html` is the supported surface**
and is the one whose data rendering was fixed (US1/US3/US4 UI edits). Embedding the
React build is **scoped out** of feature 007 and recorded as a follow-up:

- To ship `/app`, build `web-react` (`npm ci && npm run build`) and embed the output
  at `vhlocal/web/app/` so the `//go:embed all:vhlocal/web` directive serves it; then
  re-run the browser acceptance below against `/app` as well.
- The React source in this feature was updated in parallel (Scans/Dashboard error
  states, StepTracker phase-outcomes, Intelligence chip) so an embed is drop-in, but
  it is **not type-checked/bundled in this environment** (no `node_modules`, offline).
  The operator must run `npm run typecheck` before relying on the React surface.

Both surfaces consume the same API contract, so the backend work is complete for
either; only the React embed/build step remains.

## Built provenance for acceptance (SC-008)

Record, at acceptance time:

- `git rev-parse HEAD` and `git status --porcelain` of `vhlocal-go`.
- `sha256sum bin/vhlocal` and the running server's executable hash (compare, as the
  handoff evidence did).
- If `/app` is embedded: the `web-react` commit + `sha256sum` of the built bundle.

## Bounded, operator-owned live-model validation plan (T050 / T034)

**Not executed by the harness.** Do **not** auto-launch a multi-hour scan; do **not**
execute generated exploit material (constitution III). The offline suite
(`go test ./...`) plus seeded browser acceptance is the gate; this plan confirms live
behavior separately.

1. **Browser acceptance (seeded, offline server).** Serve `bin/vhlocal serve
   --reports <seeded-dir>` against the fixtures in `quickstart.md` (≥2 apps incl. a
   ledger-disabled one and an older report; the partial-run fixture). Confirm on the
   legacy surface: Scans list renders all states and shows a distinguishable error on
   a forced `/api/scans` failure; Applications list/detail populate; the partial-run
   scan never shows "all steps complete"; threat model + SBOM open and download.
   Repeat after refresh and restart.
2. **One bounded live scan.** Operator picks a small target and a sensible
   `max_partitions`/`hunt_samples`; sets a `max_budget_usd` if using a paid backend.
   Observe: the scan appears in Scans and Applications; status axes track the engine;
   verification produces decisions (not 98 "no decision"); reproduction registers
   material or explicit deferrals; the report is review-useful.
3. **Compare one representative supported finding** against the reference's report for
   a similar target (by reading the reference output the operator already has), per
   the behavior matrix. File-existence and length are not quality criteria.
4. **Record outcomes** (completion/yield/failure counts, provenance) and only then
   mark T034 in `tasks.md`.

Full live detection-recall parity remains an empirical question, separate from these
integration contracts.
