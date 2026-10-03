# Quickstart: validate the updated docs pages

Proves the feature end-to-end: the docs↔engine consistency test passes, and both surfaces render
correctly and read accurately. Run from the repo root.

## Prerequisites

- Python 3.9+ (stdlib only — no venv, no pip).
- Node + npm **only** to build/preview the React surface (`web-react/`). The default surface
  (`vhlocal/web/index.html`) needs no build.

## 1. Automated consistency check (the gate)

```bash
python3 -m unittest tests.test_docs_consistency -v     # the new drift-guard test
python3 -m unittest discover -s tests                  # full suite still green, offline
```

**Expected**: `test_docs_consistency` passes — both surfaces contain every phase name + phase ID,
every real artifact filename, the three status-axis terms, the static-only/"not executed" statement,
and the INJ/NAV/LOG classes; neither references an artifact absent from `vhlocal.phases.PHASES`; and
the two surfaces agree on the artifact set. The rest of the suite is unaffected.

**Drift demo (optional)**: temporarily add a fake `PhaseSpec` to `PHASES`, re-run — the test FAILS
naming the missing artifact on each surface. Revert. This is the silent-drift guard working.

## 2. Default served UI (`/`)

```bash
python3 -m vhlocal.server        # → http://127.0.0.1:8420
```

Open `http://127.0.0.1:8420/`, click **Docs**. Verify against the contract (C1):

- All seven steps in order, each with readable name **and** phase ID, correct reads/writes.
- Threat model marked optional.
- A section explaining the **three status axes** (execution / coverage / validation mode).
- Validation-mode honesty: findings confirmed by reasoning; **exploit tests written but not run**
  unless bash mode is enabled.
- Configurable functions (profiles, multi-sample voting, split/combined, sweep mode, strictness,
  budget cap, IaC lens, redaction, remediation, per-step model + backend routing incl.
  OpenAI-compatible), exploit chains, and an outputs/"what you get" section.
- No external network requests (check the browser network panel — offline/self-contained).

## 3. React UI (`/app`)

```bash
cd web-react && npm install && npm run build     # emits ../vhlocal/web/app/
# then reload the server from step 2 and open:
#   http://127.0.0.1:8420/app  →  Docs
# (or `npm run dev` for the Vite dev server proxying /api to the engine)
```

Verify the React Docs page shows the **same substance** as the default page (mutual consistency):
same steps, artifacts, status axes, validation-mode statement, configurable functions, capabilities,
and outputs. Confirm it renders without console errors and reaches no CDN.

## 4. Acceptance mapping

| Spec check | How verified here |
|---|---|
| SC-001/002/004/008, FR-001/002/008 | Step 1 (automated) |
| SC-003, FR-008 | Step 1 (unknown-artifact assertion + drift demo) |
| SC-005, FR-003 | Steps 2–3 (optional/selectable labeling) |
| SC-009, FR-004/012 | Steps 1–3 (validation-mode term + prose) |
| SC-010, FR-013 | Steps 1–3 (three status axes) |
| FR-005/006/007/014 | Steps 2–3 (visual) + Step 1 (term presence) |
| SC-007, FR-011 | Steps 2–3 (loads from nav, renders clean) |
| Mutual consistency | Step 1 (cross-surface) + Step 3 (visual) |
| SC-006 | Short reader comprehension check (manual) |
```
