# Contract: documentation content ↔ engine consistency

The "interface" this feature exposes is a **UI documentation contract**: what each docs surface must
contain, and the automated check that enforces it. Two consumers rely on it — the human reader
(acceptance scenarios) and `tests/test_docs_consistency.py` (the machine check).

## C1. Content contract (both surfaces)

For each surface in {`vhlocal/web/index.html`, `web-react/src/pages/Docs.tsx`}, the rendered/authored
text MUST satisfy:

1. **Steps present & ordered** — the 7 DocSteps (Recon/1, Threat model/1t, Hunt/2, Verify/2b,
   Reproduce/3, Sweep/3d, Report/4) each appear with readable name **and** phase ID, in execution
   order. (FR-001, SC-001, SC-008)
2. **Artifacts correct** — each step shows its real `reads`/`writes` filenames from
   `vhlocal.phases.PHASES`. (FR-002, SC-002/SC-004)
3. **No invented artifacts** — no `phaseN*`-style token appears that is absent from the registry.
   (FR-008, SC-003)
4. **Optionality labeled** — the threat-model step is marked optional; the page conveys phases are
   selectable. (FR-003, SC-005)
5. **Safety boundary** — states code is never executed (no shell) and no network egress except the
   model server. (FR-004)
6. **Validation mode** — states findings are confirmed by reasoning, not execution; exploit tests
   are written but not run unless bash mode is explicitly enabled. (FR-012, SC-009)
7. **Three status axes** — names execution status, coverage status, and validation mode as three
   independent signals. (FR-013, SC-010)
8. **Model/backend routing** — per-step routing (recon/hunt/verify/reproduce) and both backends
   (Ollama + OpenAI-compatible). (FR-005)
9. **Configurable functions** — the R3 set, each mapping to a real capability. (FR-006)
10. **Post-pipeline capabilities** — the R5 set, with correct output locations. (FR-007)
11. **Outputs** — the R4 deliverables and where they are found; report metadata is engine-observed.
    (FR-014)
12. **Hunt classes** — INJ, NAV, LOG present. (matches `CLASS_GROUPS`)
13. **Mutual consistency** — both surfaces agree on the step/artifact set. (spec Assumptions)
14. **Reachable & renders** — page loads from nav and renders without error. (FR-011, SC-007;
    verified manually per quickstart, not by the unit test)

## C2. Test contract — `tests/test_docs_consistency.py`

Deterministic, offline, stdlib-only. Ground truth imported from `vhlocal.phases`.

```
GROUND TRUTH:
  PHASES        = vhlocal.phases.PHASES            # readable set of phase keys + output_file + reads
  CLASSES       = vhlocal.phases.CLASS_GROUPS    # INJ / NAV / LOG
  SURFACES      = { read("vhlocal/web/index.html"),
                    read("web-react/src/pages/Docs.tsx") }
  REQUIRED_TERMS = [ static-only/"not executed",
                     "execution", "coverage", "validation mode",
                     INJ, NAV, LOG ]

ASSERT for each surface S:
  - every PhaseSpec.output_file and every reads entry (excluding the bare repo read) appears in S
  - every DocStep phase-ID label (Phase 1, 1t, 2, 2b, 3, 3d, 4) appears in S
  - every token in S matching /phase\d\w*\.md|phase\d\w*_output|results\// is a known registry artifact
  - every REQUIRED_TERM appears in S (case-insensitive where sensible)
ASSERT across surfaces:
  - the set of registry artifact names found is identical in both S  (mutual consistency)
```

**Failure semantics**: any missing artifact, missing phase ID, missing required term, an unknown
`phase*` token, or a between-surface mismatch fails the test with a message naming the surface and
the offending token — visible drift, never silent. New engine phases/artifacts (a change to
`PHASES`) fail the test until both docs surfaces are updated.

**Out of scope for the unit test** (manual, per quickstart): visual rendering, that the React build
exists, and prose quality. These are covered by C1.14 and the comprehension checks (SC-006/SC-009/
SC-010).
