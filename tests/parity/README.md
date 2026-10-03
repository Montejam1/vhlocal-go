# Offline behavior and reference-contract checks

`go test ./tests/parity` runs without a model server or Python interpreter. It
contains three complementary checks; none establishes scanner-wide parity on its
own.

- **Transcript regression:** `transcript/vulnapp.json` drives recon, hunt and
  per-candidate verification. `golden/vulnapp.json` records the expected projection.
  This older golden originated from a Go run reviewed against reference code; it
  is regression evidence, not an independent Python execution result.
- **Full pipeline:** `TestFullPipelineArtifactsAndDeterministicPhases` adds Phase 3
  reproduction, Phase 3d sweep and Phase 4 reporting. It checks registered authored
  material, explicit deferrals, supported-only assignments, deterministic phases,
  and preservation through report regeneration. Authored fixture tests are never
  executed.
- **Independent reference contracts:** `reference/contracts.json` is exported by
  the Python implementation in `../vhlocal`. `TestPythonReferenceContracts`
  compares Go against those Python results for complete/incomplete reviews,
  stale revisions, missing/duplicate decisions, distinct source sites, and
  artifact dispositions. The export records hashes of the reference source files.

The projector uses exact file/line/CWE identities. Nearby sinks must not collapse
into one test identity. Candidate line-shift stability is tested separately in
`internal/verification`; timestamps, temporary roots and raw CAND IDs remain
excluded from snapshot comparisons.

## Refreshing the independent oracle

This is an explicit migration-time developer operation, not a runtime dependency:

```bash
python3 -I tests/parity/reference/export_contracts.py ../vhlocal tests/parity/reference/contracts.json
go test ./tests/parity -count=1
```

Review changes to the inputs, reference hashes and expected results before
accepting an updated oracle. The exporter runs scanner validation functions on
temporary source fixtures. It does not import or execute target application code,
call models, or execute reproduction material.

## Limits

These are bounded contract and orchestration checks, not a detection-accuracy
benchmark. Transcript verdicts are scripted. Go still uses lexical Python scope
and source-line anchors rather than the reference's Python AST identities; other
languages retain location-based identity. A live run of the rebuilt service is
still required to assess model behavior and real scan quality.
