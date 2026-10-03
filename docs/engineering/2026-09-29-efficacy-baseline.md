# Feature 015 efficacy baseline

## Configuration differences first

| Field | Audited 014 run | 015 offline baseline |
|---|---|---|
| Provider/model | Live operator-configured verifier (see 014 handoff) | Scripted transcript / fake backend |
| Target | Operator's seeded logistics application | `testdata/benchmark/target` |
| Revision | Saved live-run provenance | Content fingerprint in baseline JSON |
| Build/prompts/schema/options | 014 saved records | `015-offline-fixture`; exact prompt/schema hashes and effective config in JSON |
| Coverage meaning | v1 read-overlap evidence | v2 validated handler dispositions |
| Sampling/seeding/budget | Saved live-run config | One sample; no seeds; no dollar budget; context 8192 |
| Live verifier comparison | Not performed here | **not run** |

These runs are not a model-accuracy before/after experiment. The offline provider
is programmed with fixture responses. The baseline proves routing, evidence
contracts, scoring, negative controls and reproducibility, not discovery skill.

`testdata/benchmark/baseline/2026-09-29-offline.json` scores 10 vulnerable entries
and nine safe controls: 3 supported detections, 0 false positives, 7 misses;
supported precision 1.0, recall 0.3. Nine safe controls are rejected. Of 19
candidates, 18 receive accepted decisions; one scripted submission fails the
contract. Keeping that failure visible tests honest accounting; it is not fixed
by relaxing evidence requirements. The baseline is intentionally partial.

The audited live run had 43 supported, 7 rejected, and 121 unresolved candidates,
including 113 without a decision. **43/171 is a supported-candidate fraction,
not recall**: the candidate set is not a ground-truth denominator.

The v1 policy permits zero deterioration for this deterministic fixture, checked
at headline, language and family level. A supported finding must match the
weakness and source anchor; a different CWE at the same line cannot earn credit.
Repeated hits cannot increase true positives. Rejected, unresolved and duplicate
candidates never earn supported detection credit. Unpriced cost remains unknown.

Normal offline reproduction:

```sh
go test ./internal/benchmark ./internal/cli ./tests/parity
```

An operator can score an existing live result without invoking a model:

```sh
bin/vhlocal bench efficacy --results /path/to/results \
  --truth testdata/benchmark/truth/ground_truth.json \
  --baseline testdata/benchmark/baseline/2026-09-29-offline.json --json
```

Use that truth only for scans of this exact benchmark target. A live baseline
must retain repeated runs, configuration differences, and run-to-run variation.
Run `verify-compare` only on a frozen candidate manifest and unchanged source
revision, naming every provider explicitly. The default comparison gate claims
no accuracy improvement without ground truth; ≥95% accepted unresolved decisions
always yields `efficacy_improved: false`, reason `all_unresolved`.
