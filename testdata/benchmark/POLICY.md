# Efficacy regression policy — version 1

```json
{"version":"1","tolerance":{"precision":0,"recall":0,"safe_control_fp":0}}
```

Compare with a frozen baseline, never an invented absolute detection threshold.
The deterministic transcript baseline allows **zero** deterioration in supported
precision/recall or safe-control false positives. Apply the declared tolerance
to the headline and each language/family; an improvement elsewhere cannot hide a
new safe-control failure. Repeated supported hits on one vulnerable truth entry
count once. A hit must match its weakness (CWE or family) and an acceptable anchor.
Rejected, unresolved and duplicate findings never earn supported credit.

Live baselines must explicitly declare tolerances and retain every scored run
with run-to-run ranges. Changing a tolerance is a reviewed baseline change, not a
way to make a failing run pass. Baseline files record target fingerprint/revision,
build, effective config, role models/provider, prompt and schema hashes, sampling,
seeding and budgets. Print configuration differences before comparative scores.

`baseline/2026-09-29-offline.json` is a **scripted transcript fixture**, not an
accuracy measurement of any model. Python confirmations and non-Python unresolved
decisions are deliberately scripted to exercise partial recall and denominators.
Live evaluations remain **not run** until explicitly launched by an operator.

Truth is outside the target and never enters scan prompts. No target code or PoC
is executed. Update the offline baseline only with an explicit reviewed command:

```sh
VHLOCAL_UPDATE_BENCH_BASELINE=1 go test ./tests/parity -run '^TestBenchmarkTranscriptIsolationAndBaseline$' -count=1
```

Normal tests do not rewrite baselines. `vhlocal bench efficacy` and
`make bench-efficacy RESULTS=/path/to/results` score existing artifacts only.
