# Feature 016 offline validation evidence

| File | What it is |
|---|---|
| `T097-test-revision-sweep.md` | audit of every test assertion the feature changed, with reasons |
| `T103-offline-gate.md` | the full offline gate result and the store-fingerprint comparison |
| `T104-operator-report.md` | scenarios 1-19 executed and mapped to tests; 20-22 recorded not run |
| `after.json` | the measured after-state of the frozen fixture, written by the report package |
| `gate-static.txt`, `offline-tests.txt`, `race-tests.txt`, `typecheck.txt`, `gate-status.txt` | raw gate output |
| `fingerprint-{before,after}.txt.summary` | the two digests that prove the operator stores were unchanged |
| `fingerprint-{before,after}.txt.count` | how many files each fingerprint covered (5,479) |

## Why the raw fingerprint listings are not committed

`validation-015/fingerprint.sh` writes two large listings per run: every file under
`~/.vhlocal` and `~/vulnhunter-reports` with its absolute path, size, mtime to the
nanosecond, and SHA-256. That is a complete inventory of the operator's machine and of every
application they have scanned, so it stays local and is covered by `.gitignore`.

The committed `.summary` files carry the SHA-256 of each listing. Before and after the gate
they are identical, which is the claim being made: the gate changed nothing in the stores.
Regenerate the listings locally with:

```bash
validation-015/fingerprint.sh validation-016/fingerprint-before.txt
# run the gate
validation-015/fingerprint.sh validation-016/fingerprint-after.txt
diff validation-016/fingerprint-before.txt validation-016/fingerprint-after.txt
```
