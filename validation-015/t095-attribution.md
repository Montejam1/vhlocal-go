# T095 — real-store fingerprint attempt, 2026-09-30

Second attempt at the literal SC-014 criterion ("real-store fingerprint
byte-identical before/after the full gate"), repeated because the first attempt was
made while the operator's scan was writing.

## Gate result

All of `gofmt -l .` (excluding the pre-existing unformatted fixture
`testdata/goapp/api/routes.go`), `go vet ./...`, `go build ./...`, the static
`CGO_ENABLED=0` binary build, `go test ./... -count=1`, `go test -race` over
engine/jobs/server/agent/apps, and `npm run typecheck` passed. `GATE_EXIT=0`.
Evidence: `offline-tests.txt`, `race-tests.txt`, `typecheck.txt`.

## Fingerprint: NOT byte-identical

| | files | listing sha256 | content sha256 |
|---|---|---|---|
| before | 4484 | `ce6a63819e4a6b44f0d8bb6d5278fdd522086d1654dae0b62f6e87cba198778a` | `cfc75d0f88ad61880558068472f4a98dbf44ce422e88ba91ed2c82760eebd5fe` |
| after | 4489 | `54fc3aa7b52e31c6511173dc54ff71db758a2010a19f52a658e07a074bc810fc` | `a2d67f609d99990198259f8c1d0951c720b509a99c899236bcf8e9233438db05` |

The stores had been quiescent for ~6 hours when the before-snapshot was taken, but
operator scan `c7514f55c559` (model `qwen3.5:122b`, remote Ollama host) resumed
during the gate. It had appeared stalled; it was not.

## Every change is attributed to the live scan

Five new files, all inside that scan's own results directory:

```
…_qwen35122b_2026-09-29-172043/results/sg-26_inj.md
…_qwen35122b_2026-09-29-172043/results/sg-26_inj.s2.md
…_qwen35122b_2026-09-29-172043/results/sg-26_inj.s3.md
…_qwen35122b_2026-09-29-172043/results/sg-26_nav.s1.md
…_qwen35122b_2026-09-29-172043/results/sg-26_nav.s2.md
```

Two files changed content: that scan's `prompts.jsonl`, and the shared
`~/.vhlocal/vhlocal.log`. No file was removed. Nothing outside the running scan's
results directory and the shared log changed.

The shared log is the only path a test could have appended to, so it was checked
directly:

- **Append-only**: the first 3,356,935 bytes of the after-file hash identically to
  the entire before-file. No pre-existing byte was rewritten.
- **Attribution**: all 12 appended lines carry the scan's job id `[c7514f55c559]`
  and its model `qwen3.5:122b`, and every `output_written` path is inside that
  scan's results directory. No test-originated line appears.
  Full delta: `shared-log-delta-during-gate.txt`.

## Verdict — T095 stays unchecked

The suite demonstrably wrote nothing to the operator's stores during this gate, and
that is the substance of SC-014. It is still **not** the literal criterion the task
states, which is a byte-identical fingerprint. A concurrent legitimate writer makes
that observation impossible, and the honest report is a positive attribution of
every changed byte rather than a claim of identity.

One residual gap this attribution cannot close on its own: a test that created and
then deleted a file inside the gate window would leave no trace here. The earlier
`bwrap` run (read-only empty directories mounted over both store paths, recorded in
`docs/engineering/2026-09-29-015-completion.md`) covers exactly that case, because
writes were impossible rather than merely unobserved. The two together are strong;
neither is the quiescent byte-identity observation.

Repeat this when no scan is running: no operator scan active in `~/.vhlocal/jobs.json`,
and `~/.vhlocal/vhlocal.log` unchanged across a few minutes. Run
`validation-015/fingerprint.sh <out>` before and after the gate and compare the two
`.summary` hashes.

Nothing here launched, interrupted, resumed or restarted a scan. No target code,
PoC or exploit was executed. No operator report was regenerated.
