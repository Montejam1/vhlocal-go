# Contract: Command-Line Interface (parity)

The Go binary is `vhlocal` with a subcommand per current Python entry point. Every flag name, default, and semantic below MUST match the current implementation; the only sanctioned change is the launch mechanism (`python3 -m vhlocal.<module>` → `vhlocal <subcommand>`).

## Subcommand map

| Today | Go subcommand | Purpose |
|---|---|---|
| `python3 -m vhlocal.run` | `vhlocal run` | Run a scan |
| `python3 -m vhlocal.server` | `vhlocal server` | Run the HTTP engine + UI |
| `python3 -m vhlocal.report` | `vhlocal report` | Regenerate consolidated report(s); delete a report |
| `python3 -m vhlocal.logs` | `vhlocal logs` | Read/slice the central log |
| `python3 -m vhlocal.sbom` | `vhlocal sbom` | Generate a CycloneDX SBOM for a repo |
| `python3 -m vhlocal.bench` | `vhlocal bench` | Benchmark inference throughput |
| `python3 -m vhlocal.batch` | `vhlocal batch` | Scan many repos from a CSV |
| `python3 -m vhlocal.authz` | `vhlocal authz` | Authorization-map maintenance/eval |
| `python3 -m vhlocal.membank` | `vhlocal membank` | Ledger maintenance |
| `python3 -m vhlocal.policy_bench` | `vhlocal policy-bench` | Policy benchmark |

`vhlocal` with no subcommand (or `-h`/`--help`) prints usage listing the subcommands. `vhlocal <sub> -h` prints that subcommand's flags. Exit codes preserved: `0` success, `2` config/usage errors (e.g. bad repo, missing phases dir, missing OpenRouter key).

## `vhlocal run` flags (parity with run.py)

Precedence for profile-overridable knobs: **built-in default < `--profile` < explicit flag** (explicit detected via set-flags only).

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--repo` | path | *(required)* | Target repository (read-only) |
| `--backend` | enum | `ollama` | `ollama` \| `openai` \| `openrouter` |
| `--out` | path | — | Exact results dir (overrides `--reports-dir`) |
| `--reports-dir` | path | `~/vulnhunter-reports` | Where reports are written |
| `--model` | string | `gpt-oss:120b` | Hunt / default model |
| `--host` | string | `$VHLOCAL_OLLAMA_HOST` or `http://localhost:11434` | Endpoint (auto `:8080` for openai, fixed host for openrouter) |
| `--skill-dir` | path | bundled (embedded) | Needs `SKILL.md` + `phases/` |
| `--temperature` | float | none | |
| `--profile` | string | none | `quick`/`thorough`/`share`/`benchmark` or user profile |
| `--verify-model` / `--verify-host` / `--verify-backend` | string/enum | fall back to hunt | Phase 2b routing |
| `--recon-model` / `--recon-host` / `--recon-backend` | string/enum | fall back to hunt | Phase 1 routing |
| `--reproduce-model` / `--reproduce-host` / `--reproduce-backend` | string/enum | fall back to hunt | Phases 3/3d/4 routing |
| `--phases` | csv | `all` | keys `1,1t,2,2b,3,3d,4` |
| `--num-ctx` | int | `131072` | Context window (do not lower below ~32k) |
| `--max-partitions` | int | `8` | Caps Phase 2 fan-out |
| `--phase2-mode` | enum | `split` | `split` \| `combined` |
| `--concurrency` | int | `1` | Needs `OLLAMA_NUM_PARALLEL` on server |
| `--reasoning-effort` | enum | none | `low` \| `medium` \| `high` |
| `--max-output-tokens` | int | `32768` | 0 = uncapped |
| `--max-budget-usd` | float | `0.0` | 0 = no cap; paid backends only |
| `--hunt-samples` | int | `1` | Clamped 1–5; unions findings |
| `--sweep-mode` | enum | `deterministic` | `deterministic` \| `model` (not profile-overridable) |
| `--quality-strictness` | enum | `balanced` | `lenient` \| `balanced` \| `strict` |
| `--seed-routes` | bool | off | |
| `--seed-prior` | bool | off | Mode B |
| `--no-enforce-coverage` | bool | coverage on | Disables enforced route coverage |
| `--iac-lens` / `--no-iac-lens` | bool | on | IaC/CI-CD lens (auto-skips when no infra) |
| `--remediate` | bool | off | Per-finding remediation DTOs |
| `--redact` | bool | off | Mask cards/SSNs/creds in artifacts |
| `--ledger` | bool | off | Merge into per-target ledger + score recall |
| `--threat-model` | bool | off | Phase 1t PASTA + SBOM |
| `--resume` | bool | off | Skip completed phases |
| `--log-file` | path | `~/.vhlocal/vhlocal.log` | Central log |
| `-v` / `--verbose` | count | 0 | Repeatable |

## `vhlocal server` flags (parity with server.py)

| Flag | Default | Notes |
|---|---|---|
| `--host` | `127.0.0.1` | Non-loopback requires `--unsafe-bind` |
| `--port` | `8420` | |
| `--skill-dir` | bundled (embedded) | |
| `--state` | `~/.vhlocal/jobs.json` | Job-queue persistence |
| `--ollama-host` | `$VHLOCAL_OLLAMA_HOST` or `http://localhost:11434` | Default endpoint (overridable per scan in UI) |
| `--reports-dir` | `~/vulnhunter-reports` | |
| `--allow-root` | `$HOME` | Repeatable; scan targets must be inside |
| `--unsafe-bind` | off | Required to bind non-loopback |
| `--log-file` | `~/.vhlocal/vhlocal.log` | |
| `-v` / `--verbose` | 0 | |

## Other subcommands

- `vhlocal report <results-dir>` — regenerate `SCAN_REPORT.md`/`.html` + `findings.json` deterministically; `--all` regenerates every report under `--reports-dir`; `--delete <results-dir>` [`--yes`] deletes a report (refuses outside reports dir; refuses a running scan).
- `vhlocal logs <scan-tag>` — print the central log or one scan's slice; flags mirror `logs.py` (`--tail`, `--level`, log path).
- `vhlocal sbom <repo>` — write a CycloneDX SBOM; `--out` (default `./sbom.cdx.json`).
- `vhlocal bench` — throughput; `--backend`, `--host`, `--model` as in `bench.py`.
- `vhlocal batch <csv>` — scan repos from a CSV (`repo[,app_id]` rows); `--skill-dir` required as today; forwards scan flags.

## Environment variables (all preserved)

`VHLOCAL_OLLAMA_HOST`, `VHLOCAL_OPENAI_HOST`, `VHLOCAL_OPENAI_API_KEY`, `VHLOCAL_OPENROUTER_API_KEY`, `VHLOCAL_LEDGER_DIR`, `VHLOCAL_PROFILES_DIR`, `VHLOCAL_LOG_FILE`, `VHLOCAL_LOG_DIR`, `VHLOCAL_ACTIVITY_FILE`. `OLLAMA_NUM_PARALLEL` is read on the Ollama server side (documented, not set by vhlocal).

## Acceptance

- Every flag above is accepted with the same name and meaning; `--flag value` and `--flag=value` both parse; booleans are presence flags; `-v` repeats.
- `--profile` precedence: default < profile < explicit, verified by a test that sets a profile and one overriding flag.
- Any deviation from a Python flag spelling is enumerated in the migration note in README/RUNBOOK (target: zero undocumented deviations — SC-003).
