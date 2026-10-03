# Implementation Plan: Restore functional scanner parity and trustworthy evidence

**Branch**: `005-scanner-parity-evidence` | **Date**: 2026-09-15 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/005-scanner-parity-evidence/spec.md`

## Summary

Restore the Go scanner to functional parity with the authoritative Python reference (`../vhlocal/vhlocal/`) so its evidence is trustworthy: usable file tools + grounded assignments, harness-controlled hunt orchestration, structured adversarial verification with handoffs, source-grounded publication + artifact validation, truthful completion/coverage/resume/regeneration, and a genuine offline differential-parity harness. Six correctness-critical Evidence-Integrity defects (zero-survivor resurrection, malformed→confirmed, artifact-manifest clobber, empty/wrong-path produced, cancellation mislabel, fabricated-attribution regeneration) are fixed first. All work is Go; Python is a test/reference dependency; all validation is offline; live validation stays operator-owned. Feature-004 behaviors and tests are preserved.

Technical approach (from research):
- **File tools**: adopt Python `tools.py` semantics — `Read` offset/limit + line numbers + continuation; `Glob`/`Grep` return **absolute** paths and resolve relatives against the repo root (fixes round-trip without `chdir`); glob uses an in-repo fnmatch→regexp translator (stdlib only, `*` spans `/`, per reference), not `filepath.Match`; skip-dir excludes on both ripgrep and fallback; harness-owned-artifact write guard; symlink-parent resolution for writes. Missing methodology file → explicit configuration error.
- **Orchestration**: port `resolve_partitions` (model-table parse + one corrective repartition + deterministic fallback), coverage + threat-model augmentation, cap→`uncovered_remaining`; INJ/NAV/LOG class split with shared+per-class prompts + sink-driven pass; IaC gating; N-sample run + identity-merge + votes; canary + breaker; a real `Phase2Mode`; manifest reflects the executed mode.
- **Verification**: candidate manifest built before 2b with a line-shift/prose-insensitive identity; a per-candidate fresh-session verifier with `capture_evidence`/`submit_verification` tools, reconciliation (quote-match + function/defense context + revision/identity + quality battery), metrics, fail-closed dispositions; handoffs generated.
- **Publication**: source-corroboration + per-class veto + logic-CWE exclusion + review records gate `statically_supported`; full tier taxonomy; artifact-manifest validation against candidate identity + on-disk files; finalize/regenerate never clobber a real manifest; dynamic state requires executor evidence.
- **Truthfulness**: produced keyed to the declared deliverable + non-empty; per-unit attribution; faithful coverage denominator + corpus; resume validates identity/verification/artifacts and counts valid resumed work; cancellation stays `cancelled`; regeneration persists real backend/model/provenance + endpoint-failure reasons (additive schema).
- **Parity**: a shared JSON interaction-transcript replayed by a Go scripted provider and a Python scripted provider; a documented generator runs the Python reference to emit **normalized semantic golden** JSON; the default `go test ./...` differential test compares Go's live semantic output to the committed goldens (hermetic, no Python at test time); an opt-in `-tags pythonref` variant subprocesses the live Python reference.

## Technical Context

**Language/Version**: Go 1.23+ (module `vhlocal`); Python 3.9+ is a **test/reference-only** dependency (reference repo `../vhlocal`).

**Primary Dependencies**: Standard library only for runtime (constitution dependency budget: baseline zero third-party runtime deps preserved — the glob matcher is an in-repo fnmatch→regexp translator, no `doublestar`/external glob lib). Test-only: the Python reference interpreter for golden regeneration (not required for the default `go test ./...`).

**Storage**: Filesystem artifacts. **Additive schema changes** (documented, FR-043): `scan_meta.json` `agents[]` gains `expected_deliverable`, `wrote_files`, `produced`, `error`, `error_kind`, `partition`, `vuln_class`; `RunRecord` gains a serialized `backend` and serialized `endpoint_failures` (replacing feature-004's `json:"-"`), plus population of the already-declared partition-accounting fields (`partition_fallback`, `partition_parse_error`, `coverage_*`, `threat_model_partitions`, `hunt_halted_reason`); new artifacts `verification_decisions.json`, `verification_metrics.json`, `verification_reconciliation.json`, `hunt_votes.json`, `phase2b_handoff.md`, per-unit hunt placeholders. Existing filenames/API paths are not broken.

**Testing**: `go test ./...`, fully offline and hermetic by default (committed semantic goldens). Opt-in differential against the live Python reference via `go test -tags pythonref` (requires `python3` + `../vhlocal`). **No live model — per operator instruction, live validation is the operator's.**

**Target Platform**: unchanged (Linux/macOS single binary).

**Performance Goals**: parity of *behavior and evidence*, not throughput. Per-agent hunt concurrency is **deferred** (serial execution is acceptable; see Complexity Tracking); N-sample and class-split increase agent count but stay bounded by existing turn/budget caps.

**Constraints**: preserve the static-only boundary, configured-endpoint routing (no silent fallback), loopback/allow-root posture, and the three independent status axes; repair/verification contact only the configured endpoint; zero new runtime dependencies.

**Scale/Scope**: large — touches `internal/tools`, `internal/agent`, `internal/engine`, `internal/phases`, `internal/inventory`, `internal/consolidate`, `internal/verification`, `internal/manifest`, `internal/report`, `internal/cli`, plus a new differential-parity harness. Grounded in the six-area audit; 6 user stories, 51 FRs (incl. 6 correctness-critical), 13 SCs.

## Constitution Check

*GATE: Must pass before Phase 0. Re-check after Phase 1.*

Corrective/parity feature — it strengthens compliance and fixes existing violations. Gate outcome: **PASS** (three justified deviations tracked below).

| Principle | Effect |
|---|---|
| I. Evidence Integrity (NON-NEGOTIABLE) | **Directly restored.** Fixes zero-survivor resurrection, malformed→confirmed, surface-signal support, artifact clobber, empty-write "produced," fabricated regeneration attribution. Support requires validated source evidence; every candidate gets a disposition. FR-C1..C6, FR-018..028, FR-C4. |
| II. Orthogonal Status | **Strengthened.** Cancellation distinct from abort/endpoint-failure; coverage names the specific entry point + evidence; incomplete/clean/degraded stay distinct; manifest reflects executed mode. FR-C5, FR-026, FR-031/032, FR-017. |
| III. Static-Only Boundary (NON-NEGOTIABLE) | **Preserved/strengthened.** Verification tools are read-only (capture_evidence reads source; submit is metadata); no shell/exec; harness-owned-artifact write guard added; dynamic state requires executor evidence (positive fail-closed guard). FR-007, FR-028, FR-040. |
| IV. Provenance | **Restored.** Real backend/model/settings persisted for deterministic regeneration; served-model provenance recorded per agent; no fabricated `ollama`. FR-035, FR-C6. |
| V. Explicit AI Failure, No Silent Fallback (NON-NEGOTIABLE) | **Preserved.** Feature-004 same-endpoint repair kept; missing methodology → explicit failure (no placeholder); breaker/canary/budget halt with recorded reasons; no provider/model switch. FR-009, FR-016, FR-042. |
| VI. Resumable, Idempotent | **Restored.** Resume validates saved-output identity/verification/artifacts and counts valid resumed work; regeneration deterministic; no manifest clobber. FR-033, FR-C3, FR-035. |
| VII. Testable Coverage | **Directly served.** Genuine offline differential parity + the full regression scenario set; every fix ships a failing-before test; hermetic `go test ./...`. FR-036..039, SC-011. |

**Safety & Technical Constraints**: Go runtime, **zero new runtime dependencies** (in-repo fnmatch translator; Python is test/reference-only), offline tests, web UI unchanged — satisfied.

### Justified deviations (Complexity Tracking)

1. **Python as a test/reference dependency.** The differential harness needs the reference's semantic output. Mitigation: default `go test ./...` stays hermetic against **committed goldens**; live-Python comparison is opt-in (`-tags pythonref`). Simpler alternative (hand-authored goldens) rejected: it reintroduces the current "golden authored to match our own fake" anti-parity the spec calls out.
2. **Candidate identity is a heuristic, not a true AST digest.** Go has no in-tree Python/JS AST. Mitigation: identity = normalized function-owner + cited-statement digest (whitespace/comment-stripped) + CWE + normalized path — line-shift/prose-insensitive per the reference's *intent*. Simpler alternative (reuse feature-004's `sha256(title|loc)`) rejected: it is prose-sensitive and breaks cross-revision reconciliation. Full AST parity deferred and documented.
3. **Per-agent hunt concurrency deferred.** Reference uses a thread pool. Mitigation: serial execution is behavior-equivalent for evidence/parity (only wall-clock differs); the differential harness normalizes ordering. Simpler alternative (implement concurrency now) rejected as out-of-scope for evidence parity and a source of nondeterminism in the parity diff.

### Post-Design Re-Check (after Phase 1)

Re-evaluated after research.md, data-model.md, contracts/, quickstart.md: **still PASS.** No new runtime dependency introduced; additive schema changes are documented and additive-only (existing keys/filenames retained), so honest evidence is added rather than sacrificed (Principle I). Verification tools remain read-only within the sandbox (III). The three deviations above are the only ones and are each mitigated. The feature-004 C-X1 "no serialized schema change" guard is intentionally superseded here by FR-043 (additive schema) and is replaced by the new differential-parity semantic diff; this is noted in data-model.md. No Complexity Tracking entries beyond the three above. Ready for `/speckit-tasks`.

## Project Structure

### Documentation (this feature)

```text
specs/005-scanner-parity-evidence/
├── plan.md              # This file
├── research.md          # Phase 0 — R1..R9 decisions
├── data-model.md        # Phase 1 — entities + additive schema + new artifacts
├── quickstart.md        # Phase 1 — offline validation (no live model)
├── contracts/
│   └── behavior.md      # Phase 1 — behavioral contracts C-* per story
└── tasks.md             # /speckit-tasks (not created here)
```

### Source Code (files this feature changes; grouped by story)

```text
# US1 — grounding + file tools
internal/tools/tools.go            # Read offset/limit + line numbers + continuation; Glob fnmatch-semantics
                                   #   + absolute paths; Grep path/glob/ignore_case/files_with_matches + skip-dir
                                   #   excludes on rg AND fallback; resolve relatives against repo root; symlink
                                   #   parent resolution for writes; harness-owned-artifact write guard
internal/tools/glob.go             # new: in-repo fnmatch→regexp translator (stdlib only, * spans /)
internal/agent/agent.go            # Read tool schema gains offset/limit; verification tool envelope (US3)
internal/engine/helpers.go         # buildTask: absolute repo path + writable-location + scope/routes + inputs
internal/engine/engine.go          # skill.Prompt/Preamble missing → explicit config failure (no placeholder)
internal/engine/skill.go           # Preamble error surfaced, not swallowed

# US2 — hunt orchestration
internal/phases/partition.go       # new: parse model partition table, corrective repartition, deterministic
                                   #   fallback, coverage augmentation, threat-model augmentation, cap→uncovered
internal/phases/phases.go          # CLASS_GROUPS dispatch wiring; hunt-target parser used (not dead)
internal/inventory/inventory.go    # cap records uncovered_remaining (no silent subs[:max]); denominator fidelity
                                   #   (router prefixes, method defaults, websocket, test-file exclusion, dedup,
                                   #   subsystem rules)
internal/engine/hunt.go            # new (extracted from helpers.runFanOut): class split (shared+per-class),
                                   #   sink-driven pass, IaC gating (_has_iac), N-sample loop + merge + votes,
                                   #   canary + breaker; per-unit attribution + placeholders
internal/engine/votes.go           # new: sample merge by block identity + vote provenance (hunt_votes.json)
internal/cli/run.go                # --phase2-mode flag; profile phase2_mode override handler; wire samples/iac
internal/engine/engine.go          # ScanSpec.Phase2Mode; manifest reflects executed mode (not hardcoded)
internal/manifest/manifest.go      # phase2_mode from executed mode; budget/breaker reasons

# US3 — verification + handoffs
internal/verification/manifest.go  # candidate manifest built BEFORE 2b; line-shift/prose-insensitive identity
internal/verification/session.go   # new: per-candidate fresh-session verifier; capture_evidence + submit_verification
internal/verification/evidence.go  # new: quote-match live source, cover cited location, revision/identity check
internal/verification/reconcile.go # new: per-candidate disposition + function/defense context + quality battery
internal/verification/handoff.go   # new: phase2b_output.md (dispositions) + phase2b_handoff.md (supported-only)
                                   #   + phase-3 assignments; zero-verified sentinel
internal/engine/engine.go          # 2b runs the verification session; collectFindings uses decisions (no raw
                                   #   fallback); phase 3 fed the handoff

# US4 — publication + artifact validation
internal/consolidate/quality.go    # source-corroboration (open cited file, match sink family), per-class veto,
                                   #   logic-CWE exclusion; retain uncertainty for uncovered/unavailable
internal/consolidate/consolidate.go# tier taxonomy (reviewed/statically_supported/hypothesis; rejected; states);
                                   #   assess from verification decisions/review records, not surface signals
internal/verification/artifacts.go # new: validate_artifacts against candidate identity + on-disk files
internal/engine/engine.go          # finalize: never clobber a real artifact_manifest; zero-verified → [] only
internal/engine/regenerate.go      # never rebuild/clobber manifests; re-reconcile existing decisions
internal/consolidate/status.go     # apply_validation: dynamic state requires executor evidence (fail-closed)

# US5 — completion / coverage / resume / regeneration
internal/agent/agent.go            # isSuccessfulWrite keyed to DeliverablePath + non-empty; Result gains
                                   #   WroteFiles/Error/ErrorKind/Produced-per-file; nudge keyed to deliverable
internal/engine/record.go          # AgentRecord additive fields; RunRecord Backend + serialized EndpointFailures
internal/engine/helpers.go         # recordAgent persists produced/error/provenance/partition/vuln_class
internal/engine/engine.go          # resume validates identity/verification/artifacts; count resumed work;
                                   #   cancellation stays cancelled (don't set Aborted; agent cancelled != endpoint)
internal/inventory/inventory.go    # coverage names entry point + disposition + evidence; corpus scope per reference
internal/engine/regenerate.go      # persist+restore real backend/model; convert StopEndpointFailure → reasons

# US6 — differential parity + regression
tests/parity/parity_test.go        # relabel filename/key checks as smoke; add semantic differential test
tests/parity/differential_test.go  # new: run Go on shared transcript; compare normalized semantics to goldens
tests/parity/transcript/           # new: shared JSON interaction transcripts (replayed by Go + Python)
tests/parity/golden/               # new: committed normalized semantic goldens (regenerated from Python)
tests/parity/genref/               # new: documented generator (subprocess Python ref) — not run by `go test`
internal/*/**_test.go              # regression scenarios (FR-039) across the touched packages
```

**Structure Decision**: No new top-level layout; new files land in the existing packages (notably a real `internal/verification` implementation and a split-out `internal/engine/hunt.go`). The one cross-cutting addition is the `tests/parity/` differential harness (transcripts + goldens + opt-in generator). No new runtime module or dependency.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| Python as a test/reference dependency | Genuine differential parity needs the reference's semantic output | Hand-authored goldens reintroduce the "golden matches our own fake" anti-parity the spec exists to remove; mitigated by hermetic committed goldens + opt-in `-tags pythonref` |
| Heuristic candidate identity (not true AST) | Go has no in-tree Python/JS AST; reconciliation must be line-shift/prose-insensitive | Reusing `sha256(title\|loc)` is prose-sensitive and breaks cross-revision reconciliation; full AST parity deferred + documented |
| Per-agent hunt concurrency deferred | Evidence/parity is independent of wall-clock; parity diff normalizes ordering | Implementing concurrency now adds nondeterminism to the parity diff and is out of the evidence scope |
