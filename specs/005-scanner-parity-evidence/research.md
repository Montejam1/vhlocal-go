# Phase 0 Research: Restore functional scanner parity and trustworthy evidence

**Feature**: 005-scanner-parity-evidence | **Date**: 2026-09-15

Decisions resolving the plan's choices, grounded in the six-area audit of Go `internal/` vs the authoritative Python `../vhlocal/vhlocal/`. Each: **Decision / Rationale / Alternatives**. These resolve the two items the spec deferred to planning (differential-harness mechanism; concurrency scope) plus the design of each restored subsystem.

---

## R1. Differential-parity harness mechanism

- **Decision**: Three layers. (1) A **shared interaction transcript** format (JSON: ordered `{match, response}` entries keyed by phase/turn/prompt-signature) replayed by a new Go scripted provider and a parallel Python scripted provider so both implementations see identical model/tool interactions over the shared `testdata/vulnapp` source fixture. (2) A **documented generator** (`tests/parity/genref/`, run manually / `-tags pythonref`) subprocesses the Python reference on a transcript and emits a **normalized semantic golden** JSON. (3) The default `go test ./...` **differential test** runs the Go engine on the same transcript and compares its normalized semantic output to the committed golden — hermetic, no Python at test time. An opt-in `go test -tags pythonref` runs Go and live Python side-by-side.
- **Rationale**: Satisfies "execute both implementations offline against shared fixtures and equivalent scripted interactions" (both ARE executed — Python at golden-generation time, Go at test time) while keeping `go test ./...` hermetic (constitution VII: offline, no live model/network). The golden IS the Python semantic output, so the diff is genuinely differential, not self-referential.
- **Alternatives**: Subprocess Python on every `go test` run (couples the default gate to a Python env + sibling repo — rejected as the default; kept as opt-in). Hand-authored goldens (reintroduces the "golden authored to match our own fake" anti-parity the spec removes — rejected).

## R2. Shared scripted model/tool interaction format

- **Decision**: A minimal JSON transcript: a list of turns, each `{ "when": {phase, turn, contains?}, "assistant": {content?, tool_calls?[]} }`; tool *results* are produced by the real sandbox tools on the shared fixture (so file-tool behavior is exercised, not mocked). Both a Go `transcriptProvider` (implements `client.Provider`) and a Python `TranscriptClient` replay it. Normalization strips timestamps, temp roots, absolute-path prefixes (to `<REPO>`/`<RESULTS>`), and orders lists by stable keys.
- **Rationale**: Keeps the model side deterministic and identical across implementations while letting each implementation's real file tools/engine run — which is exactly what parity must compare. Tool results are not scripted, so US1 tool-semantics differences surface in the diff.
- **Alternatives**: Fully recorded request/response pairs including tool results (hides tool-behavior divergence — rejected). Per-language ad-hoc fakes (not shared → not comparable — the current state, rejected).

## R3. File-tool parity (Read / Grep / Glob / sandbox)

- **Decision**: Adopt `tools.py` semantics.
  - **Read**: add `offset`/`limit`; emit line-numbered output (`%6d\t%s`) and a "more lines; re-read with offset=N" continuation; binary detection; directory rejection. Tool schema (`agent.go`) advertises `offset`/`limit`.
  - **Glob/Grep**: return **absolute** paths; resolve relative inputs against **`read_roots[0]` (repo root)**, not process CWD — fixes the round-trip without `chdir`. Grep gains `path`, `glob`, `ignore_case`, `files_with_matches`; skip-dir excludes applied on **both** the ripgrep and pure-Go paths.
  - **Glob semantics**: replicate Python `fnmatch(str(rel), pattern)` via an in-repo translator (`internal/tools/glob.go`): `*`→`.*` (spans `/`), `?`→`.`, `[...]` classes, everything else escaped, anchored full-match. No `filepath.Match`, no external glob lib.
  - **Sandbox**: resolve symlinked **parent** directories for not-yet-existent write targets (resolve the parent, then join the leaf) so writes through a symlinked results parent are confined correctly; add a **harness-owned-artifact write guard** (refuse model writes to `scan_meta.json`, `candidate_manifest.json`, `verification_decisions.json`, `findings.json`, `.vhlocal_state.json`, etc.).
- **Rationale**: The methodology (shared from the Python prompts) assumes offset/limit paging, line-numbered citation, recursive globs, and absolute round-trippable paths; the audit showed each is broken in Go, invalidating file:line evidence. Matching `tools.py` is the definition of parity here.
- **Alternatives**: Add `github.com/bmatcuk/doublestar` for globbing (violates the zero-runtime-dep baseline — rejected; in-repo fnmatch translator is ~40 lines of stdlib). `os.Chdir` to the repo to fix round-trip (process-global, unsafe with any concurrency — rejected in favor of resolving relatives against repo root + returning absolute paths).

## R4. Agent grounding (buildTask)

- **Decision**: Rewrite `buildTask` to emit the reference `build_task` header: absolute target repo (read-only), results dir (only writable location), the phase key/title assignment, the assigned scope/partition **with concrete routes** (from the augmented partition, US2), the prior-phase inputs to read first (framed), the deliverable path/contract, and the threat-model/SBOM/seed-route `extra` blocks where the reference injects them. Instructions are adapted to the real Go tool envelope (offset/limit paging is now real, so the instruction is honest).
- **Rationale**: The audit found Go never gives the agent the repo path, writable-location, assignment header, or concrete scope — so the agent cannot reliably ground citations or stay in scope. Parity requires the reference grounding.
- **Alternatives**: Keep the thin task and rely on the system prompt (insufficient — no path grounding, no scope — rejected).

## R5. Hunt orchestration

- **Decision**: Port the reference hunt spine into a new `internal/engine/hunt.go` (+ `phases/partition.go`, `engine/votes.go`):
  - **Partitions**: parse the model's Phase-1 Subgraph-Partitions table (`resolve_partitions`); on parse failure, one corrective repartition asking for strict JSON; else deterministic subsystem partitions. Record `partition_source`, `partition_fallback`, `partition_parse_error`.
  - **Augmentation**: append a coverage partition for every enumerated route file the plan omitted (`coverage_partitions_added`/`_files_added`), and additive threat-model partitions from PASTA hunt targets (`threat_model_partitions`).
  - **Cap**: hard ceiling `max_partitions + len(subsystems)`; overflow → `coverage_uncovered_remaining` + a logged warning; **never** silent `subs[:max]`.
  - **Dispatch**: `Phase2Mode ∈ {split (default), combined}`. Split = one agent per (partition × class) over `CLASS_GROUPS` (INJ/NAV/LOG) with `phase2_shared.md` + per-class reference; combined = one agent per partition with concatenated class references. Plus the **sink-driven** pass (`results/sink_driven.md`) and the conditional **IaC** pass gated on `_has_iac(repo)` + `iac_lens` + the class-iac reference existing.
  - **Samples**: run `max(1, samples)` per unit to `..._{code}.sN.md`, merge candidate blocks by stable identity (`_block_identity` = location bucket + CWE), tag `<!-- votes: k/N -->`, write `hunt_votes.json`.
  - **Safety**: a hunt **canary** proving transport before fan-out, and a **circuit breaker** (≥3 transport failures with zero successes) recording `hunt_halted_reason`; budget cap where a paid backend is configured. Cancellation excluded from the breaker.
- **Rationale**: The audit found the entire spine absent (single generic agent per partition; flags no-ops; cap silently drops scope). This is the source of narrow/incomparable hunts and dishonest manifests.
- **Alternatives**: Keep the MVP single-agent hunt (fails parity and honesty — rejected). Implement concurrency now (deferred — see R9/Complexity).

## R6. Structured adversarial verification + handoffs

- **Decision**: Build a real `internal/verification`:
  - **Candidate manifest before 2b**, keyed by a **line-shift/prose-insensitive identity**: normalized function-owner + cited-statement digest (whitespace/comment-stripped) + normalized CWE + normalized path. (Heuristic, not AST — see Complexity.)
  - **Per-candidate fresh session** verifier: a dedicated tool envelope adding `capture_evidence` (reads source lines, registers immutable `EV-<sha>` with exact quotes) and `submit_verification` (verdict ∈ supported/rejected/unresolved + rationale + entry_point + attacker_control + preconditions + defenses_reviewed + security_impact + evidence_ids + unresolved_questions); one candidate per session, `max_failures=3`.
  - **Reconcile**: iterate ALL candidates; accept `supported` only if evidence quotes byte-match live source, cover the cited location, include the containing function/defenses, match the revision/identity, and pass the quality battery; else `unresolved` with a reason; `rejected` is first-class with cited evidence. Write `verification_decisions.json`, `verification_metrics.json`, `verification_reconciliation.json`. Harness-owned outcome — never ingest a model file as the decision.
  - **Handoffs**: `verification.render` writes `phase2b_output.md` (disposition table + the explicit "acceptance includes unresolved; does not imply confirmation" note) and `phase2b_handoff.md` (supported-only), plus phase-3 assignment inputs; a "no manifest / zero supported" sentinel handoff when applicable.
  - **collectFindings** consumes decisions, not raw hunt markdown; a zero-survivor result yields zero supported and no resurrection (FR-C1); malformed/empty/invalid → unresolved, never supported (FR-C2).
- **Rationale**: The audit found none of this ported and two live bugs (resurrection, malformed→confirmed). This is the heart of trustworthy evidence.
- **Alternatives**: Keep the generic-agent 2b and post-hoc promotion (the current honesty-violating state — rejected). True AST identity (no in-tree parser — deferred).

## R7. Source-grounded publication + artifact validation

- **Decision**: Port the reference evidence discipline into `internal/consolidate/quality.go` + `consolidate.go` + a new `internal/verification/artifacts.go`:
  - `statically_supported` requires a verification `supported` decision OR a source-corroborated quality result: open the cited file and match a CWE-family **sink pattern** (`check_source_corroborated`) AND pass per-class **veto** checks (`check_class_evidence`: weak-random consumer, access-control, XSS HTML-vs-JSON, CORS credentialed-wildcard, race uniqueness, SSTI constant template); **logic/authorization CWEs can never be statically supported on prose** and remain hypotheses without a validated review record. Missing checkout/source → `unavailable` uncertainty.
  - Full tier taxonomy reachable: classification `reviewed > statically_supported > hypothesis`; assessment `supported/unresolved`; finding_state `statically_supported/dynamically_confirmed/unresolved`; verification `supported/rejected/unresolved`; artifact `authored/deferred/error`; run `incomplete/clean`.
  - `validate_artifacts`: each manifest entry references a known **supported** candidate; path relative + inside `poc/`/`exploit_tests/`; file exists and contains the candidate ID + location; status `authored` only; authored `.py` parses + has an assertion; unregistered on-disk artifacts flagged.
  - **finalize/regenerate never clobber** a real `artifact_manifest.json`: build it only when absent; write `[]` only on the legitimate zero-verified phase-3 skip; regeneration re-reconciles the **existing** decisions and reads (never rewrites) the artifact manifest.
  - `apply_validation`: `dynamically_confirmed`/`TEST_PASSED` require executor-owned evidence (exit 0 + security-property violated + matching candidate/revision); with no executor, no finding reaches passed — a positive fail-closed guard, not a hardcoded `false`.
- **Rationale**: The audit found support derived from surface signals, collapsed tiers, placeholder manifests, and the finalize/regenerate clobber (FR-C3). This makes publication source-grounded and non-destructive.
- **Alternatives**: Keep the 4-boolean quality battery (surface-signal support — rejected).

## R8. Truthful completion / coverage / resume / regeneration

- **Decision**:
  - **Produced**: `isSuccessfulWrite` checks the Write target equals the declared `DeliverablePath` **and** the file is non-empty; `Result` gains `WroteFiles`, `Error`, `ErrorKind`; nudges key off the specific missing deliverable (FR-C4).
  - **Per-unit attribution**: `AgentRecord` gains `expected_deliverable`, `wrote_files`, `produced`, `error`, `error_kind`, `partition`, `vuln_class`; failed hunt units get an explicit placeholder file (reference behavior); the hunt is complete only per the reference rule, with per-unit truth preserved.
  - **Coverage**: name the specific reviewed entry point + disposition + review evidence; match the reference **enumeration denominator** (router/blueprint prefixes, method defaults → `ROUTE` not `GET`, websocket, **test-file exclusion**, dedup, security-relevant subsystem rules) and the reference **corpus scope** (include phase1/2b/3/3d/README, not only `results/*.md`) — or record the divergence explicitly.
  - **Resume**: validate saved-output identity + verification/artifact contract (not just non-emptiness); rerun invalid units; **count valid resumed work in effective completion** so a fully-resumed run is not `incomplete`.
  - **Cancellation**: do **not** set `rec.Aborted` on cancel (reserve abort for cancellation-vs-systemic per feature-004 wording → here: `execution_status=cancelled`); a cancelled in-flight agent returns a `cancelled` stop reason and is **not** marked `endpoint_failure` and generates no endpoint-failure degradation reason (FR-C5).
  - **Regeneration**: persist the real `backend` and served model/provenance (additive `RunRecord.Backend`, per-agent provenance); serialize `endpoint_failures` (drop feature-004's `json:"-"`) and convert persisted per-agent `endpoint_failure` stop reasons into degradation reasons at finalize so regeneration is deterministic; never fabricate `ollama` (FR-C6).
- **Rationale**: The audit found each of these untruthful; they are the honesty seams across resume/regeneration.
- **Alternatives**: Keep feature-004's in-memory `EndpointFailures` (`json:"-"`) — loses reasons on regen (rejected; superseded here). Keep phase-level `deliverableValid` as the only guard — masks the suppressed-nudge bug (rejected).

## R9. Testing (offline, no live model) + concurrency scope

- **Decision**: Every behavior above ships an offline regression test that fails pre-fix, using the shared transcript + scripted providers and `testdata/vulnapp`. The required scenarios (FR-039): wrong-path/empty writes, missing prompt, results-dir discovery, citations beyond the first Read page, failed hunt units, all-candidates-rejected, absent/contradictory source evidence, malformed verification decisions, preserved artifact manifests, resume, cancellation, regeneration-after-endpoint-failure, split/samples/IaC option behavior. The differential test (R1) compares normalized semantics. **Per-agent concurrency is deferred** (serial execution; parity diff normalizes ordering). Feature-004 tests are kept green.
- **Rationale**: Constitution VII + spec SC-011; the operator owns live validation. Serial execution keeps the parity diff deterministic.
- **Alternatives**: Live-model validation (operator-owned, out of scope). Concurrency now (deferred — Complexity #3).

---

## Resolved unknowns

- Differential-harness mechanism → R1 (hermetic goldens + opt-in live Python).
- Concurrency scope → R9 (deferred, documented).
- Candidate identity without AST → R6 (heuristic digest, documented in Complexity).
- Glob dependency → R3 (in-repo fnmatch translator; zero new runtime deps).
- No `NEEDS CLARIFICATION` remains. Additive schema changes enumerated in data-model.md (permitted by FR-043).
