# Phase 0 Research: Port vhlocal to Go

**Feature**: 002-golang-port | **Date**: 2026-09-14

This document records the technical decisions that resolve the plan's open choices. Each entry: **Decision / Rationale / Alternatives considered**. The guiding constraint throughout is *interface and behavior parity* with the Python implementation and adherence to the constitution's honesty/safety principles, with a stdlib-first posture mirroring the current project's minimalism.

---

## R1. Go toolchain version

- **Decision**: Target Go 1.23+, single module. Pin the version in `go.mod`.
- **Rationale**: Provides mature `embed`, `slices`/`maps`, `min`/`max`, and stable `net/http` behavior. Widely available on Linux/macOS build hosts. No need for bleeding-edge features.
- **Alternatives**: Older Go (1.21) — works but no benefit; newer/unreleased — unnecessary risk.

## R2. CLI structure and flag-precedence parity

- **Decision**: One binary `vhlocal` with manual subcommand dispatch on `os.Args[1]`; each subcommand builds its own `flag.FlagSet`. Reproduce the current `explicit > profile > default` precedence by: (a) applying built-in defaults, (b) overlaying a loaded profile's structural knobs, (c) applying only the flags the user *actually set*, detected via `FlagSet.Visit` (which visits only set flags) rather than `VisitAll`. This is the exact analog of Python's `argparse.SUPPRESS` trick.
- **Rationale**: Stdlib `flag` covers the entire flag surface without a dependency, and `Visit` gives precise "was-set" semantics needed for profile precedence. Keeps parity with `run.py:41-49,168-181`.
- **Alternatives**: `cobra`/`urfave/cli` — ergonomic and standard for large CLIs, but adds a runtime dependency the constitution's minimalism disfavors; deferred unless the manual dispatch proves unwieldy (revisit only with explicit justification). Kept as a documented fallback, not adopted.
- **Note**: `flag` does not natively support GNU `--flag=value`/`--flag value` both plus short-combining; the current tool uses `--long` style and a single `-v/--verbose` count. A thin wrapper provides `--flag`/`--flag=value` and a repeatable count flag to match today's spellings exactly (see contracts/cli.md).

## R3. Dependency policy (Go analog of "stdlib-only")

- **Decision**: Stdlib-first. Runtime third-party dependencies are held to a small, explicitly enumerated budget and each must be justified. Baseline plan uses **zero runtime third-party deps** — `net/http`, `encoding/json`, `flag`, `embed`, `os/exec`, `html/template`, `testing`, `unicode` cover the surface. Release/build tooling (cross-compile script or a release helper) may use external tools but does not enter the runtime.
- **Rationale**: Preserves the project's core "nothing to pull in, auditable" property (constitution Safety & Technical Constraints), now expressed for Go. Fewer deps = smaller attack surface for a security tool.
- **Alternatives**: Freely use libraries (cobra, a SARIF lib, a CycloneDX lib, logrus/zap) — faster to write but expands the trust base of a security scanner and breaks the minimalism the amendment will codify. Rejected as the default.

## R4. HTTP engine + SSE

- **Decision**: `net/http` with `http.ServeMux` (Go 1.22+ pattern routing, incl. path params like `/api/scans/{id}`). SSE via a handler that sets `Content-Type: text/event-stream`, writes `data: {json}\n\n` events, flushes with `http.Flusher`, replays a backlog by `offset`, and emits `: keepalive\n\n` on a ticker. One `ThreadingHTTPServer` analog is just `http.Server` (goroutine-per-request by default).
- **Rationale**: Stdlib fully supports REST + SSE + static file serving; 1.22 mux removes the need for a router dependency. Matches `server.py` behavior including the offset/replay and keepalive.
- **Alternatives**: chi/gorilla mux — unnecessary given 1.22 patterns; a WebSocket upgrade instead of SSE — would change the API contract the UI depends on. Rejected.

## R5. Single-binary asset embedding

- **Decision**: `go:embed` the bundled `skill/` methodology tree and the built browser-UI bundle (`vhlocal/web/`, including the React `app/` output and the legacy/classic single-file HTMLs). Serve UI from the embedded FS; load phase prompts from the embedded FS by default, with `--skill-dir` overriding to a real directory (matching today's override).
- **Rationale**: Delivers FR-032 (self-contained binary, nothing to install) and preserves the offline guarantee (no CDN). The React bundle is built at build time and embedded, so runtime needs no Node.
- **Alternatives**: Ship assets alongside the binary in a directory — reintroduces an install/layout step and can drift; rejected. Fetch UI from a CDN — violates offline/no-egress; rejected.
- **Build ordering**: `npm run build` (in `web-react/`, outputs to `vhlocal/web/app`) must run before `go build` so the embed captures current assets. Encoded in the release script and documented.

## R6. JSON parity and gotchas

- **Decision**: Define Go structs with explicit `json:"..."` tags matching every Python field name (from the artifact/API research). Rules to preserve semantics: use pointer or `*T`/`omitempty` deliberately where Python emits `null` vs. omits a key; keep numbers as `int`/`float64` to match; do not rely on field ordering (JSON is order-insensitive and no consumer depends on order — confirmed by the React client reading by key). Round-trip existing Python-written artifacts in tests to prove tolerant reads (FR-028).
- **Rationale**: The React UI and downstream tooling read by key; parity is about field names, types, and null/absent behavior, not byte-order. Explicit tags prevent Go's default capitalization from leaking.
- **Alternatives**: Match Python's exact key ordering via ordered maps — unnecessary complexity for no consumer benefit; rejected. Byte-identical output — impossible anyway (timings/prose vary), and out of scope per spec assumptions.
- **Risk to verify in design**: distinguishing "field absent" from "field present but null" for optional fields (e.g. `open_findings: number | null`, `verify_model?`). Data-model.md marks each optional field's emit behavior; use `*T` for nullable-present and `omitempty` for absent.

## R7. SARIF 2.1.0 and CycloneDX emission

- **Decision**: Hand-roll Go structs for the SARIF 2.1.0 document and the CycloneDX subset vhlocal emits (driver name `vhlocal`, the exact rule/result/location/severity/CWE mapping from `sarif.py`; the CycloneDX components/properties/licenses shape from `sbom.py`). Emit via `encoding/json`.
- **Rationale**: The emitted subsets are small and fixed; hand-rolled structs keep zero runtime deps and guarantee the fields match what today's consumers accept (FR-007). Validated in tests against the current tool's output shape.
- **Alternatives**: A SARIF library and a CycloneDX library — heavier, add deps, and may emit a superset/different field choices that break parity with saved reports. Rejected.

## R8. Deterministic report rendering (HTML + Markdown)

- **Decision**: Port `render_html.py` and the markdown consolidation to Go using `html/template` (with a hardened, no-external-request, self-contained template carrying the tuned print stylesheet, severity glyph+word encoding, KPI tiles, severity meter, filter/expand JS inline) and string/template building for `SCAN_REPORT.md`. All rendering is deterministic from `scan_meta.json`/`findings.json` — no model call.
- **Rationale**: Preserves FR-008 (single self-contained file, print-to-PDF, filtered-view banner) and the honesty guarantees (engine facts authoritative). `html/template` auto-escaping helps keep served artifacts inert (FR-025).
- **Alternatives**: Embed the Python renderer's HTML as a fixed template with placeholders — brittle; a JS-side render — changes the artifact contract. Rejected. The report's interactive JS remains inline and identical in behavior.

## R9. External tools: ripgrep and git

- **Decision**: Shell out via `os/exec` to `rg` when present (Grep tool + Phase 3d deterministic sweep) with a pure-Go fallback (`filepath.WalkDir` + `regexp`, honoring the same ignore rules) when `rg` is absent — mirroring today's optional-ripgrep behavior. `git` via `os/exec` for best-effort provenance (`git_commit`/`branch`/`dirty`), empty when not a repo.
- **Rationale**: Parity with current behavior (README "ripgrep optional; falls back to a pure-Python scanner"). `os/exec` is stdlib. The fallback keeps zero hard external requirements.
- **Alternatives**: A Go regex-search library — unnecessary; requiring ripgrep — regresses the "nothing to install" property. Rejected.

## R10. Concurrency model

- **Decision**: The server's single-worker FIFO queue becomes a goroutine draining a channel of jobs, with job state guarded by a mutex and persisted atomically. Cancellation via `context.Context` cancelled by the cancel endpoint, checked between model turns to stop within one turn. Phase 2 stays **sequential** this release (concurrency deferred per spec); the existing `--concurrency` flag is preserved and honored exactly as today (it already gates on the Ollama server's parallelism).
- **Rationale**: Matches "scans are serialized / one GPU" behavior and the interrupted-job semantics; `context` gives clean cancel-within-one-turn. Preserves FR-016 and the busy-state contract.
- **Alternatives**: True parallel Phase 2 — explicitly deferred; changing serialization would alter observable behavior and risk the honesty/coverage accounting. Rejected for this release.

## R11. Testing strategy

- **Decision**: `go test ./...` as the offline gate. Backend clients tested via an in-process fake transport implementing the provider interface and via `httptest.Server` returning recorded fixtures (Ollama `/api/chat`, OpenAI `/v1/chat/completions`, OpenRouter). Engine API tested via `httptest`. Deterministic layers (consolidate, dedup, CWE/severity normalization, lifecycle, coverage status, SARIF, SBOM) get direct table tests, including degraded paths (unparseable partition table, empty deliverable, shallow run, tool-call repair, budget halt, interrupted job). The `testdata/vulnapp` scorer is ported to Go for recall + negative-control checks.
- **Rationale**: Satisfies Principle VII and FR-029/SC-006/SC-007 with no live model or network. Fakes exercise model/transport behavior as required.
- **Alternatives**: Integration tests against a live Ollama — violates offline requirement; rejected for the gate (may exist as an optional, tagged, manual suite).

## R12. Cross-platform release

- **Decision**: `go build` with `GOOS`/`GOARCH` matrix for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, driven by a simple `make release` / shell script; assets embedded so each binary is standalone. Version stamped via `-ldflags -X` into the `engine_version` field.
- **Rationale**: Delivers FR-033/SC-012 with stdlib tooling. Cross-compilation is trivial in Go since the design avoids cgo.
- **Alternatives**: `goreleaser` — convenient but a build-time dependency; optional, not required. Docker-only distribution — regresses the single-binary goal. Rejected as the default.
- **Constraint**: Avoid cgo (no C deps) so cross-compilation stays pure and static.

## R13. Unicode text normalization

- **Decision**: Port `normalize_text()` faithfully — map the specific typographic characters the Python version maps (e.g. U+2011 NON-BREAKING HYPHEN → ASCII `-`, and the other punctuation it normalizes) before any regex over model output. Centralize in `internal/phases`. Every model-output parser routes through it.
- **Rationale**: This is a load-bearing correctness fix (partition-table parsing silently collapsing). Exact character-map parity is required (FR-025, edge cases). The precise map comes from the artifact-schema research.
- **Alternatives**: Go `golang.org/x/text` normalization — a dependency and semantically different (NFC/NFKC would over-normalize); rejected in favor of the exact same targeted map.

## R14. Migration, coexistence, and backward-compatible reads

- **Decision**: The Go tree lives alongside the Python tree during migration; the delivered product is the Go binary. The Go readers for `scan_meta.json`, `findings.json`, ledgers, `applications.json`, and `jobs.json` are tolerant: unknown/extra fields ignored, missing newer fields defaulted per the documented fallback (matching the React types' "most optional" tolerance and the header-parse degradation). No requirement for Python to read Go-written files.
- **Rationale**: FR-028/SC-004 — existing on-disk scans, ledgers, and job state remain usable. One-directional compat keeps scope bounded.
- **Alternatives**: A one-time migration/converter — unnecessary since formats are unchanged; rejected. Bidirectional compat — out of scope.

## R16. Python-AST-based entry-point enumeration (parity risk)

- **Decision**: Re-implement the deterministic entry-point inventory (`inventory.py`) in Go as a **standalone parser** that recognizes the same route-registration patterns the Python `ast`-based enumerator recognizes (FastAPI `@app.get`/`APIRouter`/`include_router` prefixes; Flask `@app.route`/blueprints), producing the same coverage-ledger dispositions and the same partition-fallback synthesis. Non-Python entry points remain the documented known limitation, exactly as today. Prefer a targeted source parser (Go `go/scanner`-style tokenization is for Go, not Python, so use a purpose-built lexer/regex+heuristics tuned to the decorator/route forms actually enumerated) over embedding a Python interpreter.
- **Rationale**: The enumerator is the *coverage denominator* — a load-bearing honesty mechanism (constitution Principle II; the gvisor "0 entry points but complete" bug). Its output (route list, dispositions, `not_reviewed` gating, fallback partitions) must match. Go cannot reuse CPython's `ast`, so the recognition logic is re-expressed. Because only a small, well-defined set of route forms is actually enumerated, a focused Go parser can reach parity and is testable against the same fixtures.
- **Alternatives**:
  - *Shell out to a bundled Python AST helper* — reintroduces a Python runtime dependency, defeating the single-binary/no-prerequisite goal (FR-032); rejected.
  - *Use a third-party Go "Python parser" library* — adds a runtime dependency to a security tool and risks subtle divergence from CPython's `ast`; rejected unless a focused parser proves insufficient (then justify explicitly).
  - *Pure regex only* — likely lower fidelity on `include_router`/blueprint prefixing and multi-line decorators; use regex+heuristics only where it demonstrably matches the fixtures.
- **Risk & validation**: This is the highest-fidelity-risk area of the port. Design tasks MUST pin behavior with tests over the current `testdata/` fixtures and additional FastAPI/Flask route-shape cases, asserting identical enumerated routes, dispositions, and fallback partitions vs. the Python output. Any unavoidable divergence is documented as a known limitation (never silent — Principle II).

## R15. Governance: constitution amendment

- **Decision**: Before/at implementation, amend the constitution's *Safety & Technical Constraints › Runtime* clause (and the Principle VII test-command wording) via `/speckit-constitution`, naming the accepted risk (loss of "stock system Python, nothing to install"; adoption of Go with a small, reviewed dependency budget as the stdlib-only analog). Record the version bump and rationale.
- **Rationale**: The port fails the Runtime gate by design; governance requires the change be made knowingly and recorded (constitution Governance section). All other principles are preserved, so this is the single sanctioned deviation.
- **Alternatives**: Proceed without amending — leaves the plan in unjustified violation and blocks the review gate; rejected. Abandon the port to satisfy the clause — contradicts the user request; rejected.

---

## Resolved unknowns summary

All Technical Context items are resolved; no `NEEDS CLARIFICATION` remains for Phase 1. The single escalation (runtime language) is a tracked, justified deviation with a concrete governance action (R15), not an open question.
