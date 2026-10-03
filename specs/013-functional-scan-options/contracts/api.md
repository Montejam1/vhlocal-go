# Contract — /api/scans request validation & effective config

Changes to the scan-launch contract on `POST /api/scans` (`internal/server/handlers.go`,
`internal/server/server.go`). Behavior invariants, offline-verified. IDs map to requirements/SCs.

## Validator (replaces the compatibility-only patch)

- **C-V1 (allowlist)**: `supportedScanOptions` gains `seed_routes`, `seed_prior`, `enforce_coverage`,
  `concurrency`; every advertised option is accepted with real value validation (FR-001/007).
- **C-V2 (implemented values accepted)**: `seed_routes=true`, `seed_prior=true`, `enforce_coverage=false`,
  and `concurrency` within the supported integer range are ACCEPTED (the fixed rejections are removed as
  each behavior lands). `seed_routes=true`/`concurrency=2` are a REGRESSION that passes only after real
  behavior exists (FR-023, SC-008).
- **C-V3 (invalid still rejected, pre-queue, field-specific)**: invalid values fail BEFORE queuing with an
  actionable, field-specific message, deterministic when multiple fields are invalid, and start no model
  work (FR-004): non-bool `seed_*`; `concurrency` that is 0, negative, non-integer (`1.5`), a string, or
  above the range; unknown keys; bad `backend`/`quality_strictness` enum; `hunt_samples` ∉ 1–5;
  `max_budget_usd` < 0; per-role host without its backend.
- **C-V4 (distinct false/0/omitted/null)**: `false`, numeric `0` (where valid), omission, and `null` are
  distinct; `false` is never coerced to a default; fractional concurrency is never silently rounded (FR-003).
- **C-V5 (prerequisites/non-applicability)**: `seed_routes`/`seed_prior` with phase 1 omitted resolve to
  not-applicable (recorded, not a hard error), never silently launching an extra phase (FR-009).

## Builder (`buildScan`) — no silent drops

- **C-B1**: every accepted option maps to its `ScanSpec` field or is explicitly recorded not-applicable —
  `temperature`, `phase2_mode`, and per-role `*_backend`/`*_host` are populated (no longer dropped) (FR-007).
- **C-B2 (per-role providers)**: `engine.Providers` is built with `Verify`/`Recon`/`Reproduce` providers
  from per-role backend/host/model; blank inherits Hunt (documented); no endpoint beyond operator config;
  no silent provider switch (FR-017).
- **C-B3 (equivalence)**: the same options via UI, API, CLI, or a profile resolve to the same `ScanSpec`,
  `Providers`, and `EffectiveConfig` (FR-002).

## Effective config (response + persisted)

- **C-E1**: run metadata records `effective_config` = {requested, applied, not_applicable[]} with secrets
  removed; a provider limitation appears as not-applicable/disclosed, never as honored (FR-005/018, SC-010).
- **C-E2 (budget disclosure)**: a positive cap records real `spent_usd` accounting and enforcement; unknown
  pricing is disclosed (`priced=false`), never reported as zero cost or a false ceiling (FR-021, SC-006).

## Build identity

- **C-I1**: validation evidence records build identity (source vs embedded vs running vs older page vs
  profile vs alternate client) so a green source test is not mistaken for a fixed running app (FR-025).
