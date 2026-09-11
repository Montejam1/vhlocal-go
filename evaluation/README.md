# Evaluation set — known application-level defects

A fixed set of ground-truth defects that a scan **should** discover, used to
measure recall independently of the reporting threshold. It answers a question the
per-run counts cannot: *did hunting even generate a candidate for this bug?*

Improving the publication filters cannot recover a finding that hunting never
produced — so these cases test **discovery**, not filtering. Two classes that the
hunt has repeatedly missed are seeded here:

- **Cross-endpoint authorization consistency** — a restriction enforced on one
  route bypassable through another path (e.g. `/api/v1`) for the same resource.
- **Credential / token invalidation on state change** — e.g. a password-reset
  token that survives the password change it was issued for.

## Usage

```bash
python3 -m vhlocal.policy_bench <results_dir> evaluation/known_defects.json
```

The report gains a **Known-defect recall** column: for each policy, how many of
these defects are matched by a *substantiated* finding. `0/N` even at `lenient`
means the hunt never produced the candidate — a discovery gap to fix in the hunt
prompt/coverage, not in the checker.

## Format

A JSON list of `{cwe, file, line, ...}`. Matching (see `policy_bench._loc_match`)
is by **file basename + CWE** — the `line`, `name`, `tests`, and `note` fields are
for humans. Confirm each `cwe`/`file` against the target before trusting recall;
the seeded values are best-effort from the defect descriptions and marked with a
`CONFIRM` note.
