# Hypotheses and substantiated vulnerabilities

A candidate is labelled by the strongest evidence it clears — confidence never
exceeds evidence, but a well-formed static finding is not collapsed to a bare
hypothesis. There are three publication tiers (`classification`):

- **`hypothesis`** — clears no evidence gate: no weakness class, a placeholder /
  input-inventory title, or a source location that does not resolve against the
  scanned tree. A model's own `Confirmed`/`PASS` prose never lifts a candidate out
  of this tier on its own. Hypotheses are surfaced as worth investigating; they are
  *not* published as findings.
- **`statically_supported`** — clears the harness's own **quality battery**
  (`quality.py`, see below): a structural floor (weakness class, a concrete claim,
  a resolvable location) *plus* deterministic corroboration against the actual
  source at the configured strictness. The scanner can honestly stand behind this
  from static facts, but no independent source-grounded review exists. This is the
  useful default output of a scan.
- **`reviewed`** — additionally backed by a source-grounded review record (see
  below): the highest tier.

**Substantiated** means `statically_supported` or `reviewed` (i.e. `assessment ==
supported`). The generated Markdown/HTML report explains why each candidate was
flagged and which tier it reached. Severity describes potential impact, not
certainty.

Each JSON record includes:

- `classification`: `hypothesis`, `statically_supported`, or `reviewed`.
- `hypothesis_reason`: the hunter's candidate-specific Root Cause explanation,
  when provided; the report otherwise uses its data flow or states that no
  explanation was provided. This is a model claim, not verified evidence.
- `assessment_reason`: the validated review rationale (reviewed), the static-gate
  basis (statically_supported), or the reason further investigation is required
  (hypothesis).
- `candidate_key`: a revision-specific hash of the title, CWE, and location.
  A changed identity requires a new review; display VULN IDs are not review keys.
- `potential_severity`: potential impact, independent of assessment.

`findings` and `counts` remain candidate collections/counts for API compatibility.
Use `vulnerability_counts` (substantiated: statically_supported + reviewed),
`hypothesis_counts`, and `assessment` (with per-tier `statically_supported`,
`reviewed`, `hypotheses` totals) for separate breakdowns. Report-index finding
counts and manifest finding counts include only substantiated candidates; the
report index also carries a separate `hypotheses` count. The vulnerability ledger
records only substantiated findings — a hypothesis is not a tracked vulnerability.
SARIF hypotheses have `kind: review` and `level: note`; substantiated candidates
are `kind: fail`, with the tier, potential severity, and explanations in
properties.

## Quality checks (the `statically_supported` bar)

Metadata completeness alone does not substantiate a finding — a model can cite a
CWE and a real file yet be describing a bug that isn't there. Before a candidate
publishes, `quality.evaluate` runs a battery of **deterministic** checks against
the actual source and records them per finding as `quality_checks`
(`{name, status, reason}`, shown in the report as a `✓ / ✗ / — name` line):

- **Structural floor** (all levels): `weakness_class`, `concrete_claim`,
  `location_resolves`. Fail any → `hypothesis`.
- **Corroboration**: `source_corroborated` (the cited source, in a window around
  the line, contains a sink pattern for the CWE — reusing the `sweep` pattern
  table; N/A for logic/authorization classes with no syntactic sink),
  `flow_described` (a real source→sink / ownership-gap data flow), `agreement`
  (≥2 hunt samples reported the site, or the finding came through Phase-2b).

How much corroboration the `statically_supported` bar demands is the
`quality_strictness` config (`--quality-strictness`, the UI "Quality bar", or a
profile), recorded in `scan_meta.json` so a re-render assesses at the run's level:

- **`lenient`** — any one corroboration signal (for any class).
- **`balanced`** (default) — sink classes MUST show a source-pattern match (a
  *checked-and-absent* sink demotes to `hypothesis`); logic classes need
  `flow_described` + a line-precise location + `agreement`. When the source can't
  be checked (no checkout, or no derivable pattern) the benefit of the doubt falls
  back to flow-or-agreement, so a re-render without the tree never degrades a
  corroborated finding's tier.
- **`strict`** — sink classes need a source-pattern match AND a second signal
  (flow or agreement); logic classes as in `balanced`.

Only the `statically_supported` bar moves with this setting; the `reviewed` tier
always requires a source-grounded review record, and `hypothesis` always means the
structural floor or all corroboration failed.

## Recording an evidence review

A source-grounded review is what lifts a `statically_supported` finding to the
`reviewed` tier. The current Markdown verifier does not automatically produce one.
A reviewer or verification integration can supply `verification_records.json`
in the results directory, keyed by the candidate's `candidate_key` from JSON.
The same mapping can be supplied as `verification_records` in scan metadata.
The sidecar takes precedence; invalid JSON fails closed. Example record:

```json
{
  "<candidate_key>": {
    "verdict": "supported",
    "revision": "<scanned git_commit>",
    "reviewer": "<reviewer identity or verification job>",
    "rationale": "The request value reaches the query executor without binding, allowing the caller to change query semantics.",
    "entry_point": "GET /search",
    "attacker_control": "Query parameter q",
    "preconditions": "Authenticated search access",
    "defenses_reviewed": "The cited path contains neither parameter binding nor a query allowlist.",
    "security_impact": "The caller can access records beyond the intended search restriction.",
    "evidence": [
      {
        "path": "app/search.py",
        "start_line": 10,
        "end_line": 11,
        "quote": "<exact source lines covering the candidate location>"
      }
    ]
  }
}
```

The review gate requires a supported decision, complete reasoning fields, matching
revision, and exact source excerpts within the checkout. Evidence must cover the
candidate's cited line range. Missing checkout, changed quotes, out-of-bounds
lines, and unrelated citations mean the `reviewed` tier is not reached — a
well-formed candidate then remains `statically_supported`, and one that also fails
the static gate remains a `hypothesis`. Duplicates inherit the canonical
candidate's tier.

This validates review completeness and evidence provenance; it does not prove
the reviewer's reasoning is correct. The review producer remains responsible for
falsification, relevant defenses, and security impact. Keep hunter output separate
from that review workflow. No review is inferred from CWE descriptions, votes,
prior reports, or artifact existence.

Reproduction remains separate. An execution record needs the candidate key,
revision, a zero exit code, and an explicit `security_property_violated: true`
observation from the executor. Authored tests and a zero exit code alone do not
establish reproduction. No executor is added by this change.

## Applying this change

Restart any long-lived scanner process after updating the code. Existing saved
JSON/Markdown artifacts are not migrated automatically; explicitly regenerate a
report to apply the new assessment. HTML uses a new renderer version stamp.
Keep original scan artifacts when comparing before/after behavior.

The raw model-authored phase reports remain untrusted source artifacts. This
change governs the consolidated reports and exports; it does not repair the
separate phase-handoff parser, replace the verifier, or add runtime exploitation.
