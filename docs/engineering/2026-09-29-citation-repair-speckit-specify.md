# Claude handoff: Validate citations on submission and repair verification inputs

Prepared: 2026-09-29. Follow-up to feature 014 and the September 28 scan-reliability
handoff. This is specification input, not an implementation or a change to the
running scan. Preparing it does not change the active feature pointer.

## Start in Claude

```text
/speckit-specify Read docs/engineering/2026-09-29-citation-repair-speckit-specify.md and use its entire "Specification input" section as the feature description. Use the audit evidence as context and recheck the current implementation. Specify citation validation at finding submission, actionable bounded correction/resubmission, evidence-preserving candidate amendments, and accurate per-operation failure diagnostics. Preserve features 012–014 and current evidence standards. Create a new specification and requirements checklist; stop before planning or implementation.
```

## Audit evidence

Live job `843875fb0919`, report directory:

```text
~/vulnhunter-reports/vc-claude-code-seeded-v2-logistics-dispatch-fastapi_VULNHUNT_RESULTS_gptoss120b_2026-09-28-221735
```

At the inspected snapshot, 95 of 171 candidate verification sessions had finished:
39 accepted decisions (31 supported, 4 rejected, 4 explicitly unresolved), 43
repair-limit stops, and 13 turn-limit stops. The remaining candidates were still
pending or running. Recorded failure occurrences included 144 invalid
submissions, 47 invalid tool arguments, and 9 tool-envelope failures. These are
occurrence counts, not distinct candidates or final scan results.

The most frequent final contract violations were malformed original candidate
locations and mismatches between submitted entry points and resolved handlers.
Examples of candidate location strings rejected by the strict location parser:

```text
confirm_password_reset function, line 224-242 in backend/app/routers/auth.py
backend/app/security.py:40 - hash_token uses settings.secret_key for HMAC-SHA256.
backend/app/routers/customers.py:49-55, 62-64
```

Other observed problems included incomplete function evidence, absolute paths
passed to `capture_evidence`, out-of-bounds line ranges, and invalid regular
expressions such as `Incident(`.

Current code already validates verification submissions and sends error feedback
to the model. The missing capability is not simply "add validation":

- Hunt candidates are extracted from Markdown outputs by
  `internal/engine/verify.go:collectHuntCandidates`, then placed in a manifest.
  Do not assume a structured hunt-submission API already exists.
- `internal/verification/verification.go:validateEvidenceBacked` checks the
  original candidate's location against a strict `file:line[-end]` grammar.
- `submit_verification` can submit evidence and a verdict, but cannot repair
  that original location. Repeating the decision cannot fix malformed immutable
  input. It can only fall back to unresolved under the current interface.
- Supported decisions require full function evidence and an exact resolved
  `METHOD PATH` match where a route guard resolves. The initial context is only
  a window around the cited line; repair feedback does not supply all the
  canonical source/handler information needed to correct a mismatch efficiently.
- The loop allows 20 turns and three counted submission/envelope failures.
  Invalid tool arguments consume turns but not the three-failure allowance.
- `runVerification` emits a summary event for each failure class, attaching the
  same session-wide `LastOp` and `LastViolation` to every class. This can label a
  later submission error as the explanation for an earlier argument error.

Recheck these facts during planning. New logging exposes previously hidden
failures; more visible warnings alone do not establish that a newer scanner is
worse. The failure and recovery rates must be measured separately.

## Specification input

Create a feature named **Validated citations and bounded verification repair**.
When an AI agent submits a finding or verification decision, vhlocal-go must
validate its citations immediately, return actionable feedback for correctable
errors, allow a bounded correction and resubmission, and accept the result only
after its source evidence passes validation.

Preserve the constitution, static-only scanning, features 012–014, multi-language
inventory, existing review decisions, reports, lifecycle data, and dashboard
metrics. Extend the existing validation/repair machinery rather than introducing
parallel incompatible validators. Do not weaken evidence checks to increase
acceptance rates. Do not alter or interrupt an in-flight scan during this work.

### P1 — Validate finding citations before downstream verification

Define one structured citation contract with a repository-relative path,
one-based inclusive start/end lines, repository revision/source identity, and
an explicit primary location. Support multiple supplementary ranges as separate
citations; do not silently collapse disjoint ranges into a misleading span.
Bind handler/entry-point identities when reliably recognized; non-HTTP findings
must remain valid without an invented HTTP route.

Validate at the first finding submission/ingestion boundary, before a candidate
is considered ready for verification. Because the current hunt emits Markdown,
define how the producing agent receives feedback on invalid extracted findings
before its assignment is accepted. A structured submission tool is an available
implementation choice, not a presumed existing capability. Keep a compatible,
validated adapter for older Markdown artifacts and imports.

Distinguish citation format validity, source resolution, and evidentiary
relevance. A file and valid line numbers are necessary but do not prove that a
vulnerability exists. Validate confinement including symlinks, file existence,
range bounds, source revision, and source/handler binding. Evidence text must be
captured by the harness from the source, not trusted as model-pasted quotations.
Never execute target code or import target modules to resolve citations.

Allow deterministic normalization of unambiguous formatting differences while
preserving the original text and recording the normalization. For example, a
plain file/line followed by commentary may be parsed into structured fields
when the interpretation is unique. Ambiguous paths, multiple possible handlers,
missing lines, and semantically unrelated source must trigger clarification or
investigation by the agent, not guessed corrections. Never clamp an invalid
range silently or shift a citation to nearby code merely to make it pass.

### P1 — Return precise feedback and accept corrected resubmissions

Every validation failure must identify the candidate/submission, operation,
field, error code, received value where safe, expected contract, and whether the
error is repairable. Include source-derived aids where available: valid file
length, resolved handler identifier, canonical route name, required function
span, and missing evidence ranges. Do not include unsupported guesses or leak
out-of-repository content.

Send that feedback to the responsible agent in the same session where possible.
The agent must be able to inspect source, correct the submitted fields, and
resubmit. Validate the new submission fully. A successful format repair is not
a supported vulnerability verdict; it only makes the candidate eligible for
the remaining verification checks.

Differentiate formatting repair from substantive evidence repair. An invalid
regex needs escaping or an explicit literal-search mode; an out-of-bounds range
needs valid source coordinates; a citation to the wrong function needs source
investigation. A source-refuted claim needs rejection or unresolved status,
not repeated encouragement to obtain a supported verdict.

Document and bound repair attempts, total model turns, repeated-identical-error
handling, budget use, cancellation, and transport retries. Avoid burning an
entire verification session on a deterministic preflight failure. Stop repeated
unchanged submissions early with an explicit reason. Preserve invalid original
submissions and attempted repairs for diagnosis; do not silently drop them from
candidate totals. Exhausted repairs remain unresolved/incomplete as appropriate.
Do not manufacture successful agent completion by synthesizing an unresolved
label without disclosing that verification never completed.

### P1 — Make original candidate citations safely amendable

For existing malformed candidates, provide a validated amendment path rather
than requiring repeated verdict submissions against an unchangeable location.
Retain original and amended citations, the reason, source revision, agent,
attempt, and validation outcome. Define whether identity is preserved or a new
candidate supersedes the old one; references to decisions, evidence, reports,
artifacts, and lifecycle records must remain consistent and traceable.

Formatting normalization that resolves to the same source anchor may retain
identity under documented rules. Moving to a different handler or source anchor
requires renewed evidence validation and must not inherit a previous supported
decision. Resolve duplicates without losing originals or double-counting work.
Never let one candidate's amendment change another candidate's evidence.

Before a supported submission, expose the canonical handler identity and exact
required evidence span where the recognizer can establish them. Distinguish
display text from structured entry-point identity so appending a function name
to a human-readable label does not cause pointless exact-string retries.
Ambiguous or unsupported binding must remain explicit. Handle shared handlers,
router prefixes, multiple routes per handler, and non-route source locations.
Preserve strict checks against accidentally citing a sibling handler.

Resume must replay validated amendments idempotently and reject incompatible
revision evidence. Historical regeneration must not invoke a model, silently
rewrite original citations, fabricate missing evidence, or upgrade old results.
Keep legacy artifacts readable with honest validation/availability states.

### P1 — Accurate tool contracts and failure records

Align tool schemas, prompts, runtime argument validation, and repair feedback.
Reject malformed JSON and incorrect field types explicitly instead of ignoring
decode errors and letting absent/default arguments cause unrelated downstream
errors. Explain repository-relative paths, line conventions, and regex syntax.
Provide safe literal search where appropriate without silently changing the
meaning of a regex request.

Record each actual failed operation with its own class, message, scan/agent/
candidate/call/attempt identity, timestamp, and outcome. Do not reuse a session's
last error as the explanation for every failure category. Keep argument,
submission, provider-envelope, transport, and turn-exhaustion events distinct.
Link successful corrections to the failed attempts they repair.

Show recoverable warnings, recovered attempts, and terminal failures distinctly
in the live feed, Log, candidate detail, and reports. Retain aggregate counts
without double-counting summary events. Pending candidates must not be displayed
as completed failures. Persist enough bounded, redacted diagnostic information
to reproduce a failure; never record credentials or require hidden reasoning.

### Acceptance scenarios

1. An agent submits each audited malformed citation example. Unambiguous input
   normalizes with provenance; ambiguous/disjoint input receives field-specific
   feedback. A valid correction is accepted without losing or duplicating the
   finding. A file-only or unrelated citation cannot become valid by formatting.
2. A fake provider submits an invalid finding, receives the real validation
   feedback, reads source, and resubmits a correct citation through the production
   ingestion path. It then completes independent evidence-backed verification.
   Test the Markdown ingestion adapter as well as any structured tool path.
3. Missing files, traversal/symlink escape, invalid ranges, stale revision,
   wrong handler, fabricated evidence IDs, and mismatched quotations fail safely.
   No helper silently alters the source location to make validation succeed.
4. Candidates with original malformed locations can be amended through the
   supported interface. A source-anchor change invalidates incompatible evidence;
   resume and duplicate handling preserve history and referential integrity.
5. Correct handler evidence plus a descriptive display label does not cause a
   formatting-only rejection. A genuinely different handler remains rejected.
   Include Python, Go, JS/TS, router prefixes, shared/multiple routes, and
   non-HTTP findings, reporting unsupported recognition honestly.
6. Incomplete function evidence produces exact missing-span feedback. Capturing
   those valid ranges resolves that error, but cannot override source that
   refutes the vulnerability. Supported and rejected decisions retain their
   appropriate, distinct evidence requirements.
7. Recoverable bad paths, ranges, regexes, JSON, and argument types are corrected
   within a deterministic bounded fixture. Persistent identical failures stop
   within the documented bound with actionable unresolved/incomplete outcomes.
   Cancellation and budget limits stop further repair calls.
8. A session with an argument error followed by a submission error records two
   correctly attributed failures. Neither receives the other's operation or
   message. Recovery and failure counts agree across events, sessions, and UI.
9. Legacy regeneration does not fabricate corrections. New live diagnostics are
   durable across reconnect/restart, and prior valid results are preserved.
10. A sanitized replay fixture derived from this scan demonstrates that the
    repairable citation failures now progress through verification. Report
    acceptance, recovery, terminal failure, and model-call counts separately;
    unresolved substantive claims must not be forced to pass. No assertion that
    every live-model candidate will succeed is required or acceptable.

Use isolated offline fake-provider tests plus the project's required checks.
Include negative controls and end-to-end submission-to-report evidence, not
only parser unit tests. Any live-model rerun is a separate operator action.

During planning, inspect candidate extraction/normalization/identity,
`internal/engine/verify.go`, `internal/verification`, handler recognition,
source confinement, tool schemas, prompt capture, scan logging, resume,
reproduction references, and the shipped UI. Record which feature-014 work
already satisfies requirements and which concrete gaps remain. This feature
improves successful evidence production; it must not weaken validation.
