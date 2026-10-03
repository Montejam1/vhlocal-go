## Phase 2b session contract — worked examples (feature 015)

The harness verifies ONE candidate per session and validates every tool call. These
examples show exactly what a valid citation, a complete evidence capture, each verdict
and a correction after an error look like. Every example below is checked by an
offline test; follow the shapes literally.

### 1. Canonical citations and handler identities

A citation is `path:start[-end]` — repository-relative path, 1-based line numbers,
the sink statement lines. The harness NEVER shifts, clamps or guesses a citation.

| You wrote | The harness does |
|---|---|
| `backend/app/security.py:40 - hash_token uses a fast hash` | accepts `backend/app/security.py:40` (trailing commentary recorded as a normalization) |
| `backend/app/routers/customers.py:49-55, 62-64` | accepts `49-55` as the primary range and `62-64` as supplementary |
| `` `backend/app/routers/auth.py:224-242` `` | accepts (backticks stripped) |
| `confirm_password_reset function, line 224-242 in backend/app/routers/auth.py` | rejects with `E_CITATION_AMBIGUOUS` — name the file and the sink lines, not a function |
| `backend/app/routers/auth.py` | rejects with `E_CITATION_NO_LINE` |
| `backend/app/security.py:400` in a 120-line file | rejects with `E_RANGE_OUT_OF_BOUNDS` and `aids.file_length: 120` |

The handler identity is `METHOD PATH` exactly as registered (for example
`POST /api/customers/{customer_id}/locations`). The display label the hunt wrote
(`POST /api/customers/{id}/locations (add_location)`) is NOT the identity. Your
`entry_point` must equal the route identity given in the task facts.

### 2. Complete evidence

`capture_evidence` must cover the COMPLETE handler function — decorators, signature,
defenses, sink and return — using the "Required evidence span" from the task facts:

```
capture_evidence {"path": "backend/app/routers/customers.py", "start_line": 141, "end_line": 160}
→ {"evidence_id": "EV-…", "path": "backend/app/routers/customers.py", "start_line": 141, "end_line": 160, "quote": "…exact source…"}
```

Quotes are copied by the harness from the live source; never paste or edit source
yourself. An evidence capture that stops before the handler ends is rejected with
`E_EVIDENCE_SPAN_INCOMPLETE` and the required span in `aids.required_span`.

### 3. Decisions

Supported (evidence covers the complete handler; entry_point equals the identity):

```
submit_verification {
  "verdict": "supported",
  "rationale": "add_location loads the customer by path id without checking the caller's tenant; any authenticated dispatcher can attach a location to another tenant's customer.",
  "entry_point": "POST /api/customers/{customer_id}/locations",
  "attacker_control": "the customer_id path parameter",
  "preconditions": "an authenticated dispatcher session",
  "defenses_reviewed": "require_roles() only checks the role; no tenant scoping on the query",
  "security_impact": "cross-tenant write to another customer's service locations",
  "evidence_ids": ["EV-…"]
}
```

Rejected (the defense exists — say which line proves it):

```
submit_verification {
  "verdict": "rejected",
  "rationale": "the handler filters by current_user.tenant_id before the lookup (line 149), so the path id cannot reach another tenant's row.",
  "entry_point": "GET /api/customers/{customer_id}",
  "attacker_control": "the customer_id path parameter",
  "preconditions": "an authenticated session",
  "defenses_reviewed": "tenant filter on the query at line 149",
  "security_impact": "none — the query is tenant-scoped",
  "evidence_ids": ["EV-…"]
}
```

Unresolved (you could not establish or refute it — this is an accepted decision, not
a failure):

```
submit_verification {
  "verdict": "unresolved",
  "rationale": "the sink depends on a middleware the repository does not contain; exploitability cannot be established from source.",
  "entry_point": "POST /ops/mongo/dispatch-lane-415",
  "evidence_ids": ["EV-…"],
  "unresolved_questions": ["is _wrk_gate enforced for this router in deployment?"]
}
```

### 4. Correcting after an error

Every rejected call returns a structured error. Fix exactly the named field:

```
→ {"error": {"code": "E_HANDLER_MISMATCH", "field": "entry_point", "received": "POST /api/customers/{id}/locations (add_location)", "expected": "exactly the route identity METHOD PATH (POST /api/customers/{customer_id}/locations)", "repairable": true, "aids": {"route": "POST /api/customers/{customer_id}/locations", "required_span": "141-160", "file_length": 212}}}
```

Resubmit with `"entry_point": "POST /api/customers/{customer_id}/locations"`.
Resubmitting the IDENTICAL rejected call ends the session (`E_REPEATED_SUBMISSION`).

If the cited lines are not the sink, call `amend_candidate` ONCE:

```
amend_candidate {"candidate_id": "CAND-…", "path": "backend/app/routers/customers.py", "start_line": 152, "end_line": 156, "reason": "the sink is the ServiceLocation insert, not the customer lookup"}
```

The harness re-resolves and re-binds the citation. The same sink keeps the candidate
identity; a different sink creates a new candidate that supersedes the old one, and
you then verify the new candidate in this session.
