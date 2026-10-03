# grouping — remediation-group fixture (feature 015, T004)

`supported_findings.json` holds the 31 **supported**, non-duplicate findings from the sanitized live run
(`testdata/replay-171`) in the families the audit saw repeated, plus negative controls. `repo` points at
`testdata/replay-171/target` (stub tree whose cited lines carry the evidence quotes).

Positive groups (same family, same sink anchor in `backend/app/dispatch_operations.py`, several entry points):

| Family | Findings | Anchor lines |
|---|---|---|
| CWE-79 XSS | 5 | 84–88 |
| CWE-943 NoSQL injection | 3 | 128–134 |
| CWE-611 XXE | 3 | 155–160 |
| CWE-502 insecure deserialization (pickle) | 2 | 52–62 |
| CWE-601 open redirect | 3 | 37–40 |
| CWE-22 path traversal | 3 | 68–72 and 114–119 (two anchors → two groups) |

Negative controls:

- `dispatch_operations.py:128-134` is cited by **both** CWE-284 and CWE-943 findings — same location,
  different family → must stay separate groups.
- CWE-284 broken access control: 10 findings across distinct handlers/files (`customers.py`, `jobs.py`,
  `users.py`, `workers.py`, `io_csv.py`) — same family, different anchors and fixes → separate groups (at most
  `suggested` when in the same file with a compatible fix).
- CWE-90 (LDAP) at 130–134 vs CWE-943 at 131–133 — overlapping ranges, different families → separate.

Expected: raw supported 31; every finding in exactly one group; group ids stable across regeneration.
