# benchmark — seeded efficacy corpus (feature 015, T005)

`target/` is the scanned tree: Python (Flask `pysvc/app.py`), Go (`gosvc/main.go`), JavaScript (Express
`web/server.js`). Each seeded issue lives in one function and has a **safe control** sibling in the same
file (e.g. `search_orders` vs `get_order`). Families: sql-injection, path-traversal, deserialization,
access-control, command-injection, ssrf, xss, code-injection.

`truth/ground_truth.json` (version 2) names anchors, root causes, expected outcome and acceptable matches. It
is **outside `target/`** and must never be copied there or into a prompt (scenario 7 asserts prompt records
contain no truth id). `baseline/` holds frozen baselines; `POLICY.md` defines regression relative to them.

Nothing here is executed — the corpus is static source for the scanner and the scorer.
