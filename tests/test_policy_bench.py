"""Frozen-candidate policy replay (audit P2 #8): one candidate set through every
policy, so the only variable is the reporting threshold — not the hunt or infra."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import policy_bench  # noqa: E402


def _run(sg_body, source):
    d = Path(tempfile.mkdtemp())
    repo = Path(tempfile.mkdtemp())
    for rel, body in source.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    (d / "results").mkdir()
    (d / "results" / "sg-1_inj.md").write_text(sg_body, encoding="utf-8")
    (d / "scan_meta.json").write_text(
        json.dumps({"repo": str(repo), "git_commit": "rev1"}), encoding="utf-8")
    return d, repo


SG = (
    "#### [VULN-001] SQL injection in q\n- **Class**: CWE-89\n"
    "- **Location**: `app/db.py:2`\n- **Severity**: High\n"
    "- **Data Flow**: `u` query param -> `cur.execute(sql)` (line 2)\n\n"
    "#### [VULN-002] SSRF via webhook url\n- **Class**: CWE-918\n"
    "- **Location**: `app/db.py:2`\n- **Severity**: High\n"
    "- **Data Flow**: `payload` -> `find_one(query)` (line 2)\n"
)
SOURCE = {"app/db.py": "def q(u):\n    cur.execute('SELECT ' + u)  # find_one here too\n"}


class Replay(unittest.TestCase):
    def test_same_candidates_yield_is_monotonic(self):
        d, _repo = _run(SG, SOURCE)
        rep = policy_bench.replay(d)
        by = {p["policy"]: p for p in rep["policies"]}
        # Same frozen candidate set for every policy.
        counts = {p["policy"]: p["candidates"] for p in rep["policies"]}
        self.assertEqual(len(set(counts.values())), 1)
        # Substantiated yield never increases as the bar rises.
        self.assertGreaterEqual(by["lenient"]["substantiated"], by["balanced"]["substantiated"])
        self.assertGreaterEqual(by["balanced"]["substantiated"], by["strict"]["substantiated"])

    def test_ssrf_over_a_mongo_source_is_not_substantiated(self):
        # The frozen set includes a mislabeled SSRF whose source is a Mongo call —
        # it must not be substantiated at balanced/strict under the fixed checker.
        d, _repo = _run(SG, SOURCE)
        rep = policy_bench.replay(d)
        by = {p["policy"]: p for p in rep["policies"]}
        # Only the genuine SQLi should substantiate at balanced.
        self.assertEqual(by["balanced"]["substantiated"], 1)

    def test_known_defect_recall_scored(self):
        d, _repo = _run(SG, SOURCE)
        known = [{"cwe": "CWE-89", "file": "app/db.py", "line": 2},   # present
                 {"cwe": "CWE-611", "file": "app/xml.py", "line": 9}]  # absent
        rep = policy_bench.replay(d, known_defects=known)
        bal = {p["policy"]: p for p in rep["policies"]}["balanced"]
        self.assertEqual(bal["known_defects_total"], 2)
        self.assertEqual(bal["known_defects_substantiated"], 1)   # SQLi found, XXE not
        self.assertEqual(bal["known_defects_recall_pct"], 50)

    def test_render_is_stable(self):
        d, _repo = _run(SG, SOURCE)
        out = policy_bench.render(policy_bench.replay(d))
        self.assertIn("frozen candidate set", out)
        self.assertIn("| strict |", out)


if __name__ == "__main__":
    unittest.main()
