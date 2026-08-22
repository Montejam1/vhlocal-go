"""Deterministic Phase 3d sweep.

Replaces the model's iterative (often redundant) grepping with a direct,
complete, language-scoped sweep. Guards the properties that make it a net
quality gain: semantic-sibling coverage via the CWE table, language scoping so a
Python NoSQL `.find(` does not match JS `array.find(`, and honesty about
logic/authorization CWEs that have no syntactic sink.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.consolidate import Finding  # noqa: E402
from vhlocal.sweep import (  # noqa: E402
    patterns_for,
    render_sweep,
    run_phase3d_sweep,
    sweep_findings,
    _lang_glob,
)


def _repo(files):
    d = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return d


class TestPatterns(unittest.TestCase):
    def test_cwe_semantic_siblings(self):
        # CWE-94 code injection sweeps eval AND exec AND compile.
        pats, note = patterns_for("CWE-94", "", "eval of expr")
        joined = " ".join(pats)
        self.assertIn("eval", joined)
        self.assertIn("exec", joined)
        self.assertEqual(note, "")

    def test_deserialization_siblings(self):
        pats, _ = patterns_for("CWE-502", "raw -> pickle.loads(raw)", "pickle")
        j = " ".join(pats)
        self.assertIn("pickle", j)
        self.assertIn("yaml", j)      # semantic sibling from the table

    def test_logic_cwe_has_no_pattern(self):
        pats, note = patterns_for("CWE-639", "", "IDOR")
        self.assertEqual(pats, [])
        self.assertIn("authorization", note.lower())

    def test_pattern_extracted_from_dataflow(self):
        # An unusual sink named in the data flow is still swept.
        pats, _ = patterns_for("CWE-000", "input -> dangerous_render(input)", "x")
        self.assertTrue(any("dangerous_render" in p for p in pats))


class TestLangGlob(unittest.TestCase):
    def test_python_scopes_to_py(self):
        self.assertEqual(_lang_glob("app/x.py:12"), "*.py")

    def test_ts_family(self):
        self.assertIn("tsx", _lang_glob("web/a.tsx:5"))


class TestSweep(unittest.TestCase):
    def test_finds_extra_instances_same_language(self):
        repo = _repo({
            "backend/a.py": "def f(raw):\n    return eval(raw)\n",
            "backend/b.py": "def g(x):\n    return eval(x)\n",   # extra instance
            "frontend/c.tsx": "const y = evaluate(z)\n",          # different lang
        })
        f = Finding(id="VULN-001", title="eval inj", cwe="CWE-94",
                    location="backend/a.py:2", data_flow="raw -> eval(raw)")
        sweeps = sweep_findings(repo, [f])
        files = {i.file for i in sweeps[0].instances}
        self.assertIn("backend/a.py", files)
        self.assertIn("backend/b.py", files)          # the extra instance
        self.assertNotIn("frontend/c.tsx", files)     # language-scoped out

    def test_nosql_find_not_matching_js_array_find(self):
        repo = _repo({
            "backend/db.py": "col.find_one(query)\n",
            "frontend/list.tsx": "const w = workers.find((x) => x.id === id)\n",
        })
        f = Finding(id="VULN-006", title="NoSQL inj", cwe="CWE-943",
                    location="backend/db.py:1", data_flow="q -> col.find_one(q)")
        sweeps = sweep_findings(repo, [f])
        files = {i.file for i in sweeps[0].instances}
        self.assertIn("backend/db.py", files)
        self.assertNotIn("frontend/list.tsx", files)   # the false-positive we fixed

    def test_test_files_excluded(self):
        repo = _repo({
            "backend/a.py": "eval(x)\n",
            "backend/tests/test_a.py": "eval(y)\n",
        })
        f = Finding(id="V1", cwe="CWE-94", location="backend/a.py:1", title="e")
        files = {i.file for i in sweep_findings(repo, [f])[0].instances}
        self.assertNotIn("backend/tests/test_a.py", files)

    def test_run_writes_phase3d_output(self):
        import json
        repo = _repo({"backend/a.py": "eval(x)\nexec(y)\n"})
        results = Path(tempfile.mkdtemp())
        (results / "phase3_output.md").write_text(
            "## VULN Assignment Table\n| VULN-NNN | # | Title | Severity |\n"
            "|---|---|---|---|\n| VULN-001 | 1 | eval inj (CWE-94) | High |\n",
            encoding="utf-8")
        # give it a location via a README detail so parse_findings has a finding
        out = run_phase3d_sweep(results, repo)
        self.assertIsNotNone(out)
        self.assertTrue(out.exists())
        self.assertIn("instance", out.read_text(encoding="utf-8").lower())


if __name__ == "__main__":
    unittest.main()
