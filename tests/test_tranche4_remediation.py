"""Tranche 4 — remediation & fix verification, adapted to vhlocal's static-only
design: report-only DTOs (no source edited), a patch-safety + isolated-worktree
apply layer, and deterministic validation scoring. The model-backed diff
generation and adversarial validation personas plug into these containers."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import remediation as R  # noqa: E402


class Dtos(unittest.TestCase):
    def _findings(self):
        return [
            {"id": "VULN-001", "title": "SQLi", "cwe": "CWE-89",
             "normalized_cwe": "CWE-89", "severity": "High",
             "location": "db.py:10", "fix": "Use parameterized queries."},
            {"id": "VULN-002", "title": "XSS", "cwe": "CWE-79", "severity": "Medium",
             "location": "v.py:5", "fix": ""},                       # no fix
            {"id": "VULN-003", "title": "dup", "cwe": "CWE-79", "fix": "x",
             "duplicate_of": "VULN-001"},                            # excluded
        ]

    def test_build_dtos_excludes_dupes_and_flags_fix(self):
        dtos = R.build_dtos(self._findings())
        ids = [d["id"] for d in dtos]
        self.assertEqual(ids, ["VULN-001", "VULN-002"])
        self.assertTrue(dtos[0]["has_fix"])
        self.assertFalse(dtos[1]["has_fix"])
        self.assertEqual(dtos[0]["status"], "proposed")
        self.assertIsNone(dtos[0]["diff"])          # report-only

    def test_write_remediation_layout(self):
        d = Path(tempfile.mkdtemp())
        summary = R.write_remediation(d, self._findings())
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["with_fix"], 1)
        dto = json.loads((d / "remediation" / "VULN-001" / "remediate.json").read_text())
        self.assertEqual(dto["cwe"], "CWE-89")
        self.assertTrue((d / "remediation" / "VULN-001" / "summary.md").exists())
        self.assertTrue((d / "remediation" / "index.json").exists())


class Scoring(unittest.TestCase):
    def test_all_pass_is_fixed(self):
        v = R.score_validation({"root_cause_addressed": "pass",
                                "bypass_resistant": "pass", "no_regression": "pass"})
        self.assertEqual(v["verdict"], R.FIXED)
        self.assertEqual(v["score"], 1.0)

    def test_mixed_is_partial(self):
        v = R.score_validation({"root_cause_addressed": "partial",
                                "bypass_resistant": "pass", "no_regression": "fail"})
        self.assertEqual(v["verdict"], R.PARTIALLY_FIXED)

    def test_root_cause_fail_is_not_fixed(self):
        v = R.score_validation({"root_cause_addressed": "fail",
                                "bypass_resistant": "fail", "no_regression": "pass"})
        self.assertEqual(v["verdict"], R.NOT_FIXED)

    def test_too_many_unknown_is_unverifiable(self):
        v = R.score_validation({"root_cause_addressed": "unknown",
                                "bypass_resistant": "unknown", "no_regression": "pass"})
        self.assertEqual(v["verdict"], R.UNVERIFIABLE)
        self.assertIsNone(v["score"])


class PatchSafety(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())

    def test_confined_diff_ok(self):
        diff = "--- a/app/x.py\n+++ b/app/x.py\n@@ -1 +1 @@\n-bad\n+good\n"
        ok, bad = R.patch_confined(diff, self.repo)
        self.assertTrue(ok)
        self.assertEqual(bad, [])

    def test_traversal_diff_refused(self):
        diff = "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n-x\n+y\n"
        ok, bad = R.patch_confined(diff, self.repo)
        self.assertFalse(ok)
        self.assertIn("../../etc/passwd", bad)

    def test_absolute_path_refused(self):
        diff = "--- a//etc/shadow\n+++ b//etc/shadow\n@@ -1 +1 @@\n-x\n+y\n"
        ok, bad = R.patch_confined(diff, self.repo)
        self.assertFalse(ok)

    def test_apply_in_worktree_isolates(self):
        repo = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (repo / "app").mkdir()
        (repo / "app" / "x.py").write_text("bad\n", encoding="utf-8")
        diff = "--- a/app/x.py\n+++ b/app/x.py\n@@ -1 +1 @@\n-bad\n+good\n"
        res = R.apply_in_worktree(repo, diff)
        self.assertTrue(res["applied"])
        # the worktree copy changed; the user's repo did NOT
        self.assertEqual((repo / "app" / "x.py").read_text().strip(), "bad")
        self.assertEqual(
            (Path(res["worktree"]) / "app" / "x.py").read_text().strip(), "good")

    def test_apply_refuses_traversal_before_touching_disk(self):
        repo = Path(tempfile.mkdtemp())
        diff = "--- a/../evil\n+++ b/../evil\n@@ -1 +1 @@\n-x\n+y\n"
        res = R.apply_in_worktree(repo, diff)
        self.assertFalse(res["applied"])
        self.assertIn("escape", res["message"])


if __name__ == "__main__":
    unittest.main()
