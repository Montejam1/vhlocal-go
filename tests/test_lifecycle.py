"""Cross-run finding lifecycle (Mode A): prior-report discovery, new/persisting/
regressed/fixed labelling, and the fixed-key carry-forward that makes regression
detection work on the following run. Reconciliation must be deterministic and
never depend on line numbers or a sibling-CWE relabel."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.consolidate import (  # noqa: E402
    Finding,
    apply_knowledge,
    apply_normalized_severity,
    flag_duplicates,
)
from vhlocal.lifecycle import (  # noqa: E402
    find_prior_report,
    git_provenance,
    prior_hotspots_markdown,
    reconcile,
)


def _prep(findings):
    """Run the same enrichment a real report does, so root_cause_key is set."""
    flag_duplicates(findings)
    apply_knowledge(findings)
    apply_normalized_severity(findings)
    return findings


def _F(fid, cwe, loc, title):
    return Finding(id=fid, cwe=cwe, location=loc, title=title)


class _Harness(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.repo = str(self.base / "repo")
        Path(self.repo).mkdir()

    def _write_report(self, name, started, findings, commit="", lifecycle=None):
        d = self.base / name
        d.mkdir()
        (d / "scan_meta.json").write_text(json.dumps(
            {"repo": self.repo, "started_at": started, "git_commit": commit}))
        (d / "findings.json").write_text(json.dumps({
            "meta": {"repo": self.repo, "started_at": started, "git_commit": commit},
            "lifecycle": lifecycle or {"fixed_keys": []},
            "findings": [f.to_dict() for f in findings],
        }))
        return d

    def _reconcile(self, findings, started, commit=""):
        return reconcile(
            findings, self.base / "current",
            {"repo": self.repo, "started_at": started, "git_commit": commit},
            reports_dir=self.base)


class TestPriorDiscovery(_Harness):
    def test_no_prior_is_baseline(self):
        cur = _prep([_F("V1", "CWE-89", "app/a.py:1", "SQLi")])
        lc = self._reconcile(cur, 1000)
        self.assertFalse(lc["has_prior"])
        self.assertEqual(cur[0].finding_lifecycle, "")

    def test_picks_most_recent_earlier_same_repo(self):
        self._write_report("old", 500, _prep([_F("V1", "CWE-89", "app/a.py:1", "x")]))
        self._write_report("recent", 900, _prep([_F("V9", "CWE-22", "app/b.py:1", "y")]))
        # A later report must never be treated as "prior".
        self._write_report("future", 5000, _prep([_F("V5", "CWE-79", "app/c.py:1", "z")]))
        got = find_prior_report(self.base / "current", self.repo, 1000,
                                reports_dir=self.base)
        self.assertIsNotNone(got)
        self.assertEqual(got[0].name, "recent")

    def test_cancelled_scan_is_not_a_baseline(self):
        self._write_report("completed", 500, [])
        bad = self._write_report("cancelled", 900, [])
        data = json.loads((bad / "findings.json").read_text())
        data["run_status"] = {"execution_status": "cancelled"}
        (bad / "findings.json").write_text(json.dumps(data))
        got = find_prior_report(self.base / "current", self.repo, 1000, reports_dir=self.base)
        self.assertEqual(got[0].name, "completed")

    def test_identity_migration_does_not_claim_disappearance(self):
        self._write_report("legacy", 500, [_F("V1", "CWE-94", "a.py:2", "eval")])
        current = _F("CAND-one", "CWE-94", "a.py:2", "eval")
        current.stable_identity = "source-digest"
        result = self._reconcile([current], 1000)
        self.assertEqual(result["comparison_status"], "identity_schema_changed")
        self.assertEqual(result["not_observed"], 0)
        self.assertEqual(result["new"], 0)

    def test_different_repo_not_matched(self):
        d = self.base / "other"
        d.mkdir()
        (d / "scan_meta.json").write_text(json.dumps(
            {"repo": "/some/other/repo", "started_at": 500}))
        (d / "findings.json").write_text(json.dumps(
            {"meta": {"repo": "/some/other/repo"}, "findings": []}))
        got = find_prior_report(self.base / "current", self.repo, 1000,
                                reports_dir=self.base)
        self.assertIsNone(got)


class TestReconcile(_Harness):
    def test_new_persisting_fixed(self):
        prior = _prep([_F("V1", "CWE-89", "app/search.py:42", "SQLi"),
                       _F("V2", "CWE-502", "app/cache.py:88", "deser")])
        self._write_report("run1", 1000, prior)
        # SQLi persists (line drifted), deser gone, new path traversal.
        cur = _prep([_F("V1", "CWE-89", "app/search.py:47", "SQLi"),
                     _F("V3", "CWE-22", "app/files.py:5", "path")])
        lc = self._reconcile(cur, 2000)
        self.assertTrue(lc["has_prior"])
        self.assertEqual((lc["new"], lc["persisting"], lc["fixed"]), (1, 1, 1))
        by = {f.id: f.finding_lifecycle for f in cur}
        self.assertEqual(by["V1"], "persisting")   # survived a 5-line drift
        self.assertEqual(by["V3"], "new")
        self.assertEqual([f["id"] for f in lc["fixed_findings"]], ["V2"])
        # Canonical fields mirror the deprecated ones (audit-2 integration): a
        # disappearance is "not observed", not proven "fixed".
        self.assertEqual(lc["not_observed"], lc["fixed"])
        self.assertEqual(lc["reappeared"], lc["regressed"])
        self.assertEqual([f["id"] for f in lc["not_observed_findings"]], ["V2"])
        self.assertIn("DEPRECATED", lc["terminology"])

    def test_sibling_cwe_relabel_still_persists(self):
        # Same access-control defect, relabelled CWE-863 -> CWE-284 next run.
        self._write_report("run1", 1000,
                           _prep([_F("V1", "CWE-863", "app/authz.py:10", "IDOR")]))
        cur = _prep([_F("V1", "CWE-284", "app/authz.py:10", "IDOR")])
        lc = self._reconcile(cur, 2000)
        self.assertEqual(cur[0].finding_lifecycle, "persisting")
        self.assertEqual(lc["persisting"], 1)

    def test_regression_via_prior_fixed_keys(self):
        r1 = _prep([_F("V1", "CWE-89", "app/s.py:1", "SQLi"),
                    _F("V2", "CWE-502", "app/c.py:1", "deser")])
        self._write_report("run1", 1000, r1)
        # run2: deser fixed.
        cur2 = _prep([_F("V1", "CWE-89", "app/s.py:1", "SQLi")])
        lc2 = self._reconcile(cur2, 2000)
        self.assertEqual(lc2["fixed"], 1)
        self._write_report("run2", 2000, cur2, lifecycle=lc2)
        # run3: deser returns -> regressed (run2 recorded it fixed).
        cur3 = _prep([_F("V1", "CWE-89", "app/s.py:1", "SQLi"),
                      _F("V2", "CWE-502", "app/c.py:3", "deser")])
        lc3 = self._reconcile(cur3, 3000)
        by = {f.id: f.finding_lifecycle for f in cur3}
        self.assertEqual(by["V2"], "regressed")
        self.assertEqual(lc3["regressed"], 1)
        # V2 is present again, so it is no longer carried as a fixed key.
        self.assertEqual(lc3["fixed_keys"], [])

    def test_fixed_key_persists_while_still_absent(self):
        r1 = _prep([_F("V2", "CWE-502", "app/c.py:1", "deser")])
        self._write_report("run1", 1000, r1)
        cur2 = _prep([_F("V1", "CWE-89", "app/s.py:1", "SQLi")])   # deser fixed
        lc2 = self._reconcile(cur2, 2000)
        self._write_report("run2", 2000, cur2, lifecycle=lc2)
        # run3 still without deser: it stays a carried fixed key.
        cur3 = _prep([_F("V1", "CWE-89", "app/s.py:1", "SQLi")])
        lc3 = self._reconcile(cur3, 3000)
        self.assertEqual(len(lc3["fixed_keys"]), 1)


class TestSeedMode(_Harness):
    def test_no_prior_seed_is_empty(self):
        md, name = prior_hotspots_markdown(
            self.base / "current", self.repo, 1000, reports_dir=self.base)
        self.assertEqual((md, name), ("", ""))

    def test_seed_lists_located_findings_only(self):
        r1 = _prep([_F("V1", "CWE-89", "app/search.py:42", "SQLi in q"),
                    _F("V2", "CWE-502", "app/cache.py:88", "deser"),
                    _F("V3", "CWE-22", "", "orphan-no-loc-finding")])
        self._write_report("run1", 1000, r1)
        md, name = prior_hotspots_markdown(
            self.base / "current", self.repo, 2000, reports_dir=self.base)
        self.assertEqual(name, "run1")
        # Framed as leads to re-verify, never confirmed.
        self.assertIn("independently re-verify", md.lower())
        self.assertIn("app/search.py:42", md)
        self.assertIn("app/cache.py:88", md)
        # The location-less finding is skipped, and that is disclosed.
        self.assertNotIn("orphan-no-loc-finding", md)
        self.assertIn("2 of 3", md)

    def test_seed_uses_canonical_family_name(self):
        self._write_report("run1", 1000,
                           _prep([_F("V1", "CWE-639", "app/authz.py:10", "IDOR")]))
        md, _ = prior_hotspots_markdown(
            self.base / "current", self.repo, 2000, reports_dir=self.base)
        self.assertIn("Broken Access Control", md)


class TestSeededCaveat(_Harness):
    def _run_dir(self):
        from vhlocal.consolidate import write_consolidated
        d = self.base / "repo-run-9000"
        d.mkdir()
        (d / "scan_meta.json").write_text(json.dumps({
            "repo": self.repo, "started_at": 9000, "finished_at": 9010,
            "model": "gpt-oss:120b", "seeded_from_prior": "repo-run-1000"}))
        (d / "README.md").write_text(
            "# R\n\n| ID | Title | CWE | Severity |\n|---|---|---|---|\n"
            "| VULN-001 | SQLi | CWE-89 | High |\n")
        write_consolidated(d)
        return d

    def test_caveat_in_markdown_and_html(self):
        d = self._run_dir()
        md = (d / "SCAN_REPORT.md").read_text()
        html = (d / "SCAN_REPORT.html").read_text()
        self.assertIn("Seeded run (Mode B)", md)
        self.assertIn("not an independent sample", md)
        self.assertIn("Seeded run (Mode B)", html)
        self.assertIn("repo-run-1000", md)


class TestGitProvenance(_Harness):
    def test_non_git_dir_is_empty(self):
        prov = git_provenance(Path(self.repo))
        self.assertEqual(prov["git_commit"], "")
        self.assertFalse(prov["git_dirty"])


if __name__ == "__main__":
    unittest.main()
