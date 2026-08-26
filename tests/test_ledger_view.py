"""The ledger-view backend (list_ledgers / load_ledger) powers the UI's per-
application vulnerability-ledger page: it rolls each persisted target ledger up
to headline numbers and serves the full finding list by a path-safe slug."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import membank as M  # noqa: E402


def _write_ledger(dir_, slug, target, findings, runs, updated):
    (Path(dir_) / (slug + ".json")).write_text(json.dumps({
        "target": target, "updated": updated,
        "runs_recorded": runs, "findings": findings,
    }), encoding="utf-8")


class LedgerView(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._prev = os.environ.get("VHLOCAL_LEDGER_DIR")
        os.environ["VHLOCAL_LEDGER_DIR"] = self.dir

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("VHLOCAL_LEDGER_DIR", None)
        else:
            os.environ["VHLOCAL_LEDGER_DIR"] = self._prev

    def _sample(self):
        return [
            {"key": "k1", "title": "SQLi in search", "canonical_cwe": "CWE-89",
             "severity": "High", "location": "s.py:10", "status": "open",
             "confidence": "reliable", "confirmed_count": 3, "cross_family": True},
            {"key": "k2", "title": "IDOR on orders", "canonical_cwe": "CWE-639",
             "severity": "Medium", "location": "o.py:20", "status": "regressed",
             "confidence": "provisional", "confirmed_count": 1},
            {"key": "k3", "title": "Old XSS", "canonical_cwe": "CWE-79",
             "severity": "Low", "location": "x.py:5", "status": "fixed",
             "confidence": "provisional", "confirmed_count": 2},
        ]

    def test_list_empty_when_no_dir(self):
        os.environ["VHLOCAL_LEDGER_DIR"] = str(Path(self.dir) / "does-not-exist")
        self.assertEqual(M.list_ledgers(), [])

    def test_list_summarizes(self):
        _write_ledger(self.dir, "app-abcd1234", "/repos/app",
                      self._sample(), ["r1", "r2"], 1000.0)
        ls = M.list_ledgers()
        self.assertEqual(len(ls), 1)
        s = ls[0]
        self.assertEqual(s["slug"], "app-abcd1234")
        self.assertEqual(s["target_name"], "app")
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["open"], 1)
        self.assertEqual(s["fixed"], 1)
        self.assertEqual(s["regressed"], 1)
        self.assertEqual(s["reliable"], 1)
        self.assertEqual(s["runs_recorded"], 2)
        self.assertEqual(s["by_severity"], {"High": 1, "Medium": 1, "Low": 1})

    def test_list_sorted_newest_first(self):
        _write_ledger(self.dir, "old-1111", "/repos/old", [], [], 100.0)
        _write_ledger(self.dir, "new-2222", "/repos/new", [], [], 900.0)
        slugs = [s["slug"] for s in M.list_ledgers()]
        self.assertEqual(slugs, ["new-2222", "old-1111"])

    def test_load_by_slug(self):
        _write_ledger(self.dir, "app-abcd1234", "/repos/app",
                      self._sample(), ["r1"], 1000.0)
        led = M.load_ledger("app-abcd1234")
        self.assertIsNotNone(led)
        self.assertEqual(led["slug"], "app-abcd1234")
        self.assertEqual(len(led["findings"]), 3)
        self.assertEqual(led["summary"]["total"], 3)
        self.assertEqual(led["summary"]["target_name"], "app")

    def test_load_unknown_slug_is_none(self):
        self.assertIsNone(M.load_ledger("nope"))

    def test_load_traversal_is_none(self):
        # A slug is matched against the enumerated directory, never joined to a
        # path — traversal attempts simply do not match any stem.
        _write_ledger(self.dir, "app-abcd1234", "/repos/app", [], [], 1.0)
        self.assertIsNone(M.load_ledger("../../etc/passwd"))
        self.assertIsNone(M.load_ledger("..%2f..%2fapp-abcd1234"))

    def test_unknown_target_name(self):
        _write_ledger(self.dir, "blank-0000", "", [], [], 1.0)
        self.assertEqual(M.list_ledgers()[0]["target_name"], "(unknown target)")


if __name__ == "__main__":
    unittest.main()
