"""Per-target vulnerability ledger (membank). The ledger is the honest coverage
of a codebase: the union of confirmed findings across every opted-in run, deduped
by a stable cross-run key. These tests pin the properties the design depends on —
key stability/distinctness, idempotent merges, confidence tiers that resist a
lenient verify, and the recall summary that scores each run against the union."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.consolidate import (  # noqa: E402
    CLASS_STATICALLY_SUPPORTED,
    Finding,
    apply_knowledge,
    apply_normalized_severity,
    flag_duplicates,
)
from vhlocal import membank  # noqa: E402


def _prep(findings):
    """Run the enrichment a real report does, so root_cause_key is populated —
    that is the field ledger_key parses."""
    flag_duplicates(findings)
    apply_knowledge(findings)
    apply_normalized_severity(findings)
    return findings


def _F(fid, cwe, loc, title, data_flow=""):
    # Ledger findings are substantiated by definition — only non-hypothesis
    # candidates enter the ledger (a hypothesis is not a tracked vulnerability).
    return Finding(id=fid, cwe=cwe, location=loc, title=title, data_flow=data_flow,
                   classification=CLASS_STATICALLY_SUPPORTED)


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._prev = os.environ.get("VHLOCAL_LEDGER_DIR")
        os.environ["VHLOCAL_LEDGER_DIR"] = self._tmp.name
        self.repo = "/code/acme-shop"

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("VHLOCAL_LEDGER_DIR", None)
        else:
            os.environ["VHLOCAL_LEDGER_DIR"] = self._prev
        self._tmp.cleanup()

    def _meta(self, model="gpt-oss:120b", verify="", when=1000.0):
        return {"repo": self.repo, "model": model,
                "verify_model": verify, "finished_at": when}


class LedgerKey(_Base):
    def test_two_sinks_same_file_are_distinct(self):
        # eval() and render() in one module are different bugs — must not merge.
        ev = _F("V1", "CWE-94", "app/views.py:10", "eval injection",
                "request.body -> eval(code)")
        ss = _F("V2", "CWE-94", "app/views.py:55", "SSTI",
                "request.name -> render(tmpl)")
        _prep([ev, ss])
        self.assertNotEqual(membank.ledger_key(ev), membank.ledger_key(ss))

    def test_sink_key_ignores_line_drift(self):
        # Same sink, different line across runs — one identity, not two.
        a = _F("V1", "CWE-89", "db/users.py:20", "SQLi", "q -> execute(sql)")
        b = _F("V1", "CWE-89", "db/users.py:140", "SQLi", "q -> execute(sql)")
        _prep([a]); _prep([b])
        self.assertEqual(membank.ledger_key(a), membank.ledger_key(b))

    def test_colocated_logic_findings_stay_distinct(self):
        # No syntactic sink -> raw-CWE + line bucket keeps a ledger-manip bug and
        # an IDOR apart even though both normalize to the CWE-284 family.
        auth = _F("V1", "CWE-285", "app/auth.py:42", "improper authorization")
        idor = _F("V2", "CWE-639", "app/auth.py:44", "IDOR")
        _prep([auth, idor])
        self.assertNotEqual(membank.ledger_key(auth), membank.ledger_key(idor))


class Merge(_Base):
    def test_idempotent_by_run_id(self):
        f = _F("V1", "CWE-89", "db/users.py:20", "SQLi", "q -> execute(sql)")
        _prep([f])
        rd = Path("/results/run-alpha")
        s1 = membank.update_ledger(rd, [f], self._meta())
        s2 = membank.update_ledger(rd, [f], self._meta())
        self.assertEqual(s1["runs_recorded"], 1)
        self.assertEqual(s2["runs_recorded"], 1)   # same run never double-counts
        self.assertEqual(s2["total_known"], 1)

    def test_union_grows_across_runs(self):
        a = _F("V1", "CWE-89", "db/users.py:20", "SQLi", "q -> execute(sql)")
        b = _F("V2", "CWE-79", "app/views.py:9", "XSS", "name -> render(tmpl)")
        _prep([a]); _prep([b])
        membank.update_ledger(Path("/r/run1"), [a], self._meta(when=1))
        s = membank.update_ledger(Path("/r/run2"), [b], self._meta(when=2))
        self.assertEqual(s["runs_recorded"], 2)
        self.assertEqual(s["total_known"], 2)   # union of both runs
        self.assertEqual(s["found"], 1)         # run2 found only its own
        self.assertEqual(s["new"], 1)

    def test_duplicates_excluded_from_merge(self):
        a = _F("V1", "CWE-89", "db/users.py:20", "SQLi", "q -> execute(sql)")
        dup = _F("V2", "CWE-89", "db/users.py:22", "SQLi dup", "q -> execute(sql)")
        _prep([a, dup])   # flag_duplicates marks the co-located twin
        self.assertTrue(a.duplicate_of or dup.duplicate_of)
        s = membank.update_ledger(Path("/r/run1"), [a, dup], self._meta())
        self.assertEqual(s["total_known"], 1)


class Confidence(_Base):
    def _entry_conf(self):
        led = membank._load(self.repo)
        return led["findings"][0]["confidence"]

    def test_tiers_escalate_with_run_count(self):
        def one():
            return _prep([_F("V1", "CWE-89", "db/u.py:20", "SQLi",
                             "q -> execute(sql)")])
        membank.update_ledger(Path("/r/r1"), one(), self._meta(when=1))
        self.assertEqual(self._entry_conf(), "provisional")
        membank.update_ledger(Path("/r/r2"), one(), self._meta(when=2))
        self.assertEqual(self._entry_conf(), "confirmed")
        membank.update_ledger(Path("/r/r3"), one(), self._meta(when=3))
        self.assertEqual(self._entry_conf(), "reliable")

    def test_cross_family_single_run_is_confirmed(self):
        # A find corroborated by a different-provider verify counts more than a
        # single same-family sighting — provisional would let it pollute quietly.
        f = _prep([_F("V1", "CWE-89", "db/u.py:20", "SQLi", "q -> execute(sql)")])
        membank.update_ledger(Path("/r/r1"), f,
                              self._meta(model="gpt-oss:120b", verify="glm-4.6"))
        self.assertEqual(self._entry_conf(), "confirmed")

    def test_same_family_verify_is_not_cross_family(self):
        f = _prep([_F("V1", "CWE-89", "db/u.py:20", "SQLi", "q -> execute(sql)")])
        membank.update_ledger(Path("/r/r1"), f,
                              self._meta(model="gpt-oss:120b", verify="gpt-oss:20b"))
        self.assertEqual(self._entry_conf(), "provisional")


class Coverage(_Base):
    def test_recall_and_missed(self):
        a = _F("V1", "CWE-89", "db/users.py:20", "SQLi", "q -> execute(sql)")
        b = _F("V2", "CWE-79", "app/views.py:9", "XSS", "name -> render(tmpl)")
        _prep([a]); _prep([b])
        membank.update_ledger(Path("/r/run1"), [a, b], self._meta(when=1))
        # run2 reproduces only the SQLi
        a2 = _F("V1", "CWE-89", "db/users.py:33", "SQLi", "q -> execute(sql)")
        _prep([a2])
        s = membank.update_ledger(Path("/r/run2"), [a2], self._meta(when=2))
        self.assertEqual(s["open_known"], 2)
        self.assertEqual(s["found"], 1)
        self.assertEqual(s["recall_pct"], 50)
        self.assertEqual(s["missed_count"], 1)
        titles = [m["title"] for m in s["missed"]]
        self.assertIn("XSS", titles)

    def test_regression_reopens_fixed(self):
        f = _prep([_F("V1", "CWE-89", "db/u.py:20", "SQLi", "q -> execute(sql)")])
        membank.update_ledger(Path("/r/r1"), f, self._meta(when=1))
        # mark it fixed in the persisted ledger, then a later run finds it again
        led = membank._load(self.repo)
        led["findings"][0]["status"] = "fixed"
        membank._save(self.repo, led)
        f2 = _prep([_F("V1", "CWE-89", "db/u.py:24", "SQLi", "q -> execute(sql)")])
        membank.update_ledger(Path("/r/r2"), f2, self._meta(when=2))
        led = membank._load(self.repo)
        self.assertEqual(led["findings"][0]["status"], "regressed")


if __name__ == "__main__":
    unittest.main()
