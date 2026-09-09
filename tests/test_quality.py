"""Pre-report quality battery — corroborating a candidate against the real source.

These lock in the "happy medium": metadata completeness alone never publishes a
finding; a sink claim must be backed by a matching sink in the cited source (or,
for logic classes, by a described flow + a precise location + agreement), at a
strictness the operator sets."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import quality  # noqa: E402
from vhlocal.consolidate import Finding  # noqa: E402


def _repo(files):
    d = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return d


# A file whose cited line genuinely executes a SQL query, and one that does not.
_REPO = {
    "app/db.py": "def q(u):\n    cur.execute('SELECT * FROM t WHERE u=' + u)\n    return cur\n",
    "app/util.py": "def helper(x):\n    return x + 1\n",
}


class SourceCorroboration(unittest.TestCase):
    def setUp(self):
        self.repo = _repo(_REPO)

    def _cls(self, f, level):
        q = quality.evaluate(f, self.repo, level)
        return q.substantiated

    def test_sink_present_is_substantiated_everywhere(self):
        f = Finding(id="V1", title="SQL injection in q", cwe="CWE-89",
                    location="app/db.py:2", data_flow="u -> execute(sql)")
        for level in quality.LEVELS:
            self.assertTrue(self._cls(f, level), level)

    def test_sink_absent_demotes_at_balanced_and_strict(self):
        # The cited line has no query — a checked-and-absent sink. Balanced/strict
        # demote to hypothesis; lenient still needs *some* signal.
        f = Finding(id="V1", title="SQL injection somewhere", cwe="CWE-89",
                    location="app/util.py:1")
        self.assertFalse(self._cls(f, quality.LENIENT))    # no flow/agreement either
        self.assertFalse(self._cls(f, quality.BALANCED))
        self.assertFalse(self._cls(f, quality.STRICT))

    def test_lenient_accepts_flow_when_source_absent(self):
        # Same absent-sink finding, but now with a described flow + agreement.
        # Lenient publishes on that alone; balanced/strict still demand the source.
        f = Finding(id="V1", title="SQL injection via search", cwe="CWE-89",
                    location="app/util.py:1", data_flow="req.q -> execute(query)",
                    from_confirmed=True)
        self.assertTrue(self._cls(f, quality.LENIENT))
        self.assertFalse(self._cls(f, quality.BALANCED))
        self.assertFalse(self._cls(f, quality.STRICT))

    def test_strict_needs_a_second_signal_beyond_the_sink(self):
        # Source sink present but no flow and no agreement: balanced accepts,
        # strict does not.
        f = Finding(id="V1", title="SQL injection in q", cwe="CWE-89",
                    location="app/db.py:2")
        self.assertTrue(self._cls(f, quality.BALANCED))
        self.assertFalse(self._cls(f, quality.STRICT))


class LogicClasses(unittest.TestCase):
    """IDOR/authz/TOCTOU have no syntactic sink — corroborated by flow + a precise
    location + agreement, never by a source pattern."""

    def setUp(self):
        self.repo = _repo(_REPO)

    def test_idor_with_flow_precise_and_agreement_is_supported(self):
        f = Finding(id="V1", title="IDOR on GET /users/{id}", cwe="CWE-639",
                    location="app/db.py:2", data_flow="id -> record without owner check",
                    from_confirmed=True)
        for level in quality.LEVELS:
            self.assertTrue(quality.evaluate(f, self.repo, level).substantiated, level)

    def test_idor_without_agreement_is_hypothesis_at_balanced(self):
        f = Finding(id="V1", title="IDOR on GET /users/{id}", cwe="CWE-639",
                    location="app/db.py:2", data_flow="id -> record without owner check")
        # No votes, not confirmed: lenient still accepts (flow is a signal), but
        # balanced/strict require agreement for a logic class.
        self.assertTrue(quality.evaluate(f, self.repo, quality.LENIENT).substantiated)
        self.assertFalse(quality.evaluate(f, self.repo, quality.BALANCED).substantiated)

    def test_idor_without_precise_location_is_hypothesis(self):
        f = Finding(id="V1", title="IDOR somewhere in users", cwe="CWE-639",
                    location="app/db.py", data_flow="id -> record without owner check",
                    from_confirmed=True)
        self.assertFalse(quality.evaluate(f, self.repo, quality.BALANCED).substantiated)

    def test_votes_satisfy_agreement(self):
        f = Finding(id="V1", title="IDOR on GET /users/{id}", cwe="CWE-639",
                    location="app/db.py:2", data_flow="id -> record without owner check",
                    votes=3, vote_samples=5)
        self.assertTrue(quality.evaluate(f, self.repo, quality.BALANCED).substantiated)


class StructuralFloor(unittest.TestCase):
    def setUp(self):
        self.repo = _repo(_REPO)

    def test_missing_cwe_is_hypothesis_at_every_level(self):
        f = Finding(id="V1", title="Something bad in db", cwe="",
                    location="app/db.py:2", data_flow="u -> execute(sql)",
                    from_confirmed=True, votes=5, vote_samples=5)
        for level in quality.LEVELS:
            self.assertFalse(quality.evaluate(f, self.repo, level).substantiated, level)

    def test_placeholder_title_is_hypothesis(self):
        # A padding row (Phase 3 emits "Placeholder for additional finding") never
        # clears the concrete-claim floor, even with a CWE + a real sink location.
        f = Finding(id="V1", title="Placeholder for additional finding", cwe="CWE-89",
                    location="app/db.py:2", data_flow="u -> execute(sql)")
        self.assertFalse(quality.evaluate(f, self.repo, quality.LENIENT).substantiated)

    def test_unresolvable_location_is_hypothesis(self):
        f = Finding(id="V1", title="SQL injection", cwe="CWE-89",
                    location="app/ghost.py:2", data_flow="u -> execute(sql)")
        self.assertFalse(quality.evaluate(f, self.repo, quality.BALANCED).substantiated)


class LevelAndRepoRobustness(unittest.TestCase):
    def test_unknown_level_defaults_to_balanced(self):
        self.assertEqual(quality.normalize_level("whatever"), quality.BALANCED)
        self.assertEqual(quality.normalize_level(None), quality.BALANCED)
        self.assertEqual(quality.normalize_level("strict"), quality.STRICT)

    def test_no_checkout_gives_benefit_of_doubt_for_sink(self):
        # Source can't be checked (repo None). A well-formed sink candidate is not
        # demoted just because we couldn't read the tree — it leans on other
        # signals (a re-render must not degrade a finding's tier).
        f = Finding(id="V1", title="SQL injection in q", cwe="CWE-89",
                    location="app/db.py:2", data_flow="u -> execute(sql)",
                    from_confirmed=True)
        self.assertTrue(quality.evaluate(f, None, quality.BALANCED).substantiated)

    def test_checks_are_recorded(self):
        f = Finding(id="V1", title="SQL injection in q", cwe="CWE-89",
                    location="app/db.py:2")
        q = quality.evaluate(f, _repo(_REPO), quality.BALANCED)
        names = {c.name for c in q.checks}
        self.assertIn("source_corroborated", names)
        self.assertIn("agreement", names)
        self.assertTrue(all(c.status in (quality.PASS, quality.FAIL, quality.NA)
                            for c in q.checks))


if __name__ == "__main__":
    unittest.main()
