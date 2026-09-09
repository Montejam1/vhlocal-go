"""Three publication tiers: a bare hypothesis (clears no evidence gate), a
statically-supported finding (the harness's own static gate: weakness class +
concrete claim + a resolvable location), and a reviewed vulnerability (a
source-grounded review record). Confidence never exceeds evidence, but a
well-formed static finding is useful default output — not collapsed to a
hypothesis. Leaked input-inventory rows are not candidates at all."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import consolidate as C  # noqa: E402
from vhlocal.consolidate import (  # noqa: E402
    ASSESS_SUPPORTED,
    ASSESS_UNRESOLVED,
    CLASS_HYPOTHESIS,
    CLASS_STATICALLY_SUPPORTED,
    STATE_STATIC_SUPPORTED,
    STATE_UNRESOLVED,
    Finding,
)


def _repo(files):
    """files: a list of paths (empty bodies) or a {path: body} dict."""
    d = Path(tempfile.mkdtemp())
    items = files.items() if isinstance(files, dict) else ((f, "x\n") for f in files)
    for rel, body in items:
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return d


class InventoryRows(unittest.TestCase):
    def test_inventory_titles_are_not_candidates(self):
        for t in [
            "payload.name (RegionCreate)",
            "payload.code (RegionCreate)",
            "Path parameter region_id (PUT)",
            "payload.description (RegionUpdate)",
            "Query param q",
            "region_id path parameter",
        ]:
            f = Finding(id="V1", title=t, cwe="", location="regions.py:33")
            self.assertTrue(C._is_inventory_row(f), t)
            self.assertTrue(C._is_placeholder(f), t)

    def test_real_findings_are_not_inventory(self):
        for t, cwe in [
            ("SQL injection in the search handler", "CWE-89"),
            ("IDOR on GET /api/users/{id}", "CWE-639"),
            ("Path Traversal / Arbitrary File Write via `name`", "CWE-22"),
        ]:
            f = Finding(id="V1", title=t, cwe=cwe, location="app/x.py:10")
            self.assertFalse(C._is_inventory_row(f), t)

    def test_inventory_with_a_cwe_is_kept(self):
        # If the model DID attach a weakness class, it isn't a bare inventory row.
        f = Finding(id="V1", title="payload.name (RegionCreate)", cwe="CWE-20",
                    location="regions.py:33")
        self.assertFalse(C._is_inventory_row(f))


class StaticGate(unittest.TestCase):
    def _assess(self, f, repo=None):
        C.assess_candidates([f], {"repo": str(repo) if repo else ""})
        return f.assessment, f.classification

    def test_wellformed_sink_candidate_is_statically_supported(self):
        # A sink class corroborated by a matching sink in the cited source clears
        # the (balanced-default) bar: supported, statically_supported tier.
        repo = _repo({"app/search.py":
                      "def s(q):\n    cur.execute('SELECT * FROM t WHERE q=' + q)\n"})
        f = Finding(id="V1", title="SQL injection in search", cwe="CWE-89",
                    location="app/search.py:2", data_flow="q -> execute(sql)")
        self.assertEqual(self._assess(f, repo),
                         (ASSESS_SUPPORTED, CLASS_STATICALLY_SUPPORTED))

    def test_logic_candidate_with_flow_and_agreement_is_supported(self):
        # A logic class (IDOR) has no syntactic sink; a described flow + a precise
        # location (basename-matched) + agreement carry it. The basename match
        # (regions.py → backend/app/routers/regions.py) resolves the location.
        repo = _repo(["backend/app/routers/regions.py"])
        f = Finding(id="V1", title="IDOR on region", cwe="CWE-639",
                    location="regions.py:50",
                    data_flow="region_id -> record returned without an owner check",
                    from_confirmed=True)
        self.assertEqual(self._assess(f, repo),
                         (ASSESS_SUPPORTED, CLASS_STATICALLY_SUPPORTED))

    def test_missing_cwe_is_hypothesis(self):
        repo = _repo(["app/x.py"])
        f = Finding(id="V1", title="Something suspicious here", cwe="",
                    location="app/x.py:1")
        self.assertEqual(self._assess(f, repo),
                         (ASSESS_UNRESOLVED, CLASS_HYPOTHESIS))

    def test_weak_title_is_hypothesis(self):
        repo = _repo(["app/x.py"])
        f = Finding(id="V1", title="POST /api/x", cwe="CWE-89", location="app/x.py:1")
        self.assertEqual(self._assess(f, repo),
                         (ASSESS_UNRESOLVED, CLASS_HYPOTHESIS))

    def test_citation_to_missing_file_is_hypothesis(self):
        # A source reference that doesn't resolve against the scanned tree fails.
        repo = _repo(["app/real.py"])
        f = Finding(id="V1", title="SQLi in ghost", cwe="CWE-89",
                    location="app/ghost.py:9")
        self.assertEqual(self._assess(f, repo),
                         (ASSESS_UNRESOLVED, CLASS_HYPOTHESIS))

    def test_missing_location_is_hypothesis(self):
        repo = _repo(["app/x.py"])
        f = Finding(id="V1", title="SQLi in handler", cwe="CWE-89", location="")
        self.assertEqual(self._assess(f, repo),
                         (ASSESS_UNRESOLVED, CLASS_HYPOTHESIS))

    def test_no_repo_context_leans_on_other_signals(self):
        # When the checkout is unavailable the source can't be corroborated, so a
        # candidate keeps its static-support tier only if another signal backs it
        # (a described flow or agreement) — this preserves a corroborated finding's
        # tier across a re-render without the tree, without promoting a bare claim.
        f = Finding(id="V1", title="SQLi in handler", cwe="CWE-89", location="x.py:1",
                    data_flow="user input -> cursor.execute builds the query string",
                    from_confirmed=True)
        self.assertEqual(self._assess(f, None),
                         (ASSESS_SUPPORTED, CLASS_STATICALLY_SUPPORTED))

    def test_orphan_duplicate_is_hypothesis(self):
        f = Finding(id="V2", title="dup", duplicate_of="V1")
        C.assess_candidates([f], {})
        self.assertEqual(f.assessment, ASSESS_UNRESOLVED)
        self.assertEqual(f.classification, CLASS_HYPOTHESIS)


class Promotion(unittest.TestCase):
    def test_unresolved_candidate_is_not_promoted(self):
        # apply_validation must respect the gate: unresolved → STATE_UNRESOLVED,
        # never statically_supported, regardless of the model's raw claim.
        f = Finding(id="V1", title="Maybe a bug", cwe="", location="",
                    status="Confirmed", exploit_test="PASS")
        f.assessment = ASSESS_UNRESOLVED
        C.apply_validation([f], {})
        self.assertEqual(f.finding_state, STATE_UNRESOLVED)

    def test_supported_candidate_is_statically_supported(self):
        f = Finding(id="V1", title="SQLi", cwe="CWE-89", location="x.py:1")
        f.assessment = ASSESS_SUPPORTED
        C.apply_validation([f], {})
        self.assertEqual(f.finding_state, STATE_STATIC_SUPPORTED)


class Totals(unittest.TestCase):
    def test_assessment_totals_separate_tiers(self):
        fs = [
            Finding(id="V1", assessment=ASSESS_SUPPORTED,
                    classification=CLASS_STATICALLY_SUPPORTED),
            Finding(id="V2", assessment=ASSESS_SUPPORTED,
                    classification=C.CLASS_REVIEWED),
            Finding(id="V3", assessment=ASSESS_UNRESOLVED,
                    classification=CLASS_HYPOTHESIS),
            Finding(id="V4", assessment=ASSESS_SUPPORTED,
                    classification=CLASS_STATICALLY_SUPPORTED, duplicate_of="V1"),
        ]
        t = C.assessment_totals(fs)
        self.assertEqual(t["candidates"], 3)  # duplicate excluded
        self.assertEqual(t["supported"], 2)
        self.assertEqual(t["unresolved"], 1)
        self.assertEqual(t["statically_supported"], 1)
        self.assertEqual(t["reviewed"], 1)
        self.assertEqual(t["hypotheses"], 1)


if __name__ == "__main__":
    unittest.main()
