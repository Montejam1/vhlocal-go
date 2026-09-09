"""The harness owns candidate assessment: a candidate is 'supported' only when it
clears an evidence gate (weakness class + real security claim + a source location
that resolves against the scanned tree). Under-evidenced candidates stay
'unresolved' — kept and counted, never silently promoted to a finding. Leaked
input-inventory rows are not candidates at all. Reported confidence must never
exceed the evidence collected.

These lock in the failure modes from the proposal's acceptance table."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import consolidate as C  # noqa: E402
from vhlocal.consolidate import (  # noqa: E402
    ASSESS_SUPPORTED,
    ASSESS_UNRESOLVED,
    STATE_STATIC_SUPPORTED,
    STATE_UNRESOLVED,
    Finding,
)


def _repo(files):
    d = Path(tempfile.mkdtemp())
    for rel in files:
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x\n", encoding="utf-8")
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


class EvidenceGate(unittest.TestCase):
    def _assess(self, f, repo=None):
        C.assess_candidates([f], {"repo": str(repo) if repo else ""})
        return f.assessment

    def test_supported_needs_cwe_claim_and_resolvable_location(self):
        repo = _repo(["app/search.py"])
        f = Finding(id="V1", title="SQL injection in search", cwe="CWE-89",
                    location="app/search.py:12")
        self.assertEqual(self._assess(f, repo), ASSESS_SUPPORTED)

    def test_missing_cwe_is_unresolved(self):
        repo = _repo(["app/x.py"])
        f = Finding(id="V1", title="Something suspicious here", cwe="",
                    location="app/x.py:1")
        self.assertEqual(self._assess(f, repo), ASSESS_UNRESOLVED)

    def test_weak_title_is_unresolved(self):
        repo = _repo(["app/x.py"])
        f = Finding(id="V1", title="POST /api/x", cwe="CWE-89", location="app/x.py:1")
        self.assertEqual(self._assess(f, repo), ASSESS_UNRESOLVED)

    def test_citation_to_missing_file_is_unresolved(self):
        # A source reference that doesn't resolve against the scanned tree fails.
        repo = _repo(["app/real.py"])
        f = Finding(id="V1", title="SQLi in ghost", cwe="CWE-89",
                    location="app/ghost.py:9")
        self.assertEqual(self._assess(f, repo), ASSESS_UNRESOLVED)

    def test_basename_match_resolves(self):
        # The model often cites a path missing its package dir — basename match ok.
        repo = _repo(["backend/app/routers/regions.py"])
        f = Finding(id="V1", title="IDOR on region", cwe="CWE-639",
                    location="regions.py:50")
        self.assertEqual(self._assess(f, repo), ASSESS_SUPPORTED)

    def test_no_repo_context_degrades_to_supported(self):
        # An old-report re-render with no repo must not invent unresolved verdicts.
        f = Finding(id="V1", title="SQLi", cwe="CWE-89", location="x.py:1")
        self.assertEqual(self._assess(f, None), ASSESS_SUPPORTED)

    def test_duplicate_inherits_supported(self):
        f = Finding(id="V2", title="dup", duplicate_of="V1")
        C.assess_candidates([f], {})
        self.assertEqual(f.assessment, ASSESS_SUPPORTED)


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
    def test_assessment_totals_separate_supported_from_unresolved(self):
        fs = [
            Finding(id="V1", assessment=ASSESS_SUPPORTED),
            Finding(id="V2", assessment=ASSESS_SUPPORTED),
            Finding(id="V3", assessment=ASSESS_UNRESOLVED),
            Finding(id="V4", assessment=ASSESS_SUPPORTED, duplicate_of="V1"),
        ]
        t = C.assessment_totals(fs)
        self.assertEqual(t["candidates"], 3)  # duplicate excluded
        self.assertEqual(t["supported"], 2)
        self.assertEqual(t["unresolved"], 1)


if __name__ == "__main__":
    unittest.main()
