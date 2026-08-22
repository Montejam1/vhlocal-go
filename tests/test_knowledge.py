"""Per-CWE knowledge: description, exploitability, reference — and the CVE=N/A
rule that avoids matching first-party code findings to unrelated product CVEs.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.consolidate import Finding, apply_normalized_severity  # noqa: E402
from vhlocal.knowledge import (  # noqa: E402
    CVE_NA,
    apply_knowledge,
    canonical_name,
    describe,
    exploitability,
    family_of,
    normalized_cwe,
    normalized_severity,
    reference,
)


class TestKnowledge(unittest.TestCase):
    def test_description_from_cwe(self):
        self.assertIn("Deserialization", describe("CWE-502"))
        self.assertIn("CWE-502", describe("CWE-502"))

    def test_exploitability_tiers(self):
        self.assertTrue(exploitability("CWE-502").startswith("Known-exploitable"))
        self.assertIn("limited", exploitability("CWE-601").lower())
        self.assertTrue(exploitability("CWE-367").startswith("Conditionally"))

    def test_reference_is_cwe_link(self):
        self.assertIn("cwe.mitre.org/data/definitions/502", reference("CWE-502"))

    def test_unknown_cwe_is_graceful(self):
        self.assertEqual(describe("CWE-9999"), "")
        self.assertIn("See CWE reference", exploitability("CWE-9999"))
        self.assertIn("9999", reference("CWE-9999"))

    def test_apply_sets_all_fields(self):
        f = Finding(id="V1", cwe="CWE-94", title="eval")
        apply_knowledge([f])
        self.assertTrue(f.description)
        self.assertTrue(f.exploitability)
        self.assertTrue(f.reference)
        self.assertEqual(f.cve, CVE_NA)

    def test_cve_is_na_for_code_findings(self):
        # The whole point: a first-party finding never gets a product CVE.
        f = Finding(id="V1", cwe="CWE-89", title="sqli")
        apply_knowledge([f])
        self.assertIn("N/A", f.cve)
        self.assertNotRegex(f.cve, r"CVE-\d{4}-\d+")

    def test_does_not_clobber_existing(self):
        f = Finding(id="V1", cwe="CWE-94", description="hand-written")
        apply_knowledge([f])
        self.assertEqual(f.description, "hand-written")


class TestNormalizedLabels(unittest.TestCase):
    def test_family_rollup(self):
        # Access-control CWEs all roll up to the canonical CWE-284 family.
        for cwe in ("CWE-639", "CWE-862", "CWE-863", "CWE-285", "CWE-284"):
            self.assertEqual(normalized_cwe(cwe), "CWE-284", cwe)
            self.assertEqual(family_of(cwe).key, "access-control", cwe)
        self.assertEqual(canonical_name("CWE-639"), "Broken Access Control")

    def test_family_stable_across_relabels(self):
        # The same defect labelled CWE-943 vs CWE-89 must NOT collapse — they are
        # deliberately distinct families (NoSQL vs SQL). But both are stable.
        self.assertEqual(normalized_cwe("CWE-89"), "CWE-89")
        self.assertEqual(normalized_cwe("CWE-943"), "CWE-943")
        # Command-injection variants do roll together.
        self.assertEqual(normalized_cwe("CWE-77"), "CWE-78")

    def test_unknown_cwe_passthrough(self):
        # A CWE we have no family for still normalizes to itself, never crashes.
        self.assertEqual(normalized_cwe("CWE-9999"), "CWE-9999")
        self.assertEqual(normalized_cwe(""), "")
        self.assertIsNone(family_of("CWE-9999"))

    def test_deterministic_severity_baseline(self):
        # Baseline is fixed per family, independent of the model's mood.
        self.assertEqual(normalized_severity("CWE-502"), "High+")   # deser
        self.assertEqual(normalized_severity("CWE-94"), "High+")    # code inj
        self.assertEqual(normalized_severity("CWE-89"), "High")     # sqli
        self.assertEqual(normalized_severity("CWE-79"), "Medium")   # xss
        self.assertEqual(normalized_severity("CWE-601"), "Low")     # open redirect

    def test_precondition_drops_one_tier(self):
        # A gate behind auth is a precondition, not a mitigation: one tier down.
        self.assertEqual(
            normalized_severity("CWE-502", "requires a valid session token"), "High")
        self.assertEqual(
            normalized_severity("CWE-89", "authenticated user only"), "Medium")
        # Ungated text leaves the baseline untouched.
        self.assertEqual(
            normalized_severity("CWE-89", "reachable by anonymous request"), "High")

    def test_apply_sets_normalized_fields(self):
        f = Finding(id="V1", cwe="CWE-639", title="IDOR")
        apply_knowledge([f])
        self.assertEqual(f.normalized_cwe, "CWE-284")
        self.assertEqual(f.cwe_family, "access-control")
        self.assertEqual(f.canonical_name, "Broken Access Control")
        self.assertEqual(f.normalized_severity, "High")

    def test_apply_normalized_severity_swaps_and_preserves(self):
        # Model says Low, family baseline for deser is High+ -> canonical wins,
        # model's tier is preserved as reported_severity, rank is recomputed.
        f = Finding(id="V1", cwe="CWE-502", severity="Low", severity_rank=99)
        apply_knowledge([f])
        apply_normalized_severity([f])
        self.assertEqual(f.severity, "High+")
        self.assertEqual(f.reported_severity, "Low")
        self.assertLess(f.severity_rank, 99)   # re-ranked to the High+ tier

    def test_apply_normalized_severity_noop_when_equal(self):
        # When the model already agrees, nothing is stamped as "reported".
        f = Finding(id="V1", cwe="CWE-89", severity="High")
        apply_knowledge([f])
        apply_normalized_severity([f])
        self.assertEqual(f.severity, "High")
        self.assertEqual(f.reported_severity, "")

    def test_unknown_family_severity_leaves_model_value(self):
        # No family -> normalized_severity is empty -> swap is a no-op, the
        # model's own severity survives untouched.
        f = Finding(id="V1", cwe="CWE-9999", severity="Medium")
        apply_knowledge([f])
        apply_normalized_severity([f])
        self.assertEqual(f.severity, "Medium")
        self.assertEqual(f.reported_severity, "")


if __name__ == "__main__":
    unittest.main()
