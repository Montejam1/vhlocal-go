"""Tranche 1 outputs: SARIF 2.1.0 export, run_manifest.json, secret/PII redaction,
and the Scan Health section — the enterprise/CI-legible artifacts adopted from the
Visa harness gap analysis. All deterministic, stdlib only."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import redact, sarif, manifest  # noqa: E402


class Redaction(unittest.TestCase):
    def test_masks_card_ssn_key_but_not_random_digits(self):
        out, n = redact.redact_text(
            "card 4111 1111 1111 1111, ssn 123-45-6789, "
            'API_KEY = "hunter2secretvalue", order 1234567890123456')
        self.assertIn(redact.CARD_TOKEN, out)
        self.assertIn(redact.SSN_TOKEN, out)
        self.assertIn(redact.SECRET_TOKEN, out)
        self.assertNotIn("4111 1111 1111 1111", out)
        self.assertNotIn("hunter2secretvalue", out)
        # a 16-digit non-card id (Luhn fails) is left alone
        self.assertIn("1234567890123456", out)
        self.assertGreaterEqual(n, 3)

    def test_keeps_key_name_masks_value(self):
        out, _ = redact.redact_text('password = "swordfish123"')
        self.assertIn("password", out)
        self.assertNotIn("swordfish123", out)

    def test_aws_and_jwt_tokens(self):
        out, _ = redact.redact_text("AKIAIOSFODNN7EXAMPLE and eyJab.eyJcd.SflKx")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertIn(redact.KEY_TOKEN, out)

    def test_redact_findings_in_place(self):
        findings = [{"title": "leak", "location": "app.py:9",
                     "data_flow": "card 4111 1111 1111 1111 to sink",
                     "cwe": "CWE-312"}]
        n = redact.redact_findings(findings)
        self.assertEqual(n, 1)
        self.assertIn(redact.CARD_TOKEN, findings[0]["data_flow"])
        self.assertEqual(findings[0]["cwe"], "CWE-312")   # taxonomy untouched

    def test_clean_text_is_noop(self):
        out, n = redact.redact_text("no secrets here, just prose")
        self.assertEqual(n, 0)
        self.assertEqual(out, "no secrets here, just prose")


_FINDINGS = [
    {"id": "VULN-001", "title": "Unsafe eval", "severity": "High+",
     "normalized_severity": "High+", "cwe": "CWE-95", "normalized_cwe": "CWE-94",
     "canonical_name": "Code Injection", "location": "app/x.py:42",
     "finding_lifecycle": "new"},
    {"id": "VULN-002", "title": "IDOR", "severity": "Medium",
     "normalized_severity": "Medium", "cwe": "CWE-639", "normalized_cwe": "CWE-639",
     "location": "app/users.py:17"},
    {"id": "VULN-003", "title": "dup", "severity": "Low", "cwe": "CWE-79",
     "location": "app/x.py:42", "duplicate_of": "VULN-001"},
]
_META = {"repo": "/code/shop", "model": "gpt-oss:120b", "engine_version": "0.1.0"}


class Sarif(unittest.TestCase):
    def _build(self, run_status=None):
        return sarif.build_sarif(_FINDINGS, _META, run_status or {})

    def test_shape_and_version(self):
        doc = self._build()
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "vhlocal")
        # duplicate excluded -> 2 results
        self.assertEqual(len(run["results"]), 2)

    def test_levels_and_rules_and_taxa(self):
        run = self._build()["runs"][0]
        levels = {r["ruleId"]: r["level"] for r in run["results"]}
        self.assertEqual(levels["CWE-94"], "error")      # High+
        self.assertEqual(levels["CWE-639"], "warning")   # Medium
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, {"CWE-94", "CWE-639"})
        taxa_ids = {t["id"] for t in run["taxonomies"][0]["taxa"]}
        self.assertEqual(taxa_ids, {"CWE-94", "CWE-639"})
        self.assertTrue(run["tool"]["driver"]["supportedTaxonomies"])

    def test_location_parsed(self):
        run = self._build()["runs"][0]
        loc = run["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "app/x.py")
        self.assertEqual(loc["region"]["startLine"], 42)

    def test_execution_success_and_notifications(self):
        clean = self._build({"execution_status": "complete"})["runs"][0]["invocations"][0]
        self.assertTrue(clean["executionSuccessful"])
        self.assertNotIn("toolExecutionNotifications", clean)
        degraded = self._build({"execution_status": "complete",
                                "coverage_degraded_reasons": ["48 of 100 not reviewed"]})
        inv = degraded["runs"][0]["invocations"][0]
        self.assertTrue(inv["executionSuccessful"])   # degraded != failed
        self.assertEqual(len(inv["toolExecutionNotifications"]), 1)

    def test_empty_findings_is_valid(self):
        doc = sarif.build_sarif([], _META, {})
        self.assertEqual(doc["runs"][0]["results"], [])


class Manifest(unittest.TestCase):
    def test_core_fields_and_config_hash_stable(self):
        meta = dict(_META, results_dir="/reports/shop-run1", num_ctx=131072,
                    max_partitions=8, phases_requested=["1", "2"],
                    started_at=100.0, finished_at=460.0,
                    agents=[{"stopped_reason": "complete"},
                            {"stopped_reason": "error", "error_kind": "timeout"}])
        m1 = manifest.build_manifest(meta, {"execution_status": "complete",
                                            "coverage_status": "degraded"},
                                     {"High+": 1, "Medium": 1})
        self.assertEqual(m1["tool"]["name"], "vhlocal")
        self.assertEqual(m1["run_id"], "shop-run1")
        self.assertEqual(m1["models"]["hunt"], "gpt-oss:120b")
        self.assertEqual(m1["timing"]["duration_seconds"], 360.0)
        self.assertEqual(m1["outcome"]["agents_incomplete"], 1)
        self.assertEqual(m1["findings"]["total"], 2)
        self.assertTrue(m1["config"]["hash"].startswith("sha256:"))
        # same config -> same hash (deterministic, comparable across runs)
        m2 = manifest.build_manifest(dict(meta, started_at=999.0), {}, {})
        self.assertEqual(m1["config"]["hash"], m2["config"]["hash"])


if __name__ == "__main__":
    unittest.main()
