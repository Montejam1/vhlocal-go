"""Run-quality fields on the report index.

The Reports list used to carry only how MUCH a run found — never whether the run
that found it was sound. A degraded scan and a clean one were indistinguishable
until you opened each in turn. These fields come out of the same findings.json
read that already supplies the counts, so the index costs no extra I/O.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.reports import parse_report  # noqa: E402


def _report(**findings_json):
    root = Path(tempfile.mkdtemp()) / "app__gpt-oss__20260827-010101"
    root.mkdir(parents=True)
    (root / "README.md").write_text("# Report\n", encoding="utf-8")
    if findings_json:
        (root / "findings.json").write_text(
            json.dumps(findings_json), encoding="utf-8")
    return root


class RunQuality(unittest.TestCase):
    def test_full_record(self):
        rep = parse_report(_report(
            run_status={"coverage_status": "degraded",
                        "coverage_degraded_reasons": ["partition 3 halted"]},
            counts={"High": 3, "Medium": 2},
            chains=[{"id": "CHAIN-1"}, {"id": "CHAIN-2"}],
            application_intelligence={"sbom": {"total": 214}},
            vulnerability_ledger={"open_known": 17, "recall_pct": 82,
                                  "ledger_file": "/h/.vhlocal/ledgers/abc123.json"},
            findings=[{"id": "V1"}, {"id": "V2"}, {"id": "V3", "duplicate_of": "V1"}],
        ))
        self.assertEqual(rep.coverage_status, "degraded")
        self.assertTrue(rep.coverage_degraded)
        self.assertEqual(rep.recall_pct, 82)
        self.assertEqual(rep.ledger_slug, "abc123")
        self.assertEqual(rep.chains, 2)
        self.assertEqual(rep.sbom_total, 214)
        # The pre-existing contract is untouched: unique root causes only.
        self.assertEqual(rep.findings, 2)
        self.assertEqual(rep.severities, {"high": 3, "medium": 2})
        self.assertIn("recall_pct", rep.to_dict())

    def test_degraded_flag_set_by_reasons_alone(self):
        """A run can report a 'complete' status and still carry degradation
        reasons; the flag must reflect either."""
        rep = parse_report(_report(
            run_status={"coverage_status": "complete",
                        "coverage_degraded_reasons": ["one partition retried"]},
            findings=[{"id": "V1"}], counts={"Low": 1},
        ))
        self.assertTrue(rep.coverage_degraded)

    def test_first_ledger_run_is_not_zero_percent_recall(self):
        """0 of 0 known findings is not a measurement of 0% — it is the absence
        of anything to measure against, and must stay None."""
        rep = parse_report(_report(
            run_status={"coverage_status": "complete"},
            vulnerability_ledger={"open_known": 0, "recall_pct": 0,
                                  "ledger_file": "/l/x.json"},
            findings=[{"id": "V1"}], counts={"Low": 1},
        ))
        self.assertIsNone(rep.recall_pct)
        self.assertFalse(rep.coverage_degraded)

    def test_run_without_ledger_reports_no_recall(self):
        rep = parse_report(_report(
            run_status={"coverage_status": "complete"},
            findings=[{"id": "V1"}], counts={"Low": 1},
        ))
        self.assertIsNone(rep.recall_pct)
        self.assertEqual(rep.ledger_slug, "")

    def test_legacy_report_without_findings_json(self):
        """Reports predating findings.json must still parse, with the quality
        fields simply left at their defaults."""
        root = Path(tempfile.mkdtemp()) / "old__m__20250101-000000"
        root.mkdir(parents=True)
        (root / "README.md").write_text(
            "# R\n| VULN-001 | x | CWE-1 | High |\n", encoding="utf-8")
        rep = parse_report(root)
        self.assertEqual(rep.coverage_status, "")
        self.assertFalse(rep.coverage_degraded)
        self.assertIsNone(rep.recall_pct)
        self.assertEqual(rep.chains, 0)
        self.assertEqual(rep.sbom_total, 0)
        self.assertEqual(rep.findings, 1)   # README fallback still works

    def test_malformed_fields_do_not_raise(self):
        rep = parse_report(_report(
            run_status="not-a-dict",
            chains="not-a-list",
            application_intelligence={"sbom": {"total": "many"}},
            vulnerability_ledger={"open_known": 3, "recall_pct": "eighty"},
            findings=[{"id": "V1"}], counts={"Low": 1},
        ))
        self.assertEqual(rep.coverage_status, "")
        self.assertEqual(rep.chains, 0)
        self.assertEqual(rep.sbom_total, 0)
        self.assertIsNone(rep.recall_pct)


if __name__ == "__main__":
    unittest.main()
