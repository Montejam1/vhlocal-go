"""The hunt-evidence parser turns raw per-partition hunt outputs (results/sg-*.md)
into a clean findings list — robust to the format variance the class agents emit:
mixed heading styles (### [VULN-001], ## 3. VULN-001 —, ### NAV-01 — … — HIGH),
Summary tables with DIFFERENT column orders, severity/CWE prefixes baked into the
title cell, and cross-reference index rows. It becomes the authoritative source
when the downstream phases (2b/3/4) under-report it."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import consolidate as C  # noqa: E402


def _run(files):
    """Build a results dir with results/<name> = content and parse hunt evidence."""
    d = Path(tempfile.mkdtemp())
    (d / "results").mkdir()
    for name, content in files.items():
        (d / "results" / name).write_text(content, encoding="utf-8")
    return d


class HuntEvidence(unittest.TestCase):
    def _by_title(self, findings):
        return {f.title: f for f in findings}

    def test_block_style_bracket_id(self):
        f = _run({"sg-1_inj.md": (
            "# SG-1 / INJ\n\n"
            "### [VULN-001] SQL injection in the search handler\n"
            "- **Class**: CWE-89: SQL Injection\n"
            "- **Severity**: High\n"
            "- **Location**: app/search.py:42\n")})
        got = C._hunt_evidence_findings(f)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].title, "SQL injection in the search handler")
        self.assertEqual(got[0].cwe, "CWE-89")
        self.assertEqual(got[0].severity, "High")
        self.assertEqual(got[0].location, "app/search.py:42")

    def test_header_aware_table_swapped_columns(self):
        # Two files, Summary tables with CWE and Severity in OPPOSITE order — a
        # position-based parser would swap them. Header-aware parsing must not.
        f = _run({
            "sg-a_log.md": (
                "## Summary\n"
                "| ID | Title | CWE | Severity | Location |\n"
                "|----|-------|-----|----------|----------|\n"
                "| VULN-001 | Weak token expiry | CWE-613 | Medium | auth.py:10 |\n"),
            "sg-b_nav.md": (
                "## 9. Summary\n"
                "| ID | Finding | Severity | CWE | Location |\n"
                "|----|---------|----------|-----|----------|\n"
                "| VULN-001 | Missing authz on delete | High | CWE-862 | admin.py:20 |\n"),
        })
        got = self._by_title(C._hunt_evidence_findings(f))
        self.assertEqual(got["Weak token expiry"].cwe, "CWE-613")
        self.assertEqual(got["Weak token expiry"].severity, "Medium")
        # The swapped-order file must still land CWE and severity correctly.
        self.assertEqual(got["Missing authz on delete"].cwe, "CWE-862")
        self.assertEqual(got["Missing authz on delete"].severity, "High")

    def test_nav_prefix_heading_and_trailing_severity(self):
        f = _run({"sg-3_nav.md": (
            "### NAV-01 — Unauthenticated `/ops` operator backdoor — CRITICAL\n"
            "- **Location**: ops.py:16\n"
            "Some detail.\n")})
        got = C._hunt_evidence_findings(f)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].title, "Unauthenticated `/ops` operator backdoor")
        self.assertEqual(got[0].severity, "Critical")
        self.assertEqual(got[0].location, "ops.py:16")

    def test_index_row_merges_into_writeup(self):
        # An index/cross-ref table row for NAV-02 plus the real NAV-02 write-up in
        # the same file must collapse to ONE finding (the write-up's title wins),
        # not leak a titleless "NAV-02" fragment.
        f = _run({"sg-3_nav.md": (
            "## Route index\n"
            "| # | Ref |\n"
            "|---|-----|\n"
            "| 1 | NAV-02 |\n\n"
            "### NAV-02 — Password reset without admin authorization — HIGH\n"
            "- **Class**: CWE-862\n"
            "- **Location**: admin.py:84\n")})
        got = C._hunt_evidence_findings(f)
        titles = [g.title for g in got]
        self.assertEqual(titles, ["Password reset without admin authorization"])
        self.assertNotIn("NAV-02", titles)

    def test_strips_leading_severity_cwe_prefix_from_title(self):
        f = _run({"sg-5_nav.md": (
            "## Summary\n"
            "| ID | Finding | Severity | CWE | Location |\n"
            "|----|---------|----------|-----|----------|\n"
            "| VULN-001 | High - CWE-639 - Object-level IDOR on jobs | High | CWE-639 | jobs.py:73 |\n")})
        got = C._hunt_evidence_findings(f)
        self.assertEqual(got[0].title, "Object-level IDOR on jobs")
        self.assertEqual(got[0].cwe, "CWE-639")
        self.assertEqual(got[0].severity, "High")

    def test_noise_pointer_rows_dropped(self):
        f = _run({"sg-2_inj.md": (
            "### [VULN-001] Real command injection\n"
            "- **Class**: CWE-78\n"
            "- **Location**: run.py:5\n\n"
            "### [VULN-002] Cross-class (NAV) sinks - see §7\n"
            "just a pointer, no class/location\n")})
        got = C._hunt_evidence_findings(f)
        self.assertEqual([g.title for g in got], ["Real command injection"])

    def test_verdict_table_not_parsed_as_findings(self):
        # A Phase-2b-style Yes/No verdict table has no title-ish column and must
        # never be mistaken for a findings table.
        f = _run({"sg-1_nav.md": (
            "## Adjudication\n"
            "| Endpoint | Exploitable? | Notes |\n"
            "|----------|--------------|-------|\n"
            "| POST /a | Yes | reachable |\n"
            "| POST /b | No | gated |\n")})
        self.assertEqual(C._hunt_evidence_findings(f), [])

    def test_wellformed_count(self):
        good = C.Finding(id="V1", title="Real IDOR bug", cwe="CWE-639")
        weak = C.Finding(id="V2", title="POST /x", cwe="CWE-639")   # weak title
        nocwe = C.Finding(id="V3", title="Real bug", cwe="")        # no CWE
        self.assertEqual(C._wellformed_count([good, weak, nocwe]), 1)

    def test_parse_findings_prefers_hunt_over_junk_report(self):
        # A thin/mangled Phase-4 README (verdict fragments) must be overridden by
        # the well-formed hunt evidence.
        d = _run({"sg-1_inj.md": (
            "### [VULN-001] SQL injection in search\n- **Class**: CWE-89\n- **Location**: s.py:1\n\n"
            "### [VULN-002] Path traversal in upload\n- **Class**: CWE-22\n- **Location**: u.py:2\n\n"
            "### [VULN-003] SSRF in webhook\n- **Class**: CWE-918\n- **Location**: w.py:3\n\n"
            "### [VULN-004] IDOR on orders\n- **Class**: CWE-639\n- **Location**: o.py:4\n\n"
            "### [VULN-005] Open redirect\n- **Class**: CWE-601\n- **Location**: r.py:5\n")})
        (d / "README.md").write_text(
            "# Report\n\n## Findings\n| ID | Title | Severity |\n|--|--|--|\n"
            "| 1 | Yes | High |\n| 2 | No | Low |\n", encoding="utf-8")
        got = C.parse_findings(d)
        # hunt has 5 well-formed; the report has 0 → hunt wins.
        self.assertGreaterEqual(len(got), 5)
        self.assertIn("SQL injection in search", [f.title for f in got])

    def test_no_results_dir_is_empty(self):
        d = Path(tempfile.mkdtemp())
        self.assertEqual(C._hunt_evidence_findings(d), [])


if __name__ == "__main__":
    unittest.main()
