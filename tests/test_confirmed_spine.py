"""Phase 2b's confirmed set is authoritative for the finding list.

Regression for run 053536: Phase 2b confirmed ~19 findings but Phase 3/4 only
wrote up 7, and the report parsed that truncated README. The confirmed set
(from 2b + per-agent source files) must drive the finding list; Phase 3/4 only
enrich detail.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.consolidate import (  # noqa: E402
    Finding,
    flag_duplicates,
    parse_findings,
    _extract_source_findings,
    _is_placeholder,
    _norm_fid,
)

# 2b verdict table listing more confirmed findings than the README carries.
PHASE2B = """# Phase 2b Verification

## Confirmed Findings

| Finding | Source | CWE | Endpoint | Severity | Verdict |
|---|---|---|---|---|---|
| VULN-001 | sg-11_nav.md | CWE-639 | PUT /customers/{id} | High | CONFIRMED |
| VULN-002 | sg-11_nav.md | CWE-639 | POST /locations | High | CONFIRMED |
| Finding 1 | sg-5_inj.md | CWE-918 | POST /webhook | High | CONFIRMED |
| VULN-001 | sink_driven.md | CWE-502 | POST /pickle | High | CONFIRMED |
"""

# The truncated Phase-4 README (only one finding written up).
README_THIN = """# VulnHunter Security Audit Report

**Model**: gpt-oss:120b

## Summary of Confirmed Findings
| ID | Title | CWE | Severity |
|---|---|---|---|
| VULN-001 | Pickle deserialization | CWE-502 | High |
"""

SRC_NAV = """# SG-11 nav findings

#### VULN-001 IDOR – Unauthorized Customer Update
- **Class**: CWE-639: Insecure Direct Object Reference
- **Severity**: High
- **Location**: `backend/app/routers/customers.py:81-110`

#### VULN-002 IDOR – Unauthorized Location Creation
- **Class**: CWE-639: Insecure Direct Object Reference
- **Severity**: High
- **Location**: `backend/app/routers/customers.py:141-173`
"""

SRC_INJ = """# SG-5 inj findings

## Finding 1 – Server-Side Request Forgery (SSRF) via webhook URL
- **Class**: CWE-918: Server-Side Request Forgery.
- **Severity**: High
- **Location**: `backend/app/webhooks.py:84`
"""

SRC_SINK = """# sink findings

## [VULN-001] Unsafe deserialization via pickle.loads
- **Class**: CWE-502
- **Severity**: High
- **Location**: `backend/app/dispatch_operations.py:54`
"""


def _run_dir():
    d = Path(tempfile.mkdtemp())
    (d / "results").mkdir()
    (d / "phase2b_output.md").write_text(PHASE2B, encoding="utf-8")
    (d / "README.md").write_text(README_THIN, encoding="utf-8")
    (d / "results" / "sg-11_nav.md").write_text(SRC_NAV, encoding="utf-8")
    (d / "results" / "sg-5_inj.md").write_text(SRC_INJ, encoding="utf-8")
    (d / "results" / "sink_driven.md").write_text(SRC_SINK, encoding="utf-8")
    return d


class TestConfirmedSpine(unittest.TestCase):
    def test_spine_beats_thin_readme(self):
        fs = parse_findings(_run_dir())
        # 4 confirmed in 2b, not 1 from the README.
        self.assertEqual(len(fs), 4)

    def test_enriched_from_source_files(self):
        by = {f.cwe: f for f in parse_findings(_run_dir())}
        self.assertIn("IDOR", by["CWE-639"].title)
        self.assertIn("customers.py", by["CWE-639"].location)
        self.assertEqual(by["CWE-639"].severity, "High")
        self.assertIn("SSRF", by["CWE-918"].title)      # Finding-N id captured
        self.assertIn("webhooks.py", by["CWE-918"].location)

    def test_finding_n_ids_not_dropped(self):
        cwes = {f.cwe for f in parse_findings(_run_dir())}
        self.assertIn("CWE-918", cwes)   # was dropped (labelled "Finding 1")

    def test_two_idors_stay_distinct(self):
        fs = parse_findings(_run_dir())
        flag_duplicates(fs)
        idor = [f for f in fs if f.cwe == "CWE-639"]
        self.assertEqual(len(idor), 2)
        self.assertEqual(len([f for f in idor if not f.duplicate_of]), 2)


class TestTitleQualityAndSelection(unittest.TestCase):
    """A complete, well-titled Phase-4 report should win over a spine that is
    only marginally longer but full of entry-point-URL titles (run 094856:
    'Pickle deserialization RCE' rendered as 'POST /ops/bundle/...')."""

    def _dir(self):
        d = Path(tempfile.mkdtemp())
        (d / "results").mkdir()
        # Phase-2b confirmed set with weak (entry-point) identities.
        (d / "phase2b_output.md").write_text(
            "# Phase 2b\n\n## Confirmed\n\n| # | Source | CWE | Endpoint | Sev |\n"
            "|---|---|---|---|---|\n"
            "| sink-VULN-001 | ?.md | CWE-502 | POST /ops/bundle/thaw | High |\n"
            "| sink-VULN-002 | ?.md | CWE-611 | POST /ops/xml/fold | High |\n",
            encoding="utf-8")
        # A complete Phase-4 README with descriptive titles + routes.
        (d / "README.md").write_text(
            "# Audit\n\n## Summary\n| ID | Title | CWE | Severity |\n|---|---|---|---|\n"
            "| VULN-001 | Pickle deserialization RCE | CWE-502 | High |\n"
            "| VULN-002 | XXE Injection | CWE-611 | High |\n\n"
            "### VULN-001: Pickle deserialization RCE\n"
            "| **Entry Point** | POST /ops/bundle/thaw |\n"
            "| **Location** | `app/ops.py:61` |\n"
            "### VULN-002: XXE Injection\n"
            "| **Entry Point** | POST /ops/xml/fold |\n"
            "| **Location** | `app/ops.py:150` |\n",
            encoding="utf-8")
        return d

    def test_descriptive_titles_win_over_url_titles(self):
        titles = [f.title for f in parse_findings(self._dir())]
        self.assertIn("Pickle deserialization RCE", titles)
        self.assertIn("XXE Injection", titles)
        # No entry-point-URL titles survive.
        self.assertFalse(any(t.startswith("POST /") for t in titles))


class TestPlaceholderFilter(unittest.TestCase):
    """Phase 3 pads its assignment table with 'Placeholder for additional
    finding | Unrated' rows; these must never reach the report (run 033202)."""

    def test_placeholder_title_dropped(self):
        f = Finding(id="VULN-019", title="Placeholder for additional finding",
                    severity="Unrated")
        self.assertTrue(_is_placeholder(f))

    def test_contentless_row_dropped(self):
        # No CWE, no location, title just echoes the id.
        self.assertTrue(_is_placeholder(Finding(id="VULN-020", title="VULN-020")))
        self.assertTrue(_is_placeholder(Finding(id="VULN-021", title="")))

    def test_real_finding_kept(self):
        f = Finding(id="VULN-001", title="IDOR on customer update",
                    cwe="CWE-639", location="customers.py:81", severity="High")
        self.assertFalse(_is_placeholder(f))

    def test_real_finding_with_only_title_kept(self):
        # A titled finding without CWE/location is still real, not a placeholder.
        f = Finding(id="VULN-002", title="Weak randomness in token generation")
        self.assertFalse(_is_placeholder(f))

    def test_parse_findings_strips_placeholders(self):
        d = Path(tempfile.mkdtemp())
        (d / "phase3_output.md").write_text(
            "# Phase 3\n\n## VULN Assignment Table\n"
            "| VULN-NNN | # | Title | Severity |\n|---|---|---|---|\n"
            "| VULN-001 | 1 | SQL injection via q | High |\n"
            "| VULN-002 | 2 | Placeholder for additional finding | Unrated |\n"
            "| VULN-003 | 3 | Placeholder for additional finding | Unrated |\n",
            encoding="utf-8")
        titles = [f.title for f in parse_findings(d)]
        self.assertIn("SQL injection via q", " ".join(titles))
        self.assertFalse(any("laceholder" in t for t in titles))


class TestSourceExtraction(unittest.TestCase):
    def test_norm_fid(self):
        self.assertEqual(_norm_fid("VULN-001"), "VULN1")
        self.assertEqual(_norm_fid("Finding 1"), "FINDING1")
        self.assertEqual(_norm_fid("sg-2-log-Finding1"), "FINDING1")
        self.assertEqual(_norm_fid("#### [VULN-014]"), "VULN14")

    def test_extract_titles_cwe_location(self):
        d = Path(tempfile.mkdtemp())
        p = d / "s.md"
        p.write_text(SRC_NAV, encoding="utf-8")
        got = _extract_source_findings(p)
        self.assertIn("VULN1", got)
        self.assertEqual(got["VULN1"]["cwe"], "CWE-639")
        self.assertIn("customers.py:81", got["VULN1"]["location"])


if __name__ == "__main__":
    unittest.main()
