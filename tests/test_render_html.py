"""Tests for the standalone HTML report.

Guards the properties that make it shippable: self-contained, escaped,
accessible (never colour-alone), and honest about missing metadata.
"""

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import base64  # noqa: E402

from vhlocal.render_html import SEV_STYLE, render_html, write_html  # noqa: E402
from tests.test_consolidate import META, README  # noqa: E402


class _Base(unittest.TestCase):
    def build(self, readme=README, meta=META):
        d = Path(tempfile.mkdtemp())
        if readme is not None:
            (d / "README.md").write_text(readme, encoding="utf-8")
        if meta is not None:
            (d / "scan_meta.json").write_text(json.dumps(meta), encoding="utf-8")
        return d


class TestSelfContained(_Base):
    def setUp(self):
        self.html = render_html(self.build())

    def test_no_external_resources(self):
        # Self-containment = nothing is FETCHED (scripts, styles, fonts, images).
        # A user-facing hyperlink (e.g. a CWE reference link) is navigation, not a
        # fetched resource, and does not break offline rendering — so we ban the
        # actual fetch vectors, not bare "https://".
        for bad in ('src="http', "<script src", "<link ", "@import", "url(http",
                    "url('http", '<img', "unpkg", "jsdelivr", "googleapis"):
            self.assertNotIn(bad, self.html, "external resource: " + bad)

    def test_reference_url_is_a_link_not_a_resource(self):
        # The CWE reference URL must live inside an href (a clickable link), never
        # be pulled in as a resource.
        if "cwe.mitre.org" in self.html:
            self.assertIn('href="https://cwe.mitre.org', self.html)

    def test_is_a_complete_document(self):
        self.assertTrue(self.html.startswith("<!doctype html>"))
        self.assertIn("</html>", self.html)

    def test_styles_and_script_are_inline(self):
        self.assertIn("<style>", self.html)
        self.assertIn("<script>", self.html)


class TestAccessibility(_Base):
    def setUp(self):
        self.html = render_html(self.build())

    def test_severity_never_colour_alone(self):
        """Medium/High measure ΔE 13.6 — below the 15 floor. Colour cannot be
        the only channel, so every badge carries a glyph and the word."""
        # Each badge is: <span class="sevtag"><span class="glyph" …>G</span>LABEL</span>
        badges = re.findall(
            r'<span class="sevtag">(<span class="glyph"[^>]*>.*?</span>)([^<]+)</span>',
            self.html, re.S)
        self.assertTrue(badges, "no severity badges rendered")
        for glyph_span, label_text in badges:
            self.assertIn('class="glyph"', glyph_span)   # icon channel
            self.assertTrue(label_text.strip())          # text channel
        rendered = {t.strip() for _g, t in badges}
        self.assertTrue(rendered <= set(SEV_STYLE), rendered)

    def test_dark_mode_is_selected_both_ways(self):
        # OS preference AND explicit toggle, with the toggle able to win.
        self.assertIn("prefers-color-scheme: dark", self.html)
        self.assertIn(':root[data-theme="dark"]', self.html)
        self.assertIn(':not([data-theme="light"])', self.html)

    def test_meter_has_accessible_name(self):
        self.assertIn('role="img"', self.html)
        self.assertIn("aria-label", self.html)

    def test_filters_expose_pressed_state(self):
        self.assertIn('aria-pressed="false"', self.html)


class TestHonestValidationAndStatus(_Base):
    """P0-A/C/D on the HTML report."""

    def test_no_bare_pass_or_confirmed_verdict(self):
        html = render_html(self.build())
        self.assertNotIn("<dd>PASS</dd>", html)
        self.assertNotIn(">Status</dt><dd>Confirmed</dd>", html)
        self.assertIn("not run (no code executed)", html)
        self.assertIn("Scanner-reported (unverified)", html)

    def test_both_models_attributed(self):
        meta = dict(META)
        meta["verify_model"] = "qwen3.5:122b-a10b"
        html = render_html(self.build(meta=meta))
        self.assertIn("gpt-oss:120b", html)          # META hunt model
        self.assertIn("qwen3.5:122b-a10b", html)
        self.assertIn("falsification", html)

    def test_execution_and_coverage_are_separate_chips(self):
        meta = dict(META)
        meta["partitions"] = ["whole-repo"]
        meta["partition_fallback"] = True
        html = render_html(self.build(meta=meta))
        self.assertIn("exec:", html)
        self.assertIn("coverage:", html)
        self.assertIn("Coverage is degraded", html)


class TestMarkdownDownload(_Base):
    """The 'Save as Markdown' button embeds the report source as base64 so the
    download works from a file:// report with no server."""

    def setUp(self):
        self.html = render_html(self.build())

    def _embedded(self):
        m = re.search(r'id="mdSource">([^<]+)</script>', self.html)
        self.assertIsNotNone(m, "embedded markdown source missing")
        return base64.b64decode(m.group(1)).decode("utf-8")

    def test_button_and_source_present(self):
        self.assertIn('id="mdBtn"', self.html)
        self.assertIn("Save as Markdown", self.html)

    def test_download_filename_is_safe(self):
        fn = re.search(r'id="mdBtn"[^>]*data-fn="([^"]+)"', self.html).group(1)
        self.assertTrue(fn.endswith(".md"))
        # No path separators or spaces that would break the download attribute.
        self.assertNotRegex(fn, r"[/\\\s]")

    def test_embedded_source_matches_ondisk_md(self):
        from vhlocal.consolidate import write_consolidated
        d = self.build()
        write_consolidated(d)  # writes SCAN_REPORT.md
        write_html(d)          # embeds it byte-for-byte
        html = (d / "SCAN_REPORT.html").read_text(encoding="utf-8")
        b64 = re.search(r'id="mdSource">([^<]+)</script>', html).group(1)
        decoded = base64.b64decode(b64).decode("utf-8")
        self.assertEqual(decoded, (d / "SCAN_REPORT.md").read_text(encoding="utf-8"))

    def test_embedded_source_is_the_report_markdown(self):
        self.assertIn("#", self._embedded())  # has markdown headings


class TestEscaping(_Base):
    def test_model_authored_markup_is_escaped(self):
        evil = README.replace(
            "Path Traversal in Invoice",
            "<script>alert(1)</script> & \"quoted\"")
        html = render_html(self.build(readme=evil))
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)


class TestContent(_Base):
    def setUp(self):
        self.html = render_html(self.build())

    def test_metadata_rendered(self):
        self.assertIn("gpt-oss:120b", self.html)
        self.assertIn("1h 53m", self.html)
        self.assertIn("131,072", self.html)

    def test_findings_ranked_most_severe_first(self):
        # A spread across families whose deterministic baselines differ, with the
        # model's *reported* severities deliberately scrambled (a Low-labelled
        # deserialization, a Critical-labelled open redirect). Ranking must follow
        # the normalized family severity, not the model's label — so the deser
        # sorts to the top and the redirect to the bottom.
        readme = (
            "# VulnHunter Security Audit Report\n\n"
            "**Findings Summary**: 4\n\n"
            "| ID | Title | CWE | Severity | Test | Status |\n"
            "|---|---|---|---|---|---|\n"
            "| VULN-001 | Unsafe Pickle Deserialization | CWE-502 | Low | PASS | Confirmed |\n"
            "| VULN-002 | Path Traversal in Invoice | CWE-22 | Low | PASS | Confirmed |\n"
            "| VULN-003 | Reflected XSS in search | CWE-79 | Critical | PASS | Confirmed |\n"
            "| VULN-004 | Open Redirect on login | CWE-601 | Critical | PASS | Confirmed |\n")
        html = render_html(self.build(readme=readme))
        order = re.findall(r'<details class="finding" data-sev="([^"]+)"', html)
        self.assertEqual(order, ["High+", "High", "Medium", "Low"])

    def test_duplicate_excluded_from_hero_count(self):
        # 5 findings, 1 duplicate -> hero shows 4
        m = re.search(r'<div class="n">(\d+)</div>', self.html)
        self.assertEqual(m.group(1), "4")

    def test_incomplete_agent_surfaced(self):
        self.assertIn("did not finish cleanly", self.html)

    def test_static_only_stated(self):
        self.assertIn("Static analysis only", self.html)

    def test_same_model_falsification_warned(self):
        self.assertIn("same model as the hunt phase", self.html)


class TestMissingMetadata(_Base):
    def setUp(self):
        self.html = render_html(self.build(meta=None))

    def test_reports_unknown_not_zero(self):
        """Absent metadata is *unknown*; claiming 0s / 0 agents would be false."""
        self.assertIn("Unknown", self.html)
        self.assertIn("predates metadata capture", self.html)
        self.assertNotIn(">0s<", self.html)
        self.assertNotIn("Incomplete", self.html)

    def test_findings_still_render(self):
        self.assertIn('class="finding"', self.html)


class TestEmpty(_Base):
    def test_empty_dir_produces_valid_document(self):
        html = render_html(Path(tempfile.mkdtemp()))
        self.assertTrue(html.startswith("<!doctype html>"))
        self.assertIn("No findings were reported", html)

    def test_write_html_creates_file(self):
        d = self.build()
        out = write_html(d)
        self.assertTrue(out.exists())
        self.assertEqual(out.name, "SCAN_REPORT.html")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestPdfExport(_Base):
    """The PDF path is the browser's print engine — no bundled library.

    Guards the pieces that make the printed output correct rather than merely
    present: a forced-light palette, colour that survives printing, expanded
    detail sections, and an honest banner when the view is filtered.
    """

    def setUp(self):
        self.html = render_html(self.build())

    def test_button_present(self):
        self.assertIn('id="pdfBtn"', self.html)
        self.assertIn("Save as PDF", self.html)

    def test_no_bundled_pdf_library(self):
        """A PDF lib would add ~500KB and break the offline guarantee."""
        for lib in ("jspdf", "jsPDF", "html2canvas", "html2pdf", "pdfmake"):
            self.assertNotIn(lib, self.html)
        self.assertLess(len(self.html), 200_000)

    def test_page_box_and_print_block(self):
        self.assertIn("@page", self.html)
        self.assertIn("@media print", self.html)

    def test_print_forces_light_palette(self):
        """Dark theme must not print — it wastes ink and reads badly."""
        block = self.html.split("@media print{", 1)[1]
        self.assertIn(":root[data-theme]", block)
        self.assertIn("--surface-1:#ffffff", block)
        self.assertIn("--text-primary:#000000", block)

    def test_severity_colour_survives_printing(self):
        """Browsers drop backgrounds when printing; severity IS the encoding."""
        self.assertIn("print-color-adjust:exact", self.html)
        block = self.html.split("@media print{", 1)[1]
        for sel in (".meter i", ".sevtag", ".glyph"):
            self.assertIn(sel, block)

    def test_interactive_chrome_hidden_in_print(self):
        block = self.html.split("@media print{", 1)[1]
        for sel in (".controls", "button.tgl", "button.pdf", "#expandBtn"):
            self.assertIn(sel, block)

    def test_details_expanded_for_print(self):
        # CSS belt …
        block = self.html.split("@media print{", 1)[1]
        self.assertIn(".fbody{display:block}", block.replace(" ", ""))
        # … and the beforeprint braces, which restore reader state afterwards
        self.assertIn("beforeprint", self.html)
        self.assertIn("afterprint", self.html)
        self.assertIn("d.open=true", self.html.replace(" ", ""))

    def test_filtered_export_is_disclosed(self):
        """A filtered PDF that looks complete would understate the findings."""
        self.assertIn('id="printNote"', self.html)
        self.assertIn("Filtered view", self.html)
        self.assertIn("printnote{display:none", self.html.replace(" ", ""))

    def test_findings_avoid_page_breaks(self):
        block = self.html.split("@media print{", 1)[1]
        self.assertIn("break-inside:avoid", block)

    def test_title_carries_target_and_date_for_filename(self):
        # Browsers derive the default PDF filename from <title>.
        title = self.html.split("<title>")[1].split("</title>")[0]
        self.assertIn("Scan report", title)
        self.assertRegex(title, r"\d{4}-\d{2}-\d{2}")


class TestStaleRefresh(_Base):
    """SCAN_REPORT.html is a generated snapshot — renderer changes must reach
    reports that already exist, not only new scans."""

    def test_fresh_report_carries_stamp(self):
        from vhlocal.render_html import RENDERER_VERSION, write_html
        d = self.build()
        write_html(d)
        html = (d / "SCAN_REPORT.html").read_text(encoding="utf-8")
        self.assertIn("vhlocal-report/" + RENDERER_VERSION, html)

    def test_missing_html_is_stale(self):
        from vhlocal.render_html import is_stale
        self.assertTrue(is_stale(self.build()))

    def test_old_renderer_output_is_stale(self):
        from vhlocal.render_html import is_stale
        d = self.build()
        (d / "SCAN_REPORT.html").write_text(
            '<!doctype html><meta name="generator" content="vhlocal-report/1">',
            encoding="utf-8")
        self.assertTrue(is_stale(d))

    def test_current_output_is_not_stale(self):
        from vhlocal.render_html import ensure_fresh, is_stale
        d = self.build()
        ensure_fresh(d)
        self.assertFalse(is_stale(d))

    def test_ensure_fresh_rewrites_only_when_stale(self):
        from vhlocal.render_html import ensure_fresh
        d = self.build()
        self.assertTrue(ensure_fresh(d))    # first call renders
        self.assertFalse(ensure_fresh(d))   # second is a no-op

    def test_ensure_fresh_upgrades_old_output(self):
        from vhlocal.render_html import RENDERER_VERSION, ensure_fresh
        d = self.build()
        (d / "SCAN_REPORT.html").write_text("<!doctype html><p>old</p>", encoding="utf-8")
        self.assertTrue(ensure_fresh(d))
        html = (d / "SCAN_REPORT.html").read_text(encoding="utf-8")
        self.assertIn("vhlocal-report/" + RENDERER_VERSION, html)
        self.assertIn('id="pdfBtn"', html)
