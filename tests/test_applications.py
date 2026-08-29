"""Named applications tie a target's scans, ledger, SBOM and threat model together
under one slug — the SAME slug the vulnerability ledger uses. First scan names it;
later scans of the same path auto-associate; an app discovered from old
reports/ledgers can be named after the fact."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import apps  # noqa: E402
from vhlocal.membank import _slug as ledger_slug  # noqa: E402


class Applications(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._prev = os.environ.get("VHLOCAL_LEDGER_DIR")
        os.environ["VHLOCAL_LEDGER_DIR"] = str(Path(self.dir) / "ledger")

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("VHLOCAL_LEDGER_DIR", None)
        else:
            os.environ["VHLOCAL_LEDGER_DIR"] = self._prev

    def test_slug_matches_ledger_slug(self):
        self.assertEqual(apps.slug_for("/repos/app"), ledger_slug("/repos/app"))

    def test_register_names_on_first_scan(self):
        e = apps.register("/repos/app", name="My App", when=100.0)
        self.assertEqual(e["name"], "My App")
        self.assertEqual(e["slug"], apps.slug_for("/repos/app"))
        self.assertEqual(apps.get_application("/repos/app")["name"], "My App")

    def test_register_defaults_to_folder_name(self):
        e = apps.register("/repos/some-service", when=1.0)
        self.assertEqual(e["name"], "some-service")

    def test_register_is_idempotent_keeps_name(self):
        apps.register("/repos/app", name="First", when=100.0)
        # a later scan with no name must NOT clobber the chosen name
        e = apps.register("/repos/app", name="", when=200.0)
        self.assertEqual(e["name"], "First")
        self.assertEqual(e["updated"], 200.0)

    def test_register_can_update_name(self):
        apps.register("/repos/app", name="First", when=1.0)
        e = apps.register("/repos/app", name="Second", when=2.0)
        self.assertEqual(e["name"], "Second")

    def test_set_name_creates_for_autodiscovered_slug(self):
        # An app never registered (only known via reports/ledger) is named by slug.
        slug = apps.slug_for("/repos/ghost")
        self.assertIsNone(apps.get_by_slug(slug))
        e = apps.set_name(slug, "Ghost App", repo="/repos/ghost", when=5.0)
        self.assertEqual(e["name"], "Ghost App")
        self.assertEqual(apps.get_by_slug(slug)["name"], "Ghost App")

    def test_set_name_blank_rejected(self):
        slug = apps.slug_for("/repos/app")
        self.assertIsNone(apps.set_name(slug, "   "))

    def test_list_newest_first(self):
        apps.register("/repos/a", name="A", when=100.0)
        apps.register("/repos/b", name="B", when=300.0)
        apps.register("/repos/c", name="C", when=200.0)
        self.assertEqual([a["name"] for a in apps.list_applications()], ["B", "C", "A"])

    def test_valid_slug_guard(self):
        self.assertTrue(apps.is_valid_slug("app-0278b681"))
        self.assertFalse(apps.is_valid_slug("../../etc/passwd"))
        self.assertFalse(apps.is_valid_slug("a/b"))
        self.assertFalse(apps.is_valid_slug(""))


class ReportSlug(unittest.TestCase):
    def test_report_carries_matching_slug(self):
        import json
        from vhlocal.reports import parse_report
        from vhlocal.engine import SCAN_META_FILE
        d = Path(tempfile.mkdtemp())
        (d / SCAN_META_FILE).write_text(json.dumps({"repo": "/repos/app", "model": "m"}),
                                        encoding="utf-8")
        rep = parse_report(d)
        # the report's slug must equal the application/ledger slug of its repo
        self.assertEqual(rep.slug, apps.slug_for("/repos/app"))


if __name__ == "__main__":
    unittest.main()
