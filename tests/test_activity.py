"""The centralized activity log — a structured, append-only audit trail of
notable actions (scans, apps, reports, threat models), distinct from the raw
engine text log. Appends must be best-effort (never raise) and reads must be
newest-first and filterable."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import activity as A  # noqa: E402


class Activity(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.file = str(Path(self.dir) / "activity.jsonl")
        self._prev = os.environ.get("VHLOCAL_ACTIVITY_FILE")
        os.environ["VHLOCAL_ACTIVITY_FILE"] = self.file

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("VHLOCAL_ACTIVITY_FILE", None)
        else:
            os.environ["VHLOCAL_ACTIVITY_FILE"] = self._prev

    def test_record_and_recent_newest_first(self):
        A.record("scan.started", "a", ts=100.0)
        A.record("scan.completed", "b", ts=200.0)
        ev = A.recent()
        self.assertEqual([e["type"] for e in ev], ["scan.completed", "scan.started"])
        self.assertEqual(ev[0]["message"], "b")

    def test_none_fields_dropped(self):
        A.record("x", "m", findings=None, model="gpt", ts=1.0)
        e = A.recent()[0]
        self.assertNotIn("findings", e)
        self.assertEqual(e["model"], "gpt")

    def test_filters(self):
        A.record("scan.started", ts=1.0, scan="j1")
        A.record("app.forgotten", ts=2.0, app="s1")
        A.record("scan.completed", ts=3.0, scan="j2")
        self.assertEqual([e["type"] for e in A.recent(type_prefix="scan")],
                         ["scan.completed", "scan.started"])
        self.assertEqual(len(A.recent(scan="j1")), 1)
        self.assertEqual(len(A.recent(since=2.5)), 1)

    def test_limit(self):
        for i in range(10):
            A.record("e", ts=float(i))
        self.assertEqual(len(A.recent(limit=3)), 3)

    def test_recent_empty_when_no_file(self):
        os.environ["VHLOCAL_ACTIVITY_FILE"] = str(Path(self.dir) / "nope.jsonl")
        self.assertEqual(A.recent(), [])

    def test_corrupt_line_skipped(self):
        Path(self.file).write_text('{"type":"ok","ts":1}\nNOT JSON\n{"type":"ok2","ts":2}\n',
                                   encoding="utf-8")
        self.assertEqual([e["type"] for e in A.recent()], ["ok2", "ok"])

    def test_scan_finished_maps_status_to_type(self):
        A.scan_finished("j", "done", "/r/app", "m", findings=3)
        self.assertEqual(A.recent()[0]["type"], "scan.completed")
        A.scan_finished("j", "cancelled", "/r/app", "m")
        self.assertEqual(A.recent()[0]["type"], "scan.cancelled")
        A.scan_finished("j", "failed", "/r/app", "m")
        self.assertEqual(A.recent()[0]["type"], "scan.failed")

    def test_scan_finished_message_has_findings_only_when_done(self):
        A.scan_finished("j", "done", "/r/app", "m", findings=5)
        self.assertIn("5 findings", A.recent()[0]["message"])
        A.scan_finished("j", "cancelled", "/r/app", "m", findings=5)
        self.assertNotIn("5 findings", A.recent()[0]["message"])

    def test_record_never_raises_on_bad_path(self):
        # A directory that can't be created → silently no-op, not an exception.
        os.environ["VHLOCAL_ACTIVITY_FILE"] = "/proc/nonexistent/x/activity.jsonl"
        try:
            A.record("x", "m")  # must not raise
        except Exception as e:  # pragma: no cover
            self.fail("record raised: {0}".format(e))


class CentralLogRead(unittest.TestCase):
    def test_read_central_log_filters(self):
        from vhlocal.logsetup import read_central_log
        d = Path(tempfile.mkdtemp())
        log = d / "vhlocal.log"
        log.write_text(
            "2026-01-01 00:00:00 INFO    [scanA] recon start\n"
            "2026-01-01 00:00:01 WARNING [scanA] coverage degraded\n"
            "2026-01-01 00:00:02 INFO    [scanB] hunt start\n"
            "2026-01-01 00:00:03 ERROR   [scanB] agent failed\n",
            encoding="utf-8")
        # scan filter
        a = read_central_log(scan="scanA", log_file=log)
        self.assertIn("recon start", a)
        self.assertNotIn("hunt start", a)
        # level floor (WARNING+)
        w = read_central_log(level="WARNING", log_file=log)
        self.assertIn("coverage degraded", w)
        self.assertIn("agent failed", w)
        self.assertNotIn("recon start", w)
        # tail
        t = read_central_log(tail=1, log_file=log)
        self.assertEqual(t.strip().splitlines()[-1].count("agent failed"), 1)


if __name__ == "__main__":
    unittest.main()
