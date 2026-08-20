"""Tests for centralized logging."""

import logging
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import vhlocal.logsetup as L  # noqa: E402


def _reset():
    """Tear down the process-global vhlocal logger between tests."""
    lg = logging.getLogger(L.LOGGER_NAME)
    for h in list(lg.handlers):
        lg.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass
    L._configured = False
    L.set_scan(None)


class TestConfigure(unittest.TestCase):
    def setUp(self):
        _reset()
        self.addCleanup(_reset)
        self.log = Path(tempfile.mkdtemp()) / "central.log"

    def test_writes_to_central_file(self):
        L.configure_logging(0, log_file=self.log)
        logging.getLogger("vhlocal").info("hello world")
        self.assertTrue(self.log.exists())
        self.assertIn("hello world", self.log.read_text())

    def test_line_carries_scan_tag(self):
        L.configure_logging(0, log_file=self.log)
        with L.scan_context("2026-08-16-115632"):
            logging.getLogger("vhlocal.engine").info("inside a scan")
        logging.getLogger("vhlocal").info("outside a scan")
        text = self.log.read_text()
        self.assertIn("[2026-08-16-115632] inside a scan", text)
        self.assertIn("[-] outside a scan", text)

    def test_idempotent_no_duplicate_handlers(self):
        L.configure_logging(0, log_file=self.log)
        L.configure_logging(0, log_file=self.log)
        L.configure_logging(1, log_file=self.log)
        lg = logging.getLogger("vhlocal")
        from logging.handlers import RotatingFileHandler
        files = [h for h in lg.handlers if isinstance(h, RotatingFileHandler)]
        streams = [h for h in lg.handlers
                   if isinstance(h, logging.StreamHandler)
                   and not isinstance(h, RotatingFileHandler)]
        self.assertEqual(len(files), 1)
        self.assertEqual(len(streams), 1)

    def test_scan_context_restores_previous(self):
        L.set_scan("outer")
        with L.scan_context("inner"):
            self.assertEqual(L.current_scan(), "inner")
        self.assertEqual(L.current_scan(), "outer")

    def test_does_not_propagate_to_root(self):
        L.configure_logging(0, log_file=self.log)
        self.assertFalse(logging.getLogger("vhlocal").propagate)


class TestScanLines(unittest.TestCase):
    def setUp(self):
        _reset()
        self.addCleanup(_reset)
        self.log = Path(tempfile.mkdtemp()) / "central.log"

    def test_slices_one_scan(self):
        L.configure_logging(0, log_file=self.log)
        with L.scan_context("AAA"):
            logging.getLogger("vhlocal").info("line a1")
            logging.getLogger("vhlocal").info("line a2")
        with L.scan_context("BBB"):
            logging.getLogger("vhlocal").info("line b1")
        for h in logging.getLogger("vhlocal").handlers:
            h.flush()
        out = L.scan_lines("AAA", log_file=self.log)
        self.assertIn("line a1", out)
        self.assertIn("line a2", out)
        self.assertNotIn("line b1", out)

    def test_default_log_file_env(self):
        import os
        os.environ["VHLOCAL_LOG_FILE"] = "/tmp/x/custom.log"
        try:
            self.assertEqual(L.default_log_file(), Path("/tmp/x/custom.log"))
        finally:
            del os.environ["VHLOCAL_LOG_FILE"]


class TestEngineTagsRun(unittest.TestCase):
    """A scan tags its central-log lines and writes NO per-scan file."""

    def setUp(self):
        _reset()
        self.addCleanup(_reset)

    def test_no_per_scan_logfile_and_meta_records_tag(self):
        import json
        from unittest import mock
        from vhlocal import engine
        central = Path(tempfile.mkdtemp()) / "central.log"
        L.configure_logging(0, log_file=central)

        repo = Path(tempfile.mkdtemp()) / "app"
        (repo / "app").mkdir(parents=True)
        (repo / "app" / "main.py").write_text("x=1\n", encoding="utf-8")
        out = Path(tempfile.mkdtemp()) / "res"
        skill = Path(__file__).resolve().parent.parent.parent / "vulnhunt"
        if not (skill / "phases").is_dir():
            self.skipTest("vulnhunt skill dir not present")

        with mock.patch.object(engine, "make_client") as MC:
            inst = MC.return_value
            inst.model = "stub"; inst.num_ctx = 131072
            inst.preflight.return_value = None
            inst.usage = engine.Usage()
            inst.chat.side_effect = engine.OllamaError("boom", kind="parse")
            spec = engine.ScanSpec(repo=repo, skill_dir=skill, out=out, phases="1")
            engine.execute_scan(spec, attach_log_handler=False)

        # No per-scan log file in the results dir.
        self.assertFalse((out / "vhlocal.log").exists())
        # scan_meta records the tag, which is greppable in the central log.
        meta = json.loads((out / "scan_meta.json").read_text())
        self.assertTrue(meta.get("scan_tag"))
        for h in logging.getLogger("vhlocal").handlers:
            h.flush()
        self.assertIn(meta["scan_tag"], central.read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
