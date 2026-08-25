"""Prompt capture — the exact system + per-agent task prompts written to
prompts.jsonl for the UI's Prompts tab."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.engine import _capture_system, _capture_prompt, PROMPTS_FILE  # noqa: E402


class PromptCapture(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def _recs(self):
        p = self.d / PROMPTS_FILE
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def test_system_written_once_as_first_record(self):
        _capture_system(self.d, "THE SYSTEM PROMPT")
        recs = self._recs()
        self.assertEqual(recs[0]["kind"], "system")
        self.assertEqual(recs[0]["prompt"], "THE SYSTEM PROMPT")

    def test_system_is_idempotent(self):
        _capture_system(self.d, "ORIGINAL")
        _capture_system(self.d, "SHOULD NOT OVERWRITE")   # resume-safe
        recs = self._recs()
        self.assertEqual(len([r for r in recs if r["kind"] == "system"]), 1)
        self.assertEqual(recs[0]["prompt"], "ORIGINAL")

    def test_agent_prompts_appended_with_fields(self):
        _capture_system(self.d, "SYS")
        _capture_prompt(self.d, "1", "p1", "recon task")
        _capture_prompt(self.d, "2", "p2:sg-1:all", "hunt task longer")
        agents = [r for r in self._recs() if r["kind"] == "agent"]
        self.assertEqual([a["label"] for a in agents], ["p1", "p2:sg-1:all"])
        self.assertEqual(agents[0]["phase"], "1")
        self.assertEqual(agents[1]["chars"], len("hunt task longer"))
        self.assertEqual(agents[1]["prompt"], "hunt task longer")

    def test_capture_without_system_still_appends(self):
        # Order-independent: the fan-out captures agent prompts even if the
        # system record was written by execute_scan elsewhere.
        _capture_prompt(self.d, "2", "p2:sink", "sink task")
        self.assertEqual(self._recs()[0]["label"], "p2:sink")

    def test_bad_dir_is_silent(self):
        # Never fail a scan over prompt capture.
        _capture_prompt(Path("/nonexistent/dir/xyz"), "1", "p1", "x")
        _capture_system(Path("/nonexistent/dir/xyz"), "x")   # no raise


if __name__ == "__main__":
    unittest.main()
