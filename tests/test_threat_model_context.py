"""When a PASTA threat model was built, its reasoning must reach the downstream
phase prompts — not just the partitioner. The threat model informs partitioning
already; this checks that the hunt / verify / report agents are also told to read
and use it. Gated on threat_model.md existing, so default runs are unchanged."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.engine import _threat_model_note  # noqa: E402


class ThreatModelContext(unittest.TestCase):
    def test_empty_without_threat_model(self):
        d = Path(tempfile.mkdtemp())
        self.assertEqual(_threat_model_note(d), "")

    def test_present_with_threat_model(self):
        d = Path(tempfile.mkdtemp())
        (d / "threat_model.md").write_text("# TM", encoding="utf-8")
        note = _threat_model_note(d)
        self.assertTrue(note)
        # Names the file and frames the three things the agent should use.
        self.assertIn("threat_model.md", note)
        for kw in ("archetype", "threats", "attack paths"):
            self.assertIn(kw, note.lower())

    def test_note_does_not_override_input_tracing(self):
        # It must complement, not replace, the core method (trace input->sink).
        d = Path(tempfile.mkdtemp())
        (d / "threat_model.md").write_text("# TM", encoding="utf-8")
        self.assertIn("does not replace", _threat_model_note(d).lower())


if __name__ == "__main__":
    unittest.main()
