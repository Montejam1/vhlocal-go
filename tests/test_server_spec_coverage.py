"""Guard against the server silently dropping a scan option.

The server's _create_scan builds a ScanSpec with an explicit field list. When a
new option was added to ScanSpec + the UI but NOT to that list (threat_model), the
server dropped it on every scan — the box did nothing and the value was always the
default. This test fails if any body-settable ScanSpec field is missing from the
server's construction, so the two can never drift again."""

import ast
import dataclasses
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.engine import ScanSpec  # noqa: E402

# Fields the server sets from CFG / request context rather than a plain body flag,
# or that the UI deliberately doesn't expose — not expected in the keyword list.
_DERIVED = {
    "repo", "skill_dir", "out", "reports_dir", "host", "backend",
    "temperature",   # no UI/main-model temperature field
}


def _server_scanspec_kwargs():
    """The keyword names passed to ScanSpec(...) inside _create_scan."""
    src = (Path(__file__).resolve().parent.parent / "vhlocal" / "server.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "ScanSpec"):
            return {kw.arg for kw in node.keywords if kw.arg}
    raise AssertionError("no ScanSpec(...) construction found in server.py")


class ServerSpecCoverage(unittest.TestCase):
    def test_every_scanspec_field_is_set_by_the_server(self):
        fields = {f.name for f in dataclasses.fields(ScanSpec)}
        set_by_server = _server_scanspec_kwargs()
        missing = fields - set_by_server - _DERIVED
        self.assertEqual(
            missing, set(),
            "server _create_scan drops these ScanSpec fields (add them to the "
            "ScanSpec(...) construction in server.py): {0}".format(sorted(missing)))

    def test_threat_model_specifically_wired(self):
        # The regression that motivated this test.
        self.assertIn("threat_model", _server_scanspec_kwargs())


if __name__ == "__main__":
    unittest.main()
