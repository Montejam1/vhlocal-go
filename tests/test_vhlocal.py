"""Tests for the local harness. Stdlib unittest — no pytest needed.

    cd vulnhunt-local && python3 -m unittest discover -s tests -v

Coverage is focused on the logic that fails *silently*: partition parsing
(a miss costs 80% of Phase 2 coverage with no error), sandbox enforcement,
and context pruning. Those are the places a bug looks like a working run.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.agent import _estimate_tokens, _prune  # noqa: E402
from vhlocal.phases import (  # noqa: E402
    CLASS_GROUPS,
    PHASES,
    build_system,
    load_preamble,
    normalize_text,
    parse_partitions,
)
from vhlocal.tools import Sandbox, ToolError, call_tool  # noqa: E402


class TestNormalize(unittest.TestCase):
    def test_folds_unicode_hyphens(self):
        # U+2011 is what gpt-oss actually emits for "SG-1".
        self.assertEqual(normalize_text("SG‑1"), "SG-1")
        for cp in (0x2010, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212):
            self.assertEqual(normalize_text("a" + chr(cp) + "b"), "a-b")

    def test_folds_spaces_and_quotes(self):
        self.assertEqual(normalize_text("a b"), "a b")
        self.assertEqual(normalize_text("“x”"), '"x"')

    def test_ascii_unchanged(self):
        self.assertEqual(normalize_text("SG-1 | plain"), "SG-1 | plain")


class TestPartitionParsing(unittest.TestCase):
    def _write(self, body):
        tmp = Path(tempfile.mkdtemp()) / "phase1_output.md"
        tmp.write_text(body, encoding="utf-8")
        return tmp

    def test_parses_ascii_table(self):
        p = self._write(
            "### Subgraph Partitions\n"
            "| Partition | Inputs | Entry Points |\n"
            "|---|---|---|\n"
            "| SG-1 | #1 | GET /a |\n"
            "| SG-2 | #2 | GET /b |\n"
        )
        got = parse_partitions(p)
        self.assertEqual([x.ident for x in got], ["SG-1", "SG-2"])

    def test_parses_unicode_hyphen_table(self):
        """The regression that silently cut Phase 2 from 16 agents to 3."""
        p = self._write(
            "### Subgraph Partitions\n"
            "| Partition | Inputs |\n|---|---|\n"
            "| SG‑1 | #1 |\n| SG‑2 | #2 |\n| SG‑3 | #3 |\n"
        )
        got = parse_partitions(p)
        self.assertEqual([x.ident for x in got], ["SG-1", "SG-2", "SG-3"])

    def test_dedupes_and_caps(self):
        rows = "".join("| SG-{0} | x |\n".format(i) for i in range(1, 13))
        p = self._write("### Subgraph Partitions\n|P|I|\n|---|---|\n" + rows)
        got = parse_partitions(p, max_partitions=4)
        self.assertEqual(len(got), 4)

    def test_missing_file_falls_back(self):
        got = parse_partitions(Path("/nonexistent/phase1_output.md"))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].ident, "SG-1")

    def test_unparseable_falls_back_not_crash(self):
        p = self._write("no table here at all")
        got = parse_partitions(p)
        self.assertEqual(len(got), 1)

    def test_slug_is_filename_safe(self):
        p = self._write("### Subgraph Partitions\n|P|I|\n|---|---|\n| SG-7 | x |\n")
        self.assertEqual(parse_partitions(p)[0].slug, "sg-7")


class TestSandbox(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        (self.root / "repo").mkdir()
        (self.root / "out").mkdir()
        (self.root / "repo" / "a.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
        (self.root / "secret.txt").write_text("TOPSECRET", encoding="utf-8")
        self.sb = Sandbox([self.root / "repo"], self.root / "out")

    def test_read_inside_root_ok(self):
        out = call_tool(self.sb, "Read", {"file_path": str(self.root / "repo" / "a.py")})
        self.assertIn("x = 1", out)

    def test_read_outside_root_blocked(self):
        out = call_tool(self.sb, "Read", {"file_path": str(self.root / "secret.txt")})
        self.assertTrue(out.startswith("ERROR"))
        self.assertNotIn("TOPSECRET", out)

    def test_traversal_blocked(self):
        out = call_tool(
            self.sb, "Read", {"file_path": str(self.root / "repo" / ".." / "secret.txt")}
        )
        self.assertTrue(out.startswith("ERROR"))
        self.assertNotIn("TOPSECRET", out)

    def test_write_outside_results_blocked(self):
        out = call_tool(
            self.sb, "Write", {"file_path": str(self.root / "repo" / "evil.py"), "content": "x"}
        )
        self.assertTrue(out.startswith("ERROR"))
        self.assertFalse((self.root / "repo" / "evil.py").exists())

    def test_write_inside_results_ok(self):
        out = call_tool(self.sb, "Write", {"file_path": "note.md", "content": "hello"})
        self.assertFalse(out.startswith("ERROR"))
        self.assertEqual((self.root / "out" / "note.md").read_text(), "hello")

    def test_write_creates_subdirs(self):
        call_tool(self.sb, "Write", {"file_path": "results/x/y.md", "content": "z"})
        self.assertTrue((self.root / "out" / "results" / "x" / "y.md").exists())

    def test_read_has_line_numbers(self):
        out = call_tool(self.sb, "Read", {"file_path": str(self.root / "repo" / "a.py")})
        self.assertIn("1\t", out)


class TestToolAliases(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        (self.root / "f.py").write_text("hello\n", encoding="utf-8")
        self.sb = Sandbox([self.root], self.root)

    def test_lowercase_name_accepted(self):
        # gpt-oss emits `glob` / `read` rather than `Glob` / `Read`.
        self.assertFalse(call_tool(self.sb, "glob", {"pattern": "*.py"}).startswith("ERROR"))
        self.assertFalse(
            call_tool(self.sb, "read", {"file_path": str(self.root / "f.py")}).startswith("ERROR")
        )

    def test_snake_case_alias_accepted(self):
        out = call_tool(self.sb, "read_file", {"file_path": str(self.root / "f.py")})
        self.assertIn("hello", out)

    def test_unknown_tool_returns_error_not_raise(self):
        self.assertTrue(call_tool(self.sb, "nope", {}).startswith("ERROR"))

    def test_bad_args_returns_error_not_raise(self):
        self.assertTrue(call_tool(self.sb, "Read", {"wrong": 1}).startswith("ERROR"))

    def test_grep_finds_content(self):
        out = call_tool(self.sb, "Grep", {"pattern": "hello"})
        self.assertIn("f.py", out)


class TestPruning(unittest.TestCase):
    def _msgs(self, n_tool=20, size=4000):
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "task"},
        ]
        for i in range(n_tool):
            msgs.append({"role": "assistant", "content": "", "tool_calls": [{"f": i}]})
            msgs.append({"role": "tool", "tool_name": "Read", "content": "x" * size})
        return msgs

    def test_prune_reduces_estimate(self):
        msgs = self._msgs()
        before = _estimate_tokens(msgs)
        _prune(msgs, budget_tokens=before // 3)
        self.assertLess(_estimate_tokens(msgs), before)

    def test_prune_preserves_system_and_task(self):
        msgs = self._msgs()
        _prune(msgs, budget_tokens=100)
        self.assertEqual(msgs[0]["content"], "sys")
        self.assertEqual(msgs[1]["content"], "task")

    def test_prune_only_evicts_tool_messages(self):
        msgs = self._msgs()
        _prune(msgs, budget_tokens=100)
        for m in msgs:
            if m["role"] == "assistant":
                self.assertIn("tool_calls", m)

    def test_prune_terminates_when_nothing_left(self):
        msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
        self.assertEqual(_prune(msgs, budget_tokens=1), 0)


class TestPhaseWiring(unittest.TestCase):
    def test_phase_keys_unique_and_expected(self):
        keys = [p.key for p in PHASES]
        self.assertEqual(keys, ["1", "2", "2b", "3", "3d", "4"])
        self.assertEqual(len(set(keys)), len(keys))

    def test_exactly_one_fan_out_phase(self):
        self.assertEqual(sum(1 for p in PHASES if p.fan_out), 1)

    def test_three_class_groups(self):
        self.assertEqual(len(CLASS_GROUPS), 3)

    def test_preamble_extracted_from_real_skill(self):
        skill = Path(__file__).resolve().parent.parent.parent / "vulnhunt"
        if not (skill / "SKILL.md").exists():
            self.skipTest("vulnhunt/SKILL.md not present")
        pre = load_preamble(skill)
        self.assertIn("Operating Principles", pre)
        # The scope exclusions must survive extraction — without them the
        # agent reports findings in node_modules and test fixtures.
        self.assertIn("node_modules", pre)
        self.assertNotIn("## Workflow", pre)
        self.assertIn("Operating Principles", build_system(pre))


if __name__ == "__main__":
    unittest.main(verbosity=2)
