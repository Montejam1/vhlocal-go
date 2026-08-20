"""Regression tests for the crash where one bad agent killed the whole scan.

A local model deep into a long session degrades into malformed tool-call JSON;
Ollama rejects it with HTTP 500 `error parsing tool call`. The client exhausts
retries and raised OllamaError, which propagated up and crashed the job —
losing every phase already written to disk. These tests pin the fix: a failing
agent ends the agent, not the scan.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.agent import AgentResult, run_agent  # noqa: E402
from vhlocal.client import OllamaError, Usage  # noqa: E402
from vhlocal.tools import Sandbox  # noqa: E402


class _ParseErrorClient:
    """Stands in for OllamaClient. Every chat() raises the parse-error 500 the
    real server returns when the model emits malformed tool-call JSON."""
    model = "stub"
    num_ctx = 131072

    def __init__(self, kind="parse"):
        self.usage = Usage()
        self._kind = kind

    def chat(self, messages, tools=None, repair_hint=""):
        raise OllamaError(
            "Ollama HTTP 500: error parsing tool call: raw='...'", kind=self._kind)


class TestOllamaErrorKinds(unittest.TestCase):
    def test_parse_error_not_systemic(self):
        e = OllamaError("x", kind="parse")
        self.assertFalse(e.systemic)

    def test_connection_error_is_systemic(self):
        e = OllamaError("x", kind="connection")
        self.assertTrue(e.systemic)

    def test_default_kind(self):
        self.assertEqual(OllamaError("x").kind, "unknown")


class TestAgentSurvivesClientError(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "repo").mkdir()
        (self.tmp / "out").mkdir()
        self.sb = Sandbox([self.tmp / "repo"], self.tmp / "out")

    def test_parse_error_returns_failed_result_not_raise(self):
        """The exact crash: chat() raises, run_agent must NOT propagate."""
        res = run_agent(_ParseErrorClient("parse"), self.sb, "sys", "task",
                        max_turns=5, label="t")
        self.assertIsInstance(res, AgentResult)
        self.assertEqual(res.stopped_reason, "error")
        self.assertFalse(res.systemic)
        self.assertIn("parsing tool call", res.error)

    def test_connection_error_flagged_systemic(self):
        res = run_agent(_ParseErrorClient("connection"), self.sb, "sys", "task",
                        max_turns=5, label="t")
        self.assertEqual(res.stopped_reason, "error")
        self.assertTrue(res.systemic)

    def test_no_exception_escapes(self):
        try:
            run_agent(_ParseErrorClient("parse"), self.sb, "sys", "task",
                      max_turns=5, label="t")
        except OllamaError:
            self.fail("OllamaError escaped run_agent — the scan would crash")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestScanFinalizesDespiteFailures(unittest.TestCase):
    """End to end: even if the model fails every call, execute_scan must return
    normally, write scan_meta.json, and generate the consolidated report."""

    def _run(self, kind):
        import tempfile, json
        from unittest import mock
        from vhlocal import engine
        repo = Path(tempfile.mkdtemp()) / "app"
        (repo / "app").mkdir(parents=True)
        (repo / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
        out = Path(tempfile.mkdtemp()) / "results"
        skill = Path(__file__).resolve().parent.parent.parent / "vulnhunt"
        if not (skill / "phases").is_dir():
            self.skipTest("vulnhunt skill dir not present")

        events = []
        # Patch the client so preflight passes but every chat() fails.
        with mock.patch.object(engine, "make_client") as MC:
            inst = MC.return_value
            inst.model = "stub"; inst.num_ctx = 131072
            inst.preflight.return_value = None
            inst.usage = engine.Usage()
            inst.chat.side_effect = OllamaError(
                "Ollama HTTP 500: error parsing tool call", kind=kind)
            spec = engine.ScanSpec(repo=repo, skill_dir=skill, out=out)
            result = engine.execute_scan(spec, on_event=events.append,
                                         attach_log_handler=False)
        return result, out, events

    def test_parse_failures_still_finalize(self):
        """No crash; report + meta written even though every agent failed."""
        result, out, events = self._run("parse")
        self.assertTrue((out / "scan_meta.json").exists())
        self.assertTrue((out / "SCAN_REPORT.md").exists())
        self.assertTrue((out / "SCAN_REPORT.html").exists())
        self.assertTrue(any(e["type"] == "scan_done" for e in events))

    def test_systemic_failure_aborts_but_finalizes(self):
        """Connection failure ends the run early — but still writes the report
        and records the abort, rather than grinding every phase or crashing."""
        result, out, events = self._run("connection")
        self.assertTrue((out / "scan_meta.json").exists())
        import json
        meta = json.loads((out / "scan_meta.json").read_text())
        self.assertTrue(meta.get("aborted"))
        done = [e for e in events if e["type"] == "scan_done"][0]
        self.assertTrue(done.get("aborted"))
        # It must NOT have run all six phases into a dead endpoint.
        self.assertLess(len(meta.get("phases_completed", [])), 6)


class TestFreshContextRepair(unittest.TestCase):
    """The repair converts a malformed tool call into a valid one in a fresh,
    minimal context — without replaying the large context that produced it."""

    def _client(self, post_sequence):
        """OllamaClient whose _post yields the given results/exceptions in turn."""
        from vhlocal.client import OllamaClient
        c = OllamaClient(model="stub", repair_attempts=2)
        self.calls = []
        seq = iter(post_sequence)

        def fake_post(path, body):
            self.calls.append(body)
            item = next(seq)
            if isinstance(item, Exception):
                raise item
            return item

        c._post = fake_post
        return c

    def _parse_err(self):
        return OllamaError(
            "Ollama HTTP 500: error parsing tool call: "
            "raw='{\"content\":\"x\\r\"}', err=invalid character",
            kind="parse")

    def _good(self):
        return {"message": {"content": "", "tool_calls": [
            {"function": {"name": "Write",
                          "arguments": {"file_path": "/out/x.md", "content": "ok"}}}]},
                "prompt_eval_count": 200, "eval_count": 40, "total_duration": 1e9}

    def test_repair_recovers_malformed_call(self):
        """First _post fails to parse; repair succeeds → chat returns the call."""
        c = self._client([self._parse_err(), self._good()])
        res = c.chat([{"role": "user", "content": "big context"}],
                     tools=[{"type": "function", "function": {"name": "Write"}}],
                     repair_hint="Write under /out")
        self.assertEqual([tc["function"]["name"] for tc in res.tool_calls], ["Write"])

    def test_repair_uses_fresh_minimal_context(self):
        """The repair request must NOT replay the original large context."""
        c = self._client([self._parse_err(), self._good()])
        big = "x" * 5000
        c.chat([{"role": "user", "content": big}],
               tools=[{"type": "function", "function": {"name": "Write"}}])
        # calls[0] = original (contains big); calls[1] = repair (must not)
        self.assertIn(big, str(self.calls[0]))
        self.assertNotIn(big, str(self.calls[1]))
        # repair context is small: system + user only
        self.assertEqual(len(self.calls[1]["messages"]), 2)

    def test_repair_carries_error_and_intent(self):
        c = self._client([self._parse_err(), self._good()])
        c.chat([{"role": "user", "content": "ctx"}],
               tools=[{"type": "function", "function": {"name": "Write"}}])
        repair_user = self.calls[1]["messages"][1]["content"]
        self.assertIn("invalid character", repair_user)   # parser error
        self.assertIn("x\\r", repair_user)                 # the model's intent

    def test_exhausted_repair_raises_parse_error(self):
        """If every repair also fails to parse, the parse error propagates
        (run_agent then turns it into a graceful agent failure)."""
        c = self._client([self._parse_err(), self._parse_err(), self._parse_err()])
        with self.assertRaises(OllamaError) as cm:
            c.chat([{"role": "user", "content": "ctx"}],
                   tools=[{"type": "function", "function": {"name": "Write"}}])
        self.assertEqual(cm.exception.kind, "parse")

    def test_non_parse_error_not_repaired(self):
        """A connection error is systemic — repair must not swallow it."""
        conn = OllamaError("cannot reach", kind="connection")
        c = self._client([conn])
        with self.assertRaises(OllamaError) as cm:
            c.chat([{"role": "user", "content": "ctx"}],
                   tools=[{"type": "function", "function": {"name": "Write"}}])
        self.assertEqual(cm.exception.kind, "connection")
        self.assertEqual(len(self.calls), 1)   # no repair attempted


class TestReasoningEffort(unittest.TestCase):
    """Opt-in reasoning-effort lever: omitted by default (byte-for-byte
    unchanged), passed as `think` only when set."""

    def _capture(self, **kw):
        from vhlocal.client import OllamaClient
        c = OllamaClient(model="stub", **kw)
        bodies = []
        c._post = lambda path, body: (bodies.append(body) or {
            "message": {"content": "ok"},
            "prompt_eval_count": 1, "eval_count": 1, "total_duration": 1})
        c.chat([{"role": "user", "content": "hi"}])
        return bodies[0]

    def test_default_omits_think(self):
        self.assertNotIn("think", self._capture())

    def test_set_effort_passes_think(self):
        self.assertEqual(self._capture(reasoning_effort="low")["think"], "low")
