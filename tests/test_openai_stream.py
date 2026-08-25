"""Streaming transport for the OpenAI/OpenRouter client, plus the paid-backend
fail-fast. Deep-thinking models on a paid gateway hold a single non-streaming
request open long enough that the connection gets idle-killed mid-call — whole
agents died with no output. Streaming keeps bytes flowing (and captures the tokens
already generated); these tests pin the SSE reassembly and the fail-fast."""

import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.openai_client import OpenAIClient, OpenRouterClient  # noqa: E402
from vhlocal.client import OllamaError  # noqa: E402


def _sse(*events):
    """Encode dicts as an SSE body (list of bytes lines), with a keepalive comment
    and a terminating [DONE], the way OpenRouter streams."""
    lines = [b": OPENROUTER PROCESSING\n"]
    for ev in events:
        lines.append(("data: " + json.dumps(ev) + "\n").encode("utf-8"))
    lines.append(b"data: [DONE]\n")
    return lines


class StreamReassembly(unittest.TestCase):
    def setUp(self):
        self.c = OpenAIClient("m", stream=True)

    def test_content_reasoning_and_usage(self):
        raw = self.c._read_stream(iter(_sse(
            {"choices": [{"delta": {"reasoning": "hmm"}}]},
            {"choices": [{"delta": {"content": "Hel"}}]},
            {"choices": [{"delta": {"content": "lo"}}]},
            {"choices": [{"finish_reason": "stop"}]},
            {"usage": {"prompt_tokens": 11, "completion_tokens": 7}},
        )))
        res = self.c._parse(raw, 1.0)
        self.assertEqual(res.content, "Hello")
        self.assertEqual(res.thinking, "hmm")
        self.assertEqual((res.prompt_tokens, res.completion_tokens), (11, 7))
        self.assertEqual(res.done_reason, "stop")

    def test_tool_call_assembled_across_chunks(self):
        # A tool call arrives with id/name on the first fragment and its arguments
        # string split across several deltas — must reassemble into one call.
        raw = self.c._read_stream(iter(_sse(
            {"choices": [{"delta": {"tool_calls": [
                {"index": 0, "id": "call_x",
                 "function": {"name": "Read", "arguments": '{"path":'}}]}}]},
            {"choices": [{"delta": {"tool_calls": [
                {"index": 0, "function": {"arguments": ' "a.py"}'}}]}}]},
            {"choices": [{"finish_reason": "tool_calls"}]},
        )))
        res = self.c._parse(raw, 1.0)
        self.assertEqual(len(res.tool_calls), 1)
        call = res.tool_calls[0]["function"]
        self.assertEqual(call["name"], "Read")
        self.assertEqual(call["arguments"], {"path": "a.py"})   # parsed by _parse

    def test_two_parallel_tool_calls_kept_separate(self):
        raw = self.c._read_stream(iter(_sse(
            {"choices": [{"delta": {"tool_calls": [
                {"index": 0, "id": "a", "function": {"name": "Read",
                 "arguments": '{"path":"a"}'}},
                {"index": 1, "id": "b", "function": {"name": "Grep",
                 "arguments": '{"q":"x"}'}}]}}]},
        )))
        res = self.c._parse(raw, 1.0)
        names = sorted(c["function"]["name"] for c in res.tool_calls)
        self.assertEqual(names, ["Grep", "Read"])

    def test_non_sse_body_fallback(self):
        # A server that ignores stream=True returns a normal completion body.
        body = json.dumps({"choices": [{"message": {"content": "hi"}}],
                           "usage": {"prompt_tokens": 3, "completion_tokens": 1}})
        raw = self.c._read_stream(iter([body.encode("utf-8")]))
        res = self.c._parse(raw, 1.0)
        self.assertEqual(res.content, "hi")
        self.assertEqual(res.prompt_tokens, 3)

    def test_malformed_data_line_skipped_not_fatal(self):
        raw = self.c._read_stream(iter([
            b": keepalive\n",
            b"data: {not json\n",
            b'data: {"choices":[{"delta":{"content":"ok"}}]}\n',
            b"data: [DONE]\n",
        ]))
        self.assertEqual(self.c._parse(raw, 1.0).content, "ok")


class Body(unittest.TestCase):
    def test_streaming_body_requests_usage(self):
        c = OpenAIClient("m", stream=True)
        b = c._body([{"role": "user", "content": "hi"}], None)
        self.assertTrue(b["stream"])
        self.assertEqual(b["stream_options"], {"include_usage": True})

    def test_non_streaming_body_has_no_stream_options(self):
        c = OpenAIClient("m", stream=False)
        b = c._body([{"role": "user", "content": "hi"}], None)
        self.assertFalse(b["stream"])
        self.assertNotIn("stream_options", b)

    def test_openrouter_streams_and_retries_more(self):
        c = OpenRouterClient("z-ai/glm-5.3", api_key="k")
        self.assertTrue(c.stream)
        self.assertGreaterEqual(c.max_retries, 5)   # flaky-endpoint resilience


class TransientRetry(unittest.TestCase):
    """Connection resets / timeouts are TRANSIENT — a paid gateway dropping a slow
    call recovers on retry — so they must be retried, not fail the agent on the
    first blip. (The budget cap + circuit breaker bound the runaway case.)"""

    def _client(self, exc, max_retries=5):
        c = OpenAIClient("m", stream=True, max_retries=max_retries)
        c.attempts = 0

        def fake_urlopen(req, timeout=None):
            c.attempts += 1
            raise exc
        return c, fake_urlopen

    def _run(self, c, fake):
        import urllib.request
        import vhlocal.openai_client as mod
        orig, orig_sleep = urllib.request.urlopen, mod.time.sleep
        urllib.request.urlopen = fake
        mod.time.sleep = lambda s: None
        try:
            with self.assertRaises(OllamaError):
                c._post("/v1/chat/completions", {"messages": []})
        finally:
            urllib.request.urlopen = orig
            mod.time.sleep = orig_sleep

    def test_connection_reset_retried_to_cap(self):
        c, fake = self._client(ConnectionResetError("reset by peer"), max_retries=5)
        self._run(c, fake)
        self.assertEqual(c.attempts, 5)             # retried, not failed on #1

    def test_timeout_retried_to_cap(self):
        c, fake = self._client(TimeoutError("stalled"), max_retries=3)
        self._run(c, fake)
        self.assertEqual(c.attempts, 3)

    def test_transient_then_success_recovers(self):
        # First call resets, the retry succeeds — the agent must NOT die.
        import urllib.request
        import vhlocal.openai_client as mod
        c = OpenAIClient("m", stream=True, max_retries=5)
        c.attempts = 0
        ok = {"choices": [{"message": {"content": "hi"}}], "usage": {}}

        class _Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def __iter__(self): return iter([json.dumps(ok).encode()])

        def flaky(req, timeout=None):
            c.attempts += 1
            if c.attempts == 1:
                raise ConnectionResetError("reset by peer")
            return _Resp()
        orig, orig_sleep = urllib.request.urlopen, mod.time.sleep
        urllib.request.urlopen = flaky
        mod.time.sleep = lambda s: None
        try:
            data, _ = c._post("/v1/chat/completions", {"messages": []})
        finally:
            urllib.request.urlopen = orig
            mod.time.sleep = orig_sleep
        self.assertEqual(c.attempts, 2)
        self.assertEqual(data["choices"][0]["message"]["content"], "hi")


if __name__ == "__main__":
    unittest.main()
