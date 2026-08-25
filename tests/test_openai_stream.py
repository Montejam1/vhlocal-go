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

    def test_openrouter_defaults_to_streaming_and_fail_fast(self):
        c = OpenRouterClient("z-ai/glm-5.3", api_key="k")
        self.assertTrue(c.stream)
        self.assertTrue(c.fail_fast_connection)


class FailFast(unittest.TestCase):
    """A paid backend must not re-bill two more long calls into a dead transport:
    a connection/timeout failure raises on the first attempt, not the third."""

    def _client(self, fail_fast, exc):
        c = OpenAIClient("m", stream=True, fail_fast_connection=fail_fast,
                         max_retries=3)
        c.attempts = 0

        def fake_urlopen(req, timeout=None):
            c.attempts += 1
            raise exc
        return c, fake_urlopen

    def test_paid_raises_after_one_attempt(self):
        import urllib.request
        c, fake = self._client(True, TimeoutError("stalled"))
        orig = urllib.request.urlopen
        urllib.request.urlopen = fake
        try:
            with self.assertRaises(OllamaError) as ctx:
                c._post("/v1/chat/completions", {"messages": []})
        finally:
            urllib.request.urlopen = orig
        self.assertEqual(c.attempts, 1)             # no re-billed retries
        self.assertEqual(ctx.exception.kind, "timeout")

    def test_local_retries_all_attempts(self):
        import urllib.request
        c, fake = self._client(False, TimeoutError("stalled"))
        c.max_retries = 3
        orig = urllib.request.urlopen
        urllib.request.urlopen = fake
        # avoid real backoff sleeps
        import vhlocal.openai_client as mod
        orig_sleep = mod.time.sleep
        mod.time.sleep = lambda s: None
        try:
            with self.assertRaises(OllamaError):
                c._post("/v1/chat/completions", {"messages": []})
        finally:
            urllib.request.urlopen = orig
            mod.time.sleep = orig_sleep
        self.assertEqual(c.attempts, 3)             # retried to the cap


if __name__ == "__main__":
    unittest.main()
