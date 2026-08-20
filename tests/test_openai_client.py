"""OpenAI-compatible backend — the adapter must be a drop-in for OllamaClient.

Every format difference (string tool-call arguments, tool_call_id linkage,
reasoning field, client-side parse-error detection) is isolated in the client;
the agent loop keeps its internal Ollama-shaped format.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.client import OllamaClient, OllamaError, make_client  # noqa: E402
from vhlocal.openai_client import (  # noqa: E402
    OpenAIClient,
    _base_url,
    _to_openai_messages,
)


class TestFactory(unittest.TestCase):
    def test_default_is_ollama(self):
        self.assertIsInstance(make_client("ollama", model="m"), OllamaClient)

    def test_openai_backend(self):
        c = make_client("openai", model="m", host="http://h:8080")
        self.assertIsInstance(c, OpenAIClient)

    def test_ollama_only_kwargs_filtered(self):
        # keep_alive is Ollama-only; api_key is OpenAI-only. Neither leaks.
        make_client("openai", model="m", host="http://h", keep_alive="9m")
        make_client("ollama", model="m", api_key="secret")


class TestBaseUrl(unittest.TestCase):
    def test_strips_trailing_v1_and_slash(self):
        self.assertEqual(_base_url("http://h:8080/v1/"), "http://h:8080")
        self.assertEqual(_base_url("http://h:8080/"), "http://h:8080")
        self.assertEqual(_base_url("http://h:8080"), "http://h:8080")


class TestMessageTranslation(unittest.TestCase):
    def test_tool_call_args_stringified_and_linked(self):
        internal = [
            {"role": "user", "content": "hi", "_evicted": True},
            {"role": "assistant", "content": "",
             "tool_calls": [{"function": {"name": "Read",
                                          "arguments": {"file_path": "a.py"}}}]},
            {"role": "tool", "tool_name": "Read", "content": "data"},
        ]
        oa = _to_openai_messages(internal)
        # internal bookkeeping key stripped
        self.assertNotIn("_evicted", oa[0])
        # arguments are a JSON string on the wire
        args = oa[1]["tool_calls"][0]["function"]["arguments"]
        self.assertIsInstance(args, str)
        self.assertIn("a.py", args)
        # tool result carries the id of the call that produced it
        cid = oa[1]["tool_calls"][0]["id"]
        self.assertEqual(oa[2]["tool_call_id"], cid)

    def test_multiple_calls_link_in_order(self):
        internal = [
            {"role": "assistant", "content": "",
             "tool_calls": [{"function": {"name": "Read", "arguments": {}}},
                            {"function": {"name": "Grep", "arguments": {}}}]},
            {"role": "tool", "tool_name": "Read", "content": "r"},
            {"role": "tool", "tool_name": "Grep", "content": "g"},
        ]
        oa = _to_openai_messages(internal)
        ids = [c["id"] for c in oa[0]["tool_calls"]]
        self.assertEqual(oa[1]["tool_call_id"], ids[0])
        self.assertEqual(oa[2]["tool_call_id"], ids[1])


class TestResponseParsing(unittest.TestCase):
    def _client(self):
        return OpenAIClient(model="m", host="http://h:8080")

    def test_string_args_become_dict(self):
        raw = {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "x", "type": "function", "function": {
                "name": "Write",
                "arguments": '{"file_path": "o.md", "content": "z"}'}}]},
            "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 5}}
        r = self._client()._parse(raw, 1.5)
        self.assertEqual(r.tool_calls[0]["function"]["name"], "Write")
        self.assertEqual(r.tool_calls[0]["function"]["arguments"],
                         {"file_path": "o.md", "content": "z"})
        self.assertEqual(r.prompt_tokens, 50)
        self.assertEqual(r.completion_tokens, 5)
        self.assertEqual(r.seconds, 1.5)

    def test_reasoning_field_captured(self):
        raw = {"choices": [{"message": {"content": "hi", "reasoning": "because"}}],
               "usage": {}}
        self.assertEqual(self._client()._parse(raw, 0.1).thinking, "because")

    def test_malformed_args_raise_parse_error(self):
        raw = {"choices": [{"message": {"tool_calls": [
            {"function": {"name": "W", "arguments": "{not json"}}]}}], "usage": {}}
        with self.assertRaises(OllamaError) as cm:
            self._client()._parse(raw, 0.1)
        self.assertEqual(cm.exception.kind, "parse")
        self.assertIn("not json", cm.exception.bad_output)

    def test_dict_args_passthrough(self):
        # Some servers already return arguments as an object.
        raw = {"choices": [{"message": {"tool_calls": [
            {"function": {"name": "R", "arguments": {"path": "x"}}}]}}], "usage": {}}
        r = self._client()._parse(raw, 0.1)
        self.assertEqual(r.tool_calls[0]["function"]["arguments"], {"path": "x"})


class TestChatIntegration(unittest.TestCase):
    def _client(self, response, **kw):
        c = OpenAIClient(model="m", host="http://h:8080", **kw)
        self.bodies = []
        c._post = lambda path, body: (self.bodies.append((path, body)) or
                                      (response, 0.5))
        return c

    def test_chat_parses_and_accounts_usage(self):
        resp = {"choices": [{"message": {"content": "done"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2}}
        c = self._client(resp)
        r = c.chat([{"role": "user", "content": "go"}])
        self.assertEqual(r.content, "done")
        self.assertEqual(c.usage.prompt_tokens, 10)
        # request went to the OpenAI endpoint
        self.assertEqual(self.bodies[0][0], "/v1/chat/completions")

    def test_reasoning_effort_passed_only_when_set(self):
        resp = {"choices": [{"message": {"content": "x"}}], "usage": {}}
        c = self._client(resp)
        c.chat([{"role": "user", "content": "go"}])
        self.assertNotIn("reasoning_effort", self.bodies[0][1])
        c2 = self._client(resp, reasoning_effort="low")
        c2.chat([{"role": "user", "content": "go"}])
        self.assertEqual(self.bodies[0][1]["reasoning_effort"], "low")


if __name__ == "__main__":
    unittest.main()
