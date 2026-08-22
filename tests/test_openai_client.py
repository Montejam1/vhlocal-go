"""OpenAI-compatible backend — the adapter must be a drop-in for OllamaClient.

Every format difference (string tool-call arguments, tool_call_id linkage,
reasoning field, client-side parse-error detection) is isolated in the client;
the agent loop keeps its internal Ollama-shaped format.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.client import OllamaClient, OllamaError, make_client  # noqa: E402
from vhlocal.openai_client import (  # noqa: E402
    DEFAULT_OPENROUTER_HOST,
    OpenAIClient,
    OpenRouterClient,
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


class TestOpenRouter(unittest.TestCase):
    def _client(self, response, **kw):
        c = OpenRouterClient(model="moonshotai/kimi-k3", api_key="k", **kw)
        self.bodies = []
        c._post = lambda path, body: (self.bodies.append((path, body)) or
                                      (response, 0.5))
        return c

    def test_factory_returns_openrouter_client(self):
        c = make_client("openrouter", model="x")
        self.assertIsInstance(c, OpenRouterClient)
        # fixed cloud host, regardless of any host kwarg being absent
        self.assertEqual(c.host, DEFAULT_OPENROUTER_HOST)

    def test_reasoning_is_nested_object_not_flat(self):
        resp = {"choices": [{"message": {"content": "x"}}], "usage": {}}
        # unset -> no reasoning at all
        self._client(resp).chat([{"role": "user", "content": "go"}])
        self.assertNotIn("reasoning", self.bodies[0][1])
        self.assertNotIn("reasoning_effort", self.bodies[0][1])
        # set -> nested {"effort": ...}, never the flat OpenAI key
        self._client(resp, reasoning_effort="high").chat([{"role": "user", "content": "go"}])
        self.assertEqual(self.bodies[0][1]["reasoning"], {"effort": "high"})
        self.assertNotIn("reasoning_effort", self.bodies[0][1])

    def test_key_from_env_never_from_kwargs_leak(self):
        # The factory must NOT thread api_key through (it would land in a spec).
        c = make_client("openrouter", model="x", api_key="should_be_ignored")
        self.assertNotEqual(c.api_key, "should_be_ignored")

    def test_preflight_requires_key(self):
        import os
        saved = os.environ.pop("VHLOCAL_OPENROUTER_API_KEY", None)
        try:
            c = OpenRouterClient(model="x", api_key="")
            with self.assertRaises(OllamaError) as cm:
                c.preflight()
            self.assertIn("API key", str(cm.exception))
        finally:
            if saved is not None:
                os.environ["VHLOCAL_OPENROUTER_API_KEY"] = saved

    def test_attribution_headers(self):
        c = OpenRouterClient(model="x", api_key="k")
        h = c._headers()
        self.assertEqual(h["Authorization"], "Bearer k")
        self.assertIn("X-Title", h)

    def test_max_tokens_capped_by_default(self):
        # Every request must cap completion length so a paid gateway does not
        # pre-authorize the model's full output. Default is applied.
        resp = {"choices": [{"message": {"content": "x"}}], "usage": {}}
        self._client(resp).chat([{"role": "user", "content": "go"}])
        self.assertEqual(self.bodies[0][1]["max_tokens"], 32768)
        # explicit override honoured; 0 disables the cap entirely
        self._client(resp, max_tokens=4096).chat([{"role": "user", "content": "go"}])
        self.assertEqual(self.bodies[0][1]["max_tokens"], 4096)
        self._client(resp, max_tokens=0).chat([{"role": "user", "content": "go"}])
        self.assertNotIn("max_tokens", self.bodies[0][1])

    def test_429_retries_instead_of_failing(self):
        import io
        import time as _t
        import urllib.error
        import vhlocal.openai_client as oc
        calls = {"n": 0}
        reset_ms = int((_t.time() + 3) * 1000)
        body = ('{"error":{"message":"Rate limit","metadata":{"headers":'
                '{"X-RateLimit-Reset":"%d"}}}}' % reset_ms).encode()
        ok = {"choices": [{"message": {"content": "recovered"}}], "usage": {}}

        class _Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return json.dumps(ok).encode()

        def flaky(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise urllib.error.HTTPError("u", 429, "Too Many", {}, io.BytesIO(body))
            return _Resp()

        c = OpenRouterClient(model="x", api_key="k", max_retries=3)
        saved_open, saved_sleep = oc.urllib.request.urlopen, oc.time.sleep
        oc.urllib.request.urlopen = flaky
        oc.time.sleep = lambda s: None      # don't actually wait
        try:
            data, _ = c._post("/v1/chat/completions", {})
        finally:
            oc.urllib.request.urlopen = saved_open
            oc.time.sleep = saved_sleep
        self.assertEqual(calls["n"], 2)     # one 429, then a successful retry
        self.assertEqual(data["choices"][0]["message"]["content"], "recovered")

    def test_rate_limit_wait_honors_reset_window(self):
        import time as _t
        from vhlocal.openai_client import _rate_limit_wait

        class _E:
            headers = None
        reset_ms = int((_t.time() + 30) * 1000)
        detail = ('{"error":{"metadata":{"headers":{"X-RateLimit-Reset":"%d"}}}}'
                  % reset_ms)
        w = _rate_limit_wait(_E(), detail, 1)
        self.assertGreater(w, 20)
        self.assertLessEqual(w, 60)   # capped

    def test_402_message_is_clean_and_scrubs_key_url(self):
        import urllib.error
        import io
        body = (b'{"error":{"message":"needs credits, visit '
                b'https://openrouter.ai/keys/SECRETHASH to adjust"}}')

        def boom(url, data=None, timeout=None):
            raise urllib.error.HTTPError(url, 402, "Payment Required", {},
                                         io.BytesIO(body))
        c = OpenRouterClient(model="x", api_key="k", max_retries=1)
        import vhlocal.openai_client as oc
        saved = oc.urllib.request.urlopen
        oc.urllib.request.urlopen = boom
        try:
            with self.assertRaises(OllamaError) as cm:
                c._post("/v1/chat/completions", {})
        finally:
            oc.urllib.request.urlopen = saved
        msg = str(cm.exception)
        self.assertIn("402", msg)
        self.assertIn("credits", msg.lower())
        self.assertNotIn("SECRETHASH", msg)   # key-identifying URL never surfaced

    def test_runtime_key_used_when_no_explicit_key(self):
        from vhlocal.openai_client import set_openrouter_key, get_openrouter_key
        try:
            set_openrouter_key("runtime-key")
            self.assertEqual(get_openrouter_key(), "runtime-key")
            # a client built with no explicit key picks up the runtime one
            self.assertEqual(OpenRouterClient(model="x").api_key, "runtime-key")
        finally:
            set_openrouter_key("")

    def test_runtime_key_never_enters_scan_spec(self):
        # The key must not be reachable through ScanSpec/its dict — that is what
        # gets persisted to jobs.json and returned to the browser.
        from vhlocal.openai_client import set_openrouter_key
        from vhlocal.engine import ScanSpec
        from pathlib import Path
        try:
            set_openrouter_key("secret-should-not-persist")
            spec = ScanSpec(repo=Path("/x"), skill_dir=Path("/y"),
                            backend="openrouter", model="anthropic/claude-fable-5")
            self.assertNotIn("secret-should-not-persist",
                             json.dumps(spec.to_dict()))
            self.assertFalse(hasattr(spec, "api_key"))
        finally:
            set_openrouter_key("")


if __name__ == "__main__":
    unittest.main()
