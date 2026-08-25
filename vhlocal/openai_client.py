"""OpenAI-compatible chat client — for `mlx_lm.server`, vLLM, LM Studio, etc.

Presents the *same* interface as ``OllamaClient`` (``chat`` / ``preflight`` /
``.usage`` / ``.model`` / ``.reasoning_effort`` …), so the engine selects a
backend by config with no other change. Every format difference is isolated
here — the agent loop keeps speaking its internal Ollama-shaped message format:

* endpoint ``/v1/chat/completions`` instead of ``/api/chat``;
* tool-call ``arguments`` are JSON *strings* on the wire (dicts internally);
* tool results need a ``tool_call_id`` linking them to the call that produced
  them (the internal format links by order), reconstructed here;
* a malformed tool call surfaces as an unparseable ``arguments`` string on an
  otherwise-200 response (not Ollama's HTTP 500), detected client-side and
  repaired in a fresh minimal context, exactly like the Ollama path;
* no server-side timing, so wall-clock is used for usage accounting.

Stdlib only, Python 3.9 compatible.
"""

import http.client
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .client import ChatResult, OllamaError, Usage

log = logging.getLogger(__name__)

DEFAULT_OPENAI_HOST = os.environ.get(
    "VHLOCAL_OPENAI_HOST", "http://localhost:8080").rstrip("/")

# OpenRouter is an OpenAI-compatible *cloud* gateway (paid, per-token). Same wire
# format as any OpenAI server, so it reuses OpenAIClient; only the fixed host,
# the bearer key, the nested `reasoning` object, and attribution headers differ.
DEFAULT_OPENROUTER_HOST = "https://openrouter.ai/api"
OPENROUTER_KEY_ENV = "VHLOCAL_OPENROUTER_API_KEY"

# The OpenRouter key may be set at runtime (from the UI) instead of the
# environment. It is held in process memory ONLY — never written to a scan spec,
# jobs.json, scan_meta.json, or the log — so a paid credential never lands on
# disk. The env var remains the fallback for headless use.
_RUNTIME_OPENROUTER_KEY = {"key": ""}


def set_openrouter_key(key: str) -> None:
    _RUNTIME_OPENROUTER_KEY["key"] = (key or "").strip()


def get_openrouter_key() -> str:
    return _RUNTIME_OPENROUTER_KEY["key"] or os.environ.get(OPENROUTER_KEY_ENV, "")


def _base_url(host: str) -> str:
    """Normalise a base URL: strip a trailing ``/v1`` and slashes so we can add
    ``/v1/chat/completions`` ourselves without doubling it."""
    h = (host or DEFAULT_OPENAI_HOST).rstrip("/")
    if h.endswith("/v1"):
        h = h[:-3]
    return h


def _rate_limit_wait(exc, detail: str, attempt: int) -> float:
    """Seconds to wait before retrying a 429, honoring the provider's reset
    window. Capped to a sane range so a bad/garbage header can't stall a scan."""
    def cap(s):
        return max(2.0, min(float(s), 60.0))
    # 1) Standard Retry-After response header (seconds).
    try:
        hdrs = getattr(exc, "headers", None)
        ra = hdrs.get("Retry-After") if hdrs else None
        if ra:
            return cap(ra)
    except (ValueError, TypeError):
        pass
    # 2) X-RateLimit-Reset (epoch, ms or s) from the body. Regex, not json.loads,
    #    so a truncated error body still yields the reset value.
    m = re.search(r'X-RateLimit-Reset"?\s*:\s*"?(\d{10,16})', detail or "")
    if m:
        try:
            val = float(m.group(1))
            reset_epoch = val / 1000.0 if val > 1e12 else val
            secs = reset_epoch - time.time()
            if secs > 0:
                return cap(secs)
        except (ValueError, TypeError):
            pass
    # 3) Fallback: grow with the attempt number.
    return cap(10.0 * attempt)


def _to_openai_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Translate the agent loop's internal (Ollama-shaped) history to OpenAI wire
    format: string tool-call arguments and tool_call_id-linked tool results."""
    out: List[Dict[str, Any]] = []
    pending_ids: List[str] = []   # ids of the current turn's calls, in order
    counter = 0
    for m in messages:
        m = {k: v for k, v in m.items() if not k.startswith("_")}
        role = m.get("role")
        if role == "assistant" and m.get("tool_calls"):
            calls = []
            pending_ids = []
            for tc in m["tool_calls"]:
                fn = tc.get("function") or {}
                cid = tc.get("id") or "call_{0}".format(counter)
                counter += 1
                pending_ids.append(cid)
                args = fn.get("arguments")
                if not isinstance(args, str):
                    args = json.dumps(args or {})
                calls.append({
                    "id": cid, "type": "function",
                    "function": {"name": fn.get("name") or "", "arguments": args},
                })
            out.append({"role": "assistant",
                        "content": m.get("content") or "", "tool_calls": calls})
        elif role == "tool":
            cid = pending_ids.pop(0) if pending_ids else "call_0"
            out.append({"role": "tool", "tool_call_id": cid,
                        "content": m.get("content") or ""})
        else:
            out.append({"role": role, "content": m.get("content") or ""})
    return out


class OpenAIClient:
    def __init__(
        self,
        model: str,
        host: str = DEFAULT_OPENAI_HOST,
        num_ctx: int = 131072,
        temperature: Optional[float] = None,
        timeout: int = 1800,
        max_retries: int = 3,
        repair_attempts: int = 2,
        reasoning_effort: Optional[str] = None,
        api_key: Optional[str] = None,
        max_tokens: int = 32768,
        stream: bool = True,
        fail_fast_connection: bool = False,
    ):
        self.model = model
        self.host = _base_url(host)
        # Stream the completion (SSE). Deep-thinking models on a paid gateway can
        # hold a single non-streaming request open for 10-20 minutes; an idle
        # connection that long is routinely dropped by the gateway's edge and any
        # intermediary proxy, which surfaced as whole agents failing with no
        # output. Streaming keeps bytes flowing so the connection is never idle,
        # and captures the tokens already generated instead of discarding them.
        self.stream = bool(stream)
        # Paid backends: a transport failure (connection reset / stall) should NOT
        # be retried 2 more times — each retry is another billed long call into
        # the same wall. Surface it fast and let the canary / circuit breaker
        # decide, rather than tripling the spend on a doomed call.
        self.fail_fast_connection = bool(fail_fast_connection)
        # Cap the completion length. Critical for paid gateways (OpenRouter):
        # without it they pre-authorize the model's FULL max output (e.g. 65k
        # tokens) against your balance on every call — a 402 on a modest balance.
        # 0 disables the cap. The harness's real per-call output is small; this
        # headroom also covers a reasoning model's thinking tokens.
        self.max_tokens = int(max_tokens or 0)
        # Kept for agent.py's context-headroom warning only; the OpenAI server
        # fixes its context at load time, so it is never sent in a request.
        self.num_ctx = num_ctx
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        self.repair_attempts = repair_attempts
        self.reasoning_effort = reasoning_effort
        self.api_key = api_key or os.environ.get("VHLOCAL_OPENAI_API_KEY", "")
        self.usage = Usage()
        # USD per token, for the budget cap. 0 for local/self-hosted (free);
        # OpenRouterClient resolves real prices via resolve_pricing().
        self.price_prompt = 0.0
        self.price_completion = 0.0

    def resolve_pricing(self) -> None:
        """No-op for a local/self-hosted OpenAI-compatible server (free)."""
        return

    # ---------------- request building ----------------

    def _body(self, messages, tools) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "model": self.model, "messages": messages, "stream": self.stream,
        }
        if self.stream:
            # Ask the server to emit a final usage chunk; without it a streamed
            # response carries no token counts (standard OpenAI streaming option).
            body["stream_options"] = {"include_usage": True}
        if self.max_tokens > 0:
            body["max_tokens"] = self.max_tokens
        if self.temperature is not None:
            body["temperature"] = self.temperature
        if tools:
            body["tools"] = tools
        # Best-effort: servers that support gpt-oss reasoning honour this;
        # others ignore an unknown field. Omitted when None.
        if self.reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort
        return body

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        repair_hint: str = "",
    ) -> ChatResult:
        body = self._body(_to_openai_messages(messages), tools)
        try:
            raw, seconds = self._post("/v1/chat/completions", body)
            result = self._parse(raw, seconds)
        except OllamaError as exc:
            if exc.kind != "parse" or not tools:
                raise
            result = self._repair(exc, tools, repair_hint)
            if result is None:
                raise
        self.usage.add(result.prompt_tokens, result.completion_tokens, result.seconds)
        return result

    # ---------------- response parsing ----------------

    def _parse(self, raw: Dict[str, Any], seconds: float) -> ChatResult:
        choices = raw.get("choices") or []
        if not choices:
            raise OllamaError("OpenAI response had no choices", kind="http")
        choice = choices[0]
        msg = choice.get("message") or {}
        # gpt-oss reasoning surfaces under different keys across servers.
        thinking = msg.get("reasoning") or msg.get("reasoning_content") or ""

        internal_calls: List[Dict[str, Any]] = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            name = fn.get("name") or ""
            args = fn.get("arguments")
            if isinstance(args, dict):
                parsed = args
            elif args in (None, ""):
                parsed = {}
            else:
                try:
                    parsed = json.loads(args)
                except (ValueError, TypeError) as exc:
                    # A malformed tool call — the OpenAI analogue of Ollama's
                    # "error parsing tool call". Formatted so OllamaError's
                    # bad_output/parser_detail parse it and the shared repair
                    # flow applies.
                    raise OllamaError(
                        "tool-call parse: raw='{0}', err={1}".format(args, exc),
                        kind="parse")
            internal_calls.append({"function": {"name": name, "arguments": parsed}})

        usage = raw.get("usage") or {}
        prompt_tok = int(usage.get("prompt_tokens") or 0)
        completion_tok = int(usage.get("completion_tokens") or 0)
        return ChatResult(
            content=msg.get("content") or "",
            thinking=thinking,
            tool_calls=internal_calls,
            prompt_tokens=prompt_tok,
            completion_tokens=completion_tok,
            seconds=seconds,
            done_reason=choice.get("finish_reason") or "",
        )

    def _repair(self, exc, tools, repair_hint=""):
        """Fresh-context repair of a malformed tool call — mirrors OllamaClient."""
        bad = exc.bad_output or "(no parsable tool call)"
        detail = exc.parser_detail or "malformed tool call"
        sys_msg = (
            "You emit exactly one tool call and nothing else. Emit valid JSON "
            "arguments: escape newlines as \\n, escape all control characters, "
            "and close every quote and brace.")
        user_msg = (
            "Your previous tool call could not be parsed and was discarded.\n\n"
            "Parser error: {err}\n\nWhat you emitted:\n{bad}\n\n{hint}"
            "Re-issue that single action now as one valid tool call.").format(
                err=detail, bad=bad[:2000],
                hint=(repair_hint + "\n\n") if repair_hint else "")
        msgs = [{"role": "system", "content": sys_msg},
                {"role": "user", "content": user_msg}]
        for attempt in range(1, self.repair_attempts + 1):
            try:
                raw, seconds = self._post("/v1/chat/completions",
                                          self._body(msgs, tools))
                result = self._parse(raw, seconds)
            except OllamaError as rexc:
                log.warning("repair attempt %d/%d failed (%s): %s",
                            attempt, self.repair_attempts, rexc.kind, rexc)
                if rexc.systemic:
                    return None
                continue
            if result.tool_calls:
                log.info("recovered malformed tool call via fresh-context repair "
                         "(attempt %d)", attempt)
                return result
        return None

    # ---------------- transport ----------------

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = "Bearer " + self.api_key
        return h

    def _read_stream(self, resp) -> Dict[str, Any]:
        """Assemble an SSE completion stream back into a single non-streamed
        response dict, so ``_parse`` handles it unchanged. Accumulates content,
        reasoning, and per-index tool-call argument fragments; keepalive comment
        lines (``: ...``) are what keep the connection from going idle. Falls back
        to parsing a whole-body JSON if the server ignored ``stream`` and replied
        with a normal completion."""
        content, reasoning = [], []
        calls: Dict[int, Dict[str, Any]] = {}
        finish_reason = ""
        usage: Dict[str, Any] = {}
        saw_sse = False
        buf: List[str] = []
        for raw_line in resp:
            line = raw_line.decode("utf-8", "replace")
            buf.append(line)
            line = line.strip()
            if not line or line.startswith(":"):
                continue   # blank separator or keepalive comment
            if not line.startswith("data:"):
                continue
            saw_sse = True
            data_str = line[5:].strip()
            if data_str == "[DONE]":
                break
            try:
                chunk = json.loads(data_str)
            except ValueError:
                continue
            if chunk.get("usage"):
                usage = chunk["usage"]
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                if delta.get("content"):
                    content.append(delta["content"])
                r = delta.get("reasoning") or delta.get("reasoning_content")
                if r:
                    reasoning.append(r)
                for tc in delta.get("tool_calls") or []:
                    idx = tc.get("index", 0)
                    slot = calls.setdefault(idx, {"id": "", "name": "", "args": []})
                    if tc.get("id"):
                        slot["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        slot["name"] = fn["name"]
                    if fn.get("arguments"):
                        slot["args"].append(fn["arguments"])
                if choice.get("finish_reason"):
                    finish_reason = choice["finish_reason"]
        if not saw_sse:
            # Server ignored stream=True and returned a normal body.
            try:
                return json.loads("".join(buf))
            except ValueError:
                pass
        tool_calls = []
        for idx in sorted(calls):
            s = calls[idx]
            tool_calls.append({
                "id": s["id"] or "call_{0}".format(idx), "type": "function",
                "function": {"name": s["name"], "arguments": "".join(s["args"])},
            })
        msg: Dict[str, Any] = {"content": "".join(content),
                               "reasoning": "".join(reasoning)}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        return {"choices": [{"message": msg, "finish_reason": finish_reason}],
                "usage": usage}

    def _post(self, path: str, body: Dict[str, Any]):
        url = self.host + path
        payload = json.dumps(body).encode("utf-8")
        last_err = None
        for attempt in range(1, self.max_retries + 1):
            req = urllib.request.Request(url, data=payload, headers=self._headers())
            started = time.time()
            wait = None   # per-attempt backoff override (rate limits set this)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if self.stream:
                        data = self._read_stream(resp)
                    else:
                        data = json.loads(resp.read().decode("utf-8"))
                return data, time.time() - started
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", "replace")[:500]
                except Exception:
                    pass
                if exc.code == 402:
                    # Insufficient credits. Don't dump the body — it echoes a
                    # key-identifying settings URL that would land in the log.
                    raise OllamaError(
                        "HTTP 402: insufficient OpenRouter credits (or the key's "
                        "monthly limit). Add credits, raise the key limit, or "
                        "lower 'Max output tokens'.", kind="http")
                if exc.code == 429:
                    # Transient rate limit — back off (honoring the reset window)
                    # and retry rather than failing the agent. A popular model on
                    # OpenRouter's shared pool caps RPM across ALL users.
                    wait = _rate_limit_wait(exc, detail, attempt)
                    last_err = OllamaError(
                        "HTTP 429: rate limited (shared capacity for this model). "
                        "Lower concurrency, add your own provider key on "
                        "OpenRouter, or pick a less-throttled model.",
                        kind="rate_limit")
                else:
                    # Scrub any URL from the surfaced detail so a key-settings
                    # link never reaches the log verbatim.
                    detail = re.sub(r"https?://\S+", "<url>", detail)
                    if exc.code not in (500, 502, 503, 504):
                        raise OllamaError(
                            "OpenAI HTTP {0}: {1}".format(exc.code, detail),
                            kind="http")
                    last_err = OllamaError(
                        "OpenAI HTTP {0}: {1}".format(exc.code, detail), kind="http")
            except urllib.error.URLError as exc:
                last_err = OllamaError(
                    "cannot reach OpenAI-compatible server at {0}: {1}. Is it "
                    "running (e.g. `mlx_lm.server`)?".format(self.host, exc.reason),
                    kind="connection")
            except http.client.IncompleteRead as exc:
                # The stream was cut off mid-body (a dropped connection). Kept
                # NON-systemic ("timeout") on purpose: one truncated stream must
                # not hard-abort the whole hunt — the circuit breaker halts on a
                # *storm*, and the canary catches a wholly-broken transport up
                # front. A genuine can't-reach is the URLError case above.
                last_err = OllamaError(
                    "stream from {0} truncated after {1:.0f}s: {2}".format(
                        self.host, time.time() - started, exc), kind="timeout")
            except (TimeoutError, OSError) as exc:
                # ConnectionReset/Aborted/BrokenPipe (OSError subclasses) and bare
                # timeouts are transient transport failures the breaker/canary act
                # on — non-systemic so a single blip doesn't kill the run.
                last_err = OllamaError(
                    "request to {0} failed after {1:.0f}s: {2}".format(
                        self.host, time.time() - started, exc), kind="timeout")
            # Connection resets / timeouts on a paid gateway are usually TRANSIENT
            # (GLM/OpenRouter drops a slow-thinking call, the next one succeeds), so
            # we retry them like any other backend rather than failing the agent on
            # the first blip — that was killing whole runs on a merely flaky
            # endpoint. Runaway spend is bounded by the budget cap and the circuit
            # breaker, not by refusing to retry.
            if attempt < self.max_retries:
                backoff = wait if wait is not None else 5 * attempt
                log.warning("openai call failed (attempt %d/%d): %s — retrying "
                            "in %.0fs", attempt, self.max_retries, last_err, backoff)
                time.sleep(backoff)
        raise last_err if last_err else OllamaError("unknown backend failure")

    def preflight(self) -> None:
        try:
            req = urllib.request.Request(self.host + "/v1/models",
                                         headers=self._headers())
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise OllamaError(
                "cannot reach OpenAI-compatible server at {0}: {1}\nStart one "
                "with e.g. `mlx_lm.server --model {2}`.".format(
                    self.host, exc, self.model))
        names = [m.get("id", "") for m in (data.get("data") or [])]
        # Lenient: many servers report a path or a single loaded model.
        if names and self.model not in names and not any(
                self.model.split(":")[0] in n for n in names):
            log.warning("model %r not in server list %s — proceeding anyway",
                        self.model, names)


class OpenRouterClient(OpenAIClient):
    """OpenAI-compatible client aimed at OpenRouter (https://openrouter.ai).

    A *paid cloud* backend: requests leave the machine and bill your OpenRouter
    account per token. The key comes from ``$VHLOCAL_OPENROUTER_API_KEY`` — it is
    never accepted over the wire, stored in a scan's spec, or written to disk.
    """

    def __init__(self, model, host=None, api_key=None, **kw):
        # A paid gateway can be flaky (intermittent connection resets on a slow
        # thinking model). Retry a bit more than a local server so a single reset
        # doesn't end an agent; the budget cap + circuit breaker bound the downside.
        kw.setdefault("max_retries", 5)
        super().__init__(
            model,
            host=host or DEFAULT_OPENROUTER_HOST,
            # Runtime key (UI) or the env var — resolved at construction, never
            # passed in from a persisted spec.
            api_key=api_key or get_openrouter_key(),
            **kw)

    def _body(self, messages, tools):
        body = super()._body(messages, tools)
        # OpenRouter takes a nested reasoning object, not the top-level
        # `reasoning_effort` OpenAI servers use. Translate; omit when unset so the
        # model keeps its own default.
        body.pop("reasoning_effort", None)
        if self.reasoning_effort:
            body["reasoning"] = {"effort": self.reasoning_effort}
        return body

    def _headers(self):
        h = super()._headers()
        # Optional OpenRouter attribution — harmless if ignored.
        h["X-Title"] = "vhlocal"
        h["HTTP-Referer"] = "https://github.com/vulnhunter/vhlocal"
        return h

    def resolve_pricing(self) -> None:
        """Fetch this model's per-token USD price from OpenRouter (best-effort)."""
        from .pricing import openrouter_pricing
        self.price_prompt, self.price_completion = openrouter_pricing(
            self.model, self.host)

    def preflight(self):
        if not self.api_key:
            raise OllamaError(
                "OpenRouter API key not set. Enter it in Settings, or export {0} "
                "before launching the engine.".format(OPENROUTER_KEY_ENV))
        super().preflight()
