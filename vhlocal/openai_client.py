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

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .client import ChatResult, OllamaError, Usage

log = logging.getLogger(__name__)

DEFAULT_OPENAI_HOST = os.environ.get(
    "VHLOCAL_OPENAI_HOST", "http://localhost:8080").rstrip("/")


def _base_url(host: str) -> str:
    """Normalise a base URL: strip a trailing ``/v1`` and slashes so we can add
    ``/v1/chat/completions`` ourselves without doubling it."""
    h = (host or DEFAULT_OPENAI_HOST).rstrip("/")
    if h.endswith("/v1"):
        h = h[:-3]
    return h


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
    ):
        self.model = model
        self.host = _base_url(host)
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

    # ---------------- request building ----------------

    def _body(self, messages, tools) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "model": self.model, "messages": messages, "stream": False,
        }
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

    def _post(self, path: str, body: Dict[str, Any]):
        url = self.host + path
        payload = json.dumps(body).encode("utf-8")
        last_err = None
        for attempt in range(1, self.max_retries + 1):
            req = urllib.request.Request(url, data=payload, headers=self._headers())
            started = time.time()
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                return data, time.time() - started
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", "replace")[:500]
                except Exception:
                    pass
                if exc.code not in (500, 502, 503, 504):
                    raise OllamaError(
                        "OpenAI HTTP {0}: {1}".format(exc.code, detail), kind="http")
                last_err = OllamaError(
                    "OpenAI HTTP {0}: {1}".format(exc.code, detail), kind="http")
            except urllib.error.URLError as exc:
                last_err = OllamaError(
                    "cannot reach OpenAI-compatible server at {0}: {1}. Is it "
                    "running (e.g. `mlx_lm.server`)?".format(self.host, exc.reason),
                    kind="connection")
            except (TimeoutError, OSError) as exc:
                last_err = OllamaError(
                    "request to {0} failed after {1:.0f}s: {2}".format(
                        self.host, time.time() - started, exc), kind="timeout")
            if attempt < self.max_retries:
                backoff = 5 * attempt
                log.warning("openai call failed (attempt %d/%d): %s — retrying "
                            "in %ds", attempt, self.max_retries, last_err, backoff)
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
