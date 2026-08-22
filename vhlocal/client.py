"""Ollama native-API client.

Uses ``/api/chat`` rather than the OpenAI-compatible shim because only the
native endpoint accepts ``options.num_ctx``. That matters more than it looks:
Ollama's default context is far smaller than gpt-oss:120b's 131072, and an
over-long prompt is silently truncated rather than rejected. A truncated
phase prompt produces plausible-looking garbage, so num_ctx is always set
explicitly here.

The native endpoint also returns tool-call arguments as a dict (the OpenAI
shim returns them as a JSON string) and separates ``thinking`` from
``content``, both of which simplify the agent loop.

Stdlib only, Python 3.9 compatible — nothing to pip install.
"""

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# Where Ollama lives. Set VHLOCAL_OLLAMA_HOST once (e.g. in your shell profile)
# to point every entry point — CLI, engine, and web UI — at a remote inference
# box without passing --host on each invocation.
DEFAULT_HOST = os.environ.get("VHLOCAL_OLLAMA_HOST", "http://localhost:11434").rstrip("/")
DEFAULT_MODEL = "gpt-oss:120b"
DEFAULT_NUM_CTX = 131072

# Retry on transport hiccups and Ollama's "model is loading" window. A 65GB
# model can take tens of seconds to page in on first use.
_RETRY_STATUSES = (500, 502, 503, 504)


def make_client(backend: str = "ollama", **kwargs):
    """Construct the chat client for the selected backend.

    ``ollama`` (default) → ``OllamaClient`` (native /api/chat).
    ``openai`` → ``OpenAIClient`` — any OpenAI-compatible server: mlx_lm.server
    on Apple Silicon, vLLM on the RTX 6000, LM Studio, etc.

    Both share the same interface, so nothing downstream changes. Backend-only
    kwargs (keep_alive for Ollama, api_key for OpenAI) are filtered per backend.
    """
    common = {k: kwargs[k] for k in
              ("model", "host", "num_ctx", "temperature", "reasoning_effort")
              if k in kwargs}
    # max_tokens is honoured only by the OpenAI/OpenRouter clients (Ollama caps
    # output via context, not a wire field), so it is added per-backend below.
    if backend == "openrouter":
        # Paid OpenAI-compatible cloud gateway. Key comes from the environment
        # inside OpenRouterClient — deliberately not threaded through kwargs so it
        # can never be persisted in a scan spec.
        from .openai_client import OpenRouterClient
        if "max_tokens" in kwargs:
            common["max_tokens"] = kwargs["max_tokens"]
        return OpenRouterClient(**common)
    if backend in ("openai", "mlx", "vllm"):
        from .openai_client import OpenAIClient
        if "api_key" in kwargs:
            common["api_key"] = kwargs["api_key"]
        if "max_tokens" in kwargs:
            common["max_tokens"] = kwargs["max_tokens"]
        return OpenAIClient(**common)
    if "keep_alive" in kwargs:
        common["keep_alive"] = kwargs["keep_alive"]
    return OllamaClient(**common)


class OllamaError(RuntimeError):
    """A failure talking to Ollama, tagged by ``kind`` so callers can react.

    * ``"parse"``      — HTTP 500 ``error parsing tool call``. The request was
                         fine; the *model's* tool-call output was malformed JSON
                         (unescaped control chars, truncation, or plain prose
                         where a tool call was expected). Deep into a long agent
                         session a local model degrades into exactly this. It is
                         a per-response failure, NOT systemic — a fresh agent on
                         a smaller context is unaffected.
    * ``"connection"`` — could not reach the host. Systemic: every subsequent
                         call fails the same way, so there is no point grinding
                         the rest of the scan into a dead endpoint.
    * ``"timeout"`` / ``"http"`` / ``"unknown"`` — other transport failures.
    """

    def __init__(self, message: str, kind: str = "unknown"):
        super().__init__(message)
        self.kind = kind

    @property
    def systemic(self) -> bool:
        """A failure that will recur on every call, not just this one."""
        return self.kind == "connection"

    @property
    def bad_output(self) -> str:
        """The malformed model output (the ``raw='...'`` in a parse error)."""
        m = re.search(r"raw='(.*?)',\s*err=", str(self), re.S)
        return m.group(1) if m else ""

    @property
    def parser_detail(self) -> str:
        """The parser's complaint (the ``err=...`` in a parse error)."""
        m = re.search(r"err=(.*)$", str(self).rstrip("}").rstrip("'"), re.S)
        return m.group(1).strip() if m else ""


@dataclass
class Usage:
    """Cumulative token + wall-clock accounting across a run."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0
    seconds: float = 0.0
    # Highest single-turn prompt size seen. The headroom check in agent.py
    # uses this to warn before we silently run past num_ctx.
    peak_prompt_tokens: int = 0

    def add(self, prompt: int, completion: int, seconds: float) -> None:
        self.prompt_tokens += prompt
        self.completion_tokens += completion
        self.calls += 1
        self.seconds += seconds
        self.peak_prompt_tokens = max(self.peak_prompt_tokens, prompt)

    def merge(self, other: "Usage") -> None:
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.calls += other.calls
        self.seconds += other.seconds
        self.peak_prompt_tokens = max(self.peak_prompt_tokens, other.peak_prompt_tokens)

    def summary(self) -> str:
        tps = self.completion_tokens / self.seconds if self.seconds else 0.0
        return (
            "{calls} calls | {p:,} prompt + {c:,} completion tok | "
            "{s:.1f}s | {tps:.1f} tok/s | peak prompt {peak:,}"
        ).format(
            calls=self.calls,
            p=self.prompt_tokens,
            c=self.completion_tokens,
            s=self.seconds,
            tps=tps,
            peak=self.peak_prompt_tokens,
        )


@dataclass
class ChatResult:
    content: str
    thinking: str
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    seconds: float = 0.0
    done_reason: str = ""


class OllamaClient:
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        host: str = DEFAULT_HOST,
        num_ctx: int = DEFAULT_NUM_CTX,
        temperature: Optional[float] = None,
        timeout: int = 1800,
        max_retries: int = 3,
        keep_alive: str = "60m",
        repair_attempts: int = 2,
        reasoning_effort: Optional[str] = None,
    ):
        self.model = model
        self.host = host.rstrip("/")
        self.num_ctx = num_ctx
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        self.keep_alive = keep_alive
        # Reasoning models (gpt-oss family) accept a reasoning-effort level. None
        # leaves the model at its own default — no behavioural change. A lower
        # level cuts generated reasoning tokens (faster) at some quality cost, so
        # this is opt-in and off by default.
        self.reasoning_effort = reasoning_effort
        # A parse-error 500 means the model's tool-call output was malformed. We
        # do NOT re-send the (large) original request — replaying the context
        # that produced the garbage tends to reproduce it. Instead we repair in
        # a FRESH minimal context. This many fresh attempts before giving up.
        self.repair_attempts = repair_attempts
        self.usage = Usage()

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        repair_hint: str = "",
    ) -> ChatResult:
        options: Dict[str, Any] = {"num_ctx": self.num_ctx}
        if self.temperature is not None:
            options["temperature"] = self.temperature

        # Strip internal bookkeeping keys (e.g. agent.py's `_evicted` marker)
        # so they never reach the API as unknown message fields.
        wire_messages = [
            {k: v for k, v in m.items() if not k.startswith("_")} for m in messages
        ]

        body: Dict[str, Any] = {
            "model": self.model,
            "messages": wire_messages,
            "stream": False,
            "options": options,
            # Ollama evicts an idle model after ~5 minutes by default. A scan
            # runs 16+ agents back to back; any gap longer than that would
            # force a reload of 64GB of weights mid-run. Pin it resident.
            "keep_alive": self.keep_alive,
        }
        # Opt-in reasoning-effort level for gpt-oss-family models. Omitted when
        # None so default runs are byte-for-byte unchanged.
        if self.reasoning_effort:
            body["think"] = self.reasoning_effort
        if tools:
            body["tools"] = tools

        try:
            raw = self._post("/api/chat", body)
        except OllamaError as exc:
            if exc.kind != "parse" or not tools:
                raise
            # The model's tool-call output was malformed. Repair it in a fresh,
            # minimal context instead of replaying the large one that produced
            # the garbage. Returns None if every repair attempt also fails.
            raw = self._repair(exc, tools, options, repair_hint)
            if raw is None:
                raise
        msg = raw.get("message") or {}

        # Ollama reports counts as prompt_eval_count / eval_count, and omits
        # prompt_eval_count entirely when the prefix was served from cache.
        prompt_tok = int(raw.get("prompt_eval_count") or 0)
        completion_tok = int(raw.get("eval_count") or 0)
        seconds = float(raw.get("total_duration") or 0) / 1e9

        self.usage.add(prompt_tok, completion_tok, seconds)

        return ChatResult(
            content=msg.get("content") or "",
            thinking=msg.get("thinking") or "",
            tool_calls=list(msg.get("tool_calls") or []),
            prompt_tokens=prompt_tok,
            completion_tokens=completion_tok,
            seconds=seconds,
            done_reason=raw.get("done_reason") or "",
        )

    def _repair(self, exc, tools, options, repair_hint=""):
        """Recover a malformed tool call in a fresh, minimal context.

        The failing turn happened at the end of a long, degraded context — the
        very condition that broke the model's JSON. So we do NOT replay it.
        Instead we build a tiny context containing only what's needed to re-emit
        the one intended action correctly: the tool schema, the parser's
        complaint, and the model's own malformed attempt (which carries its
        intent — the file it was writing, or the prose describing what it meant
        to do). Returns a raw /api/chat response with a valid tool call, or None
        if the model can't produce one.
        """
        bad = exc.bad_output or "(the model emitted no parsable tool call)"
        detail = exc.parser_detail or "malformed tool call"
        sys_msg = (
            "You emit exactly one tool call and nothing else. Never write prose "
            "instead of a tool call. Never wrap a tool call in prose. Emit valid "
            "JSON: escape newlines as \\n, escape all control characters, and "
            "close every quote and brace."
        )
        user_msg = (
            "Your previous tool call could not be parsed and was discarded.\n\n"
            "Parser error: {err}\n\n"
            "What you emitted (your intended action):\n{bad}\n\n"
            "{hint}"
            "Re-issue that single action now as one valid tool call using the "
            "tools available to you. If the text above is prose describing an "
            "action rather than a tool call, convert it into the matching tool "
            "call. Do not add commentary."
        ).format(err=detail, bad=bad[:2000],
                 hint=(repair_hint + "\n\n") if repair_hint else "")

        for attempt in range(1, self.repair_attempts + 1):
            body = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": sys_msg},
                    {"role": "user", "content": user_msg},
                ],
                "tools": tools,
                "stream": False,
                "options": options,
                "keep_alive": self.keep_alive,
            }
            try:
                raw = self._post("/api/chat", body)
            except OllamaError as rexc:
                log.warning("repair attempt %d/%d failed (%s): %s",
                            attempt, self.repair_attempts, rexc.kind, rexc)
                if rexc.systemic:
                    return None
                continue
            if (raw.get("message") or {}).get("tool_calls"):
                log.info("recovered malformed tool call via fresh-context repair "
                         "(attempt %d)", attempt)
                return raw
            # No tool call in the repair either; try again.
        return None

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        url = self.host + path
        payload = json.dumps(body).encode("utf-8")
        last_err = None

        for attempt in range(1, self.max_retries + 1):
            req = urllib.request.Request(
                url, data=payload, headers={"Content-Type": "application/json"}
            )
            started = time.time()
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", "replace")[:500]
                except Exception:
                    pass
                # "error parsing tool call" is a malformed *model response*, not
                # a bad request. Retrying can recover it via sampling variance
                # (the model may emit valid JSON next time), so it stays in the
                # retry loop — but it is tagged "parse" so an exhausted retry
                # fails just this agent rather than reading as a server outage.
                kind = "parse" if "parsing tool call" in detail else "http"
                # A parse error is a bad *model response*, not a transient server
                # fault — re-sending the identical body just reproduces it. Raise
                # immediately so chat() can repair in a fresh context instead.
                if kind == "parse" or exc.code not in _RETRY_STATUSES:
                    raise OllamaError(
                        "Ollama HTTP {0}: {1}".format(exc.code, detail), kind=kind
                    ) from exc
                last_err = OllamaError(
                    "Ollama HTTP {0}: {1}".format(exc.code, detail), kind=kind
                )
            except urllib.error.URLError as exc:
                last_err = OllamaError(
                    "cannot reach Ollama at {0}: {1}. Is `ollama serve` "
                    "running?".format(self.host, exc.reason),
                    kind="connection",
                )
            except (TimeoutError, OSError) as exc:
                last_err = OllamaError(
                    "Ollama request failed after {0:.0f}s: {1}".format(
                        time.time() - started, exc
                    ),
                    kind="timeout",
                )

            if attempt < self.max_retries:
                backoff = 5 * attempt
                log.warning(
                    "ollama call failed (attempt %d/%d): %s — retrying in %ds",
                    attempt,
                    self.max_retries,
                    last_err,
                    backoff,
                )
                time.sleep(backoff)

        raise last_err if last_err else OllamaError("unknown Ollama failure")

    def preflight(self) -> None:
        """Fail fast with an actionable message before a long run starts."""
        try:
            req = urllib.request.Request(self.host + "/api/tags")
            with urllib.request.urlopen(req, timeout=10) as resp:
                tags = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise OllamaError(
                "cannot reach Ollama at {0}: {1}\nStart it with `ollama serve`.".format(
                    self.host, exc
                )
            )

        names = [m.get("name", "") for m in tags.get("models", [])]
        # Ollama reports "gpt-oss:120b"; accept a bare name without the tag too.
        if self.model not in names and not any(
            n.split(":")[0] == self.model.split(":")[0] for n in names
        ):
            raise OllamaError(
                "model {0!r} not found in Ollama.\nAvailable: {1}\n"
                "Pull it with `ollama pull {0}`.".format(self.model, ", ".join(names))
            )
