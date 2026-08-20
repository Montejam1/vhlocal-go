"""The tool loop — one isolated agent run.

This is the unit that replaces a Claude Code subagent. Each call gets a fresh
message list, so contexts stay isolated exactly as they do under the original
fan-out. Running these sequentially instead of in parallel costs wall-clock,
not quality, because they never shared context in the first place.

Two behaviours here are load-bearing for VulnHunter specifically:

1. **Context pruning.** Traces are long. When the conversation approaches
   num_ctx we evict the oldest *tool results* (never the system prompt, the
   task, or recent turns), because a silently truncated phase prompt produces
   confident nonsense.

2. **Output-file enforcement.** Every VulnHunter phase ends by writing a
   named file, and the orchestrator's contract is "verify the output file
   exists". Local models frequently narrate the answer instead of calling
   Write, so we detect that and nudge before giving up.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .client import ChatResult, OllamaClient, OllamaError, Usage
from .tools import TOOL_SCHEMAS, Sandbox, call_tool

log = logging.getLogger(__name__)

# Leave headroom below num_ctx for the next completion.
CTX_HEADROOM_TOKENS = 12_000
# Rough chars-per-token for local pruning decisions; we only need the order
# of magnitude, and Ollama gives us exact counts after each call.
CHARS_PER_TOKEN = 3.6


@dataclass
class AgentResult:
    final_text: str
    turns: int
    usage: Usage
    wrote_files: List[str] = field(default_factory=list)
    stopped_reason: str = "complete"
    transcript: List[Dict[str, Any]] = field(default_factory=list)
    # Set when stopped_reason == "error": the message, and whether the failure
    # is systemic (will recur on every call — e.g. Ollama unreachable).
    error: str = ""
    systemic: bool = False


def _estimate_tokens(messages: List[Dict[str, Any]]) -> int:
    total = 0
    for m in messages:
        total += len(str(m.get("content") or "")) / CHARS_PER_TOKEN
        for tc in m.get("tool_calls") or []:
            total += len(json.dumps(tc)) / CHARS_PER_TOKEN
    return int(total)


def _prune(messages: List[Dict[str, Any]], budget_tokens: int) -> int:
    """Evict oldest tool results until the estimate fits. Returns count evicted.

    Keeps index 0 (system) and 1 (task) always, plus the last 6 messages so
    the model retains immediate working state. Only 'tool' role messages are
    evicted — dropping an assistant turn would orphan its tool_calls and
    confuse the model about what it already did.
    """
    evicted = 0
    protected_tail = 6
    while _estimate_tokens(messages) > budget_tokens:
        victim = None
        for i in range(2, max(2, len(messages) - protected_tail)):
            # `_evicted` is what stops this loop from spinning forever: without
            # it the placeholder we just wrote is itself role="tool", so it is
            # re-selected on the next pass and the while-loop never terminates
            # once every tool message has been evicted but the estimate is
            # still over budget.
            if messages[i].get("role") == "tool" and not messages[i].get("_evicted"):
                victim = i
                break
        if victim is None:
            break
        content = messages[victim].get("content") or ""
        messages[victim] = {
            "role": "tool",
            "tool_name": messages[victim].get("tool_name", ""),
            "content": "[earlier tool result evicted to free context — {0} chars. "
            "Re-run the tool if you still need it.]".format(len(content)),
            "_evicted": True,
        }
        evicted += 1
    return evicted


def run_agent(
    client: OllamaClient,
    sandbox: Sandbox,
    system: str,
    task: str,
    max_turns: int = 60,
    expect_files: Optional[List[Path]] = None,
    label: str = "agent",
    should_cancel: Optional[Callable[[], bool]] = None,
) -> AgentResult:
    """Run one agent to completion.

    ``expect_files`` are absolute paths the phase contract says must exist when
    the agent finishes. If they're missing we push the agent once more with an
    explicit instruction before declaring failure.
    """
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": task},
    ]
    usage = Usage()
    wrote: List[str] = []
    budget = client.num_ctx - CTX_HEADROOM_TOKENS
    nudged = False
    started = time.time()

    # Grounding for fresh-context tool-call repair (client._repair). A repair
    # runs without the task context, so a Write whose path got truncated in the
    # malformed output would otherwise have nowhere to go — tell it the writable
    # root and the file(s) this phase is expected to produce.
    repair_hint = "Files may be written ONLY under: {0}.".format(sandbox.write_root)
    if expect_files:
        repair_hint += " This phase writes: {0}.".format(
            ", ".join(str(p) for p in expect_files))

    turn = 0
    while turn < max_turns:
        if should_cancel is not None and should_cancel():
            log.warning("[%s] cancelled after %d turns", label, turn)
            return AgentResult(
                final_text="",
                turns=turn,
                usage=usage,
                wrote_files=wrote,
                stopped_reason="cancelled",
                transcript=messages,
            )
        turn += 1

        evicted = _prune(messages, budget)
        if evicted:
            log.warning("[%s] pruned %d old tool result(s) to stay under context", label, evicted)

        try:
            result = client.chat(messages, tools=TOOL_SCHEMAS,
                                  repair_hint=repair_hint)
        except OllamaError as exc:
            # A local model deep into a long session degrades into malformed
            # tool-call JSON that Ollama rejects with HTTP 500. Left unguarded,
            # that exception propagates up and kills the whole scan — losing
            # every phase already written to disk. Instead, end this agent with
            # a failed result and let the pipeline continue: the phase is marked
            # "not produced", downstream phases degrade, and the consolidated
            # report is still generated from what completed.
            log.error("[%s] ollama error after %d turns (%s): %s",
                      label, turn, exc.kind, exc)
            return AgentResult(
                final_text="", turns=turn, usage=usage, wrote_files=wrote,
                stopped_reason="error", transcript=messages,
                error=str(exc), systemic=exc.systemic,
            )
        usage.add(result.prompt_tokens, result.completion_tokens, result.seconds)

        if result.prompt_tokens and result.prompt_tokens > budget:
            log.warning(
                "[%s] prompt %d tok exceeds budget %d — output may be degraded",
                label, result.prompt_tokens, budget,
            )

        if not result.tool_calls:
            # No tool call: the model believes it is finished.
            missing = [p for p in (expect_files or []) if not p.exists()]
            if missing and not nudged:
                nudged = True
                log.warning(
                    "[%s] finished without writing %s — nudging",
                    label, ", ".join(p.name for p in missing),
                )
                messages.append({"role": "assistant", "content": result.content})
                messages.append({
                    "role": "user",
                    "content": (
                        "You have not written the required output file(s): {0}\n"
                        "Do not summarise in chat. Call the Write tool now with "
                        "the exact path(s) above and the full content your "
                        "instructions specify.".format(
                            ", ".join(str(p) for p in missing)
                        )
                    ),
                })
                continue

            log.info(
                "[%s] done in %d turns, %.0fs — %s",
                label, turn, time.time() - started, usage.summary(),
            )
            return AgentResult(
                final_text=result.content,
                turns=turn,
                usage=usage,
                wrote_files=wrote,
                stopped_reason="complete" if not missing else "missing_output",
                transcript=messages,
            )

        # Record the assistant turn verbatim so the model sees its own calls.
        messages.append({
            "role": "assistant",
            "content": result.content,
            "tool_calls": result.tool_calls,
        })

        for tc in result.tool_calls:
            fn = tc.get("function") or {}
            name = fn.get("name") or ""
            args = fn.get("arguments") or {}
            log.info("[%s] turn %d → %s(%s)", label, turn, name, _brief(args))

            output = call_tool(sandbox, name, args)
            if name == "Write" and not output.startswith("ERROR"):
                target = args.get("file_path") if isinstance(args, dict) else None
                if target:
                    wrote.append(str(target))

            messages.append({
                "role": "tool",
                "tool_name": name,
                "content": output,
            })

    log.error("[%s] hit max_turns=%d without finishing", label, max_turns)
    return AgentResult(
        final_text="",
        turns=turn,
        usage=usage,
        wrote_files=wrote,
        stopped_reason="max_turns",
        transcript=messages,
    )


def _brief(args: Any, limit: int = 120) -> str:
    try:
        s = json.dumps(args)
    except Exception:
        s = str(args)
    return s if len(s) <= limit else s[:limit] + "…"
