"""Per-token USD pricing and run-cost accounting — the basis of the budget cap.

Local backends (Ollama, self-hosted OpenAI-compatible) are free, so the cap is
inert there. For OpenRouter the public model catalogue carries per-token prices
(`pricing.prompt` / `pricing.completion`, USD per token); we fetch it keyless and
cache it. Best-effort: if pricing can't be resolved the price is 0 and the cap
simply does not engage — the canary/circuit-breaker still protect the run.

Stdlib only.
"""

import json
import logging
import urllib.request
from typing import Dict, Tuple

log = logging.getLogger(__name__)

# (host, model) -> (prompt_usd_per_tok, completion_usd_per_tok)
_CACHE: Dict[Tuple[str, str], Tuple[float, float]] = {}


def _num(x) -> float:
    """Coerce to float; anything non-numeric (None, a test Mock) counts as 0."""
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def cost_usd(prompt_tokens, completion_tokens,
             price_prompt, price_completion) -> float:
    return _num(prompt_tokens) * _num(price_prompt) + \
        _num(completion_tokens) * _num(price_completion)


def openrouter_pricing(model: str, host: str) -> Tuple[float, float]:
    """(prompt, completion) USD per token for an OpenRouter model. Cached;
    returns (0, 0) if the catalogue can't be reached or the model isn't found."""
    key = (host or "", model or "")
    if key in _CACHE:
        return _CACHE[key]
    url = (host or "https://openrouter.ai/api").rstrip("/") + "/v1/models"
    prices = (0.0, 0.0)
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
        for m in data.get("data", []):
            if m.get("id") == model:
                pr = m.get("pricing") or {}
                prices = (float(pr.get("prompt") or 0),
                          float(pr.get("completion") or 0))
                break
    except Exception as exc:  # pragma: no cover - network best-effort
        log.warning("could not resolve OpenRouter pricing for %s: %s", model, exc)
    _CACHE[key] = prices
    return prices


class Budget:
    """Hard USD ceiling for a run. `cap` <= 0 disables it. `spent()` sums each
    distinct client's own token usage times its own per-token price, so a
    multi-model run (paid hunt + free local verify) is costed correctly."""

    def __init__(self, cap_usd: float, clients):
        self.cap = float(cap_usd or 0)
        self.clients = list(clients or [])
        self.halted_reason = ""

    def spent(self) -> float:
        total = 0.0
        for c in self.clients:
            u = getattr(c, "usage", None)
            if u is None:
                continue
            total += cost_usd(getattr(u, "prompt_tokens", 0),
                              getattr(u, "completion_tokens", 0),
                              getattr(c, "price_prompt", 0.0),
                              getattr(c, "price_completion", 0.0))
        return total

    def enabled(self) -> bool:
        return self.cap > 0

    def exceeded(self) -> bool:
        return self.enabled() and self.spent() >= self.cap

    def note(self) -> str:
        return ("budget cap reached: ${0:.2f} spent of ${1:.2f} cap — halting to "
                "avoid further spend. Partial results are preserved.".format(
                    self.spent(), self.cap))
