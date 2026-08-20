"""Measure LLM serving throughput so config tuning is data-driven, not guessed.

This workload is *prefill-bound* (~130:1 prompt:completion), so the number that
matters is prompt-processing speed, not generation speed. This tool reports both,
straight from the model's own timing (``prompt_eval_duration`` /
``eval_duration``), which excludes network and queueing. It can also fire
concurrent requests to measure the *real* parallel speedup on this hardware —
the thing we could only estimate.

Run it against an idle server (no scan in flight — it competes for the GPU):

    python3 -m vhlocal.bench                          # prefill + generation probe
    python3 -m vhlocal.bench --prompt-tokens 74000    # match a heavy agent turn
    python3 -m vhlocal.bench --concurrency 2          # real parallel speedup
    python3 -m vhlocal.bench --num-ctx 98304          # try a smaller context

Tuning loop: change one Ollama setting (num_batch, -c, OLLAMA_NUM_PARALLEL),
restart Ollama, re-run, compare prefill tok/s. The winner is empirical.
"""

import argparse
import json
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .client import DEFAULT_HOST, DEFAULT_MODEL, DEFAULT_NUM_CTX

# Deterministic filler (~4 chars/token). We don't tokenize locally — the server
# reports the true prompt_eval_count, which is what we divide by.
_WORDS = (
    "the service authenticates a request when the caller presents a valid token "
    "otherwise it returns forbidden and logs the attempt for later review by an "
    "operator who inspects the audit trail across every region and tenant scope "
).split()


def _make_prompt(approx_tokens: int, nonce: str = "") -> str:
    """Build a prompt of ~approx_tokens. A non-empty `nonce` makes it unique so
    the server can't serve it from a previous call's cache — essential for
    measuring *cold* prefill (an agent's first turn) rather than a cache hit."""
    target_chars = max(16, approx_tokens) * 4
    out: List[str] = [nonce] if nonce else []
    n = len(nonce)
    i = 0
    while n < target_chars:
        w = _WORDS[i % len(_WORDS)]
        # Sprinkle the nonce through the body too, so no long cacheable prefix
        # survives even if the leading token is stripped.
        out.append(w if i % 40 else (nonce + w))
        n += len(w) + 1
        i += 1
    return " ".join(out)


def _post(host: str, path: str, body: Dict[str, Any], timeout: int) -> Dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        host.rstrip("/") + path, data=data,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# Set by main() from --backend. Ollama returns server-side prefill/gen durations;
# OpenAI-compatible servers (mlx_lm/vLLM) do not, so timing is wall-clock only.
_BACKEND = "ollama"


def _one_call(host: str, model: str, prompt: str, gen_tokens: int,
              num_ctx: int, timeout: int = 1800) -> Dict[str, Any]:
    if _BACKEND == "openai":
        body = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False, "temperature": 0, "max_tokens": gen_tokens,
        }
        t0 = time.time()
        raw = _post(host, "/v1/chat/completions", body, timeout)
        wall = time.time() - t0
        usage = raw.get("usage") or {}
        p_tok = int(usage.get("prompt_tokens") or 0)
        g_tok = int(usage.get("completion_tokens") or 0)
        # No server-side split → attribute wall to prefill for a big-prompt/1-gen
        # probe and to generation for a small-prompt/many-gen probe. Good enough
        # to compare against Ollama's own wall-clock.
        return {
            "wall": wall, "prompt_tokens": p_tok, "prompt_s": wall,
            "gen_tokens": g_tok, "gen_s": wall,
            "prefill_tps": (p_tok / wall) if wall else 0.0,
            "gen_tps": (g_tok / wall) if wall else 0.0,
            "cached_prefix": False,
        }
    body = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "keep_alive": "60m",
        "options": {"num_ctx": num_ctx, "num_predict": gen_tokens, "temperature": 0},
    }
    t0 = time.time()
    raw = _post(host, "/api/generate", body, timeout)
    wall = time.time() - t0
    p_tok = int(raw.get("prompt_eval_count") or 0)
    p_ns = int(raw.get("prompt_eval_duration") or 0)
    g_tok = int(raw.get("eval_count") or 0)
    g_ns = int(raw.get("eval_duration") or 0)
    return {
        "wall": wall,
        "prompt_tokens": p_tok, "prompt_s": p_ns / 1e9,
        "gen_tokens": g_tok, "gen_s": g_ns / 1e9,
        "prefill_tps": (p_tok / (p_ns / 1e9)) if p_ns else 0.0,
        "gen_tps": (g_tok / (g_ns / 1e9)) if g_ns else 0.0,
        "cached_prefix": p_ns == 0 and p_tok == 0,  # Ollama omits when fully cached
    }


def _warmup(host: str, model: str, num_ctx: int) -> None:
    try:
        _one_call(host, model, "warmup", 1, num_ctx, timeout=600)
    except Exception as exc:  # pragma: no cover - network
        print("warmup failed: {0}".format(exc), file=sys.stderr)


def _probe(host: str, model: str, prompt_tokens: int, gen_tokens: int,
           num_ctx: int, repeat: int, nonce: str, label: str
           ) -> Optional[Dict[str, float]]:
    runs = []
    for i in range(repeat):
        # A fresh nonce per iteration → every measurement is a cold prefill, not
        # a cache hit off the previous iteration.
        prompt = _make_prompt(prompt_tokens, "{0}i{1} ".format(nonce, i))
        try:
            runs.append(_one_call(host, model, prompt, gen_tokens, num_ctx))
        except urllib.error.URLError as exc:
            print("  {0}: request failed ({1})".format(label, exc), file=sys.stderr)
            return None
    prefill = statistics.median(r["prefill_tps"] for r in runs)
    gen = statistics.median(r["gen_tps"] for r in runs)
    wall = statistics.median(r["wall"] for r in runs)
    ptok = runs[-1]["prompt_tokens"]
    return {"prefill_tps": prefill, "gen_tps": gen, "wall": wall, "prompt_tokens": ptok}


def _cache_probe(host: str, model: str, prompt_tokens: int, num_ctx: int,
                 nonce: str) -> Dict[str, Any]:
    """Does the server reuse a cached prefix across calls, or re-prefill it?

    This is the crux of the agent loop's cost. A vhlocal agent's turn N sends
    turn N-1's whole context plus a new tool result — the prefix is unchanged, so
    a well-behaved server should prefill only the *delta*. We simulate that: call
    1 sends a **unique** base prompt (so it is genuinely cold), call 2 sends the
    same base + a small continuation.

    Judge by TIME, not token count: Ollama reports the full ``prompt_eval_count``
    even when it served the prefix from cache, so only ``prompt_eval_duration``
    reveals the truth. If call 2's prefill time is a small fraction of call 1's,
    the prefix was reused (turns are cheap). If it's about the same, every turn
    re-prefills the whole growing context — the worst case.
    """
    # Nonce makes the base unique so a prior probe can't have cached it.
    base = nonce + " " + _make_prompt(prompt_tokens)
    delta = " " + nonce + "x " + _make_prompt(200)
    c1 = _one_call(host, model, base, 1, num_ctx)          # cold full prefill
    c2 = _one_call(host, model, base + delta, 1, num_ctx)  # extends the same prefix
    cold_s = c1["prompt_s"]
    second_s = c2["prompt_s"]
    # second_s ≈ 0 means fully cached (Ollama omitted the duration). Otherwise a
    # small fraction of cold_s means only the delta was prefilled.
    ratio = (second_s / cold_s) if cold_s else 1.0
    return {
        "base_tokens": c1["prompt_tokens"],
        "cold_prefill_s": cold_s,
        "second_prefill_s": second_s,
        "ratio": ratio,
        "cached": second_s < cold_s * 0.5,
    }


def _concurrency_probe(host: str, model: str, prompt_tokens: int, gen_tokens: int,
                       num_ctx: int, n: int, nonce: str) -> Dict[str, Any]:
    """Fire n calls concurrently; compare to a single call. Real work only.

    Every call uses a DISTINCT prompt (unique nonce) so none is a cache hit and
    each does genuine cold prefill. If the server has one slot (-np 1) the calls
    serialize and total wall ~ n x single. With n parallel slots they overlap.
    speedup = n x single / concurrent.
    """
    single = _one_call(host, model, _make_prompt(prompt_tokens, nonce + "solo "),
                       gen_tokens, num_ctx)
    results: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def worker(k):
        p = _make_prompt(prompt_tokens, "{0}c{1} ".format(nonce, k))
        r = _one_call(host, model, p, gen_tokens, num_ctx)
        with lock:
            results.append(r)

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(n)]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    concurrent_wall = time.time() - t0
    ideal = single["wall"]  # one call's wall time
    speedup = (n * ideal) / concurrent_wall if concurrent_wall else 0.0
    return {
        "n": n, "single_wall": ideal, "concurrent_wall": concurrent_wall,
        "speedup": speedup,
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="vhlocal.bench",
        description="Measure prefill/generation throughput of the LLM server.")
    ap.add_argument("--host", default=None,
                    help="Server URL (default: Ollama :11434, or :8080 for "
                         "--backend openai)")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--backend", choices=["ollama", "openai"], default="ollama",
                    help="'openai' benchmarks an OpenAI-compatible server "
                         "(mlx_lm.server / vLLM) via wall-clock timing")
    ap.add_argument("--num-ctx", type=int, default=DEFAULT_NUM_CTX)
    ap.add_argument("--prompt-tokens", type=int, default=20000,
                    help="Approx prompt size for the prefill probe (default 20k, "
                         "≈ the real average agent turn)")
    ap.add_argument("--gen-tokens", type=int, default=256,
                    help="Tokens to generate in the generation probe")
    ap.add_argument("--repeat", type=int, default=3,
                    help="Median over N runs per probe")
    ap.add_argument("--concurrency", type=int, default=1,
                    help="If >1, also measure the real parallel speedup")
    ap.add_argument("--cache-probe", action="store_true",
                    help="Measure whether the server reuses a cached prefix "
                         "across calls (the crux of the agent-loop cost)")
    args = ap.parse_args(argv)

    global _BACKEND
    _BACKEND = args.backend
    if not args.host:
        from .openai_client import DEFAULT_OPENAI_HOST
        args.host = DEFAULT_OPENAI_HOST if args.backend == "openai" else DEFAULT_HOST

    print("Benchmarking {0} @ {1} ({2} backend)".format(
        args.model, args.host, args.backend))
    print("(run against an IDLE server — a scan in flight will skew every number)")
    if args.backend == "openai":
        print("(openai backend has no server-side prefill/gen split — timing is "
              "wall-clock; the cache-probe is Ollama-only)")
    print()

    print("Loading model (warmup)…")
    _warmup(args.host, args.model, args.num_ctx)

    # Unique per-invocation nonce so every probe measures COLD work, never a
    # cache hit off a previous run (the trap that produced 843k tok/s).
    nonce = "vhb{0} ".format(int(time.time()))

    # Prefill probe: big prompt, 1 output token → isolates prompt processing.
    pf = _probe(args.host, args.model, args.prompt_tokens, 1, args.num_ctx,
                args.repeat, nonce + "pf", "prefill")
    # Generation probe: tiny prompt, many output tokens → isolates decode.
    gp = _probe(args.host, args.model, 64, args.gen_tokens, args.num_ctx,
                args.repeat, nonce + "gen", "generation")

    print("\n=== Throughput (from the model's own timing) ===")
    if pf:
        print("  Prefill    : {0:>8.1f} tok/s   ({1} prompt tokens, {2:.1f}s wall)"
              .format(pf["prefill_tps"], pf["prompt_tokens"], pf["wall"]))
    if gp:
        print("  Generation : {0:>8.1f} tok/s".format(gp["gen_tps"]))

    if pf and pf["prefill_tps"]:
        # Upper bound only: assumes every call cold-prefills its whole context.
        # Prefix caching (run --cache-probe) means most turns prefill just a
        # small delta, so the real prompt-processing time is far below this.
        est_prefill_s = 633 * 20600 / pf["prefill_tps"]
        print("\n  Upper bound: if NOTHING cached, ~633 calls x ~20.6k tokens ≈ "
              "{0:.0f} min of prompt processing.".format(est_prefill_s / 60))
        print("  Caching cuts this sharply (see --cache-probe); generation "
              "(~82 tok/s x reasoning tokens) is likely the real bulk.")

    if args.cache_probe:
        print("\n=== Prefix-cache reuse (the agent-loop crux) ===")
        try:
            nonce = "vhbench{0}".format(int(time.time()))
            cq = _cache_probe(args.host, args.model, args.prompt_tokens,
                              args.num_ctx, nonce)
            print("  cold base ({0} tok) prefill : {1:.2f}s".format(
                cq["base_tokens"], cq["cold_prefill_s"]))
            print("  same prefix + ~200 tok      : {0:.2f}s prefill".format(
                cq["second_prefill_s"]))
            print("  2nd-call prefill / cold     : {0:.0%}".format(cq["ratio"]))
            if cq["cached"]:
                print("  → caching WORKS: extending a cached prefix prefills only the "
                      "delta. Per-turn cost is small;\n    the lever is fewer/shorter "
                      "agents, not caching.")
            else:
                print("  → caching is NOT kicking in: extending the prefix re-prefills "
                      "the whole context. This is the\n    dominant cost — reducing "
                      "per-agent context or fixing cache reuse beats every other lever.")
        except urllib.error.URLError as exc:
            print("  cache probe failed: {0}".format(exc), file=sys.stderr)

    if args.concurrency > 1:
        print("\n=== Parallel speedup (concurrency={0}) ===".format(args.concurrency))
        print("Requires OLLAMA_NUM_PARALLEL >= {0} on the server, else calls "
              "serialize.".format(args.concurrency))
        try:
            cp = _concurrency_probe(args.host, args.model, args.prompt_tokens, 1,
                                    args.num_ctx, args.concurrency, nonce + "cc")
            print("  single call wall     : {0:.1f}s".format(cp["single_wall"]))
            print("  {0} concurrent wall   : {1:.1f}s".format(cp["n"], cp["concurrent_wall"]))
            print("  measured speedup     : {0:.2f}x  (1.0 = fully serial, "
                  "{1:.1f} = perfect)".format(cp["speedup"], float(cp["n"])))
            if cp["speedup"] < 1.15:
                print("  → effectively serial: is OLLAMA_NUM_PARALLEL set and "
                      "Ollama restarted?")
        except urllib.error.URLError as exc:
            print("  concurrency probe failed: {0}".format(exc), file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
