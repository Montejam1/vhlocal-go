"""Hunt cost-guards: the pre-fan-out canary and the in-fan-out circuit breaker.

A paid multi-model run once burned $16 because 16 of 21 GLM hunt agents died on
dropped connections while only 2 completed — the run marched the whole fleet off
the same cliff. These guards make that un-repeatable: the canary aborts before any
fan-out spend when the transport can't complete a single call, and the breaker
halts the fan-out once enough agents fail on transport with none succeeding."""

import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import vhlocal.engine as engine  # noqa: E402
from vhlocal.agent import AgentResult  # noqa: E402
from vhlocal.client import ChatResult, OllamaError, Usage  # noqa: E402
from vhlocal.engine import RunRecord, _run_fan_out  # noqa: E402
from vhlocal.phases import PHASES_BY_KEY, build_system  # noqa: E402
from vhlocal.tools import Sandbox  # noqa: E402

FASTAPI = (
    "from fastapi import APIRouter\n"
    "router = APIRouter(prefix='/ops')\n"
    "@router.post('/thaw')\ndef thaw(raw: bytes): ...\n"
    "@router.get('/trace')\ndef trace(): ...\n"
)
AUTH = (
    "from fastapi import FastAPI\napp = FastAPI()\n"
    "@app.post('/login')\ndef login(): ...\n"
)


class _Client:
    """Hunt client whose canary call always succeeds (transport is up)."""
    model = "stub:1"

    def chat(self, messages, tools=None, repair_hint=""):
        return ChatResult(content="READY", thinking="", tool_calls=[],
                          prompt_tokens=1, completion_tokens=1, seconds=0.0)


class _DeadClient(_Client):
    """Canary call fails with a transport error."""
    def __init__(self, kind="timeout"):
        self._kind = kind

    def chat(self, messages, tools=None, repair_hint=""):
        raise OllamaError("dropped", kind=self._kind)


def _repo():
    d = Path(tempfile.mkdtemp())
    (d / "backend" / "app").mkdir(parents=True)
    (d / "backend" / "app" / "ops.py").write_text(FASTAPI, encoding="utf-8")
    (d / "backend" / "app" / "auth.py").write_text(AUTH, encoding="utf-8")
    return d


def _harness(client, fake_run_agent, canary=True, concurrency=1,
             phase2_mode="combined", samples=1, budget=None):
    repo = _repo()
    results = Path(tempfile.mkdtemp())
    phases_dir = Path("../vulnhunt/phases").resolve()
    sandbox = Sandbox(read_roots=[repo, results], write_root=results)
    record = RunRecord()
    events = []
    lock = threading.Lock()

    def emit(ev):
        with lock:
            events.append(ev)

    total = Usage()
    orig = engine.run_agent
    engine.run_agent = fake_run_agent
    try:
        err = _run_fan_out(
            client, sandbox, build_system(""), PHASES_BY_KEY["2"],
            phases_dir, repo, results, 8, total, emit, lambda: False, record,
            enforce_coverage=True, phase2_mode=phase2_mode,
            concurrency=concurrency, canary=canary, samples=samples, budget=budget)
    finally:
        engine.run_agent = orig
    return err, record, events, results


def _all_transport_fail(client, sandbox, system, task, max_turns=0,
                        expect_files=None, label="", should_cancel=None):
    return AgentResult(final_text="", turns=1, usage=Usage(),
                       stopped_reason="error", error="dropped",
                       systemic=False, error_kind="timeout")


class Canary(unittest.TestCase):
    def test_dead_transport_aborts_before_fan_out(self):
        ran = {"n": 0}

        def fake(*a, **k):
            ran["n"] += 1
            return AgentResult(final_text="", turns=1, usage=Usage(),
                               stopped_reason="complete")
        err, record, events, _ = _harness(_DeadClient("timeout"), fake)
        self.assertIsNotNone(err)                       # aborted
        self.assertIn("canary", err.lower())
        self.assertEqual(ran["n"], 0)                   # no hunt agents spent
        self.assertTrue(any(e.get("type") == "canary" and not e.get("ok")
                            for e in events))

    def test_canary_can_be_disabled(self):
        ran = {"n": 0}

        def fake(*a, **k):
            ran["n"] += 1
            for f in (k.get("expect_files") or a[5] if len(a) > 5 else []):
                Path(f).write_text("# x\n", encoding="utf-8")
            return AgentResult(final_text="", turns=1, usage=Usage(),
                               stopped_reason="complete")
        # A dead canary client, but canary disabled -> fan-out proceeds.
        err, record, events, _ = _harness(_DeadClient(), fake, canary=False)
        self.assertGreater(ran["n"], 0)


class Breaker(unittest.TestCase):
    def test_trips_when_all_transport_fail(self):
        # Split mode: 2 partitions x 3 classes = 6 units. Canary passes (transport
        # was up), then every agent dies on transport.
        err, record, events, results = _harness(
            _Client(), _all_transport_fail, phase2_mode="split")
        self.assertIsNone(err)                          # NOT a systemic abort
        self.assertTrue(record.hunt_halted_reason)      # breaker recorded it
        self.assertTrue(any(e.get("type") == "breaker_tripped" for e in events))
        # Fewer than the full fleet ran: the breaker halted the rest.
        errored = [a for a in record.agents if a["stopped_reason"] == "error"]
        self.assertLess(len(record.agents), 6)          # halted before all 6
        self.assertGreaterEqual(len(errored), 3)        # tripped after >=3

    def test_does_not_trip_when_agents_succeed(self):
        # First agent succeeds -> transport is trusted -> a later failure never
        # trips the breaker.
        state = {"n": 0}

        def mixed(client, sandbox, system, task, max_turns=0, expect_files=None,
                  label="", should_cancel=None):
            state["n"] += 1
            if state["n"] == 1:
                for f in (expect_files or []):
                    Path(f).write_text("# ok\n", encoding="utf-8")
                return AgentResult(final_text="ok", turns=2, usage=Usage(),
                                   stopped_reason="complete")
            return AgentResult(final_text="", turns=1, usage=Usage(),
                               stopped_reason="error", error="blip",
                               systemic=False, error_kind="timeout")
        err, record, events, _ = _harness(_Client(), mixed, phase2_mode="split")
        self.assertIsNone(err)
        self.assertFalse(record.hunt_halted_reason)     # never tripped
        self.assertFalse(any(e.get("type") == "breaker_tripped" for e in events))

    def test_non_transport_errors_do_not_trip(self):
        # A model-output failure ("parse") is not a transport storm; the breaker
        # must ignore it, so every unit still runs.
        def parse_fail(client, sandbox, system, task, max_turns=0,
                       expect_files=None, label="", should_cancel=None):
            return AgentResult(final_text="", turns=1, usage=Usage(),
                               stopped_reason="error", error="bad json",
                               systemic=False, error_kind="parse")
        err, record, events, _ = _harness(_Client(), parse_fail,
                                          phase2_mode="split")
        self.assertIsNone(err)
        self.assertFalse(any(e.get("type") == "breaker_tripped" for e in events))
        self.assertGreaterEqual(len(record.agents), 6)  # all 6 units ran


class _CostClient(_Client):
    """Canary-capable client that also tracks usage + a per-token price, so the
    budget cap can be exercised end-to-end."""
    def __init__(self, price_prompt=0.0):
        self.usage = Usage()
        self.price_prompt = price_prompt
        self.price_completion = 0.0


class Sampling(unittest.TestCase):
    def test_runs_n_samples_and_unions(self):
        calls = {"n": 0}

        def fake(client, sandbox, system, task, max_turns=0, expect_files=None,
                 label="", should_cancel=None):
            calls["n"] += 1
            for f in (expect_files or []):
                Path(f).write_text("## Finding {0}\ncand at x.py:{0}\n".format(calls["n"]),
                                   encoding="utf-8")
            return AgentResult(final_text="ok", turns=2, usage=Usage(),
                               stopped_reason="complete")
        err, record, events, results = _harness(_Client(), fake, samples=2,
                                                phase2_mode="combined")
        # 2 partitions × 1 combined unit, each sampled 2× => >=4 unit runs (+ sink)
        self.assertGreaterEqual(calls["n"], 4)
        merged = list(results.glob("results/*_all.md"))
        self.assertTrue(merged)
        self.assertIn("union of", merged[0].read_text())
        # each partition/class unit notes its sample count (sink agent excepted)
        sampled = [a for a in record.agents if "samples" in a]
        self.assertTrue(sampled and all(a["samples"] == 2 for a in sampled))


class BudgetHalt(unittest.TestCase):
    def test_budget_cap_halts_fan_out_early(self):
        from vhlocal.pricing import Budget
        client = _CostClient(price_prompt=1.0)   # $1 per prompt token

        def fake(client, sandbox, system, task, max_turns=0, expect_files=None,
                 label="", should_cancel=None):
            client.usage.add(10, 0, 0.01)         # $10 per call — over a $5 cap
            for f in (expect_files or []):
                Path(f).write_text("## F\nx\n", encoding="utf-8")
            return AgentResult(final_text="ok", turns=1, usage=Usage(),
                               stopped_reason="complete")
        budget = Budget(5.0, [client])
        # split mode = 6 units; the cap should trip after the first and skip the rest
        err, record, events, results = _harness(client, fake, samples=1,
                                                phase2_mode="split", budget=budget)
        p2 = [a for a in record.agents if a.get("phase") == "2"]
        self.assertLess(len(p2), 6)               # halted before the full fleet
        self.assertGreaterEqual(len(p2), 1)


if __name__ == "__main__":
    unittest.main()
