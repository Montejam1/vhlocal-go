"""Parallel Phase-2 dispatch must produce the same result as serial.

Concurrency is a quality-neutral speed lever: agents are independent, so running
them through a thread pool must record the same agents and merge the same usage
as the sequential path. We stub run_agent so no model is needed.
"""

import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import vhlocal.engine as engine  # noqa: E402
from vhlocal.client import Usage  # noqa: E402
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


class _StubClient:
    model = "stub:1"


def _fake_run_agent(concurrent_tracker=None):
    """Return a run_agent stub that writes each agent's out file and records
    concurrency (how many ran at once)."""
    from vhlocal.agent import AgentResult

    def fake(client, sandbox, system, task, max_turns=0, expect_files=None,
             label="", should_cancel=None):
        if concurrent_tracker is not None:
            concurrent_tracker.enter()
        try:
            for f in (expect_files or []):
                Path(f).write_text("# {0}\n\n### VULN-1 stub (CWE-502)\n".format(label),
                                   encoding="utf-8")
            u = Usage()
            u.add(100, 10, 0.01)
            return AgentResult(final_text="ok", turns=3, usage=u,
                               stopped_reason="complete")
        finally:
            if concurrent_tracker is not None:
                concurrent_tracker.exit()
    return fake


class _Peak:
    def __init__(self):
        self.cur = 0
        self.peak = 0
        self._l = threading.Lock()

    def enter(self):
        with self._l:
            self.cur += 1
            self.peak = max(self.peak, self.cur)
        time.sleep(0.02)  # hold the slot so overlap is observable

    def exit(self):
        with self._l:
            self.cur -= 1


class TestParallelDispatch(unittest.TestCase):
    def _repo(self):
        d = Path(tempfile.mkdtemp())
        (d / "backend" / "app").mkdir(parents=True)
        (d / "backend" / "app" / "ops.py").write_text(FASTAPI, encoding="utf-8")
        (d / "backend" / "app" / "auth.py").write_text(AUTH, encoding="utf-8")
        return d

    def _run(self, concurrency, tracker=None):
        repo = self._repo()
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
        engine.run_agent = _fake_run_agent(tracker)
        try:
            err = _run_fan_out(
                _StubClient(), sandbox, build_system(""), PHASES_BY_KEY["2"],
                phases_dir, repo, results, 8, total, emit,
                lambda: False, record, enforce_coverage=True,
                phase2_mode="combined", concurrency=concurrency)
        finally:
            engine.run_agent = orig
        return err, record, total, events

    def test_serial_and_parallel_record_same_agents(self):
        _, rec1, tot1, _ = self._run(1)
        _, rec3, tot3, _ = self._run(3)
        labels1 = sorted(a["label"] for a in rec1.agents)
        labels3 = sorted(a["label"] for a in rec3.agents)
        self.assertEqual(labels1, labels3)                 # same agent set
        self.assertEqual(tot1.calls, tot3.calls)           # no lost usage merges
        self.assertGreater(tot3.calls, 1)

    def test_parallel_actually_overlaps(self):
        tracker = _Peak()
        self._run(3, tracker)
        self.assertGreaterEqual(tracker.peak, 2)           # agents ran concurrently

    def test_no_events_lost_under_lock(self):
        _, rec, _, events = self._run(4)
        starts = [e for e in events if e.get("type") == "agent_start"]
        dones = [e for e in events if e.get("type") == "agent_done"]
        self.assertEqual(len(starts), len(dones))
        self.assertEqual(len(dones), len(rec.agents))


if __name__ == "__main__":
    unittest.main()
