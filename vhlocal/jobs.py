"""Job queue and store for the scan engine.

**Scans are serialized deliberately.** One 64GB model occupies the GPU; two
concurrent scans do not run twice as fast, they thrash. A single worker thread
drains a FIFO queue, so submitting five scans is a valid thing to do — they
just run one after another.

Events are retained per job in a bounded ring buffer and simultaneously fanned
out to any live SSE subscribers. A late-joining browser therefore gets the
backlog and then continues live, which is what makes reload-during-a-scan work.

State persists to a JSON file so the queue survives a server restart. Jobs that
were mid-flight when the process died are marked `interrupted` on load rather
than being silently resurrected — their scan process is gone.
"""

import json
import logging
import queue
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .engine import ScanError, ScanSpec, execute_scan, resolve_results_dir
from .logsetup import scan_context

log = logging.getLogger(__name__)

MAX_EVENTS_PER_JOB = 4000

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_INTERRUPTED = "interrupted"

TERMINAL = {STATUS_DONE, STATUS_FAILED, STATUS_CANCELLED, STATUS_INTERRUPTED}


@dataclass
class Job:
    id: str
    spec: Dict[str, Any]
    status: str = STATUS_QUEUED
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    results_dir: Optional[str] = None
    error: Optional[str] = None
    usage: Optional[str] = None
    # Live progress summary, updated as events arrive.
    phase: Optional[str] = None
    agent_label: Optional[str] = None
    agent_index: int = 0
    agent_total: int = 0
    # Live dashboard stats (running totals from events; 0 until first update).
    prompt_tokens: int = 0
    completion_tokens: int = 0
    findings_count: int = 0
    findings_stage: str = ""   # "" | "confirmed" | "final"
    current_model: str = ""    # model of the most recent agent (per-phase)

    def public(self) -> Dict[str, Any]:
        d = asdict(self)
        d["elapsed"] = (
            (self.finished_at or time.time()) - self.started_at
            if self.started_at else 0.0
        )
        return d


class JobStore:
    def __init__(self, state_file: Path, auto_start: bool = True):
        """``auto_start=False`` keeps ``submit`` from launching the worker.

        Useful for tests and for any caller that wants to inspect or drain the
        queue before scans begin consuming the GPU.
        """
        self.auto_start = auto_start
        self.state_file = Path(state_file)
        self._lock = threading.RLock()
        self._jobs: Dict[str, Job] = {}
        self._events: Dict[str, List[Dict[str, Any]]] = {}
        self._subscribers: Dict[str, List["queue.Queue"]] = {}
        self._cancelled: set = set()
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._current: Optional[str] = None
        self._worker: Optional[threading.Thread] = None
        self._stopping = threading.Event()
        self._load()

    # ---------------- persistence ----------------

    def _load(self) -> None:
        if not self.state_file.exists():
            return
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("could not read job state (%s); starting fresh", exc)
            return
        for jd in raw.get("jobs", []):
            try:
                job = Job(**jd)
            except TypeError:
                continue
            # A job that claims to be running cannot be: its thread died with
            # the previous process. Never silently re-run it — a scan is
            # expensive and may have side effects on disk.
            if job.status in (STATUS_RUNNING, STATUS_QUEUED):
                job.status = STATUS_INTERRUPTED
                job.error = job.error or "server restarted while job was active"
                job.finished_at = job.finished_at or time.time()
            self._jobs[job.id] = job

    def _save(self) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_file.with_suffix(".tmp")
            payload = {"jobs": [asdict(j) for j in self._jobs.values()]}
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(self.state_file)
        except Exception as exc:  # pragma: no cover - disk issues
            log.warning("could not persist job state: %s", exc)

    # ---------------- queue control ----------------

    def start_worker(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._stopping.clear()
        self._worker = threading.Thread(target=self._run_worker, daemon=True)
        self._worker.start()

    def stop_worker(self) -> None:
        self._stopping.set()
        self._queue.put("")  # unblock the get()

    def submit(self, spec: ScanSpec) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], spec=spec.to_dict())
        # Resolve now so the UI can show where output will land before the
        # scan starts. resolve_results_dir stamps a timestamp, so computing it
        # later would produce a different directory than the scan uses.
        try:
            resolved = resolve_results_dir(spec)
            job.results_dir = str(resolved)
            job.spec["out"] = str(resolved)
        except Exception:
            pass
        with self._lock:
            self._jobs[job.id] = job
            self._events[job.id] = []
            self._save()
        self._queue.put(job.id)
        if self.auto_start:
            self.start_worker()
        return job

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.status in TERMINAL:
                return False
            self._cancelled.add(job_id)
            if job.status == STATUS_QUEUED:
                job.status = STATUS_CANCELLED
                job.finished_at = time.time()
                self._save()
                self._emit(job_id, {"type": "scan_done", "cancelled": True,
                                    "seconds": 0, "usage": ""})
        return True

    # ---------------- accessors ----------------

    def list_jobs(self) -> List[Dict[str, Any]]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: -j.created_at)
            return [j.public() for j in jobs]

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            return job.public() if job else None

    def events_since(self, job_id: str, offset: int) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._events.get(job_id, [])[offset:])

    def subscribe(self, job_id: str) -> "queue.Queue":
        q: "queue.Queue" = queue.Queue()
        with self._lock:
            self._subscribers.setdefault(job_id, []).append(q)
        return q

    def unsubscribe(self, job_id: str, q: "queue.Queue") -> None:
        with self._lock:
            subs = self._subscribers.get(job_id, [])
            if q in subs:
                subs.remove(q)

    def is_busy(self) -> bool:
        with self._lock:
            return self._current is not None

    # ---------------- internals ----------------

    def _emit(self, job_id: str, event: Dict[str, Any]) -> None:
        event = dict(event)
        event.setdefault("ts", time.time())
        with self._lock:
            buf = self._events.setdefault(job_id, [])
            buf.append(event)
            if len(buf) > MAX_EVENTS_PER_JOB:
                del buf[: len(buf) - MAX_EVENTS_PER_JOB]
            subs = list(self._subscribers.get(job_id, []))
            self._update_progress(job_id, event)
        for q in subs:
            try:
                q.put_nowait(event)
            except Exception:
                pass

    def _update_progress(self, job_id: str, ev: Dict[str, Any]) -> None:
        job = self._jobs.get(job_id)
        if not job:
            return
        t = ev.get("type")
        if t == "phase_start":
            job.phase = "{0} — {1}".format(ev.get("key"), ev.get("title"))
        elif t in ("agent_start", "agent_skip"):
            job.agent_label = ev.get("label")
            job.agent_index = int(ev.get("index") or 0)
            job.agent_total = int(ev.get("total") or 0)
            if ev.get("model"):
                job.current_model = ev.get("model")
        if "prompt_tokens" in ev:
            job.prompt_tokens = int(ev.get("prompt_tokens") or 0)
            job.completion_tokens = int(ev.get("completion_tokens") or 0)
        if t == "findings":
            # "final" supersedes "confirmed"; never let a later confirmed
            # (there is only one) regress the final count.
            if job.findings_stage != "final":
                job.findings_count = int(ev.get("count") or 0)
                job.findings_stage = ev.get("stage") or job.findings_stage

    def _run_worker(self) -> None:
        while not self._stopping.is_set():
            try:
                job_id = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            if not job_id or self._stopping.is_set():
                continue

            with self._lock:
                job = self._jobs.get(job_id)
                if not job or job.status in TERMINAL:
                    continue
                if job_id in self._cancelled:
                    job.status = STATUS_CANCELLED
                    job.finished_at = time.time()
                    self._save()
                    continue
                job.status = STATUS_RUNNING
                job.started_at = time.time()
                self._current = job_id
                self._save()

            self._emit(job_id, {"type": "queue", "message": "scan started"})

            # Durable per-job log alongside the artifacts. The in-memory event
            # ring is lost on restart, so the central log is the durable record
            # of *how* a scan ran — its lines are tagged with this job id (see
            # logsetup.scan_context), so a server-run scan is recoverable from
            # the shared log without a per-folder file.
            try:
                spec = ScanSpec.from_dict(job.spec)
                with scan_context(job.id):
                    result = execute_scan(
                        spec,
                        on_event=lambda ev, jid=job_id: self._emit(jid, ev),
                        should_cancel=lambda jid=job_id: jid in self._cancelled,
                    )
                with self._lock:
                    job.results_dir = str(result.results_dir)
                    job.usage = result.usage.summary()
                    job.status = STATUS_CANCELLED if result.cancelled else STATUS_DONE
                    job.finished_at = time.time()
                    self._save()
            except ScanError as exc:
                self._fail(job, "configuration: {0}".format(exc))
            except Exception as exc:  # pragma: no cover - defensive
                log.exception("job %s crashed", job_id)
                self._fail(job, "{0}: {1}".format(type(exc).__name__, exc))
            finally:
                with self._lock:
                    self._current = None
                    self._cancelled.discard(job_id)
                self._emit(job_id, {"type": "job_end", "status": job.status})

    def _fail(self, job: Job, message: str) -> None:
        with self._lock:
            job.status = STATUS_FAILED
            job.error = message
            job.finished_at = time.time()
            self._save()
        self._emit(job.id, {"type": "error", "message": message})
