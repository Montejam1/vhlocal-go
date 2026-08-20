"""HTTP engine for vhlocal — stdlib only.

    python3 -m vhlocal.server

Then open http://127.0.0.1:8420. (The vulnhunt skill is bundled; override with
--skill-dir only if you keep your own copy.)

Design notes:

* **Binds to 127.0.0.1 by default.** This server executes scans against
  filesystem paths the caller names and serves files back. It has no
  authentication, so it must not be exposed to a network. Binding elsewhere
  requires the explicit ``--unsafe-bind`` acknowledgement.
* **Artifact serving is path-checked.** Report files are served only from
  inside a job's own results directory, resolved before a prefix comparison so
  `../` cannot escape.
* **Scan roots are allow-listed.** A browser can only start scans under
  directories passed via ``--allow-root`` (default: your home directory), so a
  stray request cannot point the engine at `/`.
"""

import argparse
import json
import logging
import mimetypes
import os
import queue
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .client import DEFAULT_HOST, DEFAULT_MODEL, DEFAULT_NUM_CTX, OllamaClient, OllamaError
from .engine import DEFAULT_REPORTS_DIR, ScanError, ScanSpec, select_phases
from .reports import list_reports, resolve_report
from .jobs import JobStore
from .logsetup import configure_logging
from .render_html import SCAN_REPORT_HTML, ensure_fresh
from .phases import PHASES

log = logging.getLogger("vhlocal.server")

WEB_DIR = Path(__file__).resolve().parent / "web"
DEFAULT_PORT = 8420


class Config:
    def __init__(self, skill_dir: Path, allow_roots: List[Path], store: JobStore,
                 host: str, port: int, reports_dir: Path,
                 ollama_host: str = DEFAULT_HOST):
        self.skill_dir = skill_dir
        self.reports_dir = reports_dir
        self.ollama_host = ollama_host
        self.allow_roots = [p.resolve() for p in allow_roots]
        self.store = store
        self.host = host
        self.port = port

    def path_allowed(self, target: Path) -> bool:
        t = target.resolve()
        for root in self.allow_roots:
            if t == root or str(t).startswith(str(root) + os.sep):
                return True
        return False


CFG: Optional[Config] = None


def _ollama_models(host: str) -> List[Dict[str, Any]]:
    import urllib.request
    try:
        with urllib.request.urlopen(host.rstrip("/") + "/api/tags", timeout=5) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as exc:
        raise OllamaError(str(exc))
    out = []
    for m in data.get("models", []):
        out.append({
            "name": m.get("name"),
            "size": m.get("size"),
            "family": (m.get("details") or {}).get("family"),
        })
    return sorted(out, key=lambda m: m["name"] or "")


class Handler(BaseHTTPRequestHandler):
    server_version = "vhlocal"
    protocol_version = "HTTP/1.1"

    # ---------- helpers ----------

    def _json(self, obj: Any, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _err(self, message: str, status: int = 400) -> None:
        self._json({"error": message}, status)

    def _body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("%s - %s", self.address_string(), fmt % args)

    # ---------- routing ----------

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            return self._serve_web("index.html")
        if path.startswith("/static/"):
            return self._serve_web(path[len("/static/"):])
        if path == "/api/config":
            return self._json({
                "skill_dir": str(CFG.skill_dir),
                "reports_dir": str(CFG.reports_dir),
                "allow_roots": [str(p) for p in CFG.allow_roots],
                "phases": [{"key": p.key, "title": p.title} for p in PHASES],
                "defaults": {"model": DEFAULT_MODEL, "num_ctx": DEFAULT_NUM_CTX,
                             "ollama_host": CFG.ollama_host},
            })
        if path == "/api/models":
            host = (qs.get("host") or [CFG.ollama_host])[0]
            try:
                return self._json({"models": _ollama_models(host)})
            except OllamaError as exc:
                return self._err("cannot reach Ollama at {0}: {1}".format(host, exc), 502)
        if path == "/api/reports":
            return self._json({
                "reports_dir": str(CFG.reports_dir),
                "reports": [r.to_dict() for r in list_reports(
                    CFG.reports_dir, self._job_result_dirs())],
            })
        if path.startswith("/api/reports/"):
            rest = path[len("/api/reports/"):]
            parts = rest.split("/", 1)
            rid = urllib.parse.unquote(parts[0])
            tail = parts[1] if len(parts) > 1 else ""
            root = resolve_report(CFG.reports_dir, rid, self._job_result_dirs())
            if root is None:
                return self._err("no such report", 404)
            if tail == "files":
                return self._json(self._list_files(root))
            if tail.startswith("file"):
                return self._read_file(root, (qs.get("path") or [""])[0])
            return self._err("not found", 404)
        if path == "/api/scans":
            return self._json({"jobs": CFG.store.list_jobs(),
                               "busy": CFG.store.is_busy()})
        if path.startswith("/api/scans/"):
            rest = path[len("/api/scans/"):]
            parts = rest.split("/", 1)
            job_id = parts[0]
            tail = parts[1] if len(parts) > 1 else ""
            if not tail:
                job = CFG.store.get(job_id)
                return self._json(job) if job else self._err("no such job", 404)
            if tail == "events":
                return self._sse(job_id, int((qs.get("offset") or ["0"])[0]))
            if tail == "artifacts":
                return self._artifacts(job_id)
            if tail == "log":
                return self._scan_log(job_id)
            if tail.startswith("file"):
                return self._file(job_id, (qs.get("path") or [""])[0])
        return self._err("not found", 404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/api/scans":
            return self._create_scan(self._body())
        if path.startswith("/api/scans/") and path.endswith("/cancel"):
            job_id = path[len("/api/scans/"):-len("/cancel")]
            ok = CFG.store.cancel(job_id)
            return self._json({"cancelled": ok}) if ok else self._err(
                "job not cancellable", 409)
        return self._err("not found", 404)

    # ---------- endpoints ----------

    def _serve_web(self, name: str) -> None:
        target = (WEB_DIR / name).resolve()
        if not str(target).startswith(str(WEB_DIR.resolve())) or not target.is_file():
            return self._err("not found", 404)
        body = target.read_bytes()
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _create_scan(self, body: Dict[str, Any]) -> None:
        repo_raw = (body.get("repo") or "").strip()
        if not repo_raw:
            return self._err("repo is required")
        repo = Path(repo_raw).expanduser()
        if not repo.is_dir():
            return self._err("repo is not a directory: {0}".format(repo))
        if not CFG.path_allowed(repo):
            return self._err(
                "repo is outside the allowed roots ({0}). Restart the server "
                "with --allow-root to widen.".format(
                    ", ".join(str(p) for p in CFG.allow_roots)), 403)

        out = body.get("out")
        if out:
            outp = Path(out).expanduser()
            if not CFG.path_allowed(outp):
                return self._err("out is outside the allowed roots", 403)

        # Validate the phase selection here rather than letting the worker
        # discover it: a bad key would otherwise queue a job that fails
        # minutes later with no feedback in the submit response.
        try:
            select_phases(body.get("phases") or "all")
        except ScanError as exc:
            return self._err(str(exc))

        for numeric in ("num_ctx", "max_partitions"):
            if body.get(numeric) not in (None, ""):
                try:
                    if int(body[numeric]) <= 0:
                        return self._err("{0} must be positive".format(numeric))
                except (TypeError, ValueError):
                    return self._err("{0} must be an integer".format(numeric))

        backend = body.get("backend") or "ollama"
        host = body.get("host")
        if not host:
            if backend == "openai":
                from .openai_client import DEFAULT_OPENAI_HOST
                host = DEFAULT_OPENAI_HOST
            else:
                host = CFG.ollama_host
        spec = ScanSpec(
            repo=repo,
            skill_dir=Path(body.get("skill_dir") or CFG.skill_dir).expanduser(),
            out=Path(out).expanduser() if out else None,
            reports_dir=CFG.reports_dir,
            model=body.get("model") or DEFAULT_MODEL,
            host=host,
            num_ctx=int(body.get("num_ctx") or DEFAULT_NUM_CTX),
            phases=body.get("phases") or "all",
            max_partitions=int(body.get("max_partitions") or 8),
            verify_model=(body.get("verify_model") or None),
            verify_host=(body.get("verify_host") or None),
            resume=bool(body.get("resume")),
            # Coverage enforcement is on unless explicitly disabled.
            enforce_coverage=body.get("enforce_coverage", True) is not False,
            seed_routes=bool(body.get("seed_routes")),
            phase2_mode=(body.get("phase2_mode") or "split"),
            concurrency=int(body.get("concurrency") or 1),
            reasoning_effort=(body.get("reasoning_effort") or None),
            backend=backend,
        )
        job = CFG.store.submit(spec)
        self._json(job.public(), 201)

    def _sse(self, job_id: str, offset: int) -> None:
        if CFG.store.get(job_id) is None:
            return self._err("no such job", 404)
        q = CFG.store.subscribe(job_id)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            # Replay the backlog so a reload mid-scan still shows history.
            for ev in CFG.store.events_since(job_id, offset):
                self._sse_send(ev)
            while True:
                try:
                    ev = q.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    job = CFG.store.get(job_id)
                    if job and job["status"] in (
                        "done", "failed", "cancelled", "interrupted"
                    ):
                        break
                    continue
                self._sse_send(ev)
                if ev.get("type") == "job_end":
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            CFG.store.unsubscribe(job_id, q)

    def _sse_send(self, ev: Dict[str, Any]) -> None:
        payload = json.dumps(ev)
        self.wfile.write(("data: " + payload + "\n\n").encode("utf-8"))
        self.wfile.flush()

    def _job_result_dirs(self) -> List[Path]:
        """Results dirs recorded by jobs that used an explicit `out`.

        Folded into the report index so a scan written outside the reports
        tree is still listed rather than silently invisible.
        """
        out = []
        for j in CFG.store.list_jobs():
            rd = j.get("results_dir")
            if rd:
                out.append(Path(rd))
        return out

    def _list_files(self, root: Path) -> Dict[str, Any]:
        files = []
        for f in sorted(root.rglob("*")):
            if f.is_file() and not f.name.startswith("."):
                try:
                    rel = f.relative_to(root)
                except ValueError:
                    continue
                files.append({"path": str(rel), "size": f.stat().st_size})
        return {"root": str(root), "files": files}

    def _read_file(self, root: Path, rel: str) -> None:
        if not rel:
            return self._err("path required")
        # The HTML report is a generated snapshot — refresh it if it predates
        # the current renderer, so improvements reach old scans without the
        # operator having to remember `vhlocal.report --all`.
        if rel == SCAN_REPORT_HTML:
            try:
                if ensure_fresh(root):
                    log.info("re-rendered stale report: %s", root.name)
            except Exception as exc:  # pragma: no cover - never block serving
                log.warning("could not refresh %s: %s", root.name, exc)
        target = (root / rel).resolve()
        root_r = root.resolve()
        if target != root_r and not str(target).startswith(str(root_r) + os.sep):
            return self._err("path escapes results directory", 403)
        if not target.is_file():
            return self._err("not found", 404)
        body = target.read_bytes()
        # Serve the generated HTML report as HTML; everything else stays
        # text/plain so raw artifacts can never execute in the page context.
        ctype = ("text/html; charset=utf-8"
                 if target.suffix.lower() == ".html"
                 else "text/plain; charset=utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _job_dir(self, job_id: str) -> Optional[Path]:
        job = CFG.store.get(job_id)
        if not job or not job.get("results_dir"):
            return None
        p = Path(job["results_dir"])
        return p if p.is_dir() else None

    def _scan_log(self, job_id: str) -> None:
        """One scan's slice of the central log.

        Server-run scans no longer keep a per-folder vhlocal.log; their lines
        live in the shared central log tagged with the job id. We also try the
        results-dir stamp, since a CLI run of the same folder would be tagged
        that way instead.
        """
        from .logsetup import scan_lines
        job = CFG.store.get(job_id)
        if not job:
            return self._err("no such job", 404)
        text = scan_lines(job_id)
        if not text and job.get("results_dir"):
            import re as _re
            m = _re.search(r"(\d{4}-\d{2}-\d{2}-\d{6})$",
                           Path(job["results_dir"]).name)
            if m:
                text = scan_lines(m.group(1))
        body = (text or "(no log lines for this scan)").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _artifacts(self, job_id: str) -> None:
        root = self._job_dir(job_id)
        if root is None:
            return self._json({"files": []})
        return self._json(self._list_files(root))

    def _file(self, job_id: str, rel: str) -> None:
        root = self._job_dir(job_id)
        if root is None:
            return self._err("no results directory", 404)
        return self._read_file(root, rel)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="vhlocal.server",
        description="Run vhlocal as an HTTP engine with a web UI.",
    )
    from .phases import default_skill_dir
    ap.add_argument("--skill-dir", default=str(default_skill_dir()),
                    help="vulnhunt skill directory (SKILL.md + phases/); defaults "
                         "to the copy bundled in this repo")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--state", default=str(Path.home() / ".vhlocal" / "jobs.json"),
                    help="Where the job queue is persisted")
    ap.add_argument("--ollama-host", default=DEFAULT_HOST,
                    help="Ollama endpoint the engine defaults to "
                         "(default: $VHLOCAL_OLLAMA_HOST or localhost). "
                         "Per-scan overrides are available in the UI.")
    ap.add_argument("--reports-dir", default=str(DEFAULT_REPORTS_DIR),
                    help="Where scan reports are written and indexed "
                         "(default: ~/vulnhunter-reports)")
    ap.add_argument("--allow-root", action="append", default=None,
                    help="Directory scans may target (repeatable). Default: $HOME")
    ap.add_argument("--unsafe-bind", action="store_true",
                    help="Required to bind a non-loopback address. There is no "
                         "authentication; only do this on a trusted network.")
    ap.add_argument("--log-file", default=None,
                    help="Central log path (default: $VHLOCAL_LOG_FILE or "
                         "~/.vhlocal/vhlocal.log).")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args(argv)

    log_path = configure_logging(args.verbose, log_file=args.log_file)

    if args.host not in ("127.0.0.1", "localhost", "::1") and not args.unsafe_bind:
        print(
            "error: refusing to bind {0} without --unsafe-bind.\n"
            "This server runs scans and serves files with no authentication.".format(
                args.host),
            file=sys.stderr,
        )
        return 2

    skill_dir = Path(args.skill_dir).expanduser().resolve()
    if not (skill_dir / "phases").is_dir():
        print("error: no phases/ under {0}\nPass --skill-dir pointing at the "
              "repo's vulnhunt/ directory.".format(skill_dir), file=sys.stderr)
        return 2

    roots = [Path(p).expanduser() for p in (args.allow_root or [str(Path.home())])]
    for r in roots:
        if not r.is_dir():
            print("error: --allow-root {0} is not a directory".format(r), file=sys.stderr)
            return 2

    reports_dir = Path(args.reports_dir).expanduser().resolve()
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print("error: cannot create reports dir {0}: {1}".format(reports_dir, exc),
              file=sys.stderr)
        return 2
    # The reports dir is always writable by the engine regardless of
    # --allow-root, otherwise the default output location would be rejected
    # whenever the operator narrows the scan roots.
    if not any(reports_dir == r or str(reports_dir).startswith(str(r) + os.sep)
               for r in roots):
        roots.append(reports_dir)

    store = JobStore(Path(args.state).expanduser())
    store.start_worker()

    global CFG
    CFG = Config(skill_dir, roots, store, args.host, args.port, reports_dir,
                 ollama_host=args.ollama_host.rstrip('/'))

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.daemon_threads = True

    print("=" * 66)
    print("  vhlocal engine")
    print("  UI          http://{0}:{1}".format(args.host, args.port))
    print("  skill dir   {0}".format(skill_dir))
    print("  ollama      {0}".format(args.ollama_host))
    print("  reports     {0}".format(reports_dir))
    print("  scan roots  {0}".format(", ".join(str(r) for r in roots)))
    print("  job state   {0}".format(args.state))
    print("  log         {0}".format(log_path))
    print("  scans run one at a time (single GPU)")
    print("=" * 66)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down…")
    finally:
        store.stop_worker()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
