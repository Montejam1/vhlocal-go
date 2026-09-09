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
from .engine import (
    DEFAULT_REPORTS_DIR,
    SCAN_META_FILE,
    ScanError,
    ScanSpec,
    select_phases,
)
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


def _openai_default_host() -> str:
    from .openai_client import DEFAULT_OPENAI_HOST
    return DEFAULT_OPENAI_HOST


def _openai_models(host: str) -> List[Dict[str, Any]]:
    """List models from an OpenAI-compatible server (mlx_lm / vLLM / LM Studio)
    via ``/v1/models``. Returns the same ``name``-keyed shape as
    ``_ollama_models`` so the UI can consume either identically."""
    import urllib.request
    from .openai_client import _base_url
    url = _base_url(host) + "/v1/models"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    key = os.environ.get("VHLOCAL_OPENAI_API_KEY", "")
    if key:
        req.add_header("Authorization", "Bearer " + key)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as exc:  # reuse OllamaError as the transport-error type
        raise OllamaError(str(exc))
    out = []
    for m in data.get("data", []):
        mid = m.get("id")
        if mid:
            out.append({"name": mid, "size": None, "family": None})
    return sorted(out, key=lambda m: m["name"] or "")


def aggregate_stats(entries: List[Tuple[int, Dict[str, Any], str]]) -> Dict[str, Any]:
    """Pure aggregation for the dashboard. ``entries`` are (findings, usage-dict,
    model) tuples — one per scan. Token/time averages divide by the count of
    scans that actually recorded usage, so runs that died before writing usage
    don't drag the average to zero."""
    scans = with_usage = 0
    prompt = completion = findings = 0
    seconds = 0.0
    by_model: Dict[str, Dict[str, int]] = {}
    for fc, usage, model in entries:
        scans += 1
        findings += int(fc or 0)
        u = usage or {}
        pt = int(u.get("prompt_tokens") or 0)
        ct = int(u.get("completion_tokens") or 0)
        if pt or ct:
            with_usage += 1
            prompt += pt
            completion += ct
            seconds += float(u.get("seconds") or 0)
        bm = by_model.setdefault(model or "unknown",
                                 {"scans": 0, "tokens": 0, "findings": 0})
        bm["scans"] += 1
        bm["tokens"] += pt + ct
        bm["findings"] += int(fc or 0)
    total = prompt + completion
    return {
        "scans": scans,
        # How many of those scans actually recorded usage. Without it the UI
        # cannot tell "0 tokens" from "nothing was ever measured", and prints a
        # zero that asserts a measurement nobody took.
        "with_usage": with_usage,
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
        "avg_tokens_per_scan": round(total / with_usage) if with_usage else 0,
        "findings": findings,
        "avg_findings_per_scan": round(findings / scans, 1) if scans else 0,
        "total_seconds": round(seconds),
        "avg_seconds_per_scan": round(seconds / with_usage) if with_usage else 0,
        "by_model": by_model,
    }


def _openrouter_default_host() -> str:
    from .openai_client import DEFAULT_OPENROUTER_HOST
    return DEFAULT_OPENROUTER_HOST


def _openrouter_key_set() -> bool:
    from .openai_client import get_openrouter_key
    return bool(get_openrouter_key())


def _price_tier(prompt_per_tok: float, completion_per_tok: float) -> str:
    """Coarse $ tier from OpenRouter per-token USD pricing, keyed on the
    completion price per 1M tokens — the dominant cost of a token-heavy scan."""
    if prompt_per_tok == 0 and completion_per_tok == 0:
        return "free"
    c = completion_per_tok * 1_000_000
    if c < 1:
        return "$"
    if c < 5:
        return "$$"
    if c < 20:
        return "$$$"
    return "$$$$"


def _openrouter_models() -> List[Dict[str, Any]]:
    """OpenRouter's catalogue, each tagged with a coarse cost tier. The listing
    endpoint is public, so models can be browsed before a key is set."""
    import urllib.request
    url = _openrouter_default_host().rstrip("/") + "/v1/models"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as exc:
        raise OllamaError(str(exc))
    out = []
    for m in data.get("data", []):
        mid = m.get("id")
        if not mid:
            continue
        pr = m.get("pricing") or {}
        try:
            p = float(pr.get("prompt") or 0)
            c = float(pr.get("completion") or 0)
        except (TypeError, ValueError):
            p = c = 0.0
        out.append({"name": mid, "tier": _price_tier(p, c),
                    "context": m.get("context_length")})
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
        # The pre-2026 interface, kept alongside the redesign so it can be
        # compared or reverted to without a file swap. See index.legacy.html.
        if path in ("/legacy", "/legacy.html"):
            return self._serve_web("index.legacy.html")
        # The pre-Instrument interface, preserved verbatim when the UI was
        # restyled. Same functionality, previous look. See index.classic.html.
        if path in ("/classic", "/classic.html"):
            return self._serve_web("index.classic.html")
        if path.startswith("/static/"):
            return self._serve_web(path[len("/static/"):])
        # The React/TypeScript UI (Vite build → web/app/). Its assets live under
        # /app/assets/…; every other /app path is an SPA route that must return
        # index.html so the client router can handle it (deep links, refresh).
        if path == "/app" or path.startswith("/app/"):
            rel = path[len("/app/"):] if path.startswith("/app/") else ""
            if rel and (rel.startswith("assets/") or "." in rel.rsplit("/", 1)[-1]):
                return self._serve_web("app/" + rel)
            return self._serve_web("app/index.html")
        if path == "/api/config":
            return self._json({
                "skill_dir": str(CFG.skill_dir),
                "reports_dir": str(CFG.reports_dir),
                "allow_roots": [str(p) for p in CFG.allow_roots],
                "phases": [{"key": p.key, "title": p.title} for p in PHASES],
                "defaults": {"model": DEFAULT_MODEL, "num_ctx": DEFAULT_NUM_CTX,
                             "ollama_host": CFG.ollama_host,
                             "openai_host": _openai_default_host(),
                             "openrouter_host": _openrouter_default_host(),
                             "openrouter_key_set": _openrouter_key_set()},
            })
        if path == "/api/models":
            backend = (qs.get("backend") or ["ollama"])[0]
            if backend == "openrouter":
                try:
                    return self._json({"models": _openrouter_models()})
                except OllamaError as exc:
                    return self._err(
                        "cannot reach OpenRouter: {0}".format(exc), 502)
            default_host = (_openai_default_host() if backend == "openai"
                            else CFG.ollama_host)
            host = (qs.get("host") or [default_host])[0]
            try:
                models = (_openai_models(host) if backend == "openai"
                          else _ollama_models(host))
                return self._json({"models": models})
            except OllamaError as exc:
                label = ("OpenAI-compatible server" if backend == "openai"
                         else "Ollama")
                return self._err(
                    "cannot reach {0} at {1}: {2}".format(label, host, exc), 502)
        if path == "/api/reports":
            return self._json({
                "reports_dir": str(CFG.reports_dir),
                "reports": [r.to_dict() for r in list_reports(
                    CFG.reports_dir, self._job_result_dirs())],
            })
        if path == "/api/stats":
            return self._json(self._aggregate_stats())
        if path == "/api/profiles":
            from .profiles import list_profiles
            return self._json({"profiles": list_profiles()})
        if path == "/api/applications":
            # ?repo=<path> looks up the application for a repo (form pre-fill).
            repo = (qs.get("repo") or [""])[0]
            if repo:
                from .apps import get_application, slug_for
                app = get_application(repo)
                return self._json({"slug": slug_for(repo), "application": app})
            return self._json({"applications": self._applications()})
        if path.startswith("/api/applications/"):
            from .apps import is_valid_slug
            slug = urllib.parse.unquote(path[len("/api/applications/"):]).rstrip("/")
            if not is_valid_slug(slug):
                return self._err("bad application id", 400)
            detail = self._application_detail(slug)
            return self._json(detail) if detail else self._err("no such application", 404)
        if path == "/api/activity":
            from . import activity
            limit = int((qs.get("limit") or ["200"])[0])
            return self._json({"events": activity.recent(
                limit=min(2000, max(1, limit)),
                type_prefix=(qs.get("type") or [""])[0],
                scan=(qs.get("scan") or [""])[0])})
        if path == "/api/log":
            from .logsetup import read_central_log
            tail = int((qs.get("tail") or ["500"])[0])
            text = read_central_log(
                tail=min(20000, max(1, tail)),
                scan=(qs.get("scan") or [None])[0] or None,
                level=(qs.get("level") or [None])[0] or None)
            return self._json({"text": text})
        if path == "/api/ledgers":
            from .membank import list_ledgers
            return self._json({"ledgers": list_ledgers()})
        if path.startswith("/api/ledgers/"):
            from .membank import load_ledger
            slug = urllib.parse.unquote(path[len("/api/ledgers/"):]).rstrip("/")
            led = load_ledger(slug)
            return self._json(led) if led else self._err("no such ledger", 404)
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
        if path == "/api/openrouter-key":
            # Set the OpenRouter key in process memory only. It is never written
            # to disk or echoed back — the response is just a boolean. Not logged.
            from .openai_client import set_openrouter_key, get_openrouter_key
            body = self._body() or {}
            set_openrouter_key(body.get("api_key") or "")
            return self._json({"key_set": bool(get_openrouter_key())})
        if path.startswith("/api/scans/") and path.endswith("/cancel"):
            job_id = path[len("/api/scans/"):-len("/cancel")]
            ok = CFG.store.cancel(job_id)
            return self._json({"cancelled": ok}) if ok else self._err(
                "job not cancellable", 409)
        if path.startswith("/api/applications/"):
            # Name / rename an application: POST {name}. Works for an auto-
            # discovered app (creates its registry entry, keyed by slug).
            import time as _time
            from .apps import is_valid_slug, set_name
            slug = urllib.parse.unquote(path[len("/api/applications/"):]).rstrip("/")
            if not is_valid_slug(slug):
                return self._err("bad application id", 400)
            name = ((self._body() or {}).get("name") or "").strip()
            if not name:
                return self._err("name is required", 400)
            reg, by_slug, ledgers = self._apps_index()
            if slug not in reg and slug not in by_slug and slug not in ledgers:
                return self._err("no such application", 404)
            repo = ((reg.get(slug) or {}).get("repo")
                    or (ledgers.get(slug) or {}).get("target")
                    or (by_slug.get(slug, [None])[0].repo if by_slug.get(slug) else ""))
            ent = set_name(slug, name, repo=repo, when=_time.time())
            if ent:
                from . import activity
                activity.app_event("app.renamed", slug, name, repo)
            return self._json(ent) if ent else self._err("could not name application", 400)
        return self._err("not found", 404)

    def do_DELETE(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/reports/"):
            rid = urllib.parse.unquote(path[len("/api/reports/"):]).rstrip("/")
            root = resolve_report(CFG.reports_dir, rid, self._job_result_dirs())
            if root is None:
                return self._err("no such report", 404)
            return self._delete_report(rid, root)
        if path.startswith("/api/applications/"):
            # Forget an application: drop its registration/name + delete its
            # ledger + hide it from the list. Scan reports are KEPT (still in the
            # Reports tab); re-scanning the folder brings the app back.
            from .apps import hide, is_valid_slug
            from .membank import delete_ledger_by_slug
            slug = urllib.parse.unquote(path[len("/api/applications/"):]).rstrip("/")
            if not is_valid_slug(slug):
                return self._err("bad application id", 400)
            hide(slug)
            delete_ledger_by_slug(slug)
            from . import activity
            activity.app_event("app.forgotten", slug)
            return self._json({"forgotten": slug})
        if path.startswith("/api/ledgers/"):
            # Clear a whole ledger, or remove one tracked finding from it, without
            # forgetting the application or touching its scan reports.
            #   DELETE /api/ledgers/<slug>                 -> clear the ledger
            #   DELETE /api/ledgers/<slug>/finding?key=..  -> remove one finding
            # The finding key contains ':' and '/', so it travels URL-encoded in
            # the query string rather than the path.
            from .apps import is_valid_slug
            from .membank import delete_ledger_by_slug, remove_finding_by_slug
            from . import activity
            rest = urllib.parse.unquote(path[len("/api/ledgers/"):]).rstrip("/")
            if rest.endswith("/finding"):
                slug = rest[:-len("/finding")]
                if not is_valid_slug(slug):
                    return self._err("bad ledger id", 400)
                qs = urllib.parse.parse_qs(parsed.query)
                key = (qs.get("key") or [""])[0]
                if not key:
                    return self._err("finding key is required", 400)
                if remove_finding_by_slug(slug, key):
                    activity.record("ledger.finding_removed",
                                    "Removed a finding from ledger " + slug,
                                    slug=slug, key=key)
                    return self._json({"removed": key})
                return self._err("no such finding", 404)
            slug = rest
            if not is_valid_slug(slug):
                return self._err("bad ledger id", 400)
            if delete_ledger_by_slug(slug):
                activity.record("ledger.cleared", "Cleared ledger " + slug, slug=slug)
                return self._json({"cleared": slug})
            return self._err("no such ledger", 404)
        return self._err("not found", 404)

    # ---------- endpoints ----------

    def _delete_report(self, rid: str, root: Path) -> None:
        """Delete a report directory. Guarded three ways: the id is resolved
        against the enumerated set (never joined to a path, so no traversal); the
        resolved directory must sit inside the reports tree; and a report that a
        scan is still writing to cannot be deleted."""
        import shutil
        root = root.resolve()
        reports_root = CFG.reports_dir.resolve()
        if root != reports_root and not str(root).startswith(str(reports_root) + os.sep):
            return self._err("refusing to delete a report outside the reports "
                             "directory ({0})".format(reports_root), 403)
        if root == reports_root:
            return self._err("refusing to delete the reports directory itself", 403)
        for j in CFG.store.list_jobs():
            rd = j.get("results_dir")
            if rd and Path(rd).resolve() == root and \
                    j.get("status") in ("running", "queued"):
                return self._err("this report belongs to an active scan — cancel "
                                 "it first", 409)
        try:
            shutil.rmtree(root)
        except OSError as exc:
            return self._err("delete failed: {0}".format(exc), 500)
        log.info("deleted report %s (%s)", rid, root)
        from . import activity
        activity.report_deleted(rid)
        return self._json({"deleted": rid})

    def _serve_web(self, name: str) -> None:
        target = (WEB_DIR / name).resolve()
        if not str(target).startswith(str(WEB_DIR.resolve())) or not target.is_file():
            return self._err("not found", 404)
        body = target.read_bytes()
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # The single-file UI evolves constantly and is read from disk per request;
        # without this the browser caches index.html indefinitely and silently runs
        # an old build — a UI change (e.g. a new scan toggle) then appears "not to
        # work" because the cached JS never sends the new field. Always serve fresh.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
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
            elif backend == "openrouter":
                host = _openrouter_default_host()
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
            # Per-role model routing (all optional; blank → hunt model).
            verify_backend=(body.get("verify_backend") or None),
            recon_model=(body.get("recon_model") or None),
            recon_backend=(body.get("recon_backend") or None),
            recon_host=(body.get("recon_host") or None),
            reproduce_model=(body.get("reproduce_model") or None),
            reproduce_backend=(body.get("reproduce_backend") or None),
            reproduce_host=(body.get("reproduce_host") or None),
            resume=bool(body.get("resume")),
            # Coverage enforcement is on unless explicitly disabled.
            enforce_coverage=body.get("enforce_coverage", True) is not False,
            seed_routes=bool(body.get("seed_routes")),
            seed_prior=bool(body.get("seed_prior")),
            ledger=bool(body.get("ledger")),
            redact=bool(body.get("redact")),
            max_budget_usd=float(body.get("max_budget_usd") or 0),
            hunt_samples=int(body.get("hunt_samples") or 1),
            iac_lens=bool(body.get("iac_lens", True)),
            remediate=bool(body.get("remediate")),
            phase2_mode=(body.get("phase2_mode") or "split"),
            concurrency=int(body.get("concurrency") or 1),
            reasoning_effort=(body.get("reasoning_effort") or None),
            backend=backend,
            max_output_tokens=int(body.get("max_output_tokens") or 32768),
            sweep_mode=(body.get("sweep_mode") or "deterministic"),
            quality_strictness=(body.get("quality_strictness") or "balanced"),
            threat_model=bool(body.get("threat_model")),
        )
        # Register (or touch) the application for this target, naming it on first
        # scan. Never blocks the scan on a registry hiccup.
        try:
            import time as _time
            from . import activity
            from .apps import get_application, register, slug_for
            existed = get_application(repo) is not None
            ent = register(repo, name=(body.get("app_name") or "").strip(), when=_time.time())
            if not existed:
                activity.app_event("app.named", slug_for(repo), ent.get("name", ""), str(repo))
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("application register failed: %s", exc)
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

    def _apps_index(self):
        """Group every report by application slug and fold in the registry + the
        ledger. Returns (registry, {slug: [reports newest-first]}, {slug: ledger})."""
        from .apps import _load as apps_load
        from .membank import list_ledgers
        reg = apps_load()
        by_slug: Dict[str, list] = {}
        for r in list_reports(CFG.reports_dir, self._job_result_dirs()):
            by_slug.setdefault(r.slug or r.name, []).append(r)
        for scans in by_slug.values():
            scans.sort(key=lambda x: -(x.created or 0))
        ledgers = {L.get("slug"): L for L in list_ledgers()}
        return reg, by_slug, ledgers

    def _app_summary(self, slug, reg, by_slug, ledgers) -> Dict[str, Any]:
        scans = by_slug.get(slug, [])
        latest = scans[0] if scans else None
        entry = reg.get(slug) or {}
        led = ledgers.get(slug)
        name = (entry.get("name") or (led or {}).get("target_name")
                or (latest.repo or latest.name if latest else "") or slug)
        repo = (entry.get("repo") or (led or {}).get("target")
                or (latest.repo if latest else "") or "")
        return {
            "slug": slug, "name": name, "repo": repo,
            "named": slug in reg,
            "scans": len(scans),
            "last_scanned": (latest.created if latest else entry.get("updated")) or 0,
            "latest_findings": latest.findings if latest else 0,
            "latest_severities": latest.severities if latest else {},
            "latest_coverage": (latest.coverage_status if latest else "") or "",
            "latest_report_id": latest.id if latest else "",
            "open_findings": (led or {}).get("open"),
            "ledger_total": (led or {}).get("total"),
            "has_threat_model": any(getattr(r, "has_threat_model", False) for r in scans),
            "has_sbom": any(getattr(r, "has_sbom", False) for r in scans),
        }

    def _applications(self) -> List[Dict[str, Any]]:
        from .apps import hidden_slugs
        reg, by_slug, ledgers = self._apps_index()
        # Forgotten apps stay out of the list even though their reports remain.
        hidden = hidden_slugs()
        slugs = (set(reg) | set(by_slug) | set(ledgers)) - hidden
        out = [self._app_summary(s, reg, by_slug, ledgers) for s in slugs]
        out.sort(key=lambda a: -(a["last_scanned"] or 0))
        return out

    def _application_detail(self, slug) -> Optional[Dict[str, Any]]:
        reg, by_slug, ledgers = self._apps_index()
        if slug not in reg and slug not in by_slug and slug not in ledgers:
            return None
        summary = self._app_summary(slug, reg, by_slug, ledgers)
        scans = [{
            "id": r.id, "created": r.created, "model": r.model,
            "findings": r.findings, "hypotheses": r.hypotheses, "severities": r.severities,
            "coverage_status": r.coverage_status, "coverage_degraded": r.coverage_degraded,
            "has_report": r.has_report, "has_threat_model": r.has_threat_model,
            "has_sbom": r.has_sbom, "recall_pct": r.recall_pct, "chains": r.chains,
        } for r in by_slug.get(slug, [])]
        summary["scan_history"] = scans
        summary["has_ledger"] = slug in ledgers
        return summary

    def _aggregate_stats(self) -> Dict[str, Any]:
        """Roll up headline metrics across every report on disk. Token/time come
        from each run's scan_meta.json (findings from the report index)."""
        entries = []
        for rep in list_reports(CFG.reports_dir, self._job_result_dirs()):
            meta = None
            try:
                meta = json.loads(
                    (Path(rep.path) / SCAN_META_FILE).read_text("utf-8"))
            except (OSError, ValueError):
                pass
            entries.append((
                int(getattr(rep, "findings", 0) or 0),
                (meta or {}).get("usage") or {},
                (meta or {}).get("model") or getattr(rep, "model", "") or "unknown",
            ))
        return aggregate_stats(entries)

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
