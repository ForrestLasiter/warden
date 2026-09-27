"""Local web dashboard backend.

A dependency-free HTTP server (stdlib ``http.server``) that exposes a small JSON
API and serves the static dashboard. Design constraints for safety:

  * Binds to 127.0.0.1 only - never reachable off the machine.
  * A random per-session token is injected into the page and required on every
    /api call, so other local processes or drive-by web pages can't drive it.
  * Long operations (scan/sweep) run in background threads; the UI polls a job
    endpoint for live progress.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from ..config import Config
from ..history import History
from ..models import FileResult, Severity
from ..quarantine import Quarantine, QuarantineError
from ..scanner import Scanner
from ..sweep import SystemSweep

STATIC_DIR = Path(__file__).parent / "static"
_TOKEN = secrets.token_urlsafe(24)

# Hardening limits.
_MAX_BODY = 1 * 1024 * 1024        # 1 MiB cap on request bodies
_MAX_ACTIVE_JOBS = 2               # concurrent scan/sweep jobs
_MAX_TRACKED_JOBS = 25            # keep this many finished jobs for quarantine lookups
# Valid history entry ids look like "20260927T080130Z_scan"; anything else is
# rejected so a client can't build a path/glob that escapes the history dir.
_HISTORY_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z_(scan|sweep)$")


class JobManager:
    """Tracks background scan/sweep jobs and their live progress."""

    def __init__(self) -> None:
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, kind: str) -> str:
        job_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._jobs[job_id] = {
                "id": job_id, "kind": kind, "status": "running",
                "count": 0, "threats": 0, "report": None, "error": None,
                "categories": None,
            }
            self._evict_locked()
        return job_id

    def _evict_locked(self) -> None:
        # Drop the oldest finished jobs so memory can't grow without bound.
        finished = [jid for jid, j in self._jobs.items() if j["status"] != "running"]
        excess = len(self._jobs) - _MAX_TRACKED_JOBS
        for jid in finished[:max(0, excess)]:
            del self._jobs[jid]

    def running_count(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values() if j["status"] == "running")

    def update(self, job_id: str, **kw) -> None:
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].update(kw)

    def bump(self, job_id: str, threat: bool) -> None:
        with self._lock:
            j = self._jobs.get(job_id)
            if j:
                j["count"] += 1
                if threat:
                    j["threats"] += 1

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            j = self._jobs.get(job_id)
            return dict(j) if j else None


JOBS = JobManager()


def _run_scan_job(job_id: str, path: str, min_severity: str, save: bool, online: bool = False) -> None:
    try:
        from ..config import Config
        cfg = Config.load()
        if online:
            cfg.online_hash_lookup = True
        scanner = Scanner(cfg)

        def progress(result: FileResult) -> None:
            JOBS.bump(job_id, result.is_threat)

        report = scanner.scan_path(path, progress=progress)
        if save:
            History().save(report, kind="scan")
        JOBS.update(job_id, status="done", report=report.to_dict())
    except Exception as exc:  # noqa: BLE001
        JOBS.update(job_id, status="error", error=str(exc))


def _run_sweep_job(job_id: str, quick: bool, save: bool) -> None:
    try:
        sweeper = SystemSweep()

        def progress(result: FileResult) -> None:
            JOBS.bump(job_id, result.is_threat)

        report, categories = sweeper.run(quick=quick, progress=progress)
        if save:
            History().save(report, kind="sweep")
        JOBS.update(
            job_id, status="done", report=report.to_dict(),
            categories=[{"name": c.name, "description": c.description, "files": len(c.paths)}
                        for c in categories],
        )
    except Exception as exc:  # noqa: BLE001
        JOBS.update(job_id, status="error", error=str(exc))


class Handler(BaseHTTPRequestHandler):
    server_version = "Warden/0.1"

    # Silence default request logging (keeps the terminal clean).
    def log_message(self, *args) -> None:  # noqa: D401
        pass

    # -- helpers ----------------------------------------------------------
    def _send_json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self) -> bool:
        got = self.headers.get("X-Warden-Token", "")
        return secrets.compare_digest(got, _TOKEN)

    def _host_ok(self) -> bool:
        """Reject requests whose Host header isn't loopback.

        This defeats DNS-rebinding: even after an attacker's domain resolves to
        127.0.0.1, the browser still sends the original Host, so we never serve
        the page (and its token) or the API to a foreign origin.
        """
        host = (self.headers.get("Host") or "").strip().lower()
        port = self.server.server_address[1]
        allowed = {
            f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}",
        }
        return host in allowed

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0 or length > _MAX_BODY:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    # -- GET --------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            return self._send_json({"error": "forbidden host"}, 403)
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._serve_index()
        if path.startswith("/static/"):
            return self._serve_static(path[len("/static/"):])
        if path.startswith("/api/"):
            if not self._authed():
                return self._send_json({"error": "unauthorized"}, 403)
            return self._api_get(path)
        self._send_json({"error": "not found"}, 404)

    def _serve_index(self) -> None:
        try:
            html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
        except OSError:
            return self._send_json({"error": "index missing"}, 500)
        html = html.replace("__WARDEN_TOKEN__", _TOKEN)
        self._send_bytes(html.encode("utf-8"), "text/html; charset=utf-8")

    def _serve_static(self, rel: str) -> None:
        # Prevent path traversal with a real containment check (not a string
        # prefix, which would accept a sibling dir like 'static-evil').
        target = (STATIC_DIR / rel).resolve()
        try:
            inside = target.is_relative_to(STATIC_DIR.resolve())
        except AttributeError:  # Python < 3.9 fallback
            import os as _os
            inside = _os.path.commonpath([str(target), str(STATIC_DIR.resolve())]) == str(STATIC_DIR.resolve())
        if not inside or not target.is_file():
            return self._send_json({"error": "not found"}, 404)
        types = {".css": "text/css", ".js": "application/javascript",
                 ".svg": "image/svg+xml", ".png": "image/png"}
        ctype = types.get(target.suffix, "application/octet-stream")
        self._send_bytes(target.read_bytes(), ctype + "; charset=utf-8")

    def _api_get(self, path: str) -> None:
        if path == "/api/status":
            from .. import __version__
            s = Scanner()
            return self._send_json({
                "version": __version__,
                "engines": s.engine_status(),
                "active": s.active_engines(),
                "data_dir": str(s.config.data_dir),
            })
        if path == "/api/history":
            entries = History().list(limit=100)
            return self._send_json({"entries": [e.to_dict() for e in entries]})
        if path.startswith("/api/history/"):
            entry_id = path[len("/api/history/"):]
            if not _HISTORY_ID_RE.match(entry_id):
                return self._send_json({"error": "not found"}, 404)
            data = History().load(entry_id)
            return self._send_json(data or {"error": "not found"}, 200 if data else 404)
        if path == "/api/quarantine":
            entries = Quarantine().list_entries()
            return self._send_json({"entries": [e.to_dict() for e in entries]})
        if path.startswith("/api/job/"):
            job = JOBS.get(path[len("/api/job/"):])
            return self._send_json(job or {"error": "not found"}, 200 if job else 404)
        self._send_json({"error": "not found"}, 404)

    # -- POST -------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        if not self._host_ok():
            return self._send_json({"error": "forbidden host"}, 403)
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return self._send_json({"error": "not found"}, 404)
        if not self._authed():
            return self._send_json({"error": "unauthorized"}, 403)
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > _MAX_BODY:
            return self._send_json({"error": "request too large"}, 413)
        body = self._read_body()

        if path in ("/api/scan", "/api/sweep") and JOBS.running_count() >= _MAX_ACTIVE_JOBS:
            return self._send_json({"error": "too many concurrent scans"}, 429)

        if path == "/api/scan":
            target = str(body.get("path", "")).strip()
            if not target or not Path(target).exists():
                return self._send_json({"error": "path not found"}, 400)
            job_id = JOBS.create("scan")
            threading.Thread(
                target=_run_scan_job,
                args=(job_id, target, body.get("min_severity", "low"),
                      bool(body.get("save", True)), bool(body.get("online", False))),
                daemon=True,
            ).start()
            return self._send_json({"job": job_id})

        if path == "/api/sweep":
            job_id = JOBS.create("sweep")
            threading.Thread(
                target=_run_sweep_job,
                args=(job_id, bool(body.get("quick", False)), bool(body.get("save", True))),
                daemon=True,
            ).start()
            return self._send_json({"job": job_id})

        if path == "/api/quarantine/add":
            return self._quarantine_add(body)
        if path == "/api/quarantine/restore":
            return self._quarantine_action("restore", body)
        if path == "/api/quarantine/delete":
            return self._quarantine_action("delete", body)

        self._send_json({"error": "not found"}, 404)

    def _quarantine_add(self, body: dict) -> None:
        # SECURITY: only quarantine a file the server itself scanned and flagged.
        # We look the result up in the referenced job's stored report by index,
        # rather than trusting a client-supplied path + findings (which would let
        # any caller delete an arbitrary file).
        job_id = str(body.get("job", ""))
        index = body.get("index")
        job = JOBS.get(job_id)
        if not job or job.get("status") != "done" or not job.get("report"):
            return self._send_json({"error": "unknown or unfinished job"}, 400)
        results = job["report"].get("results", [])
        if not isinstance(index, int) or not (0 <= index < len(results)):
            return self._send_json({"error": "invalid result index"}, 400)
        result_dict = results[index]
        try:
            result = FileResult.from_dict(result_dict)
        except Exception:  # noqa: BLE001
            return self._send_json({"error": "invalid result"}, 400)
        if not result.is_threat:
            return self._send_json({"error": "result is not a threat"}, 400)
        try:
            entry = Quarantine().quarantine_file(result)
            return self._send_json({"ok": True, "id": entry.id})
        except (QuarantineError, OSError) as exc:
            return self._send_json({"error": str(exc)}, 400)

    def _quarantine_action(self, action: str, body: dict) -> None:
        entry_id = str(body.get("id", ""))
        q = Quarantine()
        try:
            if action == "restore":
                out = q.restore(entry_id)
                return self._send_json({"ok": True, "path": str(out)})
            q.delete(entry_id)
            return self._send_json({"ok": True})
        except QuarantineError as exc:
            return self._send_json({"error": str(exc)}, 400)


def serve(host: str = "127.0.0.1", port: int = 8787, open_browser: bool = True) -> None:
    Config.load().ensure_dirs()
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"Warden dashboard running at {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        httpd.server_close()
