"""Local web dashboard backend.

A dependency-free HTTP server (stdlib ``http.server``) that exposes a small JSON
API and serves the static dashboard. Design constraints for safety:

  * Binds to a loopback address only - never reachable off the machine; any
    other bind address is refused outright.
  * A random per-session token is injected into the page and required on every
    /api call, so other local processes or drive-by web pages can't drive it.
  * The Host header must be loopback (defeats DNS rebinding) and a cross-origin
    ``Origin`` / ``Sec-Fetch-Site`` is rejected on state-changing requests.
  * Every response carries a strict Content-Security-Policy and the usual
    hardening headers; nothing is cacheable.
  * Long operations (scan/sweep) run in background threads the UI polls. Each
    job can be cancelled, has a wall-clock time limit and a file limit, and the
    number of concurrent jobs is capped. A stopped job is reported incomplete.
  * The dashboard can shut the server down, so a user who launched it by
    double-clicking never has to hunt for a console window to close.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .. import audit, net
from ..config import Config
from ..history import History
from ..models import FileResult, Severity
from ..quarantine import Quarantine, QuarantineError
from ..scanner import ScanLimits, Scanner
from ..sweep import SystemSweep

STATIC_DIR = Path(__file__).parent / "static"
_TOKEN = secrets.token_urlsafe(24)
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")

# Hardening limits.
_MAX_BODY = 1 * 1024 * 1024        # 1 MiB cap on request bodies
_MAX_PATH_LEN = 4096               # scan target path
_MAX_ACTIVE_JOBS = 2               # concurrent scan/sweep jobs
_MAX_TRACKED_JOBS = 25             # keep this many finished jobs for quarantine lookups
_JOB_TIME_LIMIT = 4 * 3600         # seconds a single job may run
_JOB_MIN_TIME_LIMIT = 10
_JOB_MAX_FILES = 2_000_000         # files a single job may examine
_MAX_JOB_RESULTS = 5000            # flagged/errored results kept per job
_SOCKET_TIMEOUT = 30               # seconds an idle connection may hold a thread
# Valid history entry ids look like "20260927T080130123456Z_scan"; anything else
# is rejected so a client can't build a path/glob that escapes the history dir.
_HISTORY_ID_RE = re.compile(r"^[0-9]{8}T[0-9]+Z_(scan|sweep)$")
_JOB_ID_RE = re.compile(r"^[0-9a-f]{12}$")

_SECURITY_HEADERS = (
    # Only our own script/style/images; no inline script, no eval, no framing,
    # no form posts, no plugins, and fetch() only back to this origin.
    ("Content-Security-Policy",
     "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
     "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; "
     "frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=()"),
    ("Cache-Control", "no-store"),
)


class JobManager:
    """Tracks background scan/sweep jobs and their live progress."""

    def __init__(self) -> None:
        self._jobs: dict[str, dict] = {}
        self._cancel: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def create(self, kind: str) -> str:
        job_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._jobs[job_id] = {
                "id": job_id, "kind": kind, "status": "running",
                "count": 0, "threats": 0, "report": None, "error": None,
                "categories": None, "started": time.time(),
            }
            self._cancel[job_id] = threading.Event()
            self._evict_locked()
        return job_id

    def try_create(self, kind: str, limit: int) -> str | None:
        """Create a job unless ``limit`` are already running (checked and
        created under one lock, so two requests can't both slip through)."""
        with self._lock:
            if sum(1 for j in self._jobs.values() if j["status"] == "running") >= limit:
                return None
        return self.create(kind)

    def _evict_locked(self) -> None:
        # Drop the oldest finished jobs so memory can't grow without bound.
        finished = [jid for jid, j in self._jobs.items() if j["status"] != "running"]
        excess = len(self._jobs) - _MAX_TRACKED_JOBS
        for jid in finished[:max(0, excess)]:
            del self._jobs[jid]
            self._cancel.pop(jid, None)

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

    def cancel_event(self, job_id: str) -> threading.Event:
        with self._lock:
            return self._cancel.setdefault(job_id, threading.Event())

    def cancel(self, job_id: str) -> bool:
        """Ask a running job to stop. False if there is no such running job."""
        with self._lock:
            j = self._jobs.get(job_id)
            if not j or j["status"] != "running":
                return False
            self._cancel.setdefault(job_id, threading.Event()).set()
            return True

    def cancel_all(self) -> None:
        with self._lock:
            for ev in self._cancel.values():
                ev.set()


JOBS = JobManager()


def _time_limit(value) -> float:
    """Clamp a client-requested time limit (seconds) to the server's bounds."""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return float(_JOB_TIME_LIMIT)
    if n != n or n <= 0:       # NaN or non-positive -> server default
        return float(_JOB_TIME_LIMIT)
    return max(float(_JOB_MIN_TIME_LIMIT), min(float(_JOB_TIME_LIMIT), n))


def _slim_report(report) -> dict:
    """The report as stored on a job: summary + only the results worth showing.

    A big scan has hundreds of thousands of clean results; keeping (and
    shipping) them all would balloon memory and the response. The quarantine
    handle is an index into THIS list, on both sides.
    """
    data = report.to_dict()
    interesting = [r for r in data["results"] if r.get("findings") or r.get("error")]
    data["results_total"] = len(data["results"])
    data["results_truncated"] = len(interesting) > _MAX_JOB_RESULTS
    interesting.sort(key=lambda r: -int(r.get("verdict", 0)))
    data["results"] = interesting[:_MAX_JOB_RESULTS]
    return data


def _finish(job_id: str, report, **extra) -> None:
    status = "cancelled" if report.stopped == "cancelled" else "done"
    JOBS.update(job_id, status=status, report=_slim_report(report), **extra)


def _limits(job_id: str, time_limit: float) -> ScanLimits:
    return ScanLimits(cancel=JOBS.cancel_event(job_id).is_set, timeout=time_limit,
                      max_files=_JOB_MAX_FILES)


def _run_scan_job(job_id: str, path: str, min_severity: str, save: bool, online: bool = False,
                  time_limit: float = _JOB_TIME_LIMIT) -> None:
    try:
        cfg = Config.load()
        if online:
            cfg.online_hash_lookup = True
        scanner = Scanner(cfg)

        def progress(result: FileResult) -> None:
            JOBS.bump(job_id, result.is_threat)

        report = scanner.scan_path(path, progress=progress, limits=_limits(job_id, time_limit))
        history_id = History().save(report, kind="scan").id if save else None
        audit.record("scan.completed", cfg, **audit.scan_details(
            report, kind="scan", source="dashboard", history_id=history_id,
            online=cfg.online_hash_lookup and not net.is_offline(cfg)))
        _finish(job_id, report)
    except Exception as exc:  # noqa: BLE001
        JOBS.update(job_id, status="error", error=str(exc))


def _run_sweep_job(job_id: str, quick: bool, save: bool, online: bool = False,
                   time_limit: float = _JOB_TIME_LIMIT) -> None:
    try:
        cfg = Config.load()
        if online:
            cfg.online_hash_lookup = True
        sweeper = SystemSweep(cfg)

        def progress(result: FileResult) -> None:
            JOBS.bump(job_id, result.is_threat)

        report, categories = sweeper.run(quick=quick, progress=progress,
                                         limits=_limits(job_id, time_limit))
        history_id = History().save(report, kind="sweep").id if save else None
        audit.record("sweep.completed", cfg, **audit.scan_details(
            report, kind="sweep", source="dashboard", history_id=history_id,
            online=cfg.online_hash_lookup and not net.is_offline(cfg)))
        _finish(
            job_id, report,
            categories=[{"name": c.name, "description": c.description, "files": len(c.paths)}
                        for c in categories],
        )
    except Exception as exc:  # noqa: BLE001
        JOBS.update(job_id, status="error", error=str(exc))


class Handler(BaseHTTPRequestHandler):
    server_version = "Warden"
    sys_version = ""                # don't advertise the Python version
    timeout = _SOCKET_TIMEOUT       # an idle/slow client can't pin a thread forever

    # Silence default request logging (keeps the terminal clean).
    def log_message(self, *args) -> None:  # noqa: D401
        pass

    def end_headers(self) -> None:
        for name, value in _SECURITY_HEADERS:
            self.send_header(name, value)
        super().end_headers()

    # -- helpers ----------------------------------------------------------
    def _send_json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
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
        return secrets.compare_digest(got.encode("utf-8", "replace"), _TOKEN.encode())

    def _allowed_hosts(self) -> set[str]:
        port = self.server.server_address[1]  # type: ignore[index]
        return {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    def _host_ok(self) -> bool:
        """Reject requests whose Host header isn't loopback.

        This defeats DNS-rebinding: even after an attacker's domain resolves to
        127.0.0.1, the browser still sends the original Host, so we never serve
        the page (and its token) or the API to a foreign origin.
        """
        host = (self.headers.get("Host") or "").strip().lower()
        return host in self._allowed_hosts()

    def _origin_ok(self) -> bool:
        """For state-changing requests: refuse anything a browser marks as
        coming from another site. (Belt and braces - the token already can't be
        read cross-origin - but it costs nothing and fails closed.)"""
        origin = (self.headers.get("Origin") or "").strip().lower()
        if origin and origin not in {f"http://{h}" for h in self._allowed_hosts()}:
            return False
        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        return site in ("", "same-origin", "none")

    def _content_length(self) -> int:
        try:
            return int(self.headers.get("Content-Length", 0) or 0)
        except (ValueError, TypeError):
            return -1

    def _read_body(self) -> dict:
        length = self._content_length()
        if length <= 0 or length > _MAX_BODY:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, OSError):
            return {}
        return data if isinstance(data, dict) else {}

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
        inside = target.is_relative_to(STATIC_DIR.resolve())
        if not inside or not target.is_file():
            return self._send_json({"error": "not found"}, 404)
        types = {".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8",
                 ".svg": "image/svg+xml", ".png": "image/png"}
        self._send_bytes(target.read_bytes(), types.get(target.suffix, "application/octet-stream"))

    def _api_get(self, path: str) -> None:
        if path == "/api/status":
            from .. import __version__
            s = Scanner()
            address = self.server.server_address
            host, port = str(address[0]), int(address[1])  # type: ignore[index]
            return self._send_json({
                "version": __version__,
                "engines": s.engine_status(),
                "active": s.active_engines(),
                "advisories": s.advisories,
                "warnings": s.engine_warnings,
                "data_dir": str(s.config.data_dir),
                "offline": net.is_offline(s.config),
                "local_only": True,
                "address": f"{host}:{port}",
                "limits": {"max_active_jobs": _MAX_ACTIVE_JOBS, "job_time_limit": _JOB_TIME_LIMIT,
                           "job_max_files": _JOB_MAX_FILES},
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
            q_entries = Quarantine().list_entries()
            return self._send_json({"entries": [e.to_dict() for e in q_entries]})
        if path.startswith("/api/job/"):
            job_id = path[len("/api/job/"):]
            job = JOBS.get(job_id) if _JOB_ID_RE.match(job_id) else None
            if job:
                job["elapsed"] = round(time.time() - job.get("started", time.time()), 1)
            return self._send_json(job or {"error": "not found"}, 200 if job else 404)
        self._send_json({"error": "not found"}, 404)

    # -- POST -------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        if not self._host_ok():
            return self._send_json({"error": "forbidden host"}, 403)
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return self._send_json({"error": "not found"}, 404)
        if not self._origin_ok():
            return self._send_json({"error": "cross-origin request refused"}, 403)
        if not self._authed():
            return self._send_json({"error": "unauthorized"}, 403)
        length = self._content_length()
        if length < 0:
            return self._send_json({"error": "bad content-length"}, 400)
        if length > _MAX_BODY:
            return self._send_json({"error": "request too large"}, 413)
        body = self._read_body()

        if path == "/api/scan":
            target = body.get("path", "")
            if not isinstance(target, str):
                return self._send_json({"error": "path not found"}, 400)
            target = target.strip()
            if (not target or len(target) > _MAX_PATH_LEN or "\x00" in target
                    or not _path_exists(target)):
                return self._send_json({"error": "path not found"}, 400)
            min_severity = body.get("min_severity", "low")
            try:
                Severity.parse(min_severity)
            except (KeyError, ValueError, TypeError, AttributeError):
                return self._send_json({"error": "invalid min_severity"}, 400)
            job_id = JOBS.try_create("scan", _MAX_ACTIVE_JOBS)
            if job_id is None:
                return self._send_json({"error": "too many concurrent scans"}, 429)
            threading.Thread(
                target=_run_scan_job,
                args=(job_id, target, str(min_severity), bool(body.get("save", True)),
                      bool(body.get("online", False)), _time_limit(body.get("time_limit"))),
                daemon=True,
            ).start()
            return self._send_json({"job": job_id})

        if path == "/api/sweep":
            job_id = JOBS.try_create("sweep", _MAX_ACTIVE_JOBS)
            if job_id is None:
                return self._send_json({"error": "too many concurrent scans"}, 429)
            threading.Thread(
                target=_run_sweep_job,
                args=(job_id, bool(body.get("quick", False)), bool(body.get("save", True)),
                      bool(body.get("online", False)), _time_limit(body.get("time_limit"))),
                daemon=True,
            ).start()
            return self._send_json({"job": job_id})

        m = re.fullmatch(r"/api/job/([0-9a-f]{12})/cancel", path)
        if m:
            if JOBS.cancel(m.group(1)):
                return self._send_json({"ok": True})
            return self._send_json({"error": "no such running job"}, 404)

        if path == "/api/quarantine/add":
            return self._quarantine_add(body)
        if path == "/api/quarantine/restore":
            return self._quarantine_restore(body)
        if path == "/api/quarantine/delete":
            return self._quarantine_delete(body)
        if path == "/api/shutdown":
            return self._shutdown()

        self._send_json({"error": "not found"}, 404)

    def _quarantine_add(self, body: dict) -> None:
        # SECURITY: only quarantine a file the server itself scanned and flagged.
        # We look the result up in the referenced job's stored report by index,
        # rather than trusting a client-supplied path + findings (which would let
        # any caller delete an arbitrary file).
        job_id = str(body.get("job", ""))
        index = body.get("index")
        job = JOBS.get(job_id)
        if not job or job.get("status") not in ("done", "cancelled") or not job.get("report"):
            return self._send_json({"error": "unknown or unfinished job"}, 400)
        results = job["report"].get("results", [])
        if isinstance(index, bool) or not isinstance(index, int) or not (0 <= index < len(results)):
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

    def _quarantine_restore(self, body: dict) -> None:
        """Restore, but re-scan with the current rules first. If the item is
        still detected (or can't be re-scanned), the client must send
        ``confirm: true`` - so a restore of live malware is always a decision,
        never a mis-click."""
        entry_id = str(body.get("id", ""))
        confirm = body.get("confirm") is True
        q = Quarantine()
        try:
            if not confirm:
                try:
                    result = q.rescan(entry_id)
                except QuarantineError as exc:
                    if "no quarantine entry" in str(exc):
                        raise
                    return self._send_json({
                        "error": f"could not re-scan before restoring: {exc}",
                        "needs_confirm": True, "rescan_failed": True}, 409)
                if result.is_threat or result.errored:
                    return self._send_json({
                        "error": "still detected by the current rules" if result.is_threat
                                 else "re-scan was incomplete",
                        "needs_confirm": True, "still_threat": result.is_threat,
                        "verdict": result.verdict.label,
                        "findings": [f.name for f in result.findings][:10]}, 409)
            out = q.restore(entry_id)
            return self._send_json({"ok": True, "path": str(out)})
        except QuarantineError as exc:
            return self._send_json({"error": str(exc)}, 400)

    def _quarantine_delete(self, body: dict) -> None:
        try:
            Quarantine().delete(str(body.get("id", "")))
            return self._send_json({"ok": True})
        except QuarantineError as exc:
            return self._send_json({"error": str(exc)}, 400)

    def _shutdown(self) -> None:
        """Stop the dashboard server (running jobs are told to stop first)."""
        JOBS.cancel_all()
        self._send_json({"ok": True})
        # shutdown() blocks until serve_forever() returns, and serve_forever is
        # what's running this handler's server - so it must come from another
        # thread, after the response has gone out.
        threading.Thread(target=self.server.shutdown, daemon=True).start()


def _path_exists(target: str) -> bool:
    try:
        return Path(target).exists()
    except (OSError, ValueError):
        return False


def check_bind_host(host: str) -> str:
    """The dashboard has no accounts and no TLS: it must never listen on a
    network interface. Refuse anything that isn't loopback."""
    if host not in _LOOPBACK_HOSTS:
        raise ValueError(
            f"refusing to serve the dashboard on {host!r}: it is local-only by design "
            f"(allowed: {', '.join(_LOOPBACK_HOSTS)})")
    return host


def serve(host: str = "127.0.0.1", port: int = 8787, open_browser: bool = True) -> None:
    check_bind_host(host)
    Config.load().ensure_dirs()
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    url = f"http://{host}:{port}/"
    print("=" * 60)
    print("  Warden is running.")
    print(f"  Your browser should open to {url}")
    print("  If it doesn't, copy that address into your browser.")
    print("")
    print("  This page works only on this computer - it is not on your")
    print("  network, and other devices cannot reach it.")
    print("")
    print("  To stop: click 'Quit Warden' in the page, close this window,")
    print("  or press Ctrl+C.")
    print("=" * 60)
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    audit.record("dashboard.start", None, address=f"{host}:{port}")
    try:
        httpd.serve_forever()
        audit.record("dashboard.stop", None, address=f"{host}:{port}", reason="quit from the page")
        print("\nWarden has stopped. You can close this window.")
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        JOBS.cancel_all()
        httpd.server_close()
