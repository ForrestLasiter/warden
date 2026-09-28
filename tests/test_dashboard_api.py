"""Security tests for the local dashboard HTTP server."""

import http.client
import threading
from http.server import ThreadingHTTPServer

import pytest

from warden.gui import server as gui


@pytest.fixture()
def httpd():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), gui.Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield port
    finally:
        srv.shutdown()
        srv.server_close()


def _req(port, method, path, *, host=None, token=None, body=None, content_length=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", host if host is not None else f"127.0.0.1:{port}")
    if token is not None:
        conn.putheader("X-Warden-Token", token)
    data = body.encode() if body else b""
    conn.putheader("Content-Length", str(content_length if content_length is not None else len(data)))
    conn.endheaders()
    if data:
        conn.send(data)
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp.status


def test_status_requires_token(httpd):
    assert _req(httpd, "GET", "/api/status") == 403
    assert _req(httpd, "GET", "/api/status", token=gui._TOKEN) == 200


def test_foreign_host_is_rejected(httpd):
    # DNS-rebinding defence: a foreign Host is refused even with a valid token,
    # and the index page (which carries the token) is never served to it.
    assert _req(httpd, "GET", "/api/status", host="evil.com", token=gui._TOKEN) == 403
    assert _req(httpd, "GET", "/", host="evil.com") == 403


def test_localhost_host_allowed(httpd):
    assert _req(httpd, "GET", "/api/status", host=f"localhost:{httpd}", token=gui._TOKEN) == 200


def test_history_id_must_be_valid(httpd):
    assert _req(httpd, "GET", "/api/history/not-an-id", token=gui._TOKEN) == 404
    assert _req(httpd, "GET", "/api/history/../config", token=gui._TOKEN) == 404


def test_quarantine_add_rejects_arbitrary_path(httpd, tmp_path):
    victim = tmp_path / "important.txt"
    victim.write_text("keep me")
    body = f'{{"result": {{"path": "{victim.as_posix()}", "findings": [{{"severity": 4}}]}}}}'
    status = _req(httpd, "POST", "/api/quarantine/add", token=gui._TOKEN, body=body)
    assert status == 400           # no valid job handle -> refused
    assert victim.exists()         # and the file was never touched


def test_oversized_body_rejected(httpd):
    # An oversized request must not be processed. The server replies 413 and
    # closes without reading the body; on some platforms tearing down the
    # connection with an undrained body surfaces to the client as a reset, which
    # is still "refused, not processed" — accept either outcome.
    try:
        status = _req(httpd, "POST", "/api/scan", token=gui._TOKEN,
                      body="{}", content_length=gui._MAX_BODY + 1)
    except (ConnectionError, OSError, http.client.HTTPException):
        return
    assert status == 413
