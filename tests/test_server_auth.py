"""Authentication and CORS tests for the investigation server.

_check_auth was defined but called from exactly one place - do_POST - so
every GET endpoint served evidence to anyone who could reach the port.
"""
import http.server
import socketserver
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from lfa.server import LFAServerHandler

TOKEN = "test-secret-token"


def _find_free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path):
    """A running server with a token configured and one empty case."""
    cases_dir = tmp_path / "cases"
    (cases_dir / "CASE-1").mkdir(parents=True)

    class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    port = _find_free_port()
    httpd = ThreadedServer(("127.0.0.1", port), LFAServerHandler)
    httpd.cases_dir = cases_dir
    httpd.auth_token = TOKEN
    httpd.auto_analyse = False
    httpd.business_hours = "08-18"
    httpd.examiner = "Test"

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


PROTECTED_PATHS = [
    "/",
    "/dashboard",
    "/api/v1/cases",
    "/api/v1/cases/CASE-1/events",
    "/api/v1/cases/CASE-1/artifacts",
    "/api/v1/cases/CASE-1/artifact-content?path=/etc/passwd",
    "/api/v1/cases/CASE-1/findings",
    "/cases/CASE-1/explorer",
]


@pytest.mark.parametrize("path", PROTECTED_PATHS)
def test_endpoint_rejects_unauthenticated_request(server, path):
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{server}{path}", timeout=10)
    assert exc.value.code == 401, path


@pytest.mark.parametrize("path", PROTECTED_PATHS)
def test_endpoint_accepts_bearer_token(server, path):
    req = urllib.request.Request(
        f"{server}{path}", headers={"Authorization": f"Bearer {TOKEN}"}
    )
    # 404 is fine (empty case); 401 is not.
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        assert resp.status != 401
    except urllib.error.HTTPError as exc:
        assert exc.code != 401, path


def test_login_sets_a_cookie_and_redirects(server):
    req = urllib.request.Request(f"{server}/login?token={TOKEN}")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        resp = opener.open(req, timeout=10)
        status, headers = resp.status, resp.headers
    except urllib.error.HTTPError as exc:
        status, headers = exc.code, exc.headers

    assert status == 302
    cookie = headers.get("Set-Cookie", "")
    assert "lfa_token=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie


def test_cookie_authenticates_subsequent_requests(server):
    req = urllib.request.Request(
        f"{server}/api/v1/cases", headers={"Cookie": f"lfa_token={TOKEN}"}
    )
    resp = urllib.request.urlopen(req, timeout=10)
    assert resp.status == 200


def test_login_with_a_wrong_token_is_rejected(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{server}/login?token=wrong", timeout=10)
    assert exc.value.code == 401


def test_health_requires_auth_too(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{server}/api/v1/health", timeout=10)
    assert exc.value.code == 401


def test_no_cors_header_is_emitted(server):
    req = urllib.request.Request(
        f"{server}/api/v1/cases", headers={"Authorization": f"Bearer {TOKEN}"}
    )
    resp = urllib.request.urlopen(req, timeout=10)
    assert resp.headers.get("Access-Control-Allow-Origin") is None


def test_server_without_a_token_stays_open(tmp_path):
    """Default behaviour is unchanged: no token configured means no auth."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    port = _find_free_port()
    httpd = ThreadedServer(("127.0.0.1", port), LFAServerHandler)
    httpd.cases_dir = cases_dir
    httpd.auth_token = None
    httpd.auto_analyse = False
    httpd.business_hours = "08-18"
    httpd.examiner = "Test"

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/cases", timeout=10)
        assert resp.status == 200
    finally:
        httpd.shutdown()
        httpd.server_close()
