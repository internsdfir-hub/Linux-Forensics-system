"""Security regression tests for the investigation server (server.py).

Covers three defects found in the commercial-readiness review:

  1. Arbitrary file read: the ``".." in parts`` traversal guard on the
     ``/cases/`` static route and the ``artifact-content`` API does NOT stop an
     *absolute* path, because ``pathlib`` discards the base directory when an
     absolute path is joined onto it (``Path("cases") / "C:/x"`` -> ``C:/x``).
  2. Unsafe default: ``run_server`` must refuse to bind a non-loopback
     interface unless a token is configured, or a bare ``lfa serve`` exposes
     every case with no authentication on all interfaces.
  3. Unbounded ingest: ``POST /api/v1/ingest`` must reject a body larger than
     a configured cap instead of streaming it to disk unbounded.
"""
import http.server
import socketserver
import sys
import threading
import urllib.error
import urllib.parse
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


class _ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@pytest.fixture
def secure_server(tmp_path):
    """A running, token-protected server plus a secret file OUTSIDE cases_dir."""
    cases_dir = tmp_path / "cases"
    host_raw = cases_dir / "CASE-1" / "raw" / "host1" / "collected" / "files"
    host_raw.mkdir(parents=True)

    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-EXFIL-CONTENT", encoding="utf-8")

    port = _find_free_port()
    httpd = _ThreadedServer(("127.0.0.1", port), LFAServerHandler)
    httpd.cases_dir = cases_dir
    httpd.auth_token = TOKEN
    httpd.auto_analyse = False
    httpd.business_hours = "08-18"
    httpd.examiner = "Test"

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield {
        "url": f"http://127.0.0.1:{port}",
        "secret": secret,
        "cases_dir": cases_dir,
    }
    httpd.shutdown()
    httpd.server_close()


def _get(url: str):
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {TOKEN}"}
    )
    return urllib.request.urlopen(req, timeout=10)


# --- Finding 1: arbitrary file read via absolute path ----------------------

def test_static_route_refuses_absolute_path_outside_cases_dir(secure_server):
    """GET /cases/<abs path> must not serve a file outside cases_dir.

    The absolute path escapes because pathlib drops the base on join; this is
    cross-platform (any absolute path, POSIX or drive-letter).
    """
    secret_url = secure_server["secret"].resolve().as_posix()
    url = f"{secure_server['url']}/cases/{secret_url}"
    try:
        resp = _get(url)
        body = resp.read().decode("utf-8", errors="replace")
        assert "TOP-SECRET-EXFIL-CONTENT" not in body, (
            "server served a file outside cases_dir"
        )
    except urllib.error.HTTPError as exc:
        assert exc.code in (400, 404)


@pytest.mark.skipif(sys.platform != "win32", reason="drive-letter absolute path")
def test_artifact_content_refuses_absolute_path_outside_cases_dir(secure_server):
    """artifact-content?path=<drive-absolute> must not read outside the case.

    lstrip('/') neutralises a POSIX-absolute path, but a Windows drive path
    (C:/...) survives it and then discards the base on join.
    """
    secret_url = secure_server["secret"].resolve().as_posix()  # C:/.../secret.txt
    url = (
        f"{secure_server['url']}/api/v1/cases/CASE-1/artifact-content"
        f"?path={urllib.parse.quote(secret_url)}"
    )
    try:
        resp = _get(url)
        import json
        data = json.loads(resp.read().decode("utf-8"))
        assert "TOP-SECRET-EXFIL-CONTENT" not in data.get("content", ""), (
            "artifact-content served a file outside the case"
        )
    except urllib.error.HTTPError as exc:
        assert exc.code in (400, 404)


def test_static_route_still_rejects_dotdot_traversal(secure_server):
    """The original relative-traversal guard must remain intact."""
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"{secure_server['url']}/cases/../secret.txt")
    assert exc.value.code in (400, 404)


# --- Finding 3: unbounded ingest -------------------------------------------

@pytest.fixture
def capped_server(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir(parents=True)
    port = _find_free_port()
    httpd = _ThreadedServer(("127.0.0.1", port), LFAServerHandler)
    httpd.cases_dir = cases_dir
    httpd.auth_token = None  # focus the test on the size cap, not auth
    httpd.auto_analyse = False
    httpd.business_hours = "08-18"
    httpd.examiner = "Test"
    httpd.max_ingest_bytes = 1024  # tiny cap for the test

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield {"url": f"http://127.0.0.1:{port}", "cases_dir": cases_dir}
    httpd.shutdown()
    httpd.server_close()


def test_ingest_rejects_body_over_the_cap(capped_server):
    oversized = b"x" * 5000  # cap is 1024
    req = urllib.request.Request(
        f"{capped_server['url']}/api/v1/ingest",
        data=oversized,
        headers={"X-Case-ID": "TOOBIG"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=10)
    assert exc.value.code == 413
    # nothing should have been written for the rejected case
    assert not (capped_server["cases_dir"] / "TOOBIG" / "bundle.tar.gz").exists()


# --- Finding 2: unsafe default (open bind without a token) ------------------

def _patch_serve_forever(monkeypatch):
    from lfa import server as server_mod
    monkeypatch.setattr(
        server_mod.socketserver.ThreadingMixIn, "serve_forever",
        lambda self, *a, **k: None, raising=False,
    )


def test_run_server_refuses_open_bind_without_token(tmp_path, monkeypatch):
    from lfa import server as server_mod
    _patch_serve_forever(monkeypatch)
    with pytest.raises(SystemExit):
        server_mod.run_server(
            host="0.0.0.0", port=_find_free_port(),
            cases_dir=tmp_path / "cases", token=None,
        )


def test_run_server_allows_open_bind_with_token(tmp_path, monkeypatch):
    from lfa import server as server_mod
    _patch_serve_forever(monkeypatch)
    # must NOT raise: an authenticated network listener is the supported mode
    server_mod.run_server(
        host="0.0.0.0", port=_find_free_port(),
        cases_dir=tmp_path / "cases", token="a-real-token",
    )


def test_run_server_allows_loopback_without_token(tmp_path, monkeypatch):
    from lfa import server as server_mod
    _patch_serve_forever(monkeypatch)
    # loopback with no token is the local-review default and stays allowed
    server_mod.run_server(
        host="127.0.0.1", port=_find_free_port(),
        cases_dir=tmp_path / "cases", token=None,
    )


def test_cli_serve_plumbs_max_ingest_gb(tmp_path, monkeypatch):
    """`serve --max-ingest-gb N` must reach run_server as N GiB of bytes,
    so an examiner can lift the cap for a legitimately large bundle."""
    from lfa import __main__ as cli
    from lfa import server as server_mod

    captured = {}

    def fake_run_server(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(server_mod, "run_server", fake_run_server)
    cli.main([
        "serve", "--host", "127.0.0.1", "--port", str(_find_free_port()),
        "--cases-dir", str(tmp_path / "cases"), "--max-ingest-gb", "2",
    ])
    assert captured.get("max_ingest_bytes") == 2 * 1024 * 1024 * 1024
