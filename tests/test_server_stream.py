"""Tests for LFA Central Ingestion & Investigation Server (server.py).

Verifies:
  1. Health and status APIs.
  2. Bearer token authentication (valid, invalid, omitted).
  3. Streaming evidence ingestion (POST /api/v1/ingest).
  4. In-flight SHA-256 verification and mismatch detection.
  5. Automated analysis pipeline execution upon stream arrival.
  6. SOC web dashboard rendering and case list APIs.
  7. Report serving and path traversal protection.
"""
import hashlib
import io
import json
import socketserver
import tarfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from analyzer.lfa import __version__
from analyzer.lfa.server import LFAServerHandler


def _find_free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _create_sample_bundle(tmp_path: Path) -> tuple[Path, str, bytes]:
    """Create a minimal valid evidence bundle for streaming tests."""
    bundle_dir = tmp_path / "bundle_src"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "collected" / "files" / "etc").mkdir(parents=True, exist_ok=True)

    # os-release
    (bundle_dir / "collected" / "files" / "etc" / "os-release").write_text(
        'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n',
        encoding="utf-8",
    )
    # passwd
    (bundle_dir / "collected" / "files" / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nuser1:x:1000:1000::/home/user1:/bin/bash\n",
        encoding="utf-8",
    )

    # manifest.json
    manifest = {
        "collector_version": "1.0.0",
        "case_id": "STREAM-TEST-01",
        "operator": "test-examiner",
        "collection_start_utc": "2026-08-29T10:00:00Z",
        "collection_end_utc": "2026-08-29T10:00:05Z",
        "root": "/",
        "host": {
            "distro_id": "debian",
            "version_id": "12",
            "pretty_name": "Debian GNU/Linux 12",
            "kernel": "6.1.0",
            "hostname": "stream-target-01",
            "timezone": "UTC",
        },
        "collected_files": 2,
    }
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    # hash_manifest.csv
    hash_csv = (
        "original_path,sha256,size,mode,owner,atime,mtime,ctime,source_was_active,status\n"
        "/etc/os-release,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,60,644,0:0,1700000000,1700000000,1700000000,0,collected\n"
        "/etc/passwd,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,75,644,0:0,1700000000,1700000000,1700000000,0,collected\n"
    )
    (bundle_dir / "hash_manifest.csv").write_text(hash_csv, encoding="utf-8")
    (bundle_dir / "collector.log").write_text("collector finished successfully\n", encoding="utf-8")

    tar_path = tmp_path / "sample_bundle.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(bundle_dir / "collected", arcname="collected")
        tar.add(bundle_dir / "manifest.json", arcname="manifest.json")
        tar.add(bundle_dir / "hash_manifest.csv", arcname="hash_manifest.csv")
        tar.add(bundle_dir / "collector.log", arcname="collector.log")

    data = tar_path.read_bytes()
    sha256_hex = hashlib.sha256(data).hexdigest()
    return tar_path, sha256_hex, data


@pytest.fixture
def server_instance(tmp_path):
    """Start a local threaded LFA ingestion server on a free port."""
    port = _find_free_port()
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)

    class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        daemon_threads = True
        allow_reuse_address = True

    httpd = ThreadedServer(("127.0.0.1", port), LFAServerHandler)
    httpd.cases_dir = cases_dir  # type: ignore[attr-defined]
    httpd.auth_token = "secret-token-123"  # type: ignore[attr-defined]
    httpd.auto_analyse = True  # type: ignore[attr-defined]
    httpd.examiner = "Test Examiner"  # type: ignore[attr-defined]
    httpd.business_hours = "08-18"  # type: ignore[attr-defined]

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    yield {
        "url": f"http://127.0.0.1:{port}",
        "cases_dir": cases_dir,
        "token": "secret-token-123",
    }

    httpd.shutdown()
    httpd.server_close()


def test_server_health_and_status(server_instance):
    base_url = server_instance["url"]
    req = urllib.request.Request(f"{base_url}/api/v1/health")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "online"
        assert data["version"] == __version__
        assert data["cases_count"] == 0


def test_server_auth_rejection(server_instance, tmp_path):
    base_url = server_instance["url"]
    _, _, bundle_bytes = _create_sample_bundle(tmp_path)

    # Missing token
    req = urllib.request.Request(
        f"{base_url}/api/v1/ingest",
        data=bundle_bytes,
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 401

    # Invalid token
    req_bad = urllib.request.Request(
        f"{base_url}/api/v1/ingest",
        data=bundle_bytes,
        headers={"Authorization": "Bearer wrong-token"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info2:
        urllib.request.urlopen(req_bad)
    assert exc_info2.value.code == 401


def test_streaming_ingest_and_auto_analysis(server_instance, tmp_path):
    base_url = server_instance["url"]
    token = server_instance["token"]
    cases_dir = server_instance["cases_dir"]

    _, sha256_hex, bundle_bytes = _create_sample_bundle(tmp_path)

    # Perform authenticated streaming ingest
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Case-ID": "STREAM_INCIDENT_01",
        "X-Examiner": "SOC Lead",
        "X-Bundle-SHA256": sha256_hex,
        "Content-Type": "application/gzip",
    }
    req = urllib.request.Request(
        f"{base_url}/api/v1/ingest",
        data=bundle_bytes,
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        res_data = json.loads(resp.read().decode("utf-8"))
        assert res_data["status"] == "success"
        assert res_data["case_id"] == "STREAM_INCIDENT_01"
        assert res_data["bundle_sha256"] == sha256_hex
        assert res_data["analysed"] is True
        assert res_data["report_url"] == "/cases/STREAM_INCIDENT_01/report.html"

    # Verify disk state in cases directory
    case_folder = cases_dir / "STREAM_INCIDENT_01"
    assert (case_folder / "bundle.tar.gz").exists()
    assert (case_folder / "bundle.tar.gz.sha256").exists()
    assert (case_folder / "case.db").exists()
    assert (case_folder / "report.html").exists()
    assert (case_folder / "exports" / "events.json").exists()


def test_streaming_hash_mismatch_rejection(server_instance, tmp_path):
    base_url = server_instance["url"]
    token = server_instance["token"]

    _, _, bundle_bytes = _create_sample_bundle(tmp_path)
    bad_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Case-ID": "TAMPERED_STREAM",
        "X-Bundle-SHA256": bad_sha256,
    }
    req = urllib.request.Request(
        f"{base_url}/api/v1/ingest",
        data=bundle_bytes,
        headers=headers,
        method="POST",
    )

    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 400


def test_dashboard_and_report_serving(server_instance, tmp_path):
    base_url = server_instance["url"]
    token = server_instance["token"]

    _, sha256_hex, bundle_bytes = _create_sample_bundle(tmp_path)
    req_ingest = urllib.request.Request(
        f"{base_url}/api/v1/ingest",
        data=bundle_bytes,
        headers={"Authorization": f"Bearer {token}", "X-Case-ID": "DASHBOARD_CASE_01"},
        method="POST",
    )
    urllib.request.urlopen(req_ingest)

    # GET Dashboard HTML
    req_dash = urllib.request.Request(f"{base_url}/")
    with urllib.request.urlopen(req_dash) as resp:
        assert resp.status == 200
        html = resp.read().decode("utf-8")
        assert "LFA Forensic Ingestion Console" in html
        assert "DASHBOARD_CASE_01" in html

    # GET Case list JSON
    req_cases = urllib.request.Request(f"{base_url}/api/v1/cases")
    with urllib.request.urlopen(req_cases) as resp:
        assert resp.status == 200
        cases_data = json.loads(resp.read().decode("utf-8"))
        assert len(cases_data["cases"]) >= 1
        assert cases_data["cases"][0]["case_id"] == "DASHBOARD_CASE_01"

    # GET Report HTML
    req_rep = urllib.request.Request(f"{base_url}/cases/DASHBOARD_CASE_01/report.html")
    with urllib.request.urlopen(req_rep) as resp:
        assert resp.status == 200
        rep_html = resp.read().decode("utf-8")
        assert "Linux Forensic Analysis Report" in rep_html

    # Security: Path traversal protection
    req_bad_path = urllib.request.Request(f"{base_url}/cases/../secret.txt")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req_bad_path)
    assert exc_info.value.code in (400, 404)
