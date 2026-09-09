"""Unit tests for Web Log, FTP Log, and Browser History parsers."""
import sqlite3
from pathlib import Path
import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.weblog import WebLogParser
from lfa.parsers.ftplog import FtpLogParser
from lfa.parsers.browser import BrowserParser
from lfa.schema import validate
from lfa.timeeng import TimeContext


@pytest.fixture
def ctx(tmp_path):
    return ParseContext(
        case_id="CASE-01",
        host_id="HOST-01",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("UTC", "assumed_utc"),
        distro_profile={"distro_id": "ubuntu"},
        artifact_sha256="0" * 64,
        artifact_mtime=1700000000.0,
    )


def test_weblog_parser(tmp_path, ctx):
    log_file = tmp_path / "access.log"
    log_file.write_text(
        '192.168.1.50 - admin [10/Oct/2024:13:55:36 +0000] "GET /index.php HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"\n'
        '192.168.1.99 - - [10/Oct/2024:13:56:00 +0000] "GET /etc/passwd HTTP/1.1" 404 180 "-" "sqlmap/1.0"\n',
        encoding="utf-8",
    )
    parser = WebLogParser()
    ctx.artifact_rel = "var/log/apache2/access.log"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version

    events = list(parser.parse(log_file, ctx))
    assert len(events) == 2
    for ev in events:
        assert validate(ev) == []
        assert ev.category == "user_activity"
        assert ev.subcategory == "http_request"

    assert events[0].actor_user == "admin"
    assert events[0].source_ip == "192.168.1.50"
    assert events[0].severity == "info"

    # Suspicious pattern /etc/passwd -> elevated severity
    assert events[1].source_ip == "192.168.1.99"
    assert events[1].severity == "medium"


def test_ftplog_parser(tmp_path, ctx):
    log_file = tmp_path / "vsftpd.log"
    log_file.write_text(
        'Sun Mar 22 10:14:23 2020 [pid 1234] [msfadmin] OK LOGIN: Client "192.168.1.50"\n'
        'Sun Mar 22 10:15:10 2020 [pid 1234] [msfadmin] OK UPLOAD: Client "192.168.1.50", "/pub/malware.sh", 1234 bytes, 12.34Kbyte/sec\n',
        encoding="utf-8",
    )
    parser = FtpLogParser()
    ctx.artifact_rel = "var/log/vsftpd.log"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version

    events = list(parser.parse(log_file, ctx))
    assert len(events) == 2
    for ev in events:
        assert validate(ev) == []
        assert ev.category == "user_activity"
        assert ev.subcategory == "ftp_transfer"

    assert events[0].actor_user == "msfadmin"
    assert "LOGIN" in events[0].description
    assert events[1].severity == "medium"
    assert "UPLOAD" in events[1].description


def test_browser_parser_chrome(tmp_path, ctx):
    hist_file = tmp_path / "History"
    conn = sqlite3.connect(hist_file)
    conn.execute(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)"
    )
    conn.execute(
        "CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, start_time INTEGER, end_time INTEGER, total_bytes INTEGER, tab_url TEXT)"
    )
    # Insert a sample url with webkit epoch (13300000000000000 us)
    conn.execute(
        "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES ('https://github.com', 'GitHub', 5, 13340000000000000)"
    )
    conn.execute(
        "INSERT INTO downloads (target_path, start_time, end_time, total_bytes, tab_url) VALUES ('/home/user/tool.zip', 13340000000000000, 13340000005000000, 1024, 'https://example.com/tool.zip')"
    )
    conn.commit()
    conn.close()

    parser = BrowserParser()
    ctx.artifact_rel = "home/kali/.config/google-chrome/Default/History"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version

    events = list(parser.parse(hist_file, ctx))
    assert len(events) == 2
    for ev in events:
        assert validate(ev) == []
        assert ev.actor_user == "kali"
        assert ev.category == "user_activity"
