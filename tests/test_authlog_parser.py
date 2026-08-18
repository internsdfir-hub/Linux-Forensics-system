"""auth.log / secure parser: grammar-driven, year-inferred timestamps,
gz rotated variants, decode-error tolerance, contamination auto-tagging."""
import gzip
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lfa.parsers.authlog import AuthLogParser
from lfa.parsers.base import ParseContext
from lfa.schema import validate
from lfa.timeeng import TimeContext

AUTH_LINES = (
    "Mar 14 02:14:01 web1 sshd[900]: Failed password for admin from 203.0.113.9 port 40001 ssh2\n"
    "Mar 14 02:14:07 web1 sshd[901]: Failed password for invalid user oracle from 203.0.113.9 port 40002 ssh2\n"
    "Mar 14 02:19:07 web1 sshd[903]: Accepted password for admin from 203.0.113.9 port 40009 ssh2\n"
    "Mar 14 02:23:00 web1 useradd[9001]: new user: name=eviluser, UID=1004, GID=1004, home=/home/eviluser, shell=/bin/bash\n"
    "Mar 14 02:25:00 web1 sudo:    admin : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo eviluser\n"
    "Mar 14 02:25:01 web1 usermod[9010]: add 'eviluser' to group 'sudo'\n"
    "Mar 14 03:00:00 web1 sshd[950]: Accepted publickey for examiner from 10.9.9.9 port 55555 ssh2\n"
    "kernel: no timestamp on this line at all\n"
)


def make_ctx(tmp_path, contamination=None):
    return ParseContext(
        case_id="C1",
        host_id="H1",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("Asia/Karachi", "etc_localtime"),
        distro_profile={"distro_id": "debian"},
        artifact_sha256="a" * 64,
        artifact_mtime=datetime(2024, 3, 20, tzinfo=timezone.utc).timestamp(),
        contamination=contamination or {},
    )


def parse_file(tmp_path, content=AUTH_LINES, name="auth.log", contamination=None,
               binary=None):
    p = tmp_path / name
    if binary is not None:
        p.write_bytes(binary)
    else:
        p.write_bytes(content.encode("utf-8"))
    ctx = make_ctx(tmp_path, contamination)
    parser = AuthLogParser()
    ctx.artifact_rel = f"var/log/{name}"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(p, ctx))
    for ev in events:
        assert validate(ev) == [], ev
    return events, ctx


def test_events_extracted_with_correct_fields(tmp_path):
    events, _ = parse_file(tmp_path)
    failed = [e for e in events if e.subcategory == "failed_login"]
    assert len(failed) == 2
    assert failed[0].actor_user == "admin"
    assert failed[0].source_ip == "203.0.113.9"
    assert failed[1].actor_user == "oracle"

    accepted = [e for e in events if e.subcategory == "successful_login"]
    assert len(accepted) == 2

    sudo = [e for e in events if e.subcategory == "sudo_command"]
    assert len(sudo) == 1
    assert sudo[0].category == "privilege_escalation"
    assert "usermod -aG sudo eviluser" in sudo[0].description

    created = [e for e in events if e.subcategory == "account_created"]
    assert created and created[0].actor_user == "eviluser"
    assert created[0].actor_uid == 1004


def test_timestamps_year_inferred_and_converted(tmp_path):
    events, _ = parse_file(tmp_path)
    first = next(e for e in events if e.subcategory == "failed_login")
    assert first.timestamp_confidence == "year_inferred"
    # Karachi +05:00 -> 02:14 local is 21:14 UTC the previous day
    assert first.timestamp_utc == "2024-03-13T21:14:01+00:00"
    assert first.timestamp_local == "2024-03-14T02:14:01+05:00"


def test_offsets_point_at_source_lines(tmp_path):
    events, _ = parse_file(tmp_path)
    first = next(e for e in events if e.subcategory == "failed_login")
    assert first.raw_line_offset == 0
    second = [e for e in events if e.subcategory == "failed_login"][1]
    assert second.raw_line_offset == len(AUTH_LINES.splitlines(True)[0])


def test_gz_rotated_variant_parsed(tmp_path):
    gz_bytes = gzip.compress(AUTH_LINES.encode("utf-8"))
    events, _ = parse_file(tmp_path, name="auth.log.2.gz", binary=gz_bytes)
    assert any(e.subcategory == "failed_login" for e in events)


def test_non_utf8_bytes_survive(tmp_path):
    dirty = AUTH_LINES.encode("utf-8") + \
        b"Mar 14 04:00:00 web1 sshd[999]: Failed password for \xff\xfe from 1.2.3.4 port 1 ssh2\n"
    events, ctx = parse_file(tmp_path, binary=dirty)
    assert ctx.had_decode_errors is True
    # the dirty line still produced an event
    assert any(e.source_ip == "1.2.3.4" for e in events)


def test_contamination_session_auto_tagged(tmp_path):
    contamination = {
        "source_ip": "10.9.9.9",
        "start_utc": "2024-03-13T21:55:00Z",
        "end_utc": "2024-03-13T22:10:00Z",
    }
    events, _ = parse_file(tmp_path, contamination=contamination)
    examiner_login = next(e for e in events if e.actor_user == "examiner")
    # local 03:00 Karachi == 22:00 UTC, inside the collection window
    assert examiner_login.tool_generated_flag is True
    victim_login = next(e for e in events if e.actor_user == "admin"
                        and e.subcategory == "successful_login")
    assert victim_login.tool_generated_flag is False
