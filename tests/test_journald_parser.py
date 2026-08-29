"""journald export parser.

The on-disk journal format is undocumented and version-unstable, so the
collector exports it with the machine's own `journalctl -o json`. This
parser reads those JSON lines. journald is CORE, equal priority to
auth.log: Debian 12 and minimal cloud images have no auth.log at all
(spec trap #7).
"""
import json
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.journald import JournaldParser
from lfa.schema import validate
from lfa.timeeng import TimeContext


def jline(**kw):
    base = {
        "__REALTIME_TIMESTAMP": "1710382747000000",  # 2024-03-14T02:19:07Z
        "_HOSTNAME": "web1",
        "_COMM": "sshd",
        "SYSLOG_IDENTIFIER": "sshd",
        "_PID": "903",
        "MESSAGE": "Accepted password for admin from 203.0.113.9 port 40009 ssh2",
    }
    base.update(kw)
    return json.dumps(base)


JOURNAL = "\n".join(
    [
        jline(),
        jline(
            __REALTIME_TIMESTAMP="1710382441000000",
            MESSAGE="Failed password for admin from 203.0.113.9 port 40001 ssh2",
            _PID="900",
        ),
        jline(
            _COMM="sudo",
            SYSLOG_IDENTIFIER="sudo",
            __REALTIME_TIMESTAMP="1710382900000000",
            MESSAGE="  admin : TTY=pts/1 ; PWD=/root ; USER=root ; "
                    "COMMAND=/usr/sbin/usermod -aG sudo eviluser",
        ),
        jline(
            _COMM="useradd",
            SYSLOG_IDENTIFIER="useradd",
            __REALTIME_TIMESTAMP="1710382800000000",
            MESSAGE="new user: name=eviluser, UID=1004, GID=1004, "
                    "home=/home/eviluser, shell=/bin/bash",
        ),
        jline(
            _COMM="systemd-logind",
            SYSLOG_IDENTIFIER="systemd-logind",
            __REALTIME_TIMESTAMP="1710383000000000",
            MESSAGE="New session 42 of user eviluser.",
        ),
        jline(
            _COMM="kernel",
            SYSLOG_IDENTIFIER="kernel",
            __REALTIME_TIMESTAMP="1710383100000000",
            MESSAGE="usb 1-2: New USB device found, idVendor=0781, "
                    "idProduct=5567, bcdDevice= 1.00",
        ),
        "{ this is not valid json at all",
        jline(
            _COMM="CROND",
            SYSLOG_IDENTIFIER="CROND",
            __REALTIME_TIMESTAMP="1710383200000000",
            MESSAGE="(root) CMD (/usr/local/bin/backup.sh)",
        ),
    ]
) + "\n"


@pytest.fixture
def ctx(tmp_path):
    return ParseContext(
        case_id="C1",
        host_id="H1",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("Asia/Karachi", "etc_localtime"),
        distro_profile={"distro_id": "debian"},
        artifact_sha256="a" * 64,
    )


def parse(tmp_path, ctx, content=JOURNAL):
    p = tmp_path / "boot-0.json"
    p.write_bytes(content.encode("utf-8"))
    parser = JournaldParser()
    ctx.artifact_rel = "journal/boot-0.json"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(p, ctx))
    for ev in events:
        assert validate(ev) == [], ev
    return events


def test_timestamps_are_exact_from_realtime_microseconds(tmp_path, ctx):
    events = parse(tmp_path, ctx)
    accepted = next(e for e in events if e.subcategory == "successful_login")
    assert accepted.timestamp_confidence == "exact"
    assert accepted.timestamp_utc == "2024-03-14T02:19:07+00:00"
    assert accepted.timestamp_local == "2024-03-14T07:19:07+05:00"


def test_login_and_privilege_events_extracted(tmp_path, ctx):
    events = parse(tmp_path, ctx)
    subs = [e.subcategory for e in events]
    assert "successful_login" in subs
    assert "failed_login" in subs
    assert "sudo_command" in subs
    assert "account_created" in subs

    failed = next(e for e in events if e.subcategory == "failed_login")
    assert failed.source_ip == "203.0.113.9"
    assert failed.actor_user == "admin"

    created = next(e for e in events if e.subcategory == "account_created")
    assert created.actor_user == "eviluser"
    assert created.category == "user_accounts"


def test_unmatched_messages_still_yield_generic_events(tmp_path, ctx):
    """An analyst must be able to see the journal timeline even for lines no
    grammar rule matched - otherwise the tool silently drops evidence."""
    events = parse(tmp_path, ctx)
    generic = [e for e in events if e.subcategory == "journal_message"]
    assert generic, "expected generic journal events for unmatched messages"
    kernel_ev = next(e for e in generic if e.actor_process == "kernel")
    assert "usb 1-2" in kernel_ev.description


def test_malformed_json_line_skipped_without_crashing(tmp_path, ctx):
    events = parse(tmp_path, ctx)
    assert len(events) >= 7


def test_process_and_pid_recorded(tmp_path, ctx):
    events = parse(tmp_path, ctx)
    ev = next(e for e in events if e.subcategory == "successful_login")
    assert ev.actor_process == "sshd"
    assert "903" in (ev.notes or "")


def test_message_can_be_a_byte_array(tmp_path, ctx):
    """journalctl emits MESSAGE as an array of ints when it is not valid
    UTF-8; the parser must decode rather than crash."""
    content = json.dumps(
        {
            "__REALTIME_TIMESTAMP": "1710382747000000",
            "_COMM": "kernel",
            "MESSAGE": [72, 101, 108, 108, 111],  # "Hello"
        }
    ) + "\n"
    events = parse(tmp_path, ctx, content)
    assert events and "Hello" in events[0].description


def test_missing_timestamp_marked_unknown(tmp_path, ctx):
    content = json.dumps({"_COMM": "sshd", "MESSAGE": "no timestamp here"}) + "\n"
    events = parse(tmp_path, ctx, content)
    assert events[0].timestamp_utc is None
    assert events[0].timestamp_confidence == "unknown"


def test_journald_sequence_gap_detected(tmp_path, ctx):
    content = "\n".join([
        json.dumps({"__SEQNUM": 100, "__REALTIME_TIMESTAMP": "1710382747000000", "_COMM": "systemd", "MESSAGE": "boot msg 1"}),
        json.dumps({"__SEQNUM": 101, "__REALTIME_TIMESTAMP": "1710382748000000", "_COMM": "systemd", "MESSAGE": "boot msg 2"}),
        json.dumps({"__SEQNUM": 150, "__REALTIME_TIMESTAMP": "1710382749000000", "_COMM": "systemd", "MESSAGE": "boot msg 3"}),
    ]) + "\n"
    events = parse(tmp_path, ctx, content)
    gaps = [e for e in events if e.subcategory == "journal_sequence_gap"]
    assert len(gaps) == 1
    assert "expected seq 102, got 150" in gaps[0].description
    assert gaps[0].severity == "high"

