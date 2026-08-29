"""cron log parser (spec category 4): the execution record that proves a
scheduled job actually ran, plus crontab-edit lines that timestamp WHEN a
job was planted. Grammar-driven on top of SyslogTextParser."""
import gzip
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.cronlog import CronLogParser
from lfa.schema import validate
from lfa.timeeng import TimeContext

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "persistence"
CRON_LOG = (FIXTURES / "var/log/cron").read_bytes()


def make_ctx(tmp_path):
    return ParseContext(
        case_id="C1",
        host_id="H1",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("Asia/Karachi", "etc_localtime"),
        distro_profile={"distro_id": "debian"},
        artifact_sha256="a" * 64,
        artifact_mtime=datetime(2024, 3, 20, tzinfo=timezone.utc).timestamp(),
    )


def parse_bytes(tmp_path, data=CRON_LOG, name="cron"):
    p = tmp_path / name
    p.write_bytes(data)
    ctx = make_ctx(tmp_path)
    parser = CronLogParser()
    ctx.artifact_rel = f"var/log/{name}"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(p, ctx))
    for ev in events:
        assert validate(ev) == [], ev
    return events, ctx


def test_claims_cron_logs_and_syslog():
    parser = CronLogParser()
    for rel in ("var/log/cron", "var/log/cron.1", "var/log/cron.2.gz",
                "var/log/cron-20240314", "var/log/syslog", "var/log/syslog.1",
                "var/log/messages"):
        assert parser.can_parse(rel, {}), rel
    assert not parser.can_parse("var/log/auth.log", {})


def test_cron_commands_extracted(tmp_path):
    events, _ = parse_bytes(tmp_path)
    cmds = [e for e in events if e.subcategory == "cron_command"]
    assert len(cmds) == 3
    assert {e.category for e in cmds} == {"persistence"}
    hourly = cmds[0]
    assert hourly.actor_user == "root"
    assert hourly.actor_process == "cron"
    assert "run-parts --report /etc/cron.hourly" in hourly.description
    nested = cmds[2]
    assert nested.description.endswith(
        "test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )")


def test_session_open_close_still_matched(tmp_path):
    events, _ = parse_bytes(tmp_path)
    assert any(e.subcategory == "cron_run" and e.actor_user == "root"
               for e in events)
    assert any(e.subcategory == "cron_session_closed" for e in events)


def test_crontab_edits_are_persistence_evidence(tmp_path):
    events, _ = parse_bytes(tmp_path)
    replace = next(e for e in events if e.subcategory == "crontab_modified")
    assert replace.actor_user == "alice"
    assert replace.severity == "medium"
    assert replace.timestamp_confidence == "year_inferred"
    # 02:31:44 Karachi (+05:00) == 21:31:44 UTC the day before
    assert replace.timestamp_utc == "2024-03-13T21:31:44+00:00"
    assert replace.timestamp_local == "2024-03-14T02:31:44+05:00"
    assert any(e.subcategory == "crontab_edit" for e in events)
    assert any(e.subcategory == "cron_reload" for e in events)


def test_suspicious_cron_command_escalated(tmp_path):
    events, _ = parse_bytes(tmp_path)
    sus = [e for e in events if e.subcategory == "suspicious_cron_command"]
    assert len(sus) == 1
    assert sus[0].severity == "high"
    assert sus[0].actor_user == "alice"
    assert sus[0].timestamp_utc is not None
    assert "base64" in sus[0].description
    # the derived event quotes the command itself, not the whole syslog line
    assert sus[0].raw_line.startswith("/usr/bin/base64")


def test_anacron_lines_matched(tmp_path):
    events, _ = parse_bytes(tmp_path)
    ana = [e for e in events if e.subcategory == "anacron_job"]
    assert len(ana) == 2
    assert "cron.daily" in ana[0].description


def test_gz_rotated_and_binary_junk_do_not_raise(tmp_path):
    events, _ = parse_bytes(tmp_path, gzip.compress(CRON_LOG), name="cron.2.gz")
    assert any(e.subcategory == "cron_command" for e in events)

    junk, ctx = parse_bytes(
        tmp_path,
        b"\x00\x01\xff\xfe not a log line\nMar 14 02:17:01 web1 CRON[1]: (root) CMD\n",
        name="cron.3",
    )
    assert isinstance(junk, list)
