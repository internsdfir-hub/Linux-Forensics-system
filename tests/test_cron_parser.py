"""cron parser (spec category 4, persistence): system crontabs carry a user
field, per-user spool crontabs do not, @reboot is the classic re-infection
hook, and the file mtime is what ties a job to the incident window."""
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.cron import CronParser
from lfa.schema import validate
from lfa.timeeng import TimeContext

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "persistence"
MTIME = datetime(2024, 3, 14, 2, 31, 4, tzinfo=timezone.utc).timestamp()


@pytest.fixture
def ctx(tmp_path):
    return ParseContext(
        case_id="C1",
        host_id="H1",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("Asia/Karachi", "etc_localtime"),
        distro_profile={"distro_id": "debian"},
        artifact_sha256="a" * 64,
        artifact_mtime=MTIME,
    )


def parse(ctx, rel, root=FIXTURES):
    parser = CronParser()
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(Path(root) / rel, ctx))
    for ev in events:
        assert validate(ev) == [], ev
        assert ev.category == "persistence"
        assert ev.event_kind == "state_finding"
        assert ev.timestamp_utc is None
        assert ev.timestamp_local is None
        assert ev.timestamp_confidence == "unknown"
    return events


def test_claims_all_cron_locations():
    parser = CronParser()
    for rel in (
        "etc/crontab",
        "etc/cron.d/php",
        "var/spool/cron/crontabs/alice",
        "var/spool/cron/bob",
        "etc/cron.hourly/x",
        "etc/cron.daily/logrotate",
        "etc/cron.weekly/man-db",
        "etc/cron.monthly/0anacron",
    ):
        assert parser.can_parse(rel, {}), rel
    assert not parser.can_parse("etc/passwd", {})


def test_system_crontab_has_user_field(ctx):
    events = parse(ctx, "etc/crontab")
    jobs = [e for e in events if e.subcategory == "cron_job"]
    assert len(jobs) == 4  # 4 benign run-parts jobs; 2 more are suspicious
    hourly = next(e for e in jobs if "cron.hourly" in e.description)
    assert hourly.actor_user == "root"
    assert "17 * * * *" in hourly.description
    assert "run-parts --report /etc/cron.hourly" in hourly.description


def test_env_lines_captured(ctx):
    events = parse(ctx, "etc/crontab")
    env = {e.description.split("=")[0].split()[-1]: e
           for e in events if e.subcategory == "cron_env"}
    assert set(env) == {"SHELL", "PATH", "MAILTO"}
    assert env["MAILTO"].severity == "info"


def test_mtime_in_description_for_window_correlation(ctx):
    events = parse(ctx, "etc/crontab")
    assert all("2024-03-14T02:31:04+00:00" in e.description for e in events)
    job = next(e for e in events if e.subcategory == "cron_job")
    assert "file_mtime_epoch=" in (job.notes or "")


def test_suspicious_commands_flagged_high(ctx):
    events = parse(ctx, "etc/crontab")
    sus = [e for e in events if e.subcategory == "suspicious_cron_job"]
    assert len(sus) == 2
    assert all(e.severity == "high" for e in sus)
    piped = next(e for e in sus if "curl" in e.raw_line)
    assert "pipes downloaded content" in piped.description
    reboot = next(e for e in sus if "sysupdate" in e.raw_line)
    assert "@reboot" in reboot.description
    # /tmp and the hidden filename are both called out
    assert "/tmp" in reboot.description and "hidden" in reboot.description
    # raw_line points at the command inside the line, offset stays truthful
    body = (FIXTURES / "etc/crontab").read_bytes()
    assert body[reboot.raw_line_offset:
               reboot.raw_line_offset + len(reboot.raw_line)] == \
        reboot.raw_line.encode()


def test_special_schedule_syntax(ctx):
    events = parse(ctx, "etc/crontab")
    reboot = next(e for e in events if "@reboot" in e.description or "@reboot" in e.raw_line)
    assert reboot.actor_user == "root"
    assert "at every boot" in reboot.description



def test_spool_crontab_has_no_user_field_and_takes_user_from_filename(ctx):
    events = parse(ctx, "var/spool/cron/crontabs/alice")
    jobs = [e for e in events if e.subcategory in
            ("cron_job", "suspicious_cron_job")]
    assert len(jobs) == 2
    assert {e.actor_user for e in jobs} == {"alice"}
    backup = next(e for e in jobs if e.subcategory == "cron_job")
    assert "0 3 * * *" in backup.description
    assert "/home/alice/bin/backup.sh --quiet" in backup.description
    daily = next(e for e in jobs if e.subcategory == "suspicious_cron_job")
    assert "base64" in daily.description
    assert daily.severity == "high"


def test_cron_d_fragment_and_backdoor(ctx):
    ok = parse(ctx, "etc/cron.d/php")
    assert [e.subcategory for e in ok] == ["cron_job"]
    assert ok[0].actor_user == "root"

    bad = parse(ctx, "etc/cron.d/apache-check")
    assert bad[0].subcategory == "suspicious_cron_job"
    assert bad[0].actor_user == "www-data"
    assert bad[0].severity == "high"


def test_run_parts_script_directories(ctx):
    events = parse(ctx, "etc/cron.daily/logrotate")
    summary = next(e for e in events if e.subcategory == "cron_job")
    assert "daily" in summary.description
    assert summary.actor_user == "root"

    evil = parse(ctx, "etc/cron.daily/0update")
    sus = [e for e in evil if e.subcategory == "suspicious_cron_job"]
    assert len(sus) == 1
    assert "wget" in sus[0].raw_line


def test_garbage_and_truncated_input_does_not_raise(ctx, tmp_path):
    junk = tmp_path / "etc/cron.d"
    junk.mkdir(parents=True)
    (junk / "broken").write_bytes(
        b"\x00\x01\x02\xff\xfe garbage\nnot a crontab line\n"
        b"* * * *\n"                       # truncated schedule
        b"@bogus root /bin/true\n"
        b"= = =\n"
        b"* * * * * \n"                    # schedule with no command
    )
    events = parse(ctx, "etc/cron.d/broken", root=tmp_path)
    assert isinstance(events, list)


def test_empty_file_yields_nothing(ctx, tmp_path):
    d = tmp_path / "etc/cron.d"
    d.mkdir(parents=True)
    (d / "empty").write_bytes(b"")
    assert parse(ctx, "etc/cron.d/empty", root=tmp_path) == []
