"""systemd unit parser (spec category 4): services, timers and sockets are
the modern replacement for cron as a persistence mechanism, and a unit
under a user's ~/.config/systemd/user survives without ever touching root."""
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.systemd_unit import SystemdUnitParser
from lfa.schema import validate
from lfa.timeeng import TimeContext

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "persistence"
MTIME = datetime(2024, 3, 14, 2, 40, 0, tzinfo=timezone.utc).timestamp()


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
    parser = SystemdUnitParser()
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(Path(root) / rel, ctx))
    for ev in events:
        assert validate(ev) == [], ev
        assert ev.category == "persistence"
        assert ev.event_kind == "state_finding"
        assert ev.timestamp_utc is None and ev.timestamp_confidence == "unknown"
    return events


def test_claims_system_and_user_unit_paths():
    parser = SystemdUnitParser()
    for rel in (
        "etc/systemd/system/webhook.service",
        "etc/systemd/system/multi-user.target.wants/webhook.service",
        "etc/systemd/system/backup.timer",
        "home/alice/.config/systemd/user/pulse-sync.service",
        "root/.config/systemd/user/agent.service",
    ):
        assert parser.can_parse(rel, {}), rel
    assert not parser.can_parse("etc/crontab", {})


def test_service_unit_fields(ctx):
    events = parse(ctx, "etc/systemd/system/webhook.service")
    unit = next(e for e in events if e.subcategory == "systemd_unit")
    assert unit.actor_user == "deploy"
    assert "Deploy webhook receiver" in unit.description
    # line continuations are joined back into one command
    assert ("/opt/webhook/bin/webhook -config /etc/webhook.yml -verbose"
            in unit.description)
    assert "ExecStartPre=/usr/bin/test -x /opt/webhook/bin/webhook" in unit.description
    assert "multi-user.target" in unit.description
    assert "2024-03-14T02:40:00+00:00" in unit.description
    assert unit.severity == "info"
    assert [e for e in events if e.subcategory == "suspicious_systemd_unit"] == []


def test_timer_units(ctx):
    cal = parse(ctx, "etc/systemd/system/backup.timer")
    timer = next(e for e in cal if e.subcategory == "systemd_timer")
    assert "OnCalendar=*-*-* 03:15:00" in timer.description
    assert "backup.service" in timer.description

    boot = parse(ctx, "etc/systemd/system/update-check.timer")
    t2 = next(e for e in boot if e.subcategory == "systemd_timer")
    assert "OnBootSec=15min" in t2.description


def test_socket_unit(ctx):
    events = parse(ctx, "etc/systemd/system/debug-shell.socket")
    unit = next(e for e in events if e.subcategory == "systemd_unit")
    assert "ListenStream=4444" in unit.description


def test_execstart_in_world_writable_dir_flagged_high(ctx):
    events = parse(ctx, "etc/systemd/system/syslogd-helper.service")
    sus = next(e for e in events if e.subcategory == "suspicious_systemd_unit")
    assert sus.severity == "high"
    assert "/dev/shm" in sus.description
    assert sus.raw_line.startswith("ExecStart=")
    assert sus.actor_user == "root"


def test_user_unit_owner_from_path_and_hidden_exec(ctx):
    events = parse(ctx, "home/alice/.config/systemd/user/pulse-sync.service")
    unit = next(e for e in events if e.subcategory == "systemd_unit")
    assert unit.actor_user == "alice"
    assert "user unit" in unit.description
    sus = next(e for e in events if e.subcategory == "suspicious_systemd_unit")
    assert sus.severity == "high"
    assert "hidden" in sus.description


def test_wants_symlink_directory_handled(ctx):
    rel = "etc/systemd/system/multi-user.target.wants/syslogd-helper.service"
    events = parse(ctx, rel)
    link = next(e for e in events if e.subcategory == "systemd_enabled_link")
    assert "syslogd-helper.service" in link.description
    assert "multi-user.target" in link.description
    # a dumped symlink has no unit body: no bogus unit event from it
    assert [e for e in events if e.subcategory == "systemd_unit"] == []


def test_garbage_and_empty_units_do_not_raise(ctx, tmp_path):
    d = tmp_path / "etc/systemd/system"
    d.mkdir(parents=True)
    (d / "broken.service").write_bytes(
        b"\x00\x01\xff\xfe[Serv\nExecStart\n=orphan value\n[Install\n"
    )
    assert isinstance(parse(ctx, "etc/systemd/system/broken.service", root=tmp_path), list)
    (d / "empty.service").write_bytes(b"")
    assert parse(ctx, "etc/systemd/system/empty.service", root=tmp_path) == []
