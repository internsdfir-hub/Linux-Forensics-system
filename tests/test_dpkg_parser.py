"""dpkg.log parser (spec category 5, software changes).

dpkg.log is the Debian-family record of *what package operation happened
and when*. It carries no user - that is apt/history.log's job - so the
value here is the timeline plus the severity call: installing netcat is
interesting, REMOVING auditd or ufw is an attacker turning the lights off.

Timestamps are local host time with no offset, so the host timezone from
/etc/localtime is what makes them comparable with anything else.
"""
import gzip
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.dpkg import DpkgParser
from lfa.schema import validate
from lfa.timeeng import TimeContext

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "system"
MTIME = datetime(2024, 3, 20, tzinfo=timezone.utc).timestamp()


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
    parser = DpkgParser()
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(Path(root) / rel, ctx))
    for ev in events:
        assert validate(ev) == [], ev
        assert ev.category == "software_changes"
    return events


def test_claims_dpkg_log_and_rotations():
    parser = DpkgParser()
    for rel in ("var/log/dpkg.log", "var/log/dpkg.log.1", "var/log/dpkg.log.2.gz"):
        assert parser.can_parse(rel, {}), rel
    assert not parser.can_parse("var/log/apt/history.log", {})


def test_only_real_package_actions_emitted(ctx):
    events = parse(ctx, "var/log/dpkg.log")
    subs = [e.subcategory for e in events]
    # status / configure / trigproc / startup lines are noise
    assert set(subs) <= {"install", "upgrade", "remove", "purge"}
    assert subs.count("install") == 2
    assert subs.count("upgrade") == 1
    assert subs.count("remove") == 1
    assert subs.count("purge") == 1
    assert len(events) == 5


def test_install_event_fields(ctx):
    events = parse(ctx, "var/log/dpkg.log")
    nc = next(e for e in events if "netcat-openbsd" in e.description)
    assert nc.event_kind == "event"
    assert nc.subcategory == "install"
    assert nc.timestamp_confidence == "exact"
    # 02:30:01 Karachi (+05:00) == 21:30:01 UTC the previous day
    assert nc.timestamp_local == "2024-03-10T02:30:01+05:00"
    assert nc.timestamp_utc == "2024-03-09T21:30:01+00:00"
    assert "1.217-3" in nc.description


def test_upgrade_records_both_versions(ctx):
    events = parse(ctx, "var/log/dpkg.log")
    up = next(e for e in events if e.subcategory == "upgrade")
    assert "3.0.11-1~deb12u1" in up.description
    assert "3.0.13-1~deb12u1" in up.description
    assert up.severity == "info"


def test_attack_tool_install_is_medium(ctx):
    events = parse(ctx, "var/log/dpkg.log")
    tools = [e for e in events if e.subcategory == "install"]
    assert all(e.severity == "medium" for e in tools), [e.description for e in tools]


def test_security_tool_removal_is_high(ctx):
    events = parse(ctx, "var/log/dpkg.log")
    ufw = next(e for e in events if e.subcategory == "remove")
    auditd = next(e for e in events if e.subcategory == "purge")
    assert ufw.severity == "high"
    assert auditd.severity == "high"
    assert "security" in (ufw.notes or "").lower()


def test_offsets_point_at_source_lines(ctx):
    events = parse(ctx, "var/log/dpkg.log")
    raw = (FIXTURES / "var/log/dpkg.log").read_bytes().splitlines(True)
    expected = sum(len(line) for line in raw[:2])
    assert events[0].raw_line_offset == expected


def test_gzip_rotation_is_transparent(ctx, tmp_path):
    src = (FIXTURES / "var/log/dpkg.log").read_bytes()
    gz = tmp_path / "var/log"
    gz.mkdir(parents=True)
    (gz / "dpkg.log.2.gz").write_bytes(gzip.compress(src))
    events = parse(ctx, "var/log/dpkg.log.2.gz", root=tmp_path)
    assert len(events) == 5


def test_garbage_input_does_not_raise(ctx, tmp_path):
    junk = tmp_path / "var/log"
    junk.mkdir(parents=True)
    (junk / "dpkg.log").write_bytes(
        b"\x00\x01\x02 not a log at all\n"
        b"2024-03-10 install missing-fields\n"
        b"2024-13-45 99:99:99 install broken:amd64 <none> 1.0\n"
        b"\xff\xfe\xfd\n"
        b"2024-03-10 02:30:01 install ok-pkg:amd64 <none> 1.0\n"
    )
    events = parse(ctx, "var/log/dpkg.log", root=tmp_path)
    # the one good line still lands; nothing raised
    assert any("ok-pkg" in e.description for e in events)


def test_empty_file_is_quiet(ctx, tmp_path):
    empty = tmp_path / "var/log"
    empty.mkdir(parents=True)
    (empty / "dpkg.log").write_bytes(b"")
    assert parse(ctx, "var/log/dpkg.log", root=tmp_path) == []
