"""dnf / yum parser (spec category 5, software changes) - the RHEL-family
counterpart to dpkg_parser.

Two timestamp shapes have to coexist in one parser:
  dnf   2024-03-10T02:30:01+0500 SUBDEBUG Installed: netcat-1.2-3.x86_64
        ISO-8601 but with a COLON-LESS offset, so it needs normalising
        before fromisoformat; the year is present -> confidence "exact".
  yum   Mar 10 02:30:01 Installed: netcat-1.2-3.x86_64
        classic syslog: no year, no zone -> year inferred from the artifact
        mtime, confidence "year_inferred".
"""
import gzip
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.dnf import DnfParser
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
        distro_profile={"distro_id": "rhel"},
        artifact_sha256="a" * 64,
        artifact_mtime=MTIME,
    )


def parse(ctx, rel, root=FIXTURES):
    parser = DnfParser()
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(Path(root) / rel, ctx))
    for ev in events:
        assert validate(ev) == [], ev
        assert ev.category == "software_changes"
    return events


def test_claims_all_rhel_package_logs():
    parser = DnfParser()
    for rel in (
        "var/log/dnf.log", "var/log/dnf.log.1",
        "var/log/dnf.rpm.log", "var/log/dnf.rpm.log.4.gz",
        "var/log/yum.log", "var/log/yum.log.2.gz",
    ):
        assert parser.can_parse(rel, {}), rel
    assert not parser.can_parse("var/log/dpkg.log", {})


def test_dnf_iso_lines_parsed_with_exact_time(ctx):
    events = parse(ctx, "var/log/dnf.rpm.log")
    assert len(events) == 4
    nc = next(e for e in events if "netcat" in e.description)
    assert nc.subcategory == "package_install"
    assert nc.timestamp_confidence == "exact"
    # +0500 has no colon: normalising it is the whole point of this test
    assert nc.timestamp_utc == "2024-03-09T21:30:01+00:00"
    assert nc.timestamp_local == "2024-03-10T02:30:01+05:00"


def test_dnf_action_mapping_and_severity(ctx):
    events = parse(ctx, "var/log/dnf.rpm.log")
    by_sub = {}
    for e in events:
        by_sub.setdefault(e.subcategory, []).append(e)
    assert len(by_sub["package_install"]) == 2
    assert len(by_sub["package_upgrade"]) == 1
    assert len(by_sub["package_remove"]) == 1
    assert all(e.severity == "medium" for e in by_sub["package_install"])
    assert by_sub["package_upgrade"][0].severity == "info"
    # auditd removed on a RHEL box: the host just lost its audit trail
    assert by_sub["package_remove"][0].severity == "high"


def test_debug_noise_is_dropped(ctx):
    events = parse(ctx, "var/log/dnf.rpm.log")
    assert not any("sack setup" in e.raw_line for e in events)
    assert not any("logging initialized" in e.raw_line for e in events)


def test_yum_syslog_lines_use_year_inference(ctx):
    events = parse(ctx, "var/log/yum.log")
    assert len(events) == 3
    nc = next(e for e in events if "netcat" in e.description)
    assert nc.timestamp_confidence == "year_inferred"
    assert nc.timestamp_local == "2024-03-10T02:30:01+05:00"
    updated = next(e for e in events if "openssl" in e.description)
    assert updated.subcategory == "package_upgrade"
    erased = next(e for e in events if "clamav" in e.description)
    assert erased.subcategory == "package_remove"
    assert erased.severity == "high"


def test_gzip_rotation_is_transparent(ctx, tmp_path):
    src = (FIXTURES / "var/log/dnf.rpm.log").read_bytes()
    d = tmp_path / "var/log"
    d.mkdir(parents=True)
    (d / "dnf.rpm.log.4.gz").write_bytes(gzip.compress(src))
    assert len(parse(ctx, "var/log/dnf.rpm.log.4.gz", root=tmp_path)) == 4


def test_garbage_input_does_not_raise(ctx, tmp_path):
    d = tmp_path / "var/log"
    d.mkdir(parents=True)
    (d / "dnf.log").write_bytes(
        b"\x00\x7f\xff\xfe binary junk\n"
        b"2024-99-99T99:99:99+9999 SUBDEBUG Installed: broken-1-1.noarch\n"
        b"Installed: no-timestamp-at-all\n"
        b"2024-03-10T02:30:01+0500 SUBDEBUG Installed: ok-pkg-1.0-1.x86_64\n"
    )
    events = parse(ctx, "var/log/dnf.log", root=tmp_path)
    assert any("ok-pkg" in e.description for e in events)
    for ev in events:
        if ev.timestamp_utc is None:
            assert ev.timestamp_confidence == "unknown"


def test_empty_file_is_quiet(ctx, tmp_path):
    d = tmp_path / "var/log"
    d.mkdir(parents=True)
    (d / "yum.log").write_bytes(b"")
    assert parse(ctx, "var/log/yum.log", root=tmp_path) == []
