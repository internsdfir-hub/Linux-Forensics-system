"""apt history.log parser (spec category 5, software changes).

history.log earns its place next to dpkg.log by recording two things dpkg
cannot: the EXACT command the operator typed, and WHICH USER asked for it
(`Requested-By: alice (1000)`). "netcat appeared at 02:30" is a fact;
"alice ran `apt-get install netcat-openbsd nmap` at 02:30" is an attribution.

term.log is claimed (so it is never reported as an unparsed artifact) but
deliberately yields nothing - it is operator-visible dpkg chatter.
"""
import gzip
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lfa.parsers.apt import AptParser
from lfa.parsers.base import ParseContext
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
    parser = AptParser()
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(Path(root) / rel, ctx))
    for ev in events:
        assert validate(ev) == [], ev
        assert ev.category == "software_changes"
    return events


def test_claims_history_and_term_logs():
    parser = AptParser()
    for rel in (
        "var/log/apt/history.log",
        "var/log/apt/history.log.1.gz",
        "var/log/apt/term.log",
        "var/log/apt/term.log.2.gz",
    ):
        assert parser.can_parse(rel, {}), rel
    assert not parser.can_parse("var/log/dpkg.log", {})


def test_one_transaction_event_per_stanza(ctx):
    events = parse(ctx, "var/log/apt/history.log")
    tx = [e for e in events if e.subcategory == "apt_transaction"]
    assert len(tx) == 3
    assert "apt-get install netcat-openbsd nmap" in tx[0].description
    assert tx[0].timestamp_confidence == "exact"
    # 02:30:01 Karachi (+05:00) == 21:30:01 UTC the previous day
    assert tx[0].timestamp_local == "2024-03-10T02:30:01+05:00"
    assert tx[0].timestamp_utc == "2024-03-09T21:30:01+00:00"


def test_requested_by_becomes_actor(ctx):
    events = parse(ctx, "var/log/apt/history.log")
    tx = [e for e in events if e.subcategory == "apt_transaction"]
    assert tx[0].actor_user == "alice"
    assert tx[0].actor_uid == 1000


def test_missing_requested_by_is_reported_as_root(ctx):
    events = parse(ctx, "var/log/apt/history.log")
    unattended = next(
        e for e in events
        if e.subcategory == "apt_transaction" and "unattended" in e.description
    )
    assert unattended.actor_user == "root"
    assert unattended.actor_uid == 0
    assert "root" in (unattended.notes or "").lower()


def test_package_events_per_list_entry(ctx):
    events = parse(ctx, "var/log/apt/history.log")
    installs = [e for e in events if e.subcategory == "package_install"]
    removes = [e for e in events if e.subcategory == "package_remove"]
    upgrades = [e for e in events if e.subcategory == "package_upgrade"]
    assert {e.actor_user for e in installs} == {"alice"}
    assert sorted(e.description.split()[1] for e in installs) == [
        "netcat-openbsd:amd64", "nmap:amd64"
    ]
    assert len(removes) == 2
    assert len(upgrades) == 2
    assert "3.0.11-1~deb12u1" in upgrades[0].description
    assert "3.0.13-1~deb12u1" in upgrades[0].description
    assert len(events) == 3 + 2 + 2 + 2


def test_severity_policy_matches_dpkg(ctx):
    events = parse(ctx, "var/log/apt/history.log")
    nmap = next(e for e in events if "nmap" in e.description
                and e.subcategory == "package_install")
    auditd = next(e for e in events if "auditd" in e.description
                  and e.subcategory == "package_remove")
    openssl = next(e for e in events if "openssl" in e.description
                   and e.subcategory == "package_upgrade")
    assert nmap.severity == "medium"
    assert auditd.severity == "high"
    assert openssl.severity == "info"
    # the transaction inherits the worst severity of the packages it touched
    purge_tx = next(e for e in events if e.subcategory == "apt_transaction"
                    and "purge" in e.description)
    assert purge_tx.severity == "high"


def test_term_log_yields_nothing_but_never_crashes(ctx, tmp_path):
    term = tmp_path / "var/log/apt"
    term.mkdir(parents=True)
    (term / "term.log").write_bytes(
        b"Log started: 2024-03-10  02:30:01\n"
        b"Selecting previously unselected package netcat-openbsd.\n"
        b"\x1b[1mProgress: [ 40%]\x1b[0m \xff\xfe\n"
    )
    assert parse(ctx, "var/log/apt/term.log", root=tmp_path) == []


def test_gzip_rotation_is_transparent(ctx, tmp_path):
    src = (FIXTURES / "var/log/apt/history.log").read_bytes()
    d = tmp_path / "var/log/apt"
    d.mkdir(parents=True)
    (d / "history.log.1.gz").write_bytes(gzip.compress(src))
    events = parse(ctx, "var/log/apt/history.log.1.gz", root=tmp_path)
    assert len([e for e in events if e.subcategory == "apt_transaction"]) == 3


def test_truncated_and_garbage_stanzas_do_not_raise(ctx, tmp_path):
    d = tmp_path / "var/log/apt"
    d.mkdir(parents=True)
    (d / "history.log").write_bytes(
        b"\x00\x01\x02\xff garbage header\n"
        b"Start-Date: not-a-date\n"
        b"Install: \n"
        b"\n"
        b"Start-Date: 2024-03-10  02:30:01\n"
        b"Commandline: apt install curl\n"
        b"Install: curl:amd64 (8.0.1)\n"  # stanza truncated: no End-Date
    )
    events = parse(ctx, "var/log/apt/history.log", root=tmp_path)
    # the unterminated final stanza is still flushed
    assert any("curl" in e.description for e in events)
    # the undated stanza still produces an event, with unknown time
    undated = [e for e in events if e.timestamp_utc is None]
    assert all(e.timestamp_confidence == "unknown" for e in undated)


def test_empty_file_is_quiet(ctx, tmp_path):
    d = tmp_path / "var/log/apt"
    d.mkdir(parents=True)
    (d / "history.log").write_bytes(b"")
    assert parse(ctx, "var/log/apt/history.log", root=tmp_path) == []
