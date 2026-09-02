"""wtmp/btmp binary parser (spec trap #5).

glibc pins ut_tv to two int32 for compatibility, so struct utmp is 384
bytes on BOTH x86 and x86_64 - one layout, validated by size-modulo and a
plausible-date sanity check. The real edge case is musl/Alpine, where
wtmp/btmp are stubs and frequently empty or absent: that must be recorded
as a finding, never a crash.
"""
import struct
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.utmp import UtmpParser, UTMP_RECORD_SIZE
from lfa.schema import validate
from lfa.timeeng import TimeContext

# ut_type values
EMPTY, RUN_LVL, BOOT_TIME, NEW_TIME, OLD_TIME = 0, 1, 2, 3, 4
INIT_PROCESS, LOGIN_PROCESS, USER_PROCESS, DEAD_PROCESS = 5, 6, 7, 8


def make_record(ut_type, pid, line, user, host, tv_sec, ut_id="ts", addr=None):
    """Build one 384-byte utmp record (little-endian x86_64 glibc layout)."""
    rec = struct.pack(
        "<ii32s4s32s256s",
        ut_type,
        pid,
        line.encode()[:32].ljust(32, b"\0"),
        ut_id.encode()[:4].ljust(4, b"\0"),
        user.encode()[:32].ljust(32, b"\0"),
        host.encode()[:256].ljust(256, b"\0"),
    )
    # e_termination, e_exit, ut_session, tv_sec, tv_usec
    rec += struct.pack("<hhiii", 0, 0, 0, tv_sec, 0)
    # ut_addr_v6 (4 x int32) + reserved 20 bytes
    if addr:
        octets = [int(x) for x in addr.split(".")]
        packed_v4 = struct.unpack("<i", bytes(octets))[0]
        rec += struct.pack("<iiii", packed_v4, 0, 0, 0)
    else:
        rec += struct.pack("<iiii", 0, 0, 0, 0)
    rec += b"\0" * 20
    assert len(rec) == UTMP_RECORD_SIZE, len(rec)
    return rec


WTMP = b"".join(
    [
        make_record(BOOT_TIME, 0, "~", "reboot", "6.1.0-18-amd64", 1710300000),
        make_record(USER_PROCESS, 1234, "pts/0", "alice", "10.0.0.5",
                    1710382000, addr="10.0.0.5"),
        make_record(DEAD_PROCESS, 1234, "pts/0", "", "", 1710385600),
        make_record(USER_PROCESS, 2345, "pts/1", "admin", "203.0.113.9",
                    1710382747, addr="203.0.113.9"),
        make_record(LOGIN_PROCESS, 999, "tty1", "LOGIN", "", 1710300100),
    ]
)

BTMP = b"".join(
    [
        make_record(USER_PROCESS, 900, "ssh:notty", "admin", "203.0.113.9",
                    1710382441, addr="203.0.113.9"),
        make_record(USER_PROCESS, 901, "ssh:notty", "oracle", "203.0.113.9",
                    1710382447, addr="203.0.113.9"),
    ]
)


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


def parse(tmp_path, ctx, data, name="wtmp"):
    p = tmp_path / name
    p.write_bytes(data)
    parser = UtmpParser()
    ctx.artifact_rel = f"var/log/{name}"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(p, ctx))
    for ev in events:
        assert validate(ev) == [], ev
    return events


def test_wtmp_logins_extracted(tmp_path, ctx):
    events = parse(tmp_path, ctx, WTMP)
    logins = [e for e in events if e.subcategory == "login"]
    assert len(logins) == 2
    alice = next(e for e in logins if e.actor_user == "alice")
    assert alice.source_ip == "10.0.0.5"
    assert alice.timestamp_confidence == "exact"
    assert alice.timestamp_utc == "2024-03-14T02:06:40+00:00"
    assert "pts/0" in alice.description


def test_boot_and_logout_records(tmp_path, ctx):
    events = parse(tmp_path, ctx, WTMP)
    assert any(e.subcategory == "system_boot" for e in events)
    assert any(e.subcategory == "logout" for e in events)


def test_btmp_yields_failed_logins_at_higher_severity(tmp_path, ctx):
    events = parse(tmp_path, ctx, BTMP, name="btmp")
    assert len(events) == 2
    assert all(e.subcategory == "failed_login" for e in events)
    assert all(e.severity == "low" for e in events)
    assert {e.actor_user for e in events} == {"admin", "oracle"}
    assert all(e.source_ip == "203.0.113.9" for e in events)


def test_empty_file_reported_as_finding_not_crash(tmp_path, ctx):
    """Evidence-integrity: wtmp present but zero-length is itself a signal."""
    events = parse(tmp_path, ctx, b"")
    assert len(events) == 1
    assert events[0].event_kind == "state_finding"
    assert events[0].subcategory == "utmp_empty"
    assert events[0].severity == "medium"


def test_bad_size_reported_as_unsupported_layout(tmp_path, ctx):
    """size % 384 != 0 means a layout we do not support (e.g. musl)."""
    events = parse(tmp_path, ctx, WTMP[:1000])
    assert any(e.subcategory == "utmp_unsupported_layout" for e in events)
    # partial parse still yields the records that DID decode
    assert any(e.subcategory == "login" for e in events)


def test_implausible_timestamps_rejected(tmp_path, ctx):
    """A record whose decoded time lands outside a plausible range means we
    are misreading the layout - say so rather than emit a fake 1970 login.

    Note tv_sec is int32, so an implausible value is necessarily a SMALL
    one (a 1970-ish date from a misaligned read), never a huge one.
    """
    bad = make_record(USER_PROCESS, 1, "pts/9", "ghost", "", 100)
    events = parse(tmp_path, ctx, bad)
    assert not any(e.subcategory == "login" for e in events)
    assert any(e.subcategory == "utmp_unsupported_layout" for e in events)


def test_all_zero_records_skipped(tmp_path, ctx):
    events = parse(tmp_path, ctx, b"\0" * UTMP_RECORD_SIZE * 3)
    assert not any(e.subcategory == "login" for e in events)
    assert any(e.subcategory == "utmp_empty" for e in events)


def test_hostname_when_not_an_ip(tmp_path, ctx):
    rec = make_record(USER_PROCESS, 5, "pts/2", "bob", "workstation.local",
                      1710382000)
    events = parse(tmp_path, ctx, rec)
    login = next(e for e in events if e.subcategory == "login")
    assert login.source_host == "workstation.local"
    assert login.source_ip is None


def test_wtmpdb_sqlite_parsing(tmp_path, ctx):
    """Modern systemd / Debian / Kali wtmpdb SQLite databases."""
    import sqlite3
    db_path = tmp_path / "wtmp.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE wtmp (ID INTEGER PRIMARY KEY, Type INTEGER, User TEXT, Login INTEGER, Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT)"
    )
    conn.execute(
        "INSERT INTO wtmp VALUES (1, 3, 'kali', 1710382000000000, 1710385600000000, 'pts/0', '192.168.1.50', 'sshd')"
    )
    conn.commit()
    conn.close()

    parser = UtmpParser()
    ctx.artifact_rel = "var/log/wtmp.db"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(db_path, ctx))

    assert len(events) == 2
    login_ev = next(e for e in events if e.subcategory == "login")
    logout_ev = next(e for e in events if e.subcategory == "logout")
    assert login_ev.actor_user == "kali"
    assert login_ev.source_ip == "192.168.1.50"
    assert "sshd" in login_ev.description
    assert logout_ev.actor_user == "kali"
    assert validate(login_ev) == []
    assert validate(logout_ev) == []


def test_utmp_with_surrogate_and_non_utf8_bytes(tmp_path, ctx):
    """Raw dirty bytes in utmp headers should not crash database or JSON encoding."""
    rec = make_record(USER_PROCESS, 42, "tty1", "testuser", "host\xb9\x9e", 1710382000)
    events = parse(tmp_path, ctx, rec)
    assert len(events) == 1
    ev = events[0]
    assert validate(ev) == []
    # Ensure no surrogates in any string field
    for k, v in ev.__dict__.items():
        if isinstance(v, str):
            v.encode("utf-8")  # should not raise UnicodeEncodeError

