"""/var/log/lastlog parser (spec trap #6).

lastlog is SPARSE and UID-INDEXED: the record for uid N sits at byte offset
N * 292, so a host with the conventional uid 65534 ('nobody') has a file
whose logical size is ~19 MB while occupying a few KB on disk. Reading it
sequentially yields tens of thousands of empty records, so the parser takes
the UID list from the collected /etc/passwd and seeks only to those offsets.
lastlog is also being retired in favour of lastlog2, so an empty or absent
file has to be a finding rather than an error.
"""
import pathlib
import struct
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.lastlog import LastlogParser, LASTLOG_RECORD_SIZE
from lfa.schema import validate
from lfa.timeeng import TimeContext

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"""


def make_record(ll_time: int, line: str, host: str) -> bytes:
    rec = struct.pack(
        "<i32s256s",
        ll_time,
        line.encode()[:32].ljust(32, b"\0"),
        host.encode()[:256].ljust(256, b"\0"),
    )
    assert len(rec) == LASTLOG_RECORD_SIZE, len(rec)
    return rec


def write_lastlog(path: Path, records: dict[int, bytes]) -> None:
    """Write a genuinely sparse, uid-indexed lastlog: seek to uid*292."""
    with open(path, "wb") as fh:
        for uid in sorted(records):
            fh.seek(uid * LASTLOG_RECORD_SIZE)
            fh.write(records[uid])


@pytest.fixture
def ctx(tmp_path):
    etc = tmp_path / "collected/files/etc"
    etc.mkdir(parents=True)
    (etc / "passwd").write_text(PASSWD, encoding="utf-8")
    return ParseContext(
        case_id="C1",
        host_id="H1",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("Asia/Karachi", "etc_localtime"),
        distro_profile={"distro_id": "debian"},
        artifact_sha256="a" * 64,
    )


def parse(ctx, path):
    parser = LastlogParser()
    ctx.artifact_rel = "var/log/lastlog"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(Path(path), ctx))
    for ev in events:
        assert validate(ev) == [], ev
    return events


@pytest.fixture
def lastlog(tmp_path):
    path = tmp_path / "lastlog"
    write_lastlog(
        path,
        {
            0: make_record(1710382747, "pts/0", "203.0.113.9"),
            1000: make_record(1710300000, "tty1", ""),
            1001: make_record(0, "", ""),          # bob never logged in
            65534: make_record(1710300000, "pts/3", "workstation.local"),
        },
    )
    return path


def test_parser_claims_lastlog():
    assert LastlogParser().can_parse("var/log/lastlog", {})
    assert not LastlogParser().can_parse("var/log/wtmp", {})


def test_sparse_uid_indexed_records_decoded(lastlog, ctx):
    events = parse(ctx, lastlog)
    logins = [e for e in events if e.subcategory == "last_login"]
    assert len(logins) == 3, "one per uid with a non-zero time, no empty slots"
    assert {e.actor_user for e in logins} == {"root", "alice", "nobody"}
    for ev in logins:
        assert ev.event_kind == "event"
        assert ev.category == "login_activity"
        assert ev.timestamp_confidence == "exact"


def test_uid_and_offset_match_the_index(lastlog, ctx):
    events = parse(ctx, lastlog)
    nobody = next(e for e in events if e.actor_user == "nobody")
    assert nobody.actor_uid == 65534
    assert nobody.raw_line_offset == 65534 * LASTLOG_RECORD_SIZE
    root = next(e for e in events if e.actor_user == "root")
    assert root.actor_uid == 0
    assert root.raw_line_offset == 0


def test_timestamps_and_source_fields(lastlog, ctx):
    events = parse(ctx, lastlog)
    root = next(e for e in events if e.actor_user == "root")
    assert root.timestamp_utc == "2024-03-14T02:19:07+00:00"
    assert root.timestamp_local == "2024-03-14T07:19:07+05:00"
    assert root.source_ip == "203.0.113.9"
    assert root.source_host is None
    assert "pts/0" in root.description

    nobody = next(e for e in events if e.actor_user == "nobody")
    assert nobody.source_host == "workstation.local"
    assert nobody.source_ip is None

    alice = next(e for e in events if e.actor_user == "alice")
    assert alice.timestamp_utc == "2024-03-13T03:20:00+00:00"
    assert alice.source_ip is None and alice.source_host is None


def test_zero_time_records_are_skipped(lastlog, ctx):
    events = parse(ctx, lastlog)
    assert not any(e.actor_user == "bob" for e in events)


def test_file_is_never_slurped_whole(lastlog, ctx, monkeypatch):
    """A 19 MB logical file must not be read into memory - seek only."""
    def boom(self, *a, **k):
        raise AssertionError("lastlog must not be read sequentially/whole")

    monkeypatch.setattr(pathlib.Path, "read_bytes", boom)
    events = parse(ctx, lastlog)
    assert len(events) == 3


def test_missing_passwd_falls_back_to_bounded_scan(tmp_path):
    path = tmp_path / "lastlog"
    write_lastlog(path, {
        0: make_record(1710382747, "pts/0", "10.0.0.5"),
        5: make_record(1710382000, "tty2", ""),
    })
    ctx = ParseContext(
        case_id="C1",
        host_id="H1",
        raw_host_dir=tmp_path,  # no collected/files/etc/passwd here
        time_ctx=TimeContext("Asia/Karachi", "etc_localtime"),
        distro_profile={"distro_id": "debian"},
        artifact_sha256="a" * 64,
    )
    events = parse(ctx, path)
    logins = [e for e in events if e.subcategory == "last_login"]
    assert len(logins) == 2
    assert {e.actor_uid for e in logins} == {0, 5}
    # no username available without /etc/passwd: uid must still be reported
    assert all(e.notes and "uid list" in e.notes.lower() for e in logins)


def test_zero_length_file_is_a_finding(tmp_path, ctx):
    path = tmp_path / "lastlog"
    path.write_bytes(b"")
    events = parse(ctx, path)
    assert len(events) == 1
    assert events[0].event_kind == "state_finding"
    assert events[0].subcategory == "lastlog_absent_or_empty"
    assert events[0].severity == "low"
    assert events[0].timestamp_utc is None


def test_all_zero_records_is_a_finding(tmp_path, ctx):
    path = tmp_path / "lastlog"
    path.write_bytes(b"\0" * LASTLOG_RECORD_SIZE * 4)
    events = parse(ctx, path)
    assert [e.subcategory for e in events] == ["lastlog_absent_or_empty"]


def test_truncated_final_record_does_not_raise(tmp_path, ctx):
    path = tmp_path / "lastlog"
    data = make_record(1710382747, "pts/0", "203.0.113.9")
    with open(path, "wb") as fh:
        fh.write(data)
        fh.seek(1000 * LASTLOG_RECORD_SIZE)
        fh.write(make_record(1710382747, "pts/1", "10.0.0.5")[:100])
    events = parse(ctx, path)
    assert any(e.actor_user == "root" for e in events)
    assert any(e.subcategory == "lastlog_truncated" for e in events)


def test_binary_junk_does_not_raise(tmp_path, ctx):
    path = tmp_path / "lastlog"
    path.write_bytes(b"\xff" * 700)
    events = parse(ctx, path)
    assert isinstance(events, list)
