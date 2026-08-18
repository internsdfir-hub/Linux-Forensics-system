"""Timestamp engine (spec 2.6.2): timezone resolution chain, syslog year
inference, Dec->Jan rollover, confidence marking. The most dangerous quiet
bug in the project is a wrong-but-confident timestamp."""
from datetime import datetime, timezone

from lfa.timeeng import TimeContext, parse_syslog_prefix


def ctx_karachi():
    return TimeContext(tz_name="Asia/Karachi", tz_source="etc_localtime")


def test_tz_chain_fallback_to_utc():
    ctx = TimeContext(tz_name=None, tz_source=None)
    assert ctx.tz_source == "assumed_utc"
    assert ctx.tz_name == "UTC"


def test_bad_tz_name_degrades_to_assumed_utc():
    ctx = TimeContext(tz_name="Mars/Olympus_Mons", tz_source="etc_localtime")
    assert ctx.tz_source == "assumed_utc"


def test_syslog_classic_year_inferred_and_tz_converted():
    ctx = ctx_karachi()
    # file mtime 2024-03-20 proves the year
    mtime = datetime(2024, 3, 20, tzinfo=timezone.utc).timestamp()
    r = ctx.resolve_syslog("Mar 14 02:19:07", file_mtime=mtime)
    assert r.confidence == "year_inferred"
    # Karachi is UTC+5: local 02:19 on the 14th is 21:19 UTC on the 13th
    assert r.utc_iso == "2024-03-13T21:19:07+00:00"
    assert r.local_iso == "2024-03-14T02:19:07+05:00"
    assert r.tz_name == "Asia/Karachi"


def test_dec_to_jan_rollover_inside_one_file():
    """A file rotated in January still contains December lines: those lines
    belong to the PREVIOUS year (dedicated test required by spec 2.6.2)."""
    ctx = ctx_karachi()
    mtime = datetime(2025, 1, 3, tzinfo=timezone.utc).timestamp()
    dec = ctx.resolve_syslog("Dec 31 23:59:59", file_mtime=mtime)
    jan = ctx.resolve_syslog("Jan  1 00:00:05", file_mtime=mtime)
    assert dec.local_iso.startswith("2024-12-31")
    assert jan.local_iso.startswith("2025-01-01")
    assert dec.confidence == "year_inferred"


def test_iso_anchor_year_beats_mtime():
    """If the same file contains ISO-8601 lines, their year anchors the
    classic lines with better authority than mtime."""
    ctx = ctx_karachi()
    mtime = datetime(2026, 6, 1, tzinfo=timezone.utc).timestamp()  # touched later
    r = ctx.resolve_syslog("Mar 14 02:19:07", file_mtime=mtime, anchor_year=2023)
    assert r.local_iso.startswith("2023-03-14")


def test_iso_line_parsed_exact():
    ctx = ctx_karachi()
    r = ctx.resolve_iso("2024-03-14T02:19:07.123456+05:00")
    assert r.confidence == "exact"
    assert r.utc_iso == "2024-03-13T21:19:07.123456+00:00"


def test_iso_line_without_offset_uses_host_tz():
    ctx = ctx_karachi()
    r = ctx.resolve_iso("2024-03-14T02:19:07")
    assert r.confidence == "exact"
    assert r.utc_iso == "2024-03-13T21:19:07+00:00"


def test_no_mtime_no_anchor_means_unknown():
    ctx = ctx_karachi()
    r = ctx.resolve_syslog("Mar 14 02:19:07", file_mtime=None)
    assert r.confidence == "unknown"
    assert r.utc_iso is None


def test_epoch_resolution_is_exact():
    ctx = ctx_karachi()
    r = ctx.resolve_epoch(1710382747)  # 2024-03-14T02:19:07Z
    assert r.confidence == "exact"
    assert r.utc_iso == "2024-03-14T02:19:07+00:00"
    assert r.local_iso == "2024-03-14T07:19:07+05:00"


def test_epoch_microseconds():
    ctx = ctx_karachi()
    r = ctx.resolve_epoch_us(1710382747000000)
    assert r.utc_iso == "2024-03-14T02:19:07+00:00"


def test_parse_syslog_prefix():
    ts, rest = parse_syslog_prefix(
        "Mar 14 02:19:07 web1 sshd[123]: Failed password for admin"
    )
    assert ts == "Mar 14 02:19:07"
    assert rest.startswith("web1 sshd")
    assert parse_syslog_prefix("no timestamp here") == (None, "no timestamp here")


def test_invalid_date_feb29_nonleap_falls_back():
    ctx = ctx_karachi()
    mtime = datetime(2023, 3, 1, tzinfo=timezone.utc).timestamp()
    r = ctx.resolve_syslog("Feb 29 12:00:00", file_mtime=mtime)
    # Feb 29 2023 doesn't exist; engine must not crash and must not lie
    assert r.confidence in {"year_inferred", "unknown"}
    if r.utc_iso is not None:
        assert r.local_iso.startswith("2024-02-29") or r.local_iso.startswith("2020-02-29")
