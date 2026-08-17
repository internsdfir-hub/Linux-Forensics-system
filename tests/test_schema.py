"""Tests for the frozen NormalizedEvent schema (spec section 2.5).

The schema is the week-1 contract: every parser emits it, the DB stores it,
rules and the report consume it. These tests pin the field set, the enums,
the dedupe hash, and the deterministic event id.
"""
import dataclasses

import pytest

from lfa import schema
from lfa.schema import (
    NormalizedEvent,
    compute_event_hash,
    event_id_for,
    make_event,
    validate,
)

SPEC_FIELDS = [
    "event_id",
    "case_id",
    "host_id",
    "event_hash",
    "event_kind",
    "timestamp_utc",
    "timestamp_local",
    "timestamp_tz",
    "tz_source",
    "timestamp_confidence",
    "category",
    "subcategory",
    "actor_user",
    "actor_uid",
    "actor_process",
    "source_ip",
    "source_host",
    "description",
    "severity",
    "source_artifact_path",
    "source_artifact_sha256",
    "raw_line",
    "raw_line_offset",
    "parser_name",
    "parser_version",
    "tool_generated_flag",
    "notes",
]


def valid_kwargs(**overrides):
    kw = dict(
        case_id="CASE-001",
        host_id="host-abc",
        event_kind="event",
        timestamp_utc="2024-03-14T02:19:07+00:00",
        timestamp_local="2024-03-14T07:19:07+05:00",
        timestamp_tz="Asia/Karachi",
        tz_source="etc_localtime",
        timestamp_confidence="exact",
        category="login_activity",
        subcategory="failed_login",
        actor_user="admin",
        actor_uid=1000,
        actor_process="sshd",
        source_ip="203.0.113.9",
        source_host=None,
        description="Failed password for admin from 203.0.113.9",
        severity="low",
        source_artifact_path="var/log/auth.log",
        source_artifact_sha256="a" * 64,
        raw_line="Mar 14 02:19:07 web1 sshd[123]: Failed password ...",
        raw_line_offset=1024,
        parser_name="authlog_parser",
        parser_version="1.0",
        tool_generated_flag=False,
        notes=None,
    )
    kw.update(overrides)
    return kw


def test_field_set_matches_spec_exactly():
    names = [f.name for f in dataclasses.fields(NormalizedEvent)]
    assert names == SPEC_FIELDS


def test_make_event_produces_valid_event():
    ev = make_event(**valid_kwargs())
    assert validate(ev) == []
    assert ev.event_hash == compute_event_hash(
        ev.host_id, ev.source_artifact_path, ev.raw_line_offset, ev.raw_line
    )
    assert ev.event_id == event_id_for(ev.event_hash)


def test_event_hash_is_stable_and_sensitive():
    h1 = compute_event_hash("h", "var/log/auth.log", 10, "line")
    h2 = compute_event_hash("h", "var/log/auth.log", 10, "line")
    h3 = compute_event_hash("h", "var/log/auth.log", 11, "line")
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 64 and int(h1, 16) >= 0


def test_event_id_is_deterministic_uuid5():
    h = compute_event_hash("h", "p", 0, "x")
    assert event_id_for(h) == event_id_for(h)
    # RFC 4122 version nibble must be 5 (name-based, SHA-1)
    assert event_id_for(h)[14] == "5"


def test_invalid_enum_values_rejected():
    for field, bad in [
        ("event_kind", "happening"),
        ("tz_source", "guessed"),
        ("timestamp_confidence", "pretty_sure"),
        ("severity", "critical"),
        ("category", "cool_stuff"),
    ]:
        ev = make_event(**valid_kwargs(**{field: bad}))
        errors = validate(ev)
        assert errors, f"expected {field}={bad!r} to be rejected"
        assert any(field in e for e in errors)


def test_state_finding_allows_null_timestamp():
    ev = make_event(
        **valid_kwargs(
            event_kind="state_finding",
            timestamp_utc=None,
            timestamp_local=None,
            timestamp_confidence="unknown",
        )
    )
    assert validate(ev) == []


def test_plain_event_requires_timestamp_or_unknown_confidence():
    # an "event" with no timestamp must carry timestamp_confidence=unknown
    ev = make_event(
        **valid_kwargs(timestamp_utc=None, timestamp_local=None,
                       timestamp_confidence="exact")
    )
    assert validate(ev)


def test_raw_line_truncated_at_2kb():
    long_line = "x" * 5000
    ev = make_event(**valid_kwargs(raw_line=long_line))
    assert len(ev.raw_line.encode("utf-8")) <= 2048
    # hash must be computed over the ORIGINAL line so offsets+dedupe stay honest
    assert ev.event_hash == compute_event_hash(
        ev.host_id, ev.source_artifact_path, ev.raw_line_offset, long_line
    )


def test_bad_timestamp_format_rejected():
    ev = make_event(**valid_kwargs(timestamp_utc="14/03/2024 02:19"))
    assert any("timestamp_utc" in e for e in validate(ev))


def test_categories_are_the_eight_plus_environment():
    assert schema.CATEGORIES == frozenset(
        {
            "user_accounts",
            "login_activity",
            "privilege_escalation",
            "persistence",
            "software_changes",
            "hardware_usb",
            "network_config",
            "user_activity",
            "environment",
        }
    )
