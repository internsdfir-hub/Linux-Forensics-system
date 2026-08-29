"""Evidence-integrity and state-finding rules (spec 2.8.1).

These are the ones that make a report look professional: they reason about
what is MISSING or INCONSISTENT, not only about what is present. Absence of
evidence is itself evidence - a user with fifty recorded sessions and an
empty command history didn't get shy.
"""
import json

import pytest

from lfa import db
from lfa.rules.base import RuleRun
from lfa.rules.integrity import (
    BackwardsTimestampsRule,
    RotationGapRule,
    TimelineGapRule,
    WipedHistoryRule,
    ZeroLengthLogRule,
)
from lfa.rules.state import (
    LdPreloadRule,
    PasswordlessAccountRule,
    PrivilegedGroupRule,
    SshdConfigRule,
    Uid0Rule,
)


def run_rule(conn, rule, ctx=None):
    return list(rule.run(conn, ctx or {}))


def test_wiped_history_for_active_user(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    events = []
    for i in range(50):
        events.append(event_factory(
            raw_line=f"session {i}", raw_line_offset=i,
            subcategory="successful_login", actor_user="eviluser",
            timestamp_utc=f"2024-03-{(i % 28) + 1:02d}T10:00:00+00:00"))
    # the state finding a parser emits when the history file is empty
    events.append(event_factory(
        raw_line="empty history", raw_line_offset=999,
        event_kind="state_finding", timestamp_utc=None, timestamp_local=None,
        timestamp_confidence="unknown", category="user_activity",
        subcategory="history_missing", actor_user="eviluser",
        source_artifact_path="home/eviluser/.bash_history"))
    db.insert_events(conn, events)

    findings = run_rule(conn, WipedHistoryRule())
    assert findings
    f = findings[0]
    assert f.severity == "high"
    assert "eviluser" in f.plain.what_happened
    assert "50" in f.technical_detail
    conn.close()


def test_history_absent_for_inactive_user_is_not_flagged(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [event_factory(
        raw_line="empty history", event_kind="state_finding",
        timestamp_utc=None, timestamp_local=None,
        timestamp_confidence="unknown", category="user_activity",
        subcategory="history_missing", actor_user="ghost",
        source_artifact_path="home/ghost/.bash_history")])
    assert run_rule(conn, WipedHistoryRule()) == []
    conn.close()


def test_zero_length_login_log_flagged(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [event_factory(
        raw_line="[utmp_empty] var/log/wtmp", event_kind="state_finding",
        timestamp_utc=None, timestamp_local=None,
        timestamp_confidence="unknown", category="login_activity",
        subcategory="utmp_empty", actor_user=None,
        source_artifact_path="var/log/wtmp")])
    findings = run_rule(conn, ZeroLengthLogRule())
    assert findings and findings[0].severity == "high"
    assert "wtmp" in findings[0].plain.what_happened
    conn.close()


def test_rotation_sequence_gap(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    events = []
    for path in ("var/log/auth.log", "var/log/auth.log.1", "var/log/auth.log.3"):
        events.append(event_factory(
            raw_line=f"line from {path}", raw_line_offset=1,
            source_artifact_path=path))
    db.insert_events(conn, events)
    findings = run_rule(conn, RotationGapRule())
    assert findings
    assert "auth.log.2" in findings[0].technical_detail
    conn.close()


def test_complete_rotation_sequence_not_flagged(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    events = [event_factory(raw_line=p, raw_line_offset=1, source_artifact_path=p)
              for p in ("var/log/auth.log", "var/log/auth.log.1",
                        "var/log/auth.log.2")]
    db.insert_events(conn, events)
    assert run_rule(conn, RotationGapRule()) == []
    conn.close()


def test_timeline_gap_detected(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    events = []
    # a busy log: ~4 events/hour for 24h, then an 8-hour hole
    for hour in range(24):
        for i in range(4):
            events.append(event_factory(
                raw_line=f"h{hour}i{i}", raw_line_offset=hour * 10 + i,
                source_artifact_path="var/log/auth.log",
                timestamp_utc=f"2024-03-14T{hour:02d}:{i * 12:02d}:00+00:00"))
    for hour in range(8, 24):
        events.append(event_factory(
            raw_line=f"day2 h{hour}", raw_line_offset=1000 + hour,
            source_artifact_path="var/log/auth.log",
            timestamp_utc=f"2024-03-15T{hour:02d}:00:00+00:00"))
    db.insert_events(conn, events)
    findings = run_rule(conn, TimelineGapRule())
    assert findings, "an 8-hour hole in a busy log must be flagged"
    assert "auth.log" in findings[0].technical_detail
    conn.close()


def test_backwards_timestamps_in_one_file(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    events = [
        event_factory(raw_line="a", raw_line_offset=10,
                      source_artifact_path="var/log/auth.log",
                      timestamp_utc="2024-03-14T10:00:00+00:00"),
        event_factory(raw_line="b", raw_line_offset=20,
                      source_artifact_path="var/log/auth.log",
                      timestamp_utc="2024-03-14T11:00:00+00:00"),
        # later in the file, but EARLIER in time
        event_factory(raw_line="c", raw_line_offset=30,
                      source_artifact_path="var/log/auth.log",
                      timestamp_utc="2024-03-14T09:00:00+00:00"),
    ]
    db.insert_events(conn, events)
    findings = run_rule(conn, BackwardsTimestampsRule())
    assert findings
    assert findings[0].severity in {"medium", "high"}
    assert "clock" in findings[0].plain.why_it_matters.lower() or \
           "inserted" in findings[0].plain.why_it_matters.lower()
    conn.close()


def test_uid0_and_passwordless_state_findings(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        event_factory(raw_line="toor:x:0:0", event_kind="state_finding",
                      timestamp_utc=None, timestamp_local=None,
                      timestamp_confidence="unknown", category="user_accounts",
                      subcategory="uid0_account", actor_user="toor",
                      actor_uid=0, severity="high"),
        event_factory(raw_line="eviluser::", event_kind="state_finding",
                      timestamp_utc=None, timestamp_local=None,
                      timestamp_confidence="unknown", category="user_accounts",
                      subcategory="passwordless_account", actor_user="eviluser",
                      severity="high"),
    ])
    uid0 = run_rule(conn, Uid0Rule())
    assert uid0 and "toor" in uid0[0].plain.what_happened
    assert uid0[0].severity == "high"

    pw = run_rule(conn, PasswordlessAccountRule())
    assert pw and "eviluser" in pw[0].plain.what_happened
    conn.close()


def test_sshd_config_and_preload_rules(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        event_factory(raw_line="PermitRootLogin yes", event_kind="state_finding",
                      timestamp_utc=None, timestamp_local=None,
                      timestamp_confidence="unknown", category="persistence",
                      subcategory="sshd_setting", actor_user=None,
                      severity="high", source_artifact_path="etc/ssh/sshd_config",
                      description="PermitRootLogin is set to yes"),
        event_factory(raw_line="/usr/lib/libhide.so", event_kind="state_finding",
                      timestamp_utc=None, timestamp_local=None,
                      timestamp_confidence="unknown", category="persistence",
                      subcategory="ld_preload_set", actor_user=None,
                      severity="high", source_artifact_path="etc/ld.so.preload",
                      description="/etc/ld.so.preload loads /usr/lib/libhide.so"),
    ])
    ssh = run_rule(conn, SshdConfigRule())
    assert ssh and "root" in ssh[0].plain.what_happened.lower()

    preload = run_rule(conn, LdPreloadRule())
    assert preload and preload[0].severity == "high"
    assert "rootkit" in preload[0].plain.why_it_matters.lower()
    conn.close()


def test_privileged_group_rule(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        event_factory(raw_line="docker:x:999:alice", event_kind="state_finding",
                      timestamp_utc=None, timestamp_local=None,
                      timestamp_confidence="unknown", category="user_accounts",
                      subcategory="privileged_group_member", actor_user="alice",
                      description="User alice belongs to privileged group docker "
                                  "(docker group membership is equivalent to root)"),
    ])
    findings = run_rule(conn, PrivilegedGroupRule())
    assert findings and "alice" in findings[0].plain.what_happened
    conn.close()
