"""Unit tests for login session pairing and duration calculation in report data."""
import sqlite3
import pytest

from lfa.report.data import get_categorized_intel, _format_duration


def test_format_duration():
    assert _format_duration(45) == "45s"
    assert _format_duration(90) == "1m 30s"
    assert _format_duration(3665) == "1h 1m 5s"
    assert _format_duration(90000) == "1d 1h 0m 0s"
    assert _format_duration(-5) == "0s"


def test_session_duration_pairing():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE events ("
        "event_id TEXT, host_id TEXT, actor_user TEXT, actor_process TEXT, source_ip TEXT, source_host TEXT, "
        "category TEXT, subcategory TEXT, timestamp_utc TEXT, raw_line TEXT, description TEXT, "
        "notes TEXT, severity TEXT)"
    )

    # Login 1 with a matching logout 45 minutes later
    conn.execute(
        "INSERT INTO events VALUES ('ev1', 'H1', 'kali', 'sshd', '192.168.1.50', NULL, "
        "'login_activity', 'login', '2026-08-20T10:00:00Z', 'line=pts/0', 'Login on pts/0', NULL, 'info')"
    )
    conn.execute(
        "INSERT INTO events VALUES ('ev2', 'H1', 'kali', 'sshd', NULL, NULL, "
        "'login_activity', 'logout', '2026-08-20T10:45:00Z', 'line=pts/0', 'Session ended on pts/0', NULL, 'info')"
    )

    # Login 2 with no logout (still active/unclosed)
    conn.execute(
        "INSERT INTO events VALUES ('ev3', 'H1', 'root', 'sshd', '192.168.1.100', NULL, "
        "'login_activity', 'successful_login', '2026-08-20T11:00:00Z', 'line=pts/1', 'Accepted password for root', NULL, 'info')"
    )

    # Failed login attempts
    conn.execute(
        "INSERT INTO events VALUES ('ev4', 'H1', 'admin', 'sshd', '192.168.1.200', NULL, "
        "'login_activity', 'failed_login', '2026-08-20T11:05:00Z', 'line=ssh', 'Failed password', NULL, 'low')"
    )
    conn.execute(
        "INSERT INTO events VALUES ('ev5', 'H1', 'admin', 'sshd', '192.168.1.200', NULL, "
        "'login_activity', 'failed_login', '2026-08-20T11:06:00Z', 'line=ssh', 'Failed password', NULL, 'low')"
    )

    intel = get_categorized_intel(conn)
    sessions = intel.get("sessions", [])
    assert len(sessions) == 2

    # Verify closed session with calculated duration
    s1 = next(s for s in sessions if s["actor_user"] == "kali")
    assert s1["source_ip"] == "192.168.1.50"
    assert s1["duration"] == "45m 0s"
    assert s1["status"] == "Closed"

    # Verify active/open session
    s2 = next(s for s in sessions if s["actor_user"] == "root")
    assert s2["source_ip"] == "192.168.1.100"
    assert "Active" in s2["duration"]
    assert s2["status"] == "Active / Unclosed"

    # Verify failed logins aggregation
    fl = intel.get("failed_logins", [])
    assert len(fl) == 1
    assert fl[0]["actor_user"] == "admin"
    assert fl[0]["attempt_count"] == 2
