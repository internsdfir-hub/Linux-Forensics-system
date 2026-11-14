"""Report data extraction layer.

Aggregates statistics, event timelines, findings, artifact integrity records,
and methodology metrics from the SQLite case database and case_metadata.json.
"""
from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute(sql, params).fetchall()


def get_case_summary(conn: sqlite3.Connection, case_meta: dict) -> dict:
    meta_rows = {r["key"]: r["value"] for r in _rows(conn, "SELECT key, value FROM case_meta")}
    event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finding_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

    min_max_ts = conn.execute(
        "SELECT MIN(timestamp_utc), MAX(timestamp_utc) FROM events WHERE timestamp_utc IS NOT NULL"
    ).fetchone()

    category_counts = [
        {"category": r["category"], "count": r["cnt"]}
        for r in _rows(conn, "SELECT category, COUNT(*) as cnt FROM events GROUP BY category ORDER BY cnt DESC")
    ]

    severity_counts = Counter(
        r["severity"] for r in _rows(conn, "SELECT severity FROM findings")
    )

    hosts = list(case_meta.get("hosts", {}).keys())

    return {
        "case_id": meta_rows.get("case_id", "UNKNOWN"),
        "examiner": meta_rows.get("examiner", "Forensic Examiner"),
        "ingest_time": meta_rows.get("ingest_time", datetime.now(timezone.utc).isoformat()),
        "event_count": event_count,
        "finding_count": finding_count,
        "first_event_utc": min_max_ts[0] if min_max_ts else None,
        "last_event_utc": min_max_ts[1] if min_max_ts else None,
        "category_counts": category_counts,
        "severity_counts": {
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
        },
        "hosts": hosts,
        "hosts_meta": case_meta.get("hosts", {}),
    }


def get_findings_data(conn: sqlite3.Connection) -> list[dict]:
    rows = _rows(
        conn,
        "SELECT finding_id, rule_name, rule_version, severity, title, "
        "what_happened, why_it_matters, confidence, check_next, "
        "technical_detail, event_ids, first_ts_utc, last_ts_utc, host_id "
        "FROM findings ORDER BY CASE severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
    )
    findings = []
    for r in rows:
        event_ids = []
        if r["event_ids"]:
            try:
                event_ids = json.loads(r["event_ids"])
            except Exception:
                event_ids = [r["event_ids"]]
        findings.append({
            "finding_id": r["finding_id"],
            "rule_name": r["rule_name"],
            "rule_version": r["rule_version"],
            "severity": r["severity"],
            "title": r["title"],
            "what_happened": r["what_happened"],
            "why_it_matters": r["why_it_matters"],
            "confidence": r["confidence"],
            "check_next": r["check_next"],
            "technical_detail": r["technical_detail"],
            "event_ids": event_ids,
            "first_ts_utc": r["first_ts_utc"],
            "last_ts_utc": r["last_ts_utc"],
            "host_id": r["host_id"],
        })
    return findings


def get_artifacts_data(conn: sqlite3.Connection) -> list[dict]:
    rows = _rows(
        conn,
        "SELECT host_id, original_path, stored_path, sha256 as sha256_at_collect, "
        "verified_sha256 as sha256_at_ingest, status, mtime, size, integrity, parse_status "
        "FROM artifacts ORDER BY host_id, original_path"
    )
    return [dict(r) for r in rows]


def get_events_sample(conn: sqlite3.Connection, limit: int = 1000) -> list[dict]:
    rows = _rows(
        conn,
        "SELECT event_id, event_kind, category, subcategory, severity, "
        "timestamp_utc, timestamp_local, timestamp_confidence, "
        "actor_user, actor_uid, actor_process, source_ip, source_host, "
        "description, raw_line, source_artifact_path "
        "FROM events ORDER BY CASE WHEN timestamp_utc IS NULL THEN 1 ELSE 0 END, timestamp_utc, event_id LIMIT ?",
        (limit,)
    )
    return [dict(r) for r in rows]


def _format_duration(seconds: int | float) -> str:
    seconds = int(seconds)
    if seconds < 0:
        return "0s"
    mins, secs = divmod(seconds, 60)
    hours, mins = divmod(mins, 60)
    days, hours = divmod(hours, 24)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    if mins > 0 or hours > 0 or days > 0:
        parts.append(f"{mins}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def _extract_terminal(raw_line: str, desc: str) -> str:
    import re
    m = re.search(r"\bline=(\S+)", raw_line)
    if m:
        return m.group(1)
    m = re.search(r"\b(?:on|TTY=)(\S+)", raw_line)
    if m:
        return m.group(1)
    m = re.search(r"\b(pts/\d+|tty\d+)", desc)
    if m:
        return m.group(1)
    return "unknown"


def get_categorized_intel(conn: sqlite3.Connection) -> dict:
    """Extracts comprehensive categorized data to populate the 'Categorized Intel' tabs."""
    intel = {}

    # 1. User Information (Local Users & Group membership)
    intel["users"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT DISTINCT actor_user, description, min(timestamp_utc) as first_seen "
            "FROM events WHERE category = 'user_accounts' AND subcategory IN ('account', 'uid0_account') "
            "GROUP BY actor_user "
            "ORDER BY actor_user"
        )
    ]

    # 1b. User Creation / Deletion / Escalation Diffs
    intel["user_diffs"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT subcategory, actor_user, description, timestamp_utc, severity "
            "FROM events WHERE category = 'user_accounts' AND subcategory NOT IN ('account', 'uid0_account') "
            "OR (category = 'privilege_escalation' AND subcategory = 'group_membership_added') "
            "ORDER BY timestamp_utc DESC"
        )
    ]

    # 2. Login Activities & Duration Calculation
    logins_raw = _rows(
        conn,
        "SELECT event_id, host_id, actor_user, source_ip, source_host, timestamp_utc, raw_line, description "
        "FROM events WHERE category = 'login_activity' "
        "AND subcategory IN ('successful_login', 'session_opened', 'login') "
        "AND timestamp_utc IS NOT NULL ORDER BY timestamp_utc"
    )

    logouts_raw = _rows(
        conn,
        "SELECT event_id, host_id, actor_user, timestamp_utc, raw_line, description "
        "FROM events WHERE category = 'login_activity' "
        "AND subcategory IN ('logout', 'session_closed', 'disconnect') "
        "AND timestamp_utc IS NOT NULL ORDER BY timestamp_utc"
    )

    used_logout_ids = set()
    sessions = []
    for l in logins_raw:
        u = l["actor_user"] or "unknown"
        login_ts = l["timestamp_utc"]
        term = _extract_terminal(l["raw_line"] or "", l["description"] or "")
        matched_logout = None

        for o in logouts_raw:
            if o["event_id"] in used_logout_ids:
                continue
            if o["host_id"] == l["host_id"] and o["timestamp_utc"] >= login_ts:
                o_u = o["actor_user"]
                o_term = _extract_terminal(o["raw_line"] or "", o["description"] or "")
                if (o_u and o_u == u) or (term != "unknown" and o_term == term):
                    matched_logout = o
                    used_logout_ids.add(o["event_id"])
                    break

        duration_str = "Active / Session Open"
        logout_ts = None
        if matched_logout:
            logout_ts = matched_logout["timestamp_utc"]
            try:
                t1 = datetime.fromisoformat(login_ts.replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(logout_ts.replace("Z", "+00:00"))
                secs = (t2 - t1).total_seconds()
                if secs >= 0:
                    duration_str = _format_duration(secs)
            except Exception:
                duration_str = "Recorded"

        sessions.append({
            "actor_user": u,
            "source_ip": l["source_ip"] or l["source_host"] or "local",
            "terminal": term,
            "login_time": login_ts,
            "logout_time": logout_ts or "—",
            "duration": duration_str,
            "status": "Closed" if logout_ts else "Active / Unclosed",
        })

    intel["sessions"] = sessions

    # Backward-compatible logins aggregate
    intel["logins"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT actor_user, source_ip, subcategory, COUNT(*) as attempt_count, "
            "MIN(timestamp_utc) as first_attempt, MAX(timestamp_utc) as last_attempt "
            "FROM events WHERE category = 'login_activity' "
            "GROUP BY actor_user, source_ip, subcategory "
            "ORDER BY attempt_count DESC"
        )
    ]

    # 3. Failed Login Attempts (Distinct aggregation)
    intel["failed_logins"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT actor_user, source_ip, COUNT(*) as attempt_count, "
            "MIN(timestamp_utc) as first_attempt, MAX(timestamp_utc) as last_attempt "
            "FROM events WHERE category = 'login_activity' AND subcategory IN ('failed_login', 'invalid_user', 'auth_failure') "
            "GROUP BY actor_user, source_ip "
            "ORDER BY attempt_count DESC"
        )
    ]

    # 4. USB Device Activities
    intel["usb"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT timestamp_utc, subcategory, description, notes, raw_line "
            "FROM events WHERE category = 'hardware_usb' "
            "ORDER BY timestamp_utc"
        )
    ]

    # 5. Storage & Hard Disk Information
    intel["storage"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT subcategory, description, notes, raw_line "
            "FROM events WHERE category = 'environment' "
            "AND subcategory IN ('storage_device', 'filesystem_mount') "
            "ORDER BY subcategory"
        )
    ]

    # 6. Network Interfaces & Configuration
    intel["network_interfaces"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT subcategory, source_ip, description, notes, raw_line "
            "FROM events WHERE category = 'network_config' AND subcategory = 'network_interface' "
            "ORDER BY source_ip"
        )
    ]

    # 6b. Firewall Blocks & Known Hosts
    intel["firewall_network"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT subcategory, timestamp_utc, source_ip, description "
            "FROM events WHERE category = 'network_config' AND subcategory IN ('firewall_block', 'known_host') "
            "ORDER BY timestamp_utc DESC"
        )
    ]

    # 7. Internet & Network Activities (Broken down per Task 2 specifications)

    # 7a. Remote IP Connections (Consolidated external IPs across SSH, Web, FTP, etc.)
    intel["remote_ips"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT source_ip, COUNT(*) as connection_count, "
            "GROUP_CONCAT(DISTINCT actor_user) as users, "
            "GROUP_CONCAT(DISTINCT subcategory) as services, "
            "MIN(timestamp_utc) as first_seen, "
            "MAX(timestamp_utc) as last_seen "
            "FROM events "
            "WHERE source_ip IS NOT NULL "
            "AND source_ip NOT IN ('127.0.0.1', '::1', 'localhost', 'local', '', ':0.0', ':0') "
            "AND source_ip NOT LIKE ':%' "
            "GROUP BY source_ip "
            "ORDER BY connection_count DESC"
        )
    ]

    # 7b. SSH Connections (Inbound sshd sessions & Outbound known_hosts)
    intel["ssh_connections"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT timestamp_utc, "
            "CASE WHEN subcategory = 'known_host' THEN 'Outbound' ELSE 'Inbound' END as direction, "
            "actor_user, source_ip, subcategory, description, raw_line "
            "FROM events "
            "WHERE subcategory = 'known_host' "
            "OR actor_process = 'sshd' "
            "OR raw_line LIKE '%sshd%' "
            "ORDER BY timestamp_utc DESC LIMIT 500"
        )
    ]

    # 7c. DNS Requests & Resolver Configuration
    intel["dns_activity"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT subcategory, source_ip, source_host, description, notes, raw_line "
            "FROM events "
            "WHERE subcategory IN ('dns_nameserver', 'dns_search', 'dns_mapping', 'dns_query') "
            "OR notes IN ('resolv.conf', 'etc/hosts') "
            "ORDER BY subcategory, source_ip"
        )
    ]

    # 7d. HTTP / HTTPS Web Server Logs
    intel["http_logs"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT timestamp_utc, source_ip as client_ip, actor_user, description, notes, severity "
            "FROM events WHERE subcategory = 'http_request' "
            "ORDER BY timestamp_utc DESC LIMIT 500"
        )
    ]

    # 7e. FTP Connections & Transfers
    intel["ftp_connections"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT timestamp_utc, source_ip as client_ip, actor_user, description, notes, severity "
            "FROM events WHERE subcategory = 'ftp_transfer' "
            "OR (category = 'user_activity' AND (description LIKE '%FTP%' OR raw_line LIKE '%vsftpd%')) "
            "ORDER BY timestamp_utc DESC LIMIT 500"
        )
    ]

    # 7f. Browser Activities & Download History
    intel["browser_and_downloads"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT timestamp_utc, subcategory, actor_user, description, notes "
            "FROM events "
            "WHERE subcategory IN ('browser_history', 'browser_download') "
            "OR (category = 'user_activity' AND (description LIKE '%wget %' OR description LIKE '%curl %' OR description LIKE '%download%')) "
            "ORDER BY timestamp_utc DESC LIMIT 500"
        )
    ]

    # Legacy internet_services list for backwards compatibility
    intel["internet_services"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT subcategory, timestamp_utc, actor_user, source_ip, description, notes "
            "FROM events WHERE category = 'user_activity' "
            "AND subcategory IN ('http_request', 'ftp_transfer', 'browser_history', 'browser_download') "
            "ORDER BY timestamp_utc DESC LIMIT 500"
        )
    ]

    # 8. System Information & Additional Features
    intel["system"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT subcategory, description, raw_line, timestamp_utc "
            "FROM events WHERE category = 'environment' AND subcategory NOT IN ('journal_message', 'storage_device', 'filesystem_mount') "
            "ORDER BY subcategory, timestamp_utc"
        )
    ]

    intel["system_additional"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT category, subcategory, actor_user, timestamp_utc, description, severity "
            "FROM events WHERE subcategory IN ('suspicious_command', 'sudo_command', 'sudo_failure', 'sudo_denied', 'cron_command', 'crontab_modified', 'systemd_service', 'package_install', 'package_remove') "
            "ORDER BY timestamp_utc DESC LIMIT 500"
        )
    ]

    intel["shell_history"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT actor_user, timestamp_utc, description, notes, severity "
            "FROM events WHERE subcategory = 'shell_command' "
            "ORDER BY timestamp_utc ASC LIMIT 1500"
        )
    ]

    intel["volatile_sockets"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT subcategory, source_ip, actor_process, description, notes, severity "
            "FROM events WHERE category = 'network_config' AND subcategory IN ('established', 'listen', 'unconn', 'time_wait', 'close_wait') "
            "ORDER BY subcategory, description LIMIT 1000"
        )
    ]

    # Backward compatibility
    intel["network_persistence"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT category, subcategory, timestamp_utc, description "
            "FROM events WHERE category IN ('network_config', 'persistence', 'software_changes') "
            "ORDER BY timestamp_utc DESC LIMIT 500"
        )
    ]

    return intel
