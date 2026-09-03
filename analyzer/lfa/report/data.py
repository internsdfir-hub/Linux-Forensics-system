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


def get_categorized_intel(conn: sqlite3.Connection) -> dict:
    """Extracts categorized data to populate the 'Categorized Intel' tabs."""
    intel = {}

    # 1. User Information (Local Users)
    intel["users"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT DISTINCT actor_user, description, min(timestamp_utc) as first_seen "
            "FROM events WHERE category = 'user_accounts' "
            "GROUP BY actor_user "
            "ORDER BY actor_user"
        )
    ]

    # 2. Login Activities (Success & Failed)
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

    # 3. USB Device Activities
    intel["usb"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT timestamp_utc, description, raw_line "
            "FROM events WHERE category = 'hardware_usb' "
            "ORDER BY timestamp_utc"
        )
    ]

    # 4. System / Environment Info (Disk, OS, etc.)
    intel["system"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT subcategory, description, raw_line, timestamp_utc "
            "FROM events WHERE category = 'environment' AND subcategory != 'journal_message' "
            "ORDER BY subcategory, timestamp_utc"
        )
    ]

    # 5. Network & Persistence
    intel["network_persistence"] = [
        dict(r) for r in _rows(
            conn,
            "SELECT category, subcategory, timestamp_utc, description "
            "FROM events WHERE category IN ('network_config', 'persistence', 'software_changes') "
            "ORDER BY "
            "  CASE "
            "    WHEN category = 'persistence' THEN 1 "
            "    WHEN category = 'network_config' THEN 2 "
            "    ELSE 3 "
            "  END, "
            "  timestamp_utc DESC "
            "LIMIT 500"
        )
    ]

    return intel
