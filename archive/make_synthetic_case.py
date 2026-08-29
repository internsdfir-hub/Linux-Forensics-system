import sqlite3
import uuid
import hashlib
from datetime import datetime, timezone

def generate_event_hash(raw_line, timestamp):
    """Generates a unique SHA-256 hash for deduplication."""
    return hashlib.sha256(f"{raw_line}_{timestamp}".encode('utf-8')).hexdigest()

def populate_synthetic_data(db_path="case_database.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    # 1. Synthetic SSH Login Event (Task 2 Shared Baseline)
    event_id_1 = str(uuid.uuid4())
    raw_1 = "Aug 21 22:15:00 server01 sshd[1234]: Accepted password for root from 192.168.1.50 port 44321 ssh2"
    hash_1 = generate_event_hash(raw_1, "2026-08-21T22:15:00Z")

    cursor.execute("""
    INSERT INTO normalized_event (
        event_id, case_id, host_id, event_hash, event_kind,
        timestamp_utc, timestamp_local, timestamp_tz, tz_source, timestamp_confidence,
        category, subcategory, actor_user, actor_uid, actor_process,
        source_ip, source_host, description, severity, source_artifact_path,
        source_artifact_sha256, raw_line, raw_line_offset, parser_name, parser_version,
        tool_generated_flag, notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        event_id_1, "CASE_2026_001", "HOST_UBUNTU_01", hash_1, "event",
        "2026-08-21T22:15:00Z", "2026-08-21 22:15:00", "+00:00", "assumed_utc", "exact",
        "identity_access", "ssh_login", "root", 0, "sshd",
        "192.168.1.50", "client_host", "Successful SSH login for root", "medium", "/var/log/auth.log",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", raw_1, 1024, "authlog_parser", "1.0.0",
        0, "Synthetic test baseline"
    ))

    # 2. Synthetic Journald Log Event (Target for Thesis Detection)
    event_id_2 = str(uuid.uuid4())
    raw_2 = "Aug 21 22:16:30 server01 systemd-journald[500]: Suppressed 152 messages due to rate limiting"
    hash_2 = generate_event_hash(raw_2, "2026-08-21T22:16:30Z")

    cursor.execute("""
    INSERT INTO normalized_event (
        event_id, case_id, host_id, event_hash, event_kind,
        timestamp_utc, timestamp_local, timestamp_tz, tz_source, timestamp_confidence,
        category, subcategory, actor_user, actor_uid, actor_process,
        source_ip, source_host, description, severity, source_artifact_path,
        source_artifact_sha256, raw_line, raw_line_offset, parser_name, parser_version,
        tool_generated_flag, notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        event_id_2, "CASE_2026_001", "HOST_UBUNTU_01", hash_2, "event",
        "2026-08-21T22:16:30Z", "2026-08-21 22:16:30", "+00:00", "assumed_utc", "exact",
        "system_activity", "journal_anomaly", "systemd-journal", 0, "systemd-journald",
        None, None, "Journald record sequence jump detected", "high", "/var/log/journal/system.journal",
        "f4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afb", raw_2, 4096, "journald_parser", "1.0.0",
        1, "Synthetic tamper artifact"
    ))

    # 3. Linked Thesis Alert: Simulating Sequence Gap Detection
    alert_id = str(uuid.uuid4())
    cursor.execute("""
    INSERT INTO forensic_alerts (
        alert_id, event_id, alert_type, sequence_expected, sequence_actual,
        delta_monotonic_ms, delta_realtime_ms, anomaly_score, technical_evidence
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        alert_id, event_id_2, "SEQUENCE_GAP", 1045, 1080,
        1500.0, -3500.0, 0.95, "Sequence jump of 35 missing entries detected between monotonic timestamps."
    ))

    conn.commit()
    conn.close()
    print("[+] Synthetic case successfully populated into case_database.db!")

if __name__ == "__main__":
    populate_synthetic_data()