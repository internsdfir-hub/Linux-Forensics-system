import sqlite3
import uuid
import hashlib
import json
import os
from datetime import datetime, timezone

def generate_event_hash(raw_line, filepath):
    """Generates a unique SHA-256 hash for deduplication."""
    return hashlib.sha256(f"{raw_line}_{filepath}".encode('utf-8')).hexdigest()

def get_file_sha256(filepath):
    """Calculates SHA-256 hash of the target file for custody tracking."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def parse_journald_export(file_path="journal_export.json", case_id="CASE_2026_001", host_id="HOST_UBUNTU_01", db_path="case_database.db"):
    """
    Parses systemd-journald JSON export logs and extracts sequence numbers and timestamps.
    """
    if not os.path.exists(file_path):
        print(f"[-] Target journal export file not found: {file_path}")
        print("[!] Generating synthetic journald JSON export for verification...")
        file_path = "mock_journal.json"
        
        # Mock systemd journal JSON records (Includes normal sequence + gap sequence for testing)
        mock_data = [
            {
                "__SEQNUM": 1001,
                "__MONOTONIC_TIMESTAMP": "1000000",
                "__REALTIME_TIMESTAMP": "1724278500000000",
                "_HOSTNAME": "server01",
                "_SYSTEMD_UNIT": "sshd.service",
                "_COMM": "sshd",
                "MESSAGE": "Accepted password for root from 192.168.1.50 port 44321 ssh2",
                "_PID": "1234"
            },
            {
                "__SEQNUM": 1002,
                "__MONOTONIC_TIMESTAMP": "1005000",
                "__REALTIME_TIMESTAMP": "1724278505000000",
                "_HOSTNAME": "server01",
                "_SYSTEMD_UNIT": "systemd-journald.service",
                "_COMM": "systemd-journal",
                "MESSAGE": "Journal service started baseline logging.",
                "_PID": "500"
            },
            {
                # Intentionally creating sequence gap (1002 -> 1050) to simulate log deletion
                "__SEQNUM": 1050,
                "__MONOTONIC_TIMESTAMP": "1010000",
                "__REALTIME_TIMESTAMP": "1724278510000000",
                "_HOSTNAME": "server01",
                "_SYSTEMD_UNIT": "systemd-journald.service",
                "_COMM": "systemd-journal",
                "MESSAGE": "Suppressed 48 messages due to rate limiting or clearing.",
                "_PID": "500"
            }
        ]
        
        with open(file_path, "w") as f:
            for entry in mock_data:
                f.write(json.dumps(entry) + "\n")

    artifact_sha256 = get_file_sha256(file_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    parsed_count = 0

    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for offset, line in enumerate(f):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                entry = json.loads(line_str)
            except json.JSONDecodeError:
                continue

            seq_num = entry.get("__SEQNUM")
            message = entry.get("MESSAGE", "No message payload")
            process = entry.get("_COMM", entry.get("_SYSTEMD_UNIT", "unknown"))
            realtime_us = entry.get("__REALTIME_TIMESTAMP")
            
            #Handle string vs byte array MESSAGE payloads
            raw_msg = entry.get("MESSAGE", "No message payload")
            if isinstance(raw_msg, list):
                try:
                    message = bytes(raw_msg).decode('utf-8', errors='replace')
                except Exception:
                    message = str(raw_msg)
            else:
                message = str(raw_msg)

            # Convert Journald microsecond realtime epoch to ISO UTC
            timestamp_utc = None
            timestamp_local = None
            if realtime_us:
                try:
                    ts_sec = int(realtime_us) / 1000000.0
                    dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
                    timestamp_utc = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                    timestamp_local = dt.strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    pass

            event_id = str(uuid.uuid4())
            event_hash = generate_event_hash(line_str, file_path)
            notes = f"SEQNUM:{seq_num} | MONOTONIC:{entry.get('__MONOTONIC_TIMESTAMP')}"

            try:
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
                    event_id, case_id, host_id, event_hash, "event",
                    timestamp_utc, timestamp_local, "+00:00", "assumed_utc", "exact",
                    "system_activity", "journal_record", None, None, process,
                    None, None, message, "info", file_path,
                    artifact_sha256, line_str, offset, "journald_parser", "1.0.0",
                    0, notes
                ))
                parsed_count += 1
            except Exception as e:
                print(f"[!] Error on line {offset}: {e}")

    conn.commit()
    conn.close()
    print(f"[+] Successfully parsed {parsed_count} journald entries from {file_path}")

if __name__ == "__main__":
    parse_journald_export()