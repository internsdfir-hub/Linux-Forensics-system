import sqlite3
import uuid
import hashlib
import re
import os
from datetime import datetime

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

def parse_auth_log(file_path="/var/log/auth.log", case_id="CASE_2026_001", host_id="HOST_UBUNTU_01", db_path="case_database.db"):
    """
    Parses Linux syslog-style authentication logs (/var/log/auth.log) into normalized_event.
    """
    if not os.path.exists(file_path):
        print(f"[-] Target log file not found: {file_path}")
        print("[!] Generating mock auth.log sample for verification...")
        file_path = "mock_auth.log"
        with open(file_path, "w") as f:
            f.write("Aug 21 22:15:00 server01 sshd[1234]: Accepted password for root from 192.168.1.50 port 44321 ssh2\n")
            f.write("Aug 21 22:16:10 server01 sshd[1235]: Failed password for invalid user admin from 10.0.0.5 port 51234 ssh2\n")
            f.write("Aug 21 22:18:00 server01 sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/cat /etc/shadow\n")

    artifact_sha256 = get_file_sha256(file_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    # Regex patterns for common auth.log formats
    syslog_prefix = r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
    
    parsed_count = 0
    current_year = datetime.now().year

    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for offset, line in enumerate(f):
            line_str = line.strip()
            if not line_str:
                continue

            match = re.match(syslog_prefix, line_str)
            if not match:
                continue

            data = match.groupdict()
            message = data['message']
            process = data['process']

            # Infer UTC timestamp from Syslog header (assuming current year)
            ts_str = f"{current_year} {data['month']} {data['day']} {data['time']}"
            try:
                dt = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
                timestamp_utc = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                timestamp_local = dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                timestamp_utc = None
                timestamp_local = None

            # Categorize events based on payload indicators
            subcategory = "general_auth"
            severity = "info"
            actor_user = None
            source_ip = None

            # 1. SSH Accepted
            if "Accepted password" in message or "Accepted publickey" in message:
                subcategory = "ssh_login_success"
                severity = "medium"
                user_match = re.search(r"for\s+(\S+)", message)
                ip_match = re.search(r"from\s+(\S+)", message)
                actor_user = user_match.group(1) if user_match else None
                source_ip = ip_match.group(1) if ip_match else None

            # 2. SSH Failed / Invalid User
            elif "Failed password" in message or "Invalid user" in message:
                subcategory = "ssh_login_failed"
                severity = "high"
                user_match = re.search(r"for\s+(?:invalid user\s+)?(\S+)", message)
                ip_match = re.search(r"from\s+(\S+)", message)
                actor_user = user_match.group(1) if user_match else None
                source_ip = ip_match.group(1) if ip_match else None

            # 3. Sudo Execution
            elif "sudo" in process:
                subcategory = "privilege_escalation"
                severity = "medium"
                sudo_user = re.search(r"^(\S+)\s+:", message)
                actor_user = sudo_user.group(1) if sudo_user else None

            event_id = str(uuid.uuid4())
            event_hash = generate_event_hash(line_str, file_path)

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
                    timestamp_utc, timestamp_local, "+00:00", "log_offset", "year_inferred",
                    "identity_access", subcategory, actor_user, None, process,
                    source_ip, None, message, severity, file_path,
                    artifact_sha256, line_str, offset, "authlog_parser", "1.0.0",
                    0, "Parsed via Syslog Regex Engine"
                ))
                parsed_count += 1
            except sqlite3.IntegrityError:
                pass

    conn.commit()
    conn.close()
    print(f"[+] Successfully parsed {parsed_count} auth log entries from {file_path}")

if __name__ == "__main__":
    parse_auth_log()