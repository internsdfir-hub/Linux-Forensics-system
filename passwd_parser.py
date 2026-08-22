import sqlite3
import uuid
import hashlib
import os

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

def parse_passwd_file(file_path="/etc/passwd", case_id="CASE_2026_001", host_id="HOST_UBUNTU_01", db_path="case_database.db"):
    """
    Parses /etc/passwd and inserts structured user identity state findings into SQLite.
    """
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return

    artifact_sha256 = get_file_sha256(file_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    parsed_count = 0

    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for offset, line in enumerate(f):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            parts = line_str.split(":")
            if len(parts) < 7:
                continue

            username = parts[0]
            uid = int(parts[2]) if parts[2].isdigit() else None
            gid = parts[3]
            home_dir = parts[5]
            shell = parts[6]

            # High severity flag for non-root users with UID 0 or interactive login shells
            is_interactive = shell in ["/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish"]
            severity = "medium" if (is_interactive or uid == 0) else "info"

            description = f"System account baseline: user={username}, UID={uid}, shell={shell}"
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
                    event_id, case_id, host_id, event_hash, "state_finding",
                    None, None, None, None, "unknown",
                    "identity_access", "account_baseline", username, uid, None,
                    None, None, description, severity, file_path,
                    artifact_sha256, line_str, offset, "passwd_parser", "1.0.0",
                    0, f"Home: {home_dir}, GID: {gid}"
                ))
                parsed_count += 1
            except sqlite3.IntegrityError:
                # Duplicate entry skipped automatically via UNIQUE event_hash
                pass

    conn.commit()
    conn.close()
    print(f"[+] Successfully parsed {parsed_count} account state entries from {file_path}")

if __name__ == "__main__":
    parse_passwd_file()