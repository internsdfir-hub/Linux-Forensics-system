import sqlite3
import sys

def initialize_database(db_path="case_database.db"):
    """
    Initializes the SQLite Case Database for Task 2.
    Sets up the Normalized Event Store and the Thesis Anti-Forensics Extension.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Enable Foreign Key support in SQLite
    cursor.execute("PRAGMA foreign_keys = ON;")

    # -------------------------------------------------------------------------
    # 1. CORE TABLE: normalized_event (Task 2 Shared Baseline)
    # -------------------------------------------------------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS normalized_event (
        event_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        host_id TEXT NOT NULL,
        event_hash TEXT UNIQUE NOT NULL,
        event_kind TEXT CHECK(event_kind IN ('event', 'state_finding')) NOT NULL,
        timestamp_utc TEXT,
        timestamp_local TEXT,
        timestamp_tz TEXT,
        tz_source TEXT CHECK(tz_source IN ('etc_localtime', 'log_offset', 'assumed_utc')),
        timestamp_confidence TEXT CHECK(timestamp_confidence IN ('exact', 'year_inferred', 'unknown')),
        category TEXT NOT NULL,
        subcategory TEXT,
        actor_user TEXT,
        actor_uid INTEGER,
        actor_process TEXT,
        source_ip TEXT,
        source_host TEXT,
        description TEXT NOT NULL,
        severity TEXT CHECK(severity IN ('info', 'low', 'medium', 'high')) NOT NULL,
        source_artifact_path TEXT NOT NULL,
        source_artifact_sha256 TEXT NOT NULL,
        raw_line TEXT NOT NULL,
        raw_line_offset INTEGER,
        parser_name TEXT NOT NULL,
        parser_version TEXT NOT NULL,
        tool_generated_flag BOOLEAN DEFAULT 0,
        notes TEXT
    );
    """)

    # Performance Indexes for Correlation Layer Queries
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON normalized_event(timestamp_utc);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_category ON normalized_event(category);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_actor ON normalized_event(actor_user);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON normalized_event(source_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON normalized_event(host_id);")

    # -------------------------------------------------------------------------
    # 2. THESIS EXTENSION TABLE: forensic_alerts (Anti-Forensic Detection)
    # -------------------------------------------------------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS forensic_alerts (
        alert_id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        alert_type TEXT CHECK(alert_type IN ('SEQUENCE_GAP', 'TIMESTOMPING', 'LOG_TRUNCATION', 'INVARIANT_VIOLATION')) NOT NULL,
        sequence_expected INTEGER,
        sequence_actual INTEGER,
        delta_monotonic_ms REAL,
        delta_realtime_ms REAL,
        anomaly_score REAL NOT NULL,
        technical_evidence TEXT NOT NULL,
        FOREIGN KEY (event_id) REFERENCES normalized_event(event_id) ON DELETE CASCADE
    );
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON forensic_alerts(event_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON forensic_alerts(alert_type);")

    conn.commit()
    conn.close()
    print(f"[+] Database successfully initialized at: {db_path}")

if __name__ == "__main__":
    initialize_database()