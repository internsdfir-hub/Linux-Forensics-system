"""SQLite case store: one file per case, indexed exactly on the spec's join keys."""
from __future__ import annotations

import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .schema import FIELD_NAMES, NormalizedEvent, validate

BATCH_SIZE = 5000

_EVENT_COLS_SQL = ",\n    ".join(
    {
        "event_id": "event_id TEXT NOT NULL",
        "case_id": "case_id TEXT NOT NULL",
        "host_id": "host_id TEXT NOT NULL",
        "event_hash": "event_hash TEXT NOT NULL UNIQUE",
        "event_kind": "event_kind TEXT NOT NULL",
        "timestamp_utc": "timestamp_utc TEXT",
        "timestamp_local": "timestamp_local TEXT",
        "timestamp_tz": "timestamp_tz TEXT",
        "tz_source": "tz_source TEXT NOT NULL",
        "timestamp_confidence": "timestamp_confidence TEXT NOT NULL",
        "category": "category TEXT NOT NULL",
        "subcategory": "subcategory TEXT NOT NULL",
        "actor_user": "actor_user TEXT",
        "actor_uid": "actor_uid INTEGER",
        "actor_process": "actor_process TEXT",
        "source_ip": "source_ip TEXT",
        "source_host": "source_host TEXT",
        "description": "description TEXT NOT NULL",
        "severity": "severity TEXT NOT NULL",
        "source_artifact_path": "source_artifact_path TEXT NOT NULL",
        "source_artifact_sha256": "source_artifact_sha256 TEXT NOT NULL",
        "raw_line": "raw_line TEXT",
        "raw_line_offset": "raw_line_offset INTEGER",
        "parser_name": "parser_name TEXT NOT NULL",
        "parser_version": "parser_version TEXT NOT NULL",
        "tool_generated_flag": "tool_generated_flag INTEGER NOT NULL",
        "notes": "notes TEXT",
    }[name]
    for name in FIELD_NAMES
)

_DDL = f"""
CREATE TABLE IF NOT EXISTS events (
    {_EVENT_COLS_SQL}
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp_utc ON events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_actor_user ON events(actor_user);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_host_id ON events(host_id);

CREATE TABLE IF NOT EXISTS artifacts (
    host_id TEXT NOT NULL,
    original_path TEXT NOT NULL,
    stored_path TEXT,
    sha256 TEXT,
    size INTEGER,
    mode TEXT,
    owner TEXT,
    atime TEXT,
    mtime TEXT,
    ctime TEXT,
    source_was_active INTEGER,
    status TEXT,
    category TEXT,
    verified_sha256 TEXT,
    integrity TEXT,
    had_decode_errors INTEGER DEFAULT 0,
    parse_status TEXT,
    parse_events INTEGER DEFAULT 0,
    parse_error TEXT,
    PRIMARY KEY (host_id, original_path)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    what_happened TEXT NOT NULL,
    why_it_matters TEXT NOT NULL,
    confidence TEXT NOT NULL,
    check_next TEXT NOT NULL,
    technical_detail TEXT NOT NULL,
    first_ts_utc TEXT,
    last_ts_utc TEXT,
    host_id TEXT,
    event_ids TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


@dataclass
class InsertStats:
    inserted: int = 0
    deduped: int = 0
    invalid: int = 0


def open_case(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_DDL)
    conn.commit()
    return conn


_INSERT_SQL = (
    f"INSERT OR IGNORE INTO events ({', '.join(FIELD_NAMES)}) "
    f"VALUES ({', '.join('?' for _ in FIELD_NAMES)})"
)


def insert_events(conn: sqlite3.Connection, events: Iterable[NormalizedEvent]) -> InsertStats:
    """Batched inserts (~5000/txn) with event_hash dedupe and validation.

    Invalid events are counted and skipped; they fail their own row, never
    the pipeline (spec: 'a bad parser fails its own event').
    """
    stats = InsertStats()
    batch: list[tuple] = []

    def flush() -> None:
        if not batch:
            return
        before = conn.total_changes
        conn.executemany(_INSERT_SQL, batch)
        conn.commit()
        inserted = conn.total_changes - before
        stats.inserted += inserted
        stats.deduped += len(batch) - inserted
        batch.clear()

    for ev in events:
        problems = validate(ev)
        if problems:
            stats.invalid += 1
            continue
        row = asdict(ev)
        row["tool_generated_flag"] = int(row["tool_generated_flag"])
        batch.append(tuple(row[name] for name in FIELD_NAMES))
        if len(batch) >= BATCH_SIZE:
            flush()
    flush()
    return stats


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO case_meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    conn.commit()


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM case_meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else None
