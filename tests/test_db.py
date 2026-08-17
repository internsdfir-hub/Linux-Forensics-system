"""Tests for the SQLite case store (spec section 2.5: indexes, dedupe)."""
import sqlite3

from lfa import db


def test_open_case_creates_schema_and_is_idempotent(tmp_path):
    path = tmp_path / "case.db"
    conn = db.open_case(path)
    conn.close()
    conn = db.open_case(path)  # reopening must not fail or duplicate anything
    tables = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert {"events", "artifacts", "findings", "case_meta"} <= tables
    conn.close()


def test_indexes_match_spec_exactly(tmp_path):
    conn = db.open_case(tmp_path / "case.db")
    indexed_cols = set()
    for (name,) in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_events_%'"
    ).fetchall():
        info = conn.execute(f"PRAGMA index_info({name})").fetchall()
        indexed_cols.add(tuple(r[2] for r in info))
    # spec: exactly timestamp_utc, category, actor_user, source_ip, host_id
    assert indexed_cols == {
        ("timestamp_utc",),
        ("category",),
        ("actor_user",),
        ("source_ip",),
        ("host_id",),
    }
    conn.close()


def test_insert_events_and_dedupe(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "case.db")
    events = [
        event_factory(raw_line_offset=i, raw_line=f"line {i}") for i in range(10)
    ]
    stats = db.insert_events(conn, events)
    assert stats.inserted == 10
    assert stats.deduped == 0

    # re-collecting the same host must not double-count (spec trap #11)
    stats2 = db.insert_events(conn, events)
    assert stats2.inserted == 0
    assert stats2.deduped == 10
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 10
    conn.close()


def test_insert_rejects_invalid_events(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "case.db")
    good = event_factory(raw_line="ok")
    bad = event_factory(raw_line="bad")
    bad.severity = "catastrophic"  # not a valid enum
    stats = db.insert_events(conn, [good, bad])
    assert stats.inserted == 1
    assert stats.invalid == 1
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    conn.close()


def test_case_meta_roundtrip(tmp_path):
    conn = db.open_case(tmp_path / "case.db")
    db.set_meta(conn, "examiner", "Moharis")
    assert db.get_meta(conn, "examiner") == "Moharis"
    assert db.get_meta(conn, "missing") is None
    conn.close()


def test_events_table_columns_match_schema_fields(tmp_path):
    from lfa.schema import FIELD_NAMES

    conn = db.open_case(tmp_path / "case.db")
    cols = [r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()]
    assert cols == list(FIELD_NAMES)
    conn.close()
