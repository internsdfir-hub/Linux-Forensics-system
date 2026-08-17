"""Determinism guarantee (spec 2.5): canonical exports are byte-identical
across runs. The SQLite file itself is NOT the contract - the export is."""
import json

from lfa import canonical, db


def _seed(conn, event_factory, n=25):
    events = []
    for i in range(n):
        events.append(
            event_factory(
                raw_line=f"line {i}",
                raw_line_offset=i * 10,
                category="login_activity" if i % 2 else "persistence",
                timestamp_utc=f"2024-03-{14 + (i % 3):02d}T02:19:{i % 60:02d}+00:00",
            )
        )
    # a state finding with no timestamp must sort last, stably
    events.append(
        event_factory(
            event_kind="state_finding",
            timestamp_utc=None,
            timestamp_local=None,
            timestamp_confidence="unknown",
            category="user_accounts",
            raw_line="root::0:0::/root:/bin/bash",
            raw_line_offset=0,
        )
    )
    db.insert_events(conn, events)


def test_export_json_identical_across_runs(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "case.db")
    _seed(conn, event_factory)

    h1 = canonical.export_json(conn, tmp_path / "exp1.json")
    h2 = canonical.export_json(conn, tmp_path / "exp2.json")
    assert h1 == h2
    assert (tmp_path / "exp1.json").read_bytes() == (tmp_path / "exp2.json").read_bytes()
    conn.close()


def test_export_json_identical_after_reingest_of_same_events(tmp_path, event_factory):
    conn1 = db.open_case(tmp_path / "a.db")
    _seed(conn1, event_factory)
    conn2 = db.open_case(tmp_path / "b.db")
    _seed(conn2, event_factory)  # separate DB, same logical content
    _seed(conn2, event_factory)  # double-ingest: dedupe must keep export equal

    h1 = canonical.export_json(conn1, tmp_path / "a.json")
    h2 = canonical.export_json(conn2, tmp_path / "b.json")
    assert h1 == h2
    conn1.close()
    conn2.close()


def test_export_json_is_valid_sorted_json(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "case.db")
    _seed(conn, event_factory)
    canonical.export_json(conn, tmp_path / "exp.json")
    data = json.loads((tmp_path / "exp.json").read_text(encoding="utf-8"))
    assert isinstance(data, list) and len(data) == 26
    timestamps = [e["timestamp_utc"] for e in data if e["timestamp_utc"]]
    assert timestamps == sorted(timestamps)
    assert data[-1]["timestamp_utc"] is None  # null timestamps sort last
    conn.close()


def test_export_csv_per_category(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "case.db")
    _seed(conn, event_factory)
    hashes = canonical.export_csv_per_category(conn, tmp_path / "csv")
    assert set(hashes) == {"login_activity", "persistence", "user_accounts"}
    again = canonical.export_csv_per_category(conn, tmp_path / "csv2")
    assert hashes == again
    text = (tmp_path / "csv" / "login_activity.csv").read_text(encoding="utf-8")
    assert text.splitlines()[0].startswith("event_id,")
    assert "\r" not in text  # LF endings on every platform
    conn.close()
