"""Canonical deterministic exports.

The determinism contract (spec 2.5): analysing the same bundle twice yields
byte-identical JSON/CSV exports, verified by hash. Sort order, key order,
separators and line endings are all pinned here.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
from pathlib import Path

from .schema import FIELD_NAMES

# NULL timestamps sort last; ties broken by category then event_hash so the
# order never depends on insertion order or rowids.
_ORDER_SQL = (
    "ORDER BY (timestamp_utc IS NULL), timestamp_utc, category, event_hash"
)


def _rows(conn: sqlite3.Connection, category: str | None = None):
    where = "WHERE category = ?" if category else ""
    params = (category,) if category else ()
    sql = f"SELECT {', '.join(FIELD_NAMES)} FROM events {where} {_ORDER_SQL}"
    for row in conn.execute(sql, params):
        record = dict(zip(FIELD_NAMES, row))
        record["tool_generated_flag"] = bool(record["tool_generated_flag"])
        yield record


def _write_and_hash(out_path: Path, data: bytes) -> str:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def export_json(conn: sqlite3.Connection, out_path: str | Path) -> str:
    """Write the full-case canonical JSON export; return its sha256."""
    buf = io.StringIO()
    buf.write("[\n")
    first = True
    for record in _rows(conn):
        if not first:
            buf.write(",\n")
        buf.write(json.dumps(record, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False))
        first = False
    buf.write("\n]\n")
    return _write_and_hash(Path(out_path), buf.getvalue().encode("utf-8"))


def export_csv_per_category(conn: sqlite3.Connection, out_dir: str | Path) -> dict[str, str]:
    """Write one canonical CSV per category present; return {category: sha256}."""
    out = {}
    categories = [
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT category FROM events ORDER BY category"
        )
    ]
    for cat in categories:
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(FIELD_NAMES)
        for record in _rows(conn, category=cat):
            writer.writerow(
                ["" if record[name] is None else record[name] for name in FIELD_NAMES]
            )
        out[cat] = _write_and_hash(
            Path(out_dir) / f"{cat}.csv", buf.getvalue().encode("utf-8")
        )
    return out
