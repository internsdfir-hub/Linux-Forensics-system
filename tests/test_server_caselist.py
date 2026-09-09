"""_list_cases must read evidence databases read-only and never leak handles."""
import gc
import json
import sqlite3
from pathlib import Path

from lfa import db
from lfa.server import LFAServerHandler


def _make_case(cases_dir: Path, case_id: str, examiner: str) -> Path:
    case_dir = cases_dir / case_id
    case_dir.mkdir(parents=True)
    conn = db.open_case(case_dir / "case.db")
    db.set_case_meta(conn, "case_id", case_id)
    db.set_case_meta(conn, "examiner", examiner)
    conn.commit()
    conn.close()
    (case_dir / "report.html").write_text("<html></html>", encoding="utf-8")
    return case_dir


def _list(cases_dir: Path):
    handler = LFAServerHandler.__new__(LFAServerHandler)
    handler.server = type("S", (), {"cases_dir": cases_dir})()
    return LFAServerHandler._list_cases(handler)


def test_examiner_is_read_from_the_database(tmp_path):
    """This silently returned 'Unknown' because of a TypeError swallowed
    by a bare except."""
    cases_dir = tmp_path / "cases"
    _make_case(cases_dir, "CASE-1", "Jane Doe")

    cases = _list(cases_dir)

    assert len(cases) == 1
    assert cases[0]["examiner"] == "Jane Doe"


def test_listing_does_not_modify_the_evidence_database(tmp_path):
    """open_case() runs DDL against the case DB; a read must not touch it."""
    cases_dir = tmp_path / "cases"
    case_dir = _make_case(cases_dir, "CASE-1", "Jane Doe")
    db_file = case_dir / "case.db"

    before_mtime = db_file.stat().st_mtime_ns
    before_bytes = db_file.read_bytes()

    _list(cases_dir)
    gc.collect()

    assert db_file.stat().st_mtime_ns == before_mtime, "listing wrote to evidence"
    assert db_file.read_bytes() == before_bytes, "listing altered evidence bytes"


def test_listing_does_not_create_schema_in_a_bare_database(tmp_path):
    """A schemaless case.db discriminates old vs. new code: the old
    db.open_case() path runs CREATE TABLE IF NOT EXISTS against a file with
    no tables yet, which is a real schema write (the file grows from 0
    bytes). The new read-only path hits "no such table: events", the
    except swallows it, and the file is provably untouched at 0 bytes.
    """
    cases_dir = tmp_path / "cases"
    case_dir = cases_dir / "CASE-1"
    case_dir.mkdir(parents=True)
    db_file = case_dir / "case.db"
    conn = sqlite3.connect(str(db_file))
    conn.close()

    assert db_file.stat().st_size == 0

    cases = _list(cases_dir)
    gc.collect()

    assert db_file.stat().st_size == 0, "listing wrote a schema into a bare evidence file"
    assert cases[0]["events_count"] == 0


def test_listing_reports_counts(tmp_path):
    cases_dir = tmp_path / "cases"
    _make_case(cases_dir, "CASE-1", "Jane Doe")

    cases = _list(cases_dir)

    assert cases[0]["events_count"] == 0
    assert cases[0]["findings_count"] == 0
    assert cases[0]["high_findings"] == 0
    assert cases[0]["has_report"] is True
