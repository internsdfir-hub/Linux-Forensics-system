"""Pipeline: walk the ingested raw tree, hand each artifact to the parsers
that claim it, validate, and insert into the case DB. Records per-artifact
parse status so the report's methodology section can state what was NOT
processed."""
import json
from pathlib import Path

from tests.bundle_builder import build_bundle

from lfa import db, ingest, pipeline

FILES = {
    "/etc/os-release": b'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n',
    "/etc/passwd": (
        b"root:x:0:0:root:/root:/bin/bash\n"
        b"alice:x:1000:1000::/home/alice:/bin/bash\n"
        b"toor:x:0:0::/root:/bin/bash\n"
    ),
    "/var/log/auth.log": (
        b"Mar 14 02:14:01 web1 sshd[900]: Failed password for admin from 203.0.113.9 port 40001 ssh2\n"
        b"Mar 14 02:19:07 web1 sshd[903]: Accepted password for admin from 203.0.113.9 port 40009 ssh2\n"
    ),
    "journal/boot-0.json": (
        b'{"__REALTIME_TIMESTAMP":"1710382747000000","_COMM":"sshd",'
        b'"MESSAGE":"Accepted password for admin from 203.0.113.9 port 40009 ssh2"}\n'
    ),
    "/etc/unclaimed.conf": b"nothing parses this\n",
}


def run(tmp_path):
    bundle = build_bundle(tmp_path / "b", FILES)
    case_dir = tmp_path / "case"
    result = ingest.ingest_bundle(bundle, case_dir, examiner="Moharis")
    conn = db.open_case(case_dir / "case.db")
    stats = pipeline.parse_case(conn, case_dir, case_id="CASE-ING")
    return conn, case_dir, stats, result


def test_pipeline_produces_events_from_multiple_parsers(tmp_path):
    conn, case_dir, stats, _ = run(tmp_path)
    parsers_used = {
        r[0] for r in conn.execute("SELECT DISTINCT parser_name FROM events")
    }
    assert {"passwd_parser", "authlog_parser", "journald_parser", "env_parser"} <= parsers_used
    assert stats.events_inserted > 0
    conn.close()


def test_timezone_from_collector_manifest_is_used(tmp_path):
    conn, _, _, _ = run(tmp_path)
    row = conn.execute(
        "SELECT timestamp_tz, tz_source FROM events WHERE parser_name='authlog_parser' LIMIT 1"
    ).fetchone()
    assert row == ("Asia/Karachi", "etc_timezone")
    conn.close()


def test_host_id_matches_ingest(tmp_path):
    conn, _, _, result = run(tmp_path)
    hosts = {r[0] for r in conn.execute("SELECT DISTINCT host_id FROM events")}
    assert hosts == {result.host_id}
    conn.close()


def test_unclaimed_artifacts_recorded_as_skipped(tmp_path):
    conn, _, stats, _ = run(tmp_path)
    assert any("unclaimed.conf" in s for s in stats.skipped)
    conn.close()


def test_artifact_table_records_parse_status(tmp_path):
    conn, _, _, _ = run(tmp_path)
    rows = dict(
        conn.execute("SELECT original_path, parse_status FROM artifacts").fetchall()
    )
    assert rows["/var/log/auth.log"] == "success"
    assert rows["/etc/unclaimed.conf"] == "skip"
    conn.close()


def test_reparsing_same_case_is_idempotent(tmp_path):
    conn, case_dir, _, _ = run(tmp_path)
    before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    pipeline.parse_case(conn, case_dir, case_id="CASE-ING")
    after = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert before == after  # event_hash dedupe holds across runs
    conn.close()


def test_quarantined_files_are_not_parsed(tmp_path):
    bundle = build_bundle(tmp_path / "b", FILES, tamper={"/var/log/auth.log"})
    case_dir = tmp_path / "case"
    ingest.ingest_bundle(bundle, case_dir, examiner="M")
    conn = db.open_case(case_dir / "case.db")
    pipeline.parse_case(conn, case_dir, case_id="CASE-ING")
    n = conn.execute(
        "SELECT COUNT(*) FROM events WHERE source_artifact_path LIKE '%auth.log%'"
    ).fetchone()[0]
    assert n == 0, "an integrity-failed artifact must never reach the parsers"
    conn.close()


def test_stats_persisted_for_methodology_section(tmp_path):
    conn, _, _, _ = run(tmp_path)
    raw = db.get_meta(conn, "parser_stats")
    assert raw
    stats = json.loads(raw)
    assert stats["authlog_parser"]["success"] >= 1
    conn.close()
