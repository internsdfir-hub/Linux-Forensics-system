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


def test_crashed_parser_is_recorded_as_fail(tmp_path, monkeypatch):
    """A parser that raises must not be recorded as a successful parse."""
    from lfa import db, pipeline
    from lfa.parsers.base import BaseParser

    from bundle_builder import build_bundle

    class ExplodingParser(BaseParser):
        name = "exploding_parser"
        version = "1.0"
        artifact_category = "user_accounts"
        applies_to = ["etc/passwd"]

        def parse(self, path, context):
            raise RuntimeError("boom")
            yield  # pragma: no cover - makes this a generator

    monkeypatch.setattr(
        pipeline, "discover_parsers", lambda: [ExplodingParser()]
    )

    bundle = build_bundle(
        tmp_path / "src",
        {"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"},
    )
    case_dir = tmp_path / "case"

    from lfa import ingest
    ingest.ingest_bundle(bundle, case_dir, "Examiner")

    conn = db.open_case(case_dir / "case.db")
    pipeline.parse_case(conn, case_dir, "CASE-FAIL")

    row = conn.execute(
        "SELECT parse_status, parse_events FROM artifacts "
        "WHERE original_path = '/etc/passwd'"
    ).fetchone()
    conn.close()

    assert row is not None, "artifact row was not recorded at all"
    assert row[0] == "fail", f"expected parse_status='fail', got {row[0]!r}"
    assert row[1] == 0


def test_successful_parser_is_still_recorded_as_success(tmp_path, monkeypatch):
    from lfa import db, ingest, pipeline
    from lfa.parsers.base import BaseParser

    from bundle_builder import build_bundle

    class WorkingParser(BaseParser):
        name = "working_parser"
        version = "1.0"
        artifact_category = "user_accounts"
        applies_to = ["etc/passwd"]

        def parse(self, path, context):
            yield context.build_event(
                event_kind="event",
                timestamp_utc="2024-03-14T02:19:07+00:00",
                timestamp_local="2024-03-14T02:19:07+00:00",
                timestamp_confidence="exact",
                category="user_accounts",
                subcategory="account",
                actor_user="root",
                description="root account present",
                severity="info",
                raw_line="root:x:0:0:root:/root:/bin/bash",
                raw_line_offset=0,
            )

    monkeypatch.setattr(pipeline, "discover_parsers", lambda: [WorkingParser()])

    bundle = build_bundle(
        tmp_path / "src",
        {"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"},
    )
    case_dir = tmp_path / "case"
    ingest.ingest_bundle(bundle, case_dir, "Examiner")

    conn = db.open_case(case_dir / "case.db")
    pipeline.parse_case(conn, case_dir, "CASE-OK")

    row = conn.execute(
        "SELECT parse_status, parse_events FROM artifacts "
        "WHERE original_path = '/etc/passwd'"
    ).fetchone()
    conn.close()

    assert row[0] == "success"
    assert row[1] == 1
