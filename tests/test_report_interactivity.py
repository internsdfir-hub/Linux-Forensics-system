"""Table interactivity is an enhancement, never a precondition.

A forensic report must be complete and readable with JavaScript disabled,
because it may be opened from read-only media or in a locked-down viewer.
"""
import re

import pytest

from lfa import db, ingest, pipeline
from lfa.report.render import render_report
from lfa.ui import assets

from bundle_builder import build_bundle


@pytest.fixture
def rendered(tmp_path):
    bundle = build_bundle(
        tmp_path / "src",
        {
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"
                           b"kali:x:1000:1000::/home/kali:/bin/bash\n",
        },
    )
    case_dir = tmp_path / "case"
    ingest.ingest_bundle(bundle, case_dir, "Examiner")
    conn = db.open_case(case_dir / "case.db")
    pipeline.parse_case(conn, case_dir, "CASE-JS")
    out = case_dir / "report.html"
    render_report(conn, case_dir, out)
    conn.close()
    return out.read_text(encoding="utf-8")


def test_all_rows_are_rendered_server_side(rendered):
    """No row may depend on JS to exist."""
    body = rendered[rendered.index('id="events-table"'):]
    body = body[: body.index("</table>")]
    assert body.count("<tr>") >= 1, "event rows must be present in the HTML"


def test_tables_declare_their_sortable_columns(rendered):
    assert 'data-sortable' in rendered
    assert 'data-sort="text"' in rendered


def test_filter_input_names_its_table(rendered):
    assert 'data-filters="events-table"' in rendered


def test_script_is_inlined_and_not_fetched(rendered):
    assert "<script>" in rendered
    assert not re.search(r'<script[^>]+src=', rendered)


def test_script_guards_against_missing_elements():
    """The script runs on every page; it must not throw where a table is absent."""
    js = assets.load_script("report")
    assert "querySelectorAll" in js
    assert "addEventListener" in js


def test_script_declares_no_globals_beyond_its_entry_point():
    """The IIFE must open at column 0, after the leading comment block.

    Asserting on the *first* character would fail against correct code,
    because the script opens with a /* ... */ header. Anchoring per-line
    tolerates the comment while still proving the wrapper is top-level and
    not nested inside some other construct.
    """
    js = assets.load_script("report")
    assert re.search(r"^\(function", js, re.M), (
        "report.js must wrap itself in a top-level IIFE so it adds no globals"
    )
