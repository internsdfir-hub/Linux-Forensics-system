"""Print is a first-class output for this report.

Forensic reports get printed, converted to PDF, and attached to case files.
A dark screen theme with no page rules is not acceptable for that.
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
        {"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"},
    )
    case_dir = tmp_path / "case"
    ingest.ingest_bundle(bundle, case_dir, "Examiner")
    conn = db.open_case(case_dir / "case.db")
    pipeline.parse_case(conn, case_dir, "CASE-PRINT")
    out = case_dir / "report.html"
    render_report(conn, case_dir, out)
    conn.close()
    return out.read_text(encoding="utf-8")


def test_print_stylesheet_is_inlined(rendered):
    assert "print.css" in rendered


def test_page_rules_are_present(rendered):
    assert "@page" in rendered
    assert "@media print" in rendered


def test_findings_do_not_split_across_pages(rendered):
    print_block = rendered[rendered.index("print.css"):]
    assert "break-inside: avoid" in print_block


def test_interactive_affordances_are_hidden_in_print(rendered):
    print_block = rendered[rendered.index("print.css"):]
    assert ".table-tools" in print_block
    assert ".skip-link" in print_block


def test_document_theme_is_inlined_not_the_console_theme(rendered):
    assert "theme-document.css" in rendered
    assert "theme-console.css" not in rendered


def test_stylesheets_load_in_cascade_order(rendered):
    order = ["tokens.css", "theme-document.css", "base.css", "report.css", "print.css"]
    positions = [rendered.index(name) for name in order]
    assert positions == sorted(positions), "stylesheets must load tokens-first"


def test_base_stylesheet_has_no_raw_colour_literals():
    """The Task 2 exemption expires here."""
    text = (assets.STYLE_DIR / "base.css").read_text(encoding="utf-8")
    body = "\n".join(
        line for line in text.splitlines()
        if not line.strip().startswith(("/*", "*"))
    )
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|\brgba?\s*\(", body), (
        "base.css must reference tokens, not hardcode colour"
    )
