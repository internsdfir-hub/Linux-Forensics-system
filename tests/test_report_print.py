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


def _sheet(rendered, name):
    """The inlined text of one stylesheet, sliced on assets.load_styles' banner.

    Slicing on a bare "print.css" is wrong: the string can appear in a comment
    inside an EARLIER sheet, which silently widens the slice so a rule found in
    report.css would satisfy an assertion about print.css. The banner cannot.
    """
    start = rendered.index(f"/* --- {name}.css --- */")
    nxt = rendered.find("/* --- ", start + 1)
    return rendered[start:nxt if nxt != -1 else len(rendered)]


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
    print_block = _sheet(rendered, "print")
    assert "break-inside: avoid" in print_block


def test_interactive_affordances_are_hidden_in_print(rendered):
    print_block = _sheet(rendered, "print")
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


# --- Print honesty (found in Task 8's inspection) ---------------------------
#
# print.css caps the event table at 60 rows so the report does not print 1,500
# rows of table. But the prose above the table says "Showing up to 1500
# normalised events", and that sentence prints unchanged - so a printed
# forensic report told the reader it contained 25x more evidence than it did.

def test_printed_row_cap_is_disclosed_on_paper(rendered):
    assert "print-only" in rendered, "the print-only disclosure must be rendered"


def test_the_disclosed_cap_matches_the_cap_print_css_actually_applies(rendered):
    """The number in the prose and the number in the CSS must not drift apart."""
    rule = re.search(
        r"#events-table tbody tr:nth-child\(n \+ (\d+)\)", rendered
    )
    assert rule, "print.css must cap the event table"
    cap = int(rule.group(1)) - 1
    assert f"first {cap} rows" in rendered, (
        f"print.css hides rows past {cap}, but the prose does not say so"
    )


def test_the_print_only_note_is_hidden_on_screen(rendered):
    assert ".print-only" in _sheet(rendered, "report"), (
        "report.css must hide it on screen"
    )


def test_the_print_only_note_is_revealed_in_print(rendered):
    assert ".print-only" in _sheet(rendered, "print"), (
        "print.css must reveal it on paper"
    )
