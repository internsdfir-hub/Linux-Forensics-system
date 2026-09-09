"""Report information architecture.

The reader should learn what happened before being told how the tool was
configured. Findings come before methodology, not after it.
"""
import re

import pytest

from lfa import db, ingest, pipeline
from lfa.report.render import render_report

from bundle_builder import build_bundle


@pytest.fixture
def rendered(tmp_path):
    bundle = build_bundle(
        tmp_path / "src",
        {
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"
                           b"kali:x:1000:1000::/home/kali:/bin/bash\n",
            "/etc/os-release": b'ID=debian\nVERSION_ID="12"\n',
        },
    )
    case_dir = tmp_path / "case"
    ingest.ingest_bundle(bundle, case_dir, "Test Examiner")
    conn = db.open_case(case_dir / "case.db")
    db.set_case_meta(conn, "case_id", "CASE-IA")
    db.set_case_meta(conn, "examiner", "Test Examiner")
    pipeline.parse_case(conn, case_dir, "CASE-IA")
    out = case_dir / "report.html"
    render_report(conn, case_dir, out)
    conn.close()
    return out.read_text(encoding="utf-8")


EXPECTED_ORDER = [
    "sec-summary",
    "sec-findings",
    "sec-timeline",
    "sec-evidence",
    "sec-intel",
    "app-methodology",
    "app-undetermined",
    "app-glossary",
]


def test_all_sections_present(rendered):
    for section in EXPECTED_ORDER:
        assert f'id="{section}"' in rendered, f"missing section {section}"


def test_sections_appear_in_reader_first_order(rendered):
    positions = [rendered.index(f'id="{s}"') for s in EXPECTED_ORDER]
    assert positions == sorted(positions), "sections are out of order"


def test_findings_come_before_methodology(rendered):
    assert rendered.index('id="sec-findings"') < rendered.index('id="app-methodology"')


def test_authorisation_is_in_the_header_not_a_numbered_section(rendered):
    assert 'id="sec-auth"' not in rendered
    assert "Examiner" in rendered
    assert "Test Examiner" in rendered


def test_report_is_self_contained(rendered):
    """No remote fetches: the report must work from a USB stick, offline."""
    remote = re.findall(r'(?:src|href)\s*=\s*["\'](https?://[^"\']+)', rendered)
    assert not remote, f"report must not reference remote resources: {remote}"


def test_report_inlines_its_own_styles_and_script(rendered):
    assert "<style>" in rendered
    # The full token stack arrives in Task 6; at this point base.css is what
    # render.py loads, so assert on that rather than on tokens.css.
    assert "base.css" in rendered, "expected the stylesheet to be inlined"
    assert "<script>" in rendered


def test_all_four_charts_are_present(rendered):
    assert rendered.count("<svg") >= 4, (
        "expected severity, density, failures and user-activity charts"
    )


def test_evidence_derived_values_stay_escaped(tmp_path):
    """Regression guard: the hardening branch established this and it holds."""
    bundle = build_bundle(
        tmp_path / "src2",
        {"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"},
        hostname="<script>alert(1)</script>",
    )
    case_dir = tmp_path / "case2"
    ingest.ingest_bundle(bundle, case_dir, "<script>alert(2)</script>")
    conn = db.open_case(case_dir / "case.db")
    pipeline.parse_case(conn, case_dir, "CASE-ESC")
    out = case_dir / "report.html"
    render_report(conn, case_dir, out)
    conn.close()

    html = out.read_text(encoding="utf-8")
    assert "<script>alert(1)" not in html
    assert "<script>alert(2)" not in html
