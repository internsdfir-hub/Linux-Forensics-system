"""Report information architecture.

The reader should learn what happened before being told how the tool was
configured. Findings come before methodology, not after it.
"""
import hashlib
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


def test_host_inventory_shows_timezone_and_its_source(rendered):
    """Fix 1: Evidence must show the host inventory, not just the artifact
    table, so the timezone caveat in Appendix B can actually be evaluated."""
    assert "Asia/Karachi" in rendered
    assert "etc_timezone" in rendered


def test_artifact_table_shows_chain_of_custody_hash(rendered):
    """Fix 2: the hash at collection is the chain of custody; a pass/fail
    badge alone is not a substitute for showing it."""
    passwd_content = (
        b"root:x:0:0:root:/root:/bin/bash\n"
        b"kali:x:1000:1000::/home/kali:/bin/bash\n"
    )
    expected_prefix = hashlib.sha256(passwd_content).hexdigest()[:16]
    assert expected_prefix in rendered


def test_no_literal_html_entity_leaks_through_autoescaping(rendered):
    """Fix 3: '&mdash;' as a Jinja string literal gets double-escaped to
    '&amp;mdash;', which a browser shows as the literal text '&mdash;'.
    Entities written directly in HTML text (outside {{ }}) are unaffected
    and must keep working."""
    assert "&amp;mdash;" not in rendered
    assert "&amp;hellip;" not in rendered
    assert "&amp;middot;" not in rendered
    assert "&mdash;" in rendered  # literal markup text, e.g. in headings


def test_findings_technical_detail_shows_finding_id():
    """Fix 4: the finding id is how an examiner cross-references a finding
    against the canonical JSON/CSV exports. The fixture's minimal bundle
    does not reliably trigger a real correlation rule (most need dozens of
    events or specific conditions), so render the partial directly with a
    synthetic finding to prove the template actually emits the id."""
    from jinja2 import Environment, FileSystemLoader

    from lfa.ui import assets

    env = Environment(loader=FileSystemLoader(str(assets.TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("partials/_findings.html.j2")
    html = template.render(findings=[{
        "finding_id": "FIND-0001-TEST",
        "rule_name": "test_rule",
        "rule_version": "1.0",
        "severity": "high",
        "title": "Synthetic finding",
        "what_happened": "x", "why_it_matters": "x",
        "confidence": "High", "check_next": "x",
        "technical_detail": "x", "event_ids": [1, 2, 3],
        "first_ts_utc": None, "host_id": None,
    }])
    assert "FIND-0001-TEST" in html


def test_newly_rendered_intel_groups_are_present(rendered):
    """Fix 5: user_diffs, firewall_network and ssh_connections carry
    distinct forensic content and must be surfaced, unlike the three
    legacy/duplicate keys (logins, internet_services, network_persistence)
    that stay out."""
    assert "Account changes" in rendered
    assert "SSH connections" in rendered
    assert "Firewall and known hosts" in rendered


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
