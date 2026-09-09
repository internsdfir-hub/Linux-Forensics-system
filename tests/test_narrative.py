"""The executive summary is structured data, not Markdown.

The template renders it with autoescape on, so a finding title containing
markup or an asterisk cannot reach the page as either.
"""
from lfa.report.narrative import generate_executive_summary


def _summary(high=0, medium=0, low=0, events=1000, findings=0):
    return {
        "case_id": "CASE-205",
        "event_count": events,
        "finding_count": findings,
        "severity_counts": {"high": high, "medium": medium, "low": low, "info": 0},
    }


def _finding(severity="high", title="Brute force succeeded", check_next="Reset it."):
    return {
        "severity": severity,
        "title": title,
        "what_happened": "Someone guessed the password.",
        "why_it_matters": "The account is under someone else's control.",
        "check_next": check_next,
    }


def test_returns_structured_data_not_a_string():
    result = generate_executive_summary(_summary(), [])
    assert isinstance(result, dict)
    assert set(result) == {"headline", "key_observations", "recommended_actions"}


def test_no_field_contains_markdown_emphasis():
    result = generate_executive_summary(
        _summary(high=2, medium=4, findings=6), [_finding()]
    )
    blob = repr(result)
    assert "**" not in blob, "narrative must not emit Markdown"


def test_headline_reflects_high_severity():
    result = generate_executive_summary(_summary(high=2, medium=4, findings=6), [])
    assert "2" in result["headline"]
    assert "CASE-205" in result["headline"]


def test_headline_when_nothing_was_found():
    result = generate_executive_summary(_summary(events=1234), [])
    assert "no" in result["headline"].lower()
    assert "1,234" in result["headline"]


def test_key_observations_are_high_severity_only_and_capped():
    findings = [_finding(title=f"Finding {i}") for i in range(8)]
    findings += [_finding(severity="low", title="Ignore me")]
    result = generate_executive_summary(_summary(high=8, findings=9), findings)
    assert len(result["key_observations"]) == 5
    assert all("Ignore me" != o["title"] for o in result["key_observations"])
    assert result["key_observations"][0]["title"] == "Finding 0"


def test_recommended_actions_are_deduplicated_and_capped():
    findings = [_finding(check_next="Reset the password for 'kali'.") for _ in range(3)]
    findings += [_finding(check_next="Revoke the SSH key.")]
    result = generate_executive_summary(_summary(high=4, findings=4), findings)
    assert result["recommended_actions"] == [
        "Reset the password for 'kali'.",
        "Revoke the SSH key.",
    ]


def test_low_severity_findings_do_not_contribute_actions():
    findings = [_finding(severity="low", check_next="Probably nothing.")]
    result = generate_executive_summary(_summary(low=1, findings=1), findings)
    assert result["recommended_actions"] == []


def test_rendered_report_contains_no_markdown_asterisks(tmp_path):
    """End to end: the defect was visible as ** in real generated reports."""
    from lfa import db, ingest, pipeline
    from lfa.report.render import render_report

    from bundle_builder import build_bundle

    bundle = build_bundle(
        tmp_path / "src",
        {
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n",
            "/etc/os-release": b'ID=debian\nVERSION_ID="12"\n',
        },
    )
    case_dir = tmp_path / "case"
    ingest.ingest_bundle(bundle, case_dir, "Examiner")
    conn = db.open_case(case_dir / "case.db")
    db.set_case_meta(conn, "case_id", "CASE-MD")
    pipeline.parse_case(conn, case_dir, "CASE-MD")

    out = case_dir / "report.html"
    render_report(conn, case_dir, out)
    conn.close()

    html = out.read_text(encoding="utf-8")
    assert "**" not in html, "Markdown emphasis leaked into the rendered report"
