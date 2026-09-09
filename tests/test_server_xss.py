"""Evidence must never be rendered as markup.

examiner comes from the X-Examiner ingest header; host_id comes from
machine_id/hostname read off the machine under investigation. Both reach
server-rendered HTML.
"""
import json
from pathlib import Path

from lfa.explorer import render_explorer_html
from lfa.server import LFAServerHandler

PAYLOAD = "<script>alert('xss')</script>"


def _case_info(**overrides):
    info = {
        "case_id": "CASE-1",
        "path": "cases/CASE-1",
        "has_db": True,
        "has_report": True,
        "report_url": "/cases/CASE-1/report.html",
        "hosts": ["host-1"],
        "examiner": "Jane Doe",
        "events_count": 10,
        "findings_count": 2,
        "high_findings": 1,
        "ingest_time": "2026-09-09T10:00:00+00:00",
    }
    info.update(overrides)
    return info


def _render_dashboard(cases):
    # _render_dashboard_html reads self.auth_token (a property backed by
    # self.server), so the fake handler needs a server object.
    handler = LFAServerHandler.__new__(LFAServerHandler)
    handler.server = type("S", (), {"auth_token": None, "server_address": ("", 8443)})()
    return LFAServerHandler._render_dashboard_html(handler, cases)


def test_dashboard_escapes_a_malicious_examiner():
    html_out = _render_dashboard([_case_info(examiner=PAYLOAD)])

    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out


def test_dashboard_escapes_a_malicious_host_id():
    html_out = _render_dashboard([_case_info(hosts=[PAYLOAD])])

    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out


def test_dashboard_escapes_a_malicious_case_id():
    html_out = _render_dashboard([_case_info(case_id=PAYLOAD)])

    assert "<script>alert" not in html_out


def test_explorer_escapes_a_malicious_examiner():
    html_out = render_explorer_html("CASE-1", _case_info(examiner=PAYLOAD))

    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out


def test_explorer_escapes_a_malicious_host_id():
    html_out = render_explorer_html("CASE-1", _case_info(hosts=[PAYLOAD]))

    assert "<script>alert" not in html_out


def test_explorer_escapes_a_malicious_case_id():
    html_out = render_explorer_html(PAYLOAD, _case_info())

    assert "<script>alert" not in html_out


def test_examiner_header_is_sanitised():
    from lfa.server import sanitise_examiner

    assert "\n" not in sanitise_examiner("Jane\nDoe")
    assert "\r" not in sanitise_examiner("Jane\rDoe")
    assert len(sanitise_examiner("A" * 500)) <= 128
    assert sanitise_examiner("") == "Remote Investigator"
    assert sanitise_examiner(None) == "Remote Investigator"
    assert sanitise_examiner("Jane Doe") == "Jane Doe"


def test_dashboard_does_not_print_the_auth_token(tmp_path):
    """The copy-paste command box rendered the live token in plaintext."""
    handler = LFAServerHandler.__new__(LFAServerHandler)
    handler.server = type(
        "S", (), {"auth_token": "super-secret-token", "server_address": ("", 8443)}
    )()

    html_out = LFAServerHandler._render_dashboard_html(handler, [])

    assert "super-secret-token" not in html_out
