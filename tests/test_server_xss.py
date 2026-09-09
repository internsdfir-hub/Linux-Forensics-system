"""Server-side HTML rendering of evidence-derived values must escape them.

examiner comes from the X-Examiner ingest header; host_id comes from
machine_id/hostname read off the machine under investigation. Both reach
server-rendered HTML (the dashboard and the explorer page shell), and
this file covers that rendering path only.

Out of scope, tracked separately, and NOT covered here: analyzer/lfa/
explorer.py builds inline onclick handlers using escapeHtml where
escapeJs is required, so an HTML-attribute value that is entity-decoded
before being parsed as JavaScript (e.g. &#039; becoming a live quote) can
break out of the handler client-side. That is a pre-existing client-side
XSS distinct from the server-rendering issues this file tests, and fixing
it is out of scope for this branch.
"""
import json
import re
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
    assert "&lt;script&gt;" in html_out


def test_explorer_escapes_a_malicious_examiner():
    html_out = render_explorer_html("CASE-1", _case_info(examiner=PAYLOAD))

    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out


def test_explorer_escapes_a_malicious_host_id():
    html_out = render_explorer_html("CASE-1", _case_info(hosts=[PAYLOAD]))

    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out


def test_explorer_escapes_a_malicious_case_id():
    html_out = render_explorer_html(PAYLOAD, _case_info())

    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out


def test_explorer_case_id_with_trailing_backslash_is_a_valid_js_string():
    """html.escape does not escape backslashes and is the wrong primitive for
    a <script> sink. A case_id ending in an odd number of backslashes must
    not turn the closing quote of the CASE_ID literal into an escaped quote,
    which would leave the JS string unterminated.
    """
    html_out = render_explorer_html("foo\\", _case_info())

    match = re.search(r"const CASE_ID = (.+?);", html_out)
    assert match is not None, "CASE_ID assignment not found"

    js_literal = match.group(1)
    # json.dumps output is both valid JSON and a valid JS string literal, so
    # parsing it as JSON proves the browser would see a properly terminated
    # string assignment with the exact original value.
    assert json.loads(js_literal) == "foo\\"


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
