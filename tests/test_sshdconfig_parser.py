"""Unit tests for the sshd_config risk parser.

The parser exists to feed SshdConfigRule (previously a dead rule: the
collector gathered /etc/ssh/sshd_config but no parser turned it into the
'sshd_setting' events the rule queries for).
"""
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.sshdconfig import SshdConfigParser
from lfa.schema import validate
from lfa.timeeng import TimeContext


@pytest.fixture
def ctx(tmp_path):
    return ParseContext(
        case_id="CASE-01",
        host_id="HOST-01",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("UTC", "assumed_utc"),
        distro_profile={"distro_id": "ubuntu"},
        artifact_sha256="0" * 64,
        artifact_mtime=1700000000.0,
    )


def _parse(parser, tmp_path, ctx, text, rel="etc/ssh/sshd_config"):
    f = tmp_path / "sshd_config"
    f.write_text(text, encoding="utf-8")
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    return list(parser.parse(f, ctx))


def test_permit_root_login_yes_is_flagged(tmp_path, ctx):
    events = _parse(SshdConfigParser(), tmp_path, ctx,
                    "Protocol 2\nPermitRootLogin yes\n")
    assert len(events) == 1
    ev = events[0]
    assert validate(ev) == []
    assert ev.subcategory == "sshd_setting"
    assert ev.category == "persistence"
    assert ev.severity == "high"
    assert "PermitRootLogin" in ev.description


def test_safe_settings_emit_nothing(tmp_path, ctx):
    # PermitRootLogin no / prohibit-password and commented lines must not fire
    events = _parse(SshdConfigParser(), tmp_path, ctx,
                    "PermitRootLogin no\n"
                    "PermitRootLogin prohibit-password\n"
                    "#PasswordAuthentication yes\n"
                    "PermitEmptyPasswords no\n")
    assert events == []


def test_permit_empty_passwords_yes_is_flagged_distinctly(tmp_path, ctx):
    events = _parse(SshdConfigParser(), tmp_path, ctx,
                    "PermitEmptyPasswords yes\n")
    assert len(events) == 1
    ev = events[0]
    assert ev.subcategory == "sshd_setting"
    assert ev.severity == "high"
    # description must name the actual setting, not root login
    assert "PermitEmptyPasswords" in ev.description
    assert "PermitRootLogin" not in ev.description


def test_password_authentication_yes_is_medium(tmp_path, ctx):
    events = _parse(SshdConfigParser(), tmp_path, ctx,
                    "PasswordAuthentication yes\n")
    assert len(events) == 1
    assert events[0].severity == "medium"
    assert "PasswordAuthentication" in events[0].description


def test_case_and_whitespace_insensitive(tmp_path, ctx):
    events = _parse(SshdConfigParser(), tmp_path, ctx,
                    "   permitrootlogin    YES  \n")
    assert len(events) == 1
    assert events[0].severity == "high"
