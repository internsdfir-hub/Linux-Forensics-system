"""/etc/sudoers + /etc/sudoers.d/* parser (spec category 3).

sudoers is the file that answers "who can become root, and do they need a
password to do it". The findings that matter are NOPASSWD grants of ALL
(instant, silent root), Defaults !authenticate (the same thing globally),
and any full grant to a principal that is not root or a conventional admin
group. Line continuations are part of the syntax, so a parser that reads
line-by-line without joining them mis-reads real files.
"""
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.sudoers import SudoersParser
from lfa.schema import validate
from lfa.timeeng import TimeContext

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "useractivity"


@pytest.fixture
def ctx():
    return ParseContext(
        case_id="C1",
        host_id="H1",
        raw_host_dir=FIXTURES,
        time_ctx=TimeContext("Asia/Karachi", "etc_localtime"),
        distro_profile={"distro_id": "debian"},
        artifact_sha256="a" * 64,
    )


def parse(ctx, rel, path=None):
    parser = SudoersParser()
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(Path(path or (FIXTURES / rel)), ctx))
    for ev in events:
        assert validate(ev) == [], ev
    return events


def test_parser_claims_sudoers_and_sudoers_d():
    p = SudoersParser()
    assert p.can_parse("etc/sudoers", {})
    assert p.can_parse("etc/sudoers.d/90-evil", {})
    assert not p.can_parse("etc/passwd", {})


def test_all_events_are_state_findings_in_privilege_escalation(ctx):
    events = parse(ctx, "etc/sudoers")
    assert events
    for ev in events:
        assert ev.event_kind == "state_finding"
        assert ev.category == "privilege_escalation"
        assert ev.timestamp_utc is None
        assert ev.timestamp_local is None
        assert ev.timestamp_confidence == "unknown"


def test_defaults_lines_parsed(ctx):
    events = parse(ctx, "etc/sudoers")
    defaults = [e for e in events if e.subcategory == "sudo_defaults"]
    assert {"env_reset", "mail_badpass"} <= {
        d.description.split("Defaults setting: ")[-1].split(" ")[0] for d in defaults
    }
    assert all(e.severity == "info" for e in defaults)


def test_defaults_bang_authenticate_is_high(ctx):
    events = parse(ctx, "etc/sudoers")
    bang = [e for e in events if "!authenticate" in e.raw_line]
    assert len(bang) == 1
    assert bang[0].severity == "high"
    assert bang[0].subcategory == "passwordless_sudo"
    assert "without" in bang[0].description.lower() or "no password" in bang[0].description.lower()


def test_alias_definitions_captured_with_continuation_joined(ctx):
    events = parse(ctx, "etc/sudoers")
    aliases = [e for e in events if e.subcategory == "sudo_alias"]
    kinds = {e.description.split(" ")[0] for e in aliases}
    assert kinds == {"User_Alias", "Cmnd_Alias", "Host_Alias", "Runas_Alias"}
    cmnd = next(e for e in aliases if e.description.startswith("Cmnd_Alias"))
    # backslash continuation must be joined: both commands in one event
    assert "systemctl start nginx" in cmnd.description
    assert "systemctl stop nginx" in cmnd.description


def test_privilege_spec_lines_and_actor(ctx):
    events = parse(ctx, "etc/sudoers")
    specs = [e for e in events
             if e.subcategory in {"sudo_privilege", "passwordless_sudo"}
             and e.actor_user]
    actors = {e.actor_user for e in specs}
    assert {"root", "alice", "bob", "%sudo", "%wheel"} <= actors

    root = next(e for e in specs if e.actor_user == "root")
    assert root.severity == "info"
    sudo_group = next(e for e in specs if e.actor_user == "%sudo")
    assert sudo_group.severity == "info"


def test_full_grant_to_unconventional_user_is_medium(ctx):
    events = parse(ctx, "etc/sudoers")
    alice = next(e for e in events if e.actor_user == "alice")
    assert alice.subcategory == "sudo_privilege"
    assert alice.severity == "medium"
    bob = next(e for e in events if e.actor_user == "bob")
    assert bob.severity == "info"  # restricted command set, password required


def test_nopasswd_all_is_high_and_explained(ctx):
    events = parse(ctx, "etc/sudoers.d/90-evil")
    evil = next(e for e in events if e.actor_user == "eviluser")
    assert evil.subcategory == "passwordless_sudo"
    assert evil.severity == "high"
    d = evil.description.lower()
    assert "root" in d and "password" in d

    # NOPASSWD but a restricted command list is still notable, not critical
    svc = next(e for e in events if e.actor_user == "svcbackup")
    assert svc.subcategory == "passwordless_sudo"
    assert svc.severity == "medium"


def test_nopasswd_group_with_limited_commands(ctx):
    events = parse(ctx, "etc/sudoers")
    wheel = next(e for e in events if e.actor_user == "%wheel")
    assert wheel.subcategory == "passwordless_sudo"
    assert wheel.severity == "medium"
    assert "apt-get" in wheel.description


def test_includedir_emitted_so_report_shows_scope(ctx):
    events = parse(ctx, "etc/sudoers")
    inc = [e for e in events if e.subcategory == "includedir"]
    assert len(inc) == 1
    assert "/etc/sudoers.d" in inc[0].description


def test_event_hashes_unique_per_file(ctx):
    events = parse(ctx, "etc/sudoers")
    hashes = [e.event_hash for e in events]
    assert len(hashes) == len(set(hashes)), "duplicate hashes are dropped by the DB"


def test_garbage_and_binary_junk_do_not_raise(ctx, tmp_path):
    junk = tmp_path / "sudoers"
    junk.write_bytes(b"\x00\xff\xfe binary junk =\n" + b"\x80" * 400 +
                     b"\nDefaults\n= = =\nalice\n")
    events = parse(ctx, "etc/sudoers", path=junk)
    assert isinstance(events, list)


def test_empty_file_does_not_raise(ctx, tmp_path):
    empty = tmp_path / "sudoers"
    empty.write_bytes(b"")
    assert parse(ctx, "etc/sudoers", path=empty) == []
