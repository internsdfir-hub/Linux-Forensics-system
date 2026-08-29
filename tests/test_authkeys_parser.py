"""authorized_keys parser (spec category 4): the single most durable
backdoor on a Linux box - one line in a file nobody reads gives passwordless
root forever. Fingerprints are the SHA256 form ssh-keygen -lf prints."""
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lfa.parsers.authkeys import AuthKeysParser
from lfa.parsers.base import ParseContext
from lfa.schema import validate
from lfa.timeeng import TimeContext

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "persistence"
MTIME = datetime(2024, 3, 14, 2, 45, 30, tzinfo=timezone.utc).timestamp()


def fingerprint_of(blob_b64: str) -> str:
    digest = hashlib.sha256(base64.b64decode(blob_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


@pytest.fixture
def ctx(tmp_path):
    return ParseContext(
        case_id="C1",
        host_id="H1",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("Asia/Karachi", "etc_localtime"),
        distro_profile={"distro_id": "debian"},
        artifact_sha256="a" * 64,
        artifact_mtime=MTIME,
    )


def parse(ctx, rel, root=FIXTURES):
    parser = AuthKeysParser()
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(Path(root) / rel, ctx))
    for ev in events:
        assert validate(ev) == [], ev
        assert ev.category == "persistence"
        assert ev.event_kind == "state_finding"
        assert ev.timestamp_utc is None and ev.timestamp_confidence == "unknown"
    return events


def test_claims_all_authorized_keys_paths():
    parser = AuthKeysParser()
    for rel in ("home/alice/.ssh/authorized_keys",
                "home/alice/.ssh/authorized_keys2",
                "root/.ssh/authorized_keys"):
        assert parser.can_parse(rel, {}), rel
    assert not parser.can_parse("home/alice/.ssh/known_hosts", {})


def test_one_event_per_key_with_user_from_path(ctx):
    events = parse(ctx, "home/alice/.ssh/authorized_keys")
    keys = [e for e in events if e.subcategory == "authorized_key"]
    assert len(keys) == 4
    assert {e.actor_user for e in keys} == {"alice"}
    types = [e.description.split()[0] for e in keys]
    assert types == ["ssh-ed25519", "ssh-rsa", "ssh-rsa", "ecdsa-sha2-nistp256"]


def test_fingerprint_matches_ssh_keygen_form(ctx):
    events = parse(ctx, "home/alice/.ssh/authorized_keys")
    first = events[0]
    blob = (FIXTURES / "home/alice/.ssh/authorized_keys").read_text().splitlines()[1].split()[1]
    expected = fingerprint_of(blob)
    assert expected in first.description
    assert first.description.count("SHA256:") == 1
    assert "alice@laptop" in first.description


def test_forced_command_key_is_medium_with_options_recorded(ctx):
    events = parse(ctx, "home/alice/.ssh/authorized_keys")
    forced = next(e for e in events if "rrsync" in e.description)
    assert forced.severity == "medium"
    assert 'command="/usr/local/bin/rrsync -ro /srv/backup"' in forced.description
    assert 'from="10.0.5.7"' in forced.description
    assert "no-pty" in forced.description
    assert "backup@nas" in forced.description


def test_plain_keys_are_info(ctx):
    events = parse(ctx, "home/alice/.ssh/authorized_keys")
    plain = [e for e in events if e.subcategory == "authorized_key"
             and "rrsync" not in e.description]
    assert plain and all(e.severity == "info" for e in plain)


def test_root_key_file(ctx):
    events = parse(ctx, "root/.ssh/authorized_keys")
    keys = [e for e in events if e.subcategory == "authorized_key"]
    assert len(keys) == 2
    assert {e.actor_user for e in keys} == {"root"}
    assert any("webmaster@srv2" in e.description for e in keys)


def test_mtime_in_description_and_notes(ctx):
    events = parse(ctx, "root/.ssh/authorized_keys")
    for ev in events:
        assert "2024-03-14T02:45:30+00:00" in ev.description
        assert ev.notes == f"file_mtime_epoch={int(MTIME)}"


def test_undecodable_key_line_is_reported_not_dropped(ctx):
    events = parse(ctx, "home/alice/.ssh/authorized_keys")
    odd = [e for e in events if e.subcategory == "unparsable_key_line"]
    assert len(odd) == 1
    assert odd[0].severity == "low"
    assert "nobody@nowhere" in odd[0].raw_line


def test_binary_and_truncated_input_does_not_raise(ctx, tmp_path):
    d = tmp_path / "home/bob/.ssh"
    d.mkdir(parents=True)
    (d / "authorized_keys").write_bytes(
        b"\x00\x01\xff\xfe\n"
        b"ssh-rsa\n"                      # type with no blob
        b"ssh-ed25519 !!!!notbase64!!!! x\n"
        b"command=\"unterminated ssh-rsa AAAAB3NzaC1yc2E= who\n"
    )
    events = parse(ctx, "home/bob/.ssh/authorized_keys", root=tmp_path)
    assert isinstance(events, list)
    assert all(e.actor_user == "bob" for e in events)


def test_empty_file_yields_nothing(ctx, tmp_path):
    d = tmp_path / "root/.ssh"
    d.mkdir(parents=True)
    (d / "authorized_keys").write_bytes(b"\n\n# only a comment\n")
    assert parse(ctx, "root/.ssh/authorized_keys", root=tmp_path) == []
