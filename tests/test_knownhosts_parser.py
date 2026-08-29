"""~/.ssh/known_hosts parser (spec category 8).

known_hosts is OUTBOUND evidence: every entry is a host this user's account
connected TO and accepted a key from. Entries may be hashed (|1|salt|hash),
in which case the hostname is genuinely NOT recoverable - the parser must
say so rather than present a hash as if it were a hostname.
"""
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.knownhosts import KnownHostsParser
from lfa.schema import validate
from lfa.timeeng import TimeContext

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "useractivity"
KH = "home/alice/.ssh/known_hosts"


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
    parser = KnownHostsParser()
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(Path(path or (FIXTURES / rel)), ctx))
    for ev in events:
        assert validate(ev) == [], ev
    return events


def test_parser_claims_known_hosts_paths():
    p = KnownHostsParser()
    assert p.can_parse("home/alice/.ssh/known_hosts", {})
    assert p.can_parse("root/.ssh/known_hosts", {})
    assert p.can_parse("home/alice/.ssh/known_hosts2", {})
    assert not p.can_parse("home/alice/.ssh/authorized_keys", {})


def test_entries_are_state_findings_for_the_owning_user(ctx):
    events = parse(ctx, KH)
    assert len(events) == 6  # comment line excluded
    for ev in events:
        assert ev.event_kind == "state_finding"
        assert ev.category == "user_activity"
        assert ev.timestamp_utc is None
        assert ev.timestamp_confidence == "unknown"
        assert ev.actor_user == "alice"
        assert "connected out to" in ev.description.lower() or \
               "connected to" in ev.description.lower()


def test_hostname_and_keytype_extracted(ctx):
    events = parse(ctx, KH)
    gh = next(e for e in events if "github.com" in e.description)
    assert gh.subcategory == "known_host"
    assert gh.source_host == "github.com"
    assert gh.source_ip is None
    assert "ssh-rsa" in gh.description
    # the second comma-separated name is kept in the description
    assert "140.82.121.4" in gh.description


def test_bracketed_host_with_nonstandard_port(ctx):
    events = parse(ctx, KH)
    jump = next(e for e in events if "10.0.0.7" in e.description)
    assert jump.source_ip == "10.0.0.7"
    assert jump.source_host is None
    assert "2222" in jump.description


def test_plain_ip_entry_goes_to_source_ip(ctx):
    events = parse(ctx, KH)
    ip = next(e for e in events if e.source_ip == "203.0.113.9")
    assert ip.subcategory == "known_host"
    assert ip.source_host is None


def test_hashed_entry_is_labelled_not_faked(ctx):
    events = parse(ctx, KH)
    hashed = [e for e in events if e.subcategory == "known_host_hashed"]
    assert len(hashed) == 1
    h = hashed[0]
    assert h.source_host is None and h.source_ip is None
    assert "not recoverable" in h.description.lower()
    assert "|1|" in h.raw_line


def test_markers_recorded(ctx):
    events = parse(ctx, KH)
    ca = next(e for e in events if "example.com" in e.description)
    assert "@cert-authority" in ca.description
    rev = next(e for e in events if "badhost.example.net" in e.description)
    assert "@revoked" in rev.description


def test_actor_user_from_root_path(ctx, tmp_path):
    p = tmp_path / "known_hosts"
    p.write_text("srv1.local ssh-ed25519 AAAAC3NzaC1lZDI1NTE5key\n",
                 encoding="utf-8")
    ev = parse(ctx, "root/.ssh/known_hosts", path=p)[0]
    assert ev.actor_user == "root"


def test_malformed_and_binary_junk_do_not_raise(ctx, tmp_path):
    p = tmp_path / "known_hosts"
    p.write_bytes(b"\x00\xff\xfe\x80\n onlyonetoken\n\n#comment\n"
                  b"host ssh-rsa AAAAkey extra comment fields here\n")
    events = parse(ctx, KH, path=p)
    assert any(e.source_host == "host" for e in events)


def test_empty_file_yields_nothing(ctx, tmp_path):
    p = tmp_path / "known_hosts"
    p.write_bytes(b"")
    assert parse(ctx, KH, path=p) == []
