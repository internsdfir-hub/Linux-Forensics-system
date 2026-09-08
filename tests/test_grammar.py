"""Grammar engine (spec 2.6.3): text-log patterns live in YAML files -
new distro or format drift means a new config file, not new code."""
from pathlib import Path

from lfa.parsers.grammar import GrammarEngine

GRAMMAR_DIR = Path(__file__).resolve().parent.parent / "config" / "grammars"


def engine():
    return GrammarEngine.load(GRAMMAR_DIR, distro_id="debian")


def test_loads_common_plus_distro_rules():
    eng = engine()
    assert "sshd_failed_password" in eng.rules
    assert eng.rules["sshd_failed_password"]["category"] == "login_activity"


def test_matches_failed_password_with_groups():
    eng = engine()
    line = ("Mar 14 02:19:07 web1 sshd[1234]: Failed password for admin "
            "from 203.0.113.9 port 40001 ssh2")
    matches = eng.match_line(line)
    assert len(matches) == 1
    name, rule, groups = matches[0]
    assert name == "sshd_failed_password"
    assert groups["user"] == "admin"
    assert groups["ip"] == "203.0.113.9"
    assert rule["subcategory"] == "failed_login"
    assert rule["severity"] == "low"


def test_matches_invalid_user_variant():
    eng = engine()
    line = ("Mar 14 02:19:07 web1 sshd[1234]: Failed password for invalid "
            "user oracle from 203.0.113.9 port 40001 ssh2")
    matches = eng.match_line(line)
    assert matches and matches[0][2]["user"] == "oracle"


def test_matches_accepted_publickey():
    eng = engine()
    line = ("Mar 14 09:00:00 web1 sshd[999]: Accepted publickey for alice "
            "from 10.0.0.5 port 51234 ssh2: ED25519 SHA256:abcdef")
    matches = eng.match_line(line)
    names = [m[0] for m in matches]
    assert "sshd_accepted" in names
    _, rule, groups = matches[names.index("sshd_accepted")]
    assert groups["user"] == "alice"
    assert groups["method"] == "publickey"


def test_matches_sudo_command_with_all_fields():
    eng = engine()
    line = ("Mar 14 10:00:00 web1 sudo:    alice : TTY=pts/0 ; "
            "PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt install nc")
    matches = eng.match_line(line)
    names = [m[0] for m in matches]
    assert "sudo_command" in names
    _, rule, groups = matches[names.index("sudo_command")]
    assert groups["user"] == "alice"
    assert groups["command"] == "/usr/bin/apt install nc"
    assert rule["category"] == "privilege_escalation"


def test_matches_useradd_and_group_add():
    eng = engine()
    ua = ("Mar 14 10:05:00 web1 useradd[9001]: new user: name=eviluser, "
          "UID=1004, GID=1004, home=/home/eviluser, shell=/bin/bash")
    m1 = eng.match_line(ua)
    assert any(n == "useradd_new_user" for n, _, _ in m1)
    groups = next(g for n, _, g in m1 if n == "useradd_new_user")
    assert groups["user"] == "eviluser"
    assert groups["uid"] == "1004"

    um = "Mar 14 10:07:00 web1 usermod[9010]: add 'eviluser' to group 'sudo'"
    m2 = eng.match_line(um)
    assert any(n == "usermod_group_add" for n, _, _ in m2)


def test_non_matching_line_returns_empty():
    eng = engine()
    assert eng.match_line("Mar 14 02:19:07 web1 kernel: random noise") == []


def test_every_rule_declares_required_metadata():
    eng = engine()
    for name, rule in eng.rules.items():
        assert rule["category"], name
        assert rule["subcategory"], name
        assert rule["severity"] in {"info", "low", "medium", "high"}, name


def test_logind_username_is_unquoted(tmp_path):
    """systemd-logind wraps names in single quotes; actor_user must not."""
    from lfa.parsers.authlog import GRAMMAR_DIR
    from lfa.parsers.grammar import GrammarEngine

    engine = GrammarEngine.load(GRAMMAR_DIR, "debian")
    line = (
        "systemd-logind[712]: New session 'c1' of user 'kali' "
        "with class 'user' and type 'tty'."
    )

    matches = engine.match_line(line)
    users = [g.get("user") for _, _, g in matches if "user" in g]

    assert users, "expected the logind rule to match"
    assert all(u == "kali" for u in users), users


def test_unquoted_usernames_are_left_alone(tmp_path):
    from lfa.parsers.authlog import GRAMMAR_DIR
    from lfa.parsers.grammar import GrammarEngine

    engine = GrammarEngine.load(GRAMMAR_DIR, "debian")
    line = "sshd[123]: Failed password for admin from 203.0.113.9 port 22"

    matches = engine.match_line(line)
    users = [g.get("user") for _, _, g in matches if "user" in g]

    assert users == ["admin"]


def test_apostrophe_inside_a_name_is_preserved():
    """Only a matched surrounding pair is stripped, never an inner quote."""
    from lfa.parsers.grammar import GrammarEngine

    engine = GrammarEngine({
        "probe": {
            "pattern": r"user (?P<user>\S+)",
            "category": "login_activity",
            "subcategory": "successful_login",
            "severity": "info",
        }
    })

    assert engine.match_line("user o'brien")[0][2]["user"] == "o'brien"
    assert engine.match_line("user 'o'brien'")[0][2]["user"] == "o'brien"


def test_non_identifier_groups_are_not_normalised():
    """Only user-ish groups are touched; `session` keeps its quotes."""
    from lfa.parsers.grammar import GrammarEngine

    engine = GrammarEngine({
        "probe": {
            "pattern": r"session (?P<session>\S+) of user (?P<user>\S+)",
            "category": "login_activity",
            "subcategory": "session_opened",
            "severity": "info",
        }
    })

    groups = engine.match_line("session 'c1' of user 'kali'")[0][2]

    assert groups["user"] == "kali"
    assert groups["session"] == "'c1'"
