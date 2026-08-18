"""passwd/shadow/group parser: accounts, password states (days-since-epoch
trap #10), group memberships, and the free recent-change diff from the
backup files (spec 1.4 category 1)."""
import shutil
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.passwd import PasswdParser
from lfa.schema import validate
from lfa.timeeng import TimeContext

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "identity"


@pytest.fixture
def ctx(tmp_path):
    # mirror fixtures into a raw-host layout so the backup-diff can find
    # its sibling files
    files_dir = tmp_path / "collected/files/etc"
    files_dir.mkdir(parents=True)
    for name in ("passwd", "passwd-", "shadow", "group", "group-"):
        shutil.copy(FIXTURES / name, files_dir / name)
    return ParseContext(
        case_id="C1",
        host_id="H1",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("Asia/Karachi", "etc_localtime"),
        distro_profile={"distro_id": "debian"},
        artifact_sha256="a" * 64,
    )


def parse(ctx, rel):
    parser = PasswdParser()
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    path = ctx.raw_host_dir / "collected/files" / rel
    events = list(parser.parse(path, ctx))
    for ev in events:
        assert validate(ev) == [], ev
    return events


def test_passwd_accounts_enumerated(ctx):
    events = parse(ctx, "etc/passwd")
    accounts = [e for e in events if e.subcategory == "account"]
    assert len(accounts) == 5
    root = next(e for e in accounts if e.actor_user == "root")
    assert root.actor_uid == 0
    assert root.event_kind == "state_finding"


def test_uid0_nonroot_flagged_high(ctx):
    events = parse(ctx, "etc/passwd")
    uid0 = [e for e in events if e.subcategory == "uid0_account" and
            e.actor_user != "root"]
    assert len(uid0) == 1
    assert uid0[0].actor_user == "toor"
    assert uid0[0].severity == "high"


def test_shadow_password_states_and_days_epoch(ctx):
    events = parse(ctx, "etc/shadow")
    empty = [e for e in events if e.subcategory == "passwordless_account"]
    assert [e.actor_user for e in empty] == ["eviluser"]
    assert empty[0].severity == "high"

    locked = {e.actor_user for e in events if e.subcategory == "locked_account"}
    assert locked == {"locked", "starred"}

    # trap #10: last-changed is DAYS since epoch. 19750 days = 2024-01-28
    root_state = next(e for e in events if e.actor_user == "root"
                      and e.subcategory == "password_state")
    assert "2024-01-28" in root_state.description


def test_group_memberships_emitted(ctx):
    events = parse(ctx, "etc/group")
    sudo = next(e for e in events if e.subcategory == "group_membership"
                and "sudo" in e.description and e.actor_user == "eviluser")
    assert sudo is not None
    docker = [e for e in events if e.subcategory == "privileged_group_member"
              and "docker" in e.description]
    assert docker, "docker group membership must be flagged (docker ~ root)"


def test_backup_diff_reveals_recent_changes(ctx):
    events = parse(ctx, "etc/passwd-")
    added = {e.actor_user for e in events if e.subcategory == "account_added_since_backup"}
    removed = {e.actor_user for e in events if e.subcategory == "account_removed_since_backup"}
    assert added == {"eviluser", "toor"}
    assert removed == {"bob"}
    for e in events:
        if e.subcategory == "account_added_since_backup":
            assert e.severity == "medium"


def test_group_backup_diff(ctx):
    events = parse(ctx, "etc/group-")
    added = [e for e in events if e.subcategory == "group_member_added_since_backup"]
    assert len(added) == 1
    assert added[0].actor_user == "eviluser"
    assert "sudo" in added[0].description


def test_malformed_lines_do_not_crash(ctx, tmp_path):
    bad = tmp_path / "collected/files/etc/passwd"
    bad.write_text("root:x:0:0:root:/root:/bin/bash\nGARBAGE LINE\n::::::\n",
                   encoding="utf-8")
    events = parse(ctx, "etc/passwd")
    assert any(e.actor_user == "root" for e in events)
