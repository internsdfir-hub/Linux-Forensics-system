"""Static state-finding rules: one finding per account, not per artifact.

An account that is UID 0, or passwordless, or in a privileged group tends to
show up in several collected artifacts at once (/etc/passwd and its backup,
/etc/shadow and /etc/shadow-, auth.log, lastlog, /etc/group). Each is a
distinct event, so the rules must collapse them into one finding per account
that cites every event - not emit a duplicate finding per occurrence.
"""
from lfa import db
from lfa.rules.state import (
    PasswordlessAccountRule,
    PrivilegedGroupRule,
    Uid0Rule,
)


def run_rule(conn, rule, ctx=None):
    return list(rule.run(conn, ctx or {}))


def test_uid0_account_deduped_across_artifacts(tmp_path, event_factory):
    # sysmon (uid 0) surfaces in /etc/passwd, auth.log and lastlog - three
    # distinct events, one account, one finding.
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        event_factory(subcategory="uid0_account", actor_user="sysmon",
                      actor_uid=0, category="user_accounts",
                      source_artifact_path="etc/passwd", raw_line_offset=1,
                      raw_line="sysmon:x:0:0::/home/sysmon:/bin/bash"),
        event_factory(subcategory="account_created", actor_user="sysmon",
                      actor_uid=0, category="user_accounts",
                      source_artifact_path="var/log/auth.log", raw_line_offset=2,
                      raw_line="new user: name=sysmon, UID=0"),
        event_factory(subcategory="last_login", actor_user="sysmon",
                      actor_uid=0, category="login_activity",
                      source_artifact_path="var/log/lastlog", raw_line_offset=3,
                      raw_line="sysmon 0"),
    ])
    hits = run_rule(conn, Uid0Rule())
    assert len(hits) == 1, [h.title for h in hits]
    f = hits[0]
    assert "sysmon" in f.title
    assert len(f.event_ids) == 3      # every occurrence cited
    conn.close()


def test_passwordless_deduped_across_shadow_and_backup(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        event_factory(subcategory="passwordless_account", actor_user="svc_backup",
                      category="user_accounts", source_artifact_path="etc/shadow",
                      raw_line_offset=1, raw_line="svc_backup::19000:0:99999:7:::"),
        event_factory(subcategory="passwordless_account", actor_user="svc_backup",
                      category="user_accounts", source_artifact_path="etc/shadow-",
                      raw_line_offset=1, raw_line="svc_backup::19000:0:99999:7:::"),
    ])
    hits = run_rule(conn, PasswordlessAccountRule())
    assert len(hits) == 1, [h.title for h in hits]
    assert len(hits[0].event_ids) == 2
    conn.close()


def test_privileged_group_one_finding_lists_all_groups(tmp_path, event_factory):
    # helpdesk is in both sudo and adm -> one event per group, one finding that
    # names both. This is the case Metasploitable produced.
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        event_factory(subcategory="privileged_group_member", actor_user="helpdesk",
                      category="user_accounts", source_artifact_path="etc/group",
                      raw_line_offset=1, raw_line="sudo:x:27:helpdesk",
                      description="User helpdesk belongs to privileged group sudo"),
        event_factory(subcategory="privileged_group_member", actor_user="helpdesk",
                      category="user_accounts", source_artifact_path="etc/group",
                      raw_line_offset=2, raw_line="adm:x:4:msfadmin,helpdesk",
                      description="User helpdesk belongs to privileged group adm"),
    ])
    hits = run_rule(conn, PrivilegedGroupRule())
    assert len(hits) == 1, [h.title for h in hits]
    f = hits[0]
    assert len(f.event_ids) == 2
    # both group names appear in the finding
    assert "sudo" in f.plain.what_happened and "adm" in f.plain.what_happened
    conn.close()


def test_two_distinct_uid0_accounts_are_two_findings(tmp_path, event_factory):
    # dedup is per-account, not global: two different backdoor roots => two.
    conn = db.open_case(tmp_path / "c.db")
    db.insert_events(conn, [
        event_factory(subcategory="uid0_account", actor_user="sysmon", actor_uid=0,
                      category="user_accounts", source_artifact_path="etc/passwd",
                      raw_line_offset=1, raw_line="sysmon:x:0:0::/root:/bin/bash"),
        event_factory(subcategory="uid0_account", actor_user="toor", actor_uid=0,
                      category="user_accounts", source_artifact_path="etc/passwd",
                      raw_line_offset=2, raw_line="toor:x:0:0::/root:/bin/bash"),
    ])
    hits = run_rule(conn, Uid0Rule())
    assert len(hits) == 2
    assert {"sysmon" in h.title or "toor" in h.title for h in hits} == {True}
    conn.close()
