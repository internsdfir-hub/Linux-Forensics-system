"""Static state-finding rules (spec 2.8.1).

Evaluates system configuration findings such as non-root UID 0 accounts,
passwordless accounts, dangerous group memberships, unsafe SSH configurations,
and ld.so.preload rootkit persistence.
"""
from __future__ import annotations

import sqlite3
from typing import Iterator

from .base import BaseRule, Finding, PlainSummary


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute(sql, params).fetchall()


def _group_by_user(rows: list[sqlite3.Row]) -> dict[str, list[sqlite3.Row]]:
    """Bucket rows by actor_user, preserving order, so a state condition that
    shows up in several artifacts becomes one finding per account."""
    out: dict[str, list[sqlite3.Row]] = {}
    for r in rows:
        user = (r["actor_user"] or "unknown").strip("'\"")
        out.setdefault(user, []).append(r)
    return out


def _group_of(row: sqlite3.Row) -> str | None:
    """Best-effort group name out of a privileged_group_member event."""
    desc = row["description"] or ""
    marker = "privileged group "
    if marker in desc:
        return desc.split(marker, 1)[1].split()[0].rstrip(".,)")
    return None


class Uid0Rule(BaseRule):
    name = "uid0_account"
    version = "1.0"

    def run(self, conn: sqlite3.Connection, ctx: dict) -> Iterator[Finding]:
        query = """
            SELECT event_id, host_id, actor_user, actor_uid, description, raw_line
            FROM events
            WHERE subcategory = 'uid0_account'
               OR (actor_uid = 0 AND actor_user IS NOT NULL AND actor_user != 'root')
        """
        # One account can surface as several events (etc/passwd, auth.log
        # account_created, lastlog) - collapse them into one finding per
        # account, citing every event, instead of one finding per row.
        for user, rows in _group_by_user(_rows(conn, query)).items():
            row = rows[0]
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="high",
                title=f"Non-root account with root privileges: {user}",
                plain=PlainSummary(
                    what_happened=f"Non-root account '{user}' has UID 0 (root superuser privileges)",
                    why_it_matters="A non-root account with UID 0 provides full root access and is often created by attackers for persistent root access.",
                    confidence="High",
                    check_next="Verify when this account was added in /etc/passwd and remove unauthorized UID 0 accounts.",
                ),
                technical_detail=f"Found UID 0 account '{user}' (description: {row['description'] or row['raw_line']})",
                event_ids=[r["event_id"] for r in rows],
                host_id=row["host_id"],
            )


class PasswordlessAccountRule(BaseRule):
    name = "passwordless_account"
    version = "1.0"

    def run(self, conn: sqlite3.Connection, ctx: dict) -> Iterator[Finding]:
        query = """
            SELECT event_id, host_id, actor_user, description, raw_line
            FROM events
            WHERE subcategory = 'passwordless_account'
        """
        # etc/shadow and its etc/shadow- backup both carry the account, so it
        # appears twice - one finding per account, citing both events.
        for user, rows in _group_by_user(_rows(conn, query)).items():
            row = rows[0]
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="high",
                title=f"Passwordless user account: {user}",
                plain=PlainSummary(
                    what_happened=f"Account '{user}' has no password set in /etc/shadow",
                    why_it_matters="Passwordless accounts allow anyone to log in or switch user without authentication.",
                    confidence="High",
                    check_next="Inspect account login activity and lock or set a strong password for the account.",
                ),
                technical_detail=f"Account '{user}' has empty password hash in shadow file (raw: {row['raw_line']})",
                event_ids=[r["event_id"] for r in rows],
                host_id=row["host_id"],
            )


class PrivilegedGroupRule(BaseRule):
    name = "privileged_group_member"
    version = "1.0"

    def run(self, conn: sqlite3.Connection, ctx: dict) -> Iterator[Finding]:
        query = """
            SELECT event_id, host_id, actor_user, description, raw_line
            FROM events
            WHERE subcategory = 'privileged_group_member'
        """
        # A user in several privileged groups (e.g. both sudo and adm) yields
        # one event per group - collapse to one finding per user that names
        # every group, rather than one finding per (user, group).
        for user, rows in _group_by_user(_rows(conn, query)).items():
            groups = sorted({g for r in rows if (g := _group_of(r))})
            groups_txt = ", ".join(groups) if groups else "a privileged group"
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="medium",
                title=f"User {user} in privileged administrative group",
                plain=PlainSummary(
                    what_happened=f"User '{user}' belongs to privileged administrative group(s): {groups_txt}",
                    why_it_matters="Membership in privileged groups such as docker, sudo, or wheel grants near or total root access on the host system.",
                    confidence="High",
                    check_next="Verify whether this user account requires administrative group permissions.",
                ),
                technical_detail=f"Privileged group membership ({groups_txt}): "
                                 + "; ".join(r["description"] or r["raw_line"] for r in rows),
                event_ids=[r["event_id"] for r in rows],
                host_id=rows[0]["host_id"],
            )


class SshdConfigRule(BaseRule):
    name = "sshd_config_risk"
    version = "1.0"

    def run(self, conn: sqlite3.Connection, ctx: dict) -> Iterator[Finding]:
        query = """
            SELECT event_id, host_id, actor_user, description, raw_line
            FROM events
            WHERE subcategory = 'sshd_setting'
               OR (source_artifact_path LIKE '%sshd_config%' AND description LIKE '%PermitRootLogin%')
        """
        for row in _rows(conn, query):
            desc = row["description"] or row["raw_line"]
            # The event's own description already names the specific directive
            # (PermitRootLogin / PermitEmptyPasswords / PasswordAuthentication).
            # Drive the finding from it so a non-root setting is not mislabelled
            # as "root login enabled".
            setting = (row["raw_line"] or "").strip() or desc
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="high",
                title=f"Insecure SSH configuration: {setting}",
                plain=PlainSummary(
                    what_happened=desc,
                    why_it_matters="An over-permissive SSH daemon widens the network attack surface: direct root login, empty passwords, or password authentication all let an attacker in over the network, often with no user attribution.",
                    confidence="High",
                    check_next="Harden /etc/ssh/sshd_config: set PermitRootLogin no, PermitEmptyPasswords no, prefer key-based authentication, then restart sshd.",
                ),
                technical_detail=f"Insecure sshd configuration detected: {desc}",
                event_ids=[row["event_id"]],
                host_id=row["host_id"],
            )


class LdPreloadRule(BaseRule):
    name = "ld_preload_rootkit"
    version = "1.0"

    def run(self, conn: sqlite3.Connection, ctx: dict) -> Iterator[Finding]:
        query = """
            SELECT event_id, host_id, actor_user, description, raw_line
            FROM events
            WHERE subcategory = 'ld_preload_set'
               OR source_artifact_path LIKE '%ld.so.preload%'
        """
        for row in _rows(conn, query):
            desc = row["description"] or row["raw_line"]
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="high",
                title="Suspicious dynamic linker preload library configured",
                plain=PlainSummary(
                    what_happened="/etc/ld.so.preload is configured to preload shared libraries into all executed processes",
                    why_it_matters="ld.so.preload is commonly utilized by Linux rootkits to hook libc calls and conceal files, network connections, and processes.",
                    confidence="High",
                    check_next="Examine the referenced preload shared library and verify integrity of core system binaries.",
                ),
                technical_detail=f"Dynamic linker preload active: {desc}",
                event_ids=[row["event_id"]],
                host_id=row["host_id"],
            )
