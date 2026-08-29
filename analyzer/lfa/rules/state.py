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
        for row in _rows(conn, query):
            user = row["actor_user"] or f"UID 0 ({row['raw_line']})"
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
                event_ids=[row["event_id"]],
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
        for row in _rows(conn, query):
            user = row["actor_user"] or "unknown"
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
                event_ids=[row["event_id"]],
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
        for row in _rows(conn, query):
            user = row["actor_user"] or "unknown"
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="medium",
                title=f"User {user} in privileged administrative group",
                plain=PlainSummary(
                    what_happened=f"User '{user}' belongs to privileged administrative group",
                    why_it_matters="Membership in privileged groups such as docker, sudo, or wheel grants near or total root access on the host system.",
                    confidence="High",
                    check_next="Verify whether this user account requires administrative group permissions.",
                ),
                technical_detail=f"Privileged group membership: {row['description'] or row['raw_line']}",
                event_ids=[row["event_id"]],
                host_id=row["host_id"],
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
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="high",
                title="Insecure SSH configuration: Direct root login enabled",
                plain=PlainSummary(
                    what_happened="SSH daemon is configured to permit direct root login (PermitRootLogin yes)",
                    why_it_matters="Direct root login over SSH allows attackers to target the root account directly via brute-force and credential stuffing without user attribution.",
                    confidence="High",
                    check_next="Disable PermitRootLogin in /etc/ssh/sshd_config and require key-based sudo access.",
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
