"""auth.log / secure parser (spec category 2 and 3).

Grammar-driven: every pattern lives in config/grammars/*.yaml, so a new
distro or a format drift is a config change, not a code change. A single
line may yield more than one event - a sudo line is both privilege
escalation and timeline activity - so we yield freely.
"""
from __future__ import annotations

from pathlib import Path

from ..timeeng import find_anchor_year, parse_syslog_prefix
from .base import BaseParser, ParseContext
from .grammar import GrammarEngine

GRAMMAR_DIR = Path(__file__).resolve().parents[3] / "config" / "grammars"


class SyslogTextParser(BaseParser):
    """Shared engine for any syslog-formatted text log."""

    name = ""
    version = "1.0"
    artifact_category = ""
    applies_to: list[str] = []

    def _engine(self, context: ParseContext) -> GrammarEngine:
        distro = (context.distro_profile or {}).get("distro_id", "")
        key = f"_grammar_{distro}"
        cached = getattr(context, "_grammar_cache", None)
        if cached is None:
            cached = {}
            object.__setattr__(context, "_grammar_cache", cached)
        if key not in cached:
            cached[key] = GrammarEngine.load(GRAMMAR_DIR, distro)
        return cached[key]

    def parse(self, path: Path, context: ParseContext):
        engine = self._engine(context)

        # year anchoring: ISO lines in the same file beat file mtime
        sample = []
        for i, (_, line) in enumerate(self.iter_lines(path, context)):
            sample.append(line)
            if i > 200:
                break
        anchor = find_anchor_year(sample)

        for offset, line in self.iter_lines(path, context):
            if not line.strip():
                continue
            prefix, rest = parse_syslog_prefix(line)
            if prefix is None:
                ts = context.time_ctx.resolve_iso(line[:32])
                if ts.utc_iso is None:
                    ts = None
            else:
                ts = context.time_ctx.resolve_syslog(
                    prefix, file_mtime=context.artifact_mtime, anchor_year=anchor
                )

            for rule_name, rule, groups in engine.match_line(line):
                utc = ts.utc_iso if ts else None
                local = ts.local_iso if ts else None
                confidence = ts.confidence if ts else "unknown"
                source_ip = groups.get("ip")
                uid = None
                if groups.get("uid", "").isdigit():
                    uid = int(groups["uid"])

                yield context.build_event(
                    event_kind="event",
                    timestamp_utc=utc,
                    timestamp_local=local,
                    timestamp_confidence=confidence,
                    category=rule["category"],
                    subcategory=rule["subcategory"],
                    actor_user=groups.get("user"),
                    actor_uid=uid,
                    actor_process=rule.get("process"),
                    source_ip=source_ip,
                    description=self._describe(rule_name, rule, groups),
                    severity=rule["severity"],
                    raw_line=line,
                    raw_line_offset=offset,
                    tool_generated_flag=context.is_tool_generated(source_ip, utc),
                    notes=f"grammar:{rule_name}",
                )

    @staticmethod
    def _describe(rule_name: str, rule: dict, g: dict) -> str:
        """Plain, factual sentence per event; the report's narrative layer
        builds on these."""
        user = g.get("user", "unknown user")
        ip = g.get("ip")
        sub = rule["subcategory"]
        if sub == "failed_login":
            return f"Failed password for {user}" + (f" from {ip}" if ip else "")
        if sub == "invalid_user":
            return f"Login attempt for non-existent user {user}" + (
                f" from {ip}" if ip else "")
        if sub == "successful_login":
            method = g.get("method", "unknown method")
            return f"Successful {method} login for {user}" + (
                f" from {ip}" if ip else "")
        if sub == "session_opened":
            return f"Session opened for user {user}"
        if sub == "session_closed":
            return f"Session closed for user {user}"
        if sub == "disconnect":
            return f"Disconnected from user {user}" + (f" at {ip}" if ip else "")
        if sub == "sudo_command":
            return (f"{user} ran a command as {g.get('target_user', 'root')}: "
                    f"{g.get('command', '')}")
        if sub == "sudo_failure":
            return (f"{user} failed sudo authentication "
                    f"({g.get('failures', '?')} incorrect attempts)")
        if sub == "sudo_denied":
            return f"{user} attempted sudo but is not in sudoers"
        if sub == "su_attempt":
            return f"{user} used su to become {g.get('target_user', 'another user')}"
        if sub == "auth_failure":
            return f"PAM authentication failure for {user}" + (
                f" from {ip}" if ip else "")
        if sub == "account_created":
            return (f"New account created: {user} "
                    f"(uid={g.get('uid')}, home={g.get('home')}, "
                    f"shell={g.get('shell')})")
        if sub == "group_created":
            return f"New group created: {g.get('group')}"
        if sub == "group_membership_added":
            return f"User {user} was added to group {g.get('group')}"
        if sub == "account_deleted":
            return f"Account deleted: {user}"
        if sub == "password_changed":
            return f"Password changed for {user}"
        if sub == "password_policy_changed":
            return f"Password expiry policy changed for {user}"
        if sub == "cron_run":
            return f"Scheduled (cron) session opened for {user}"
        if sub == "firewall_block":
            return f"Firewall blocked traffic from {ip}"
        return f"{rule_name}: {g}"


class AuthLogParser(SyslogTextParser):
    name = "authlog_parser"
    version = "1.0"
    artifact_category = "login_activity"
    applies_to = [
        "var/log/auth.log", "var/log/auth.log.*",
        "var/log/secure", "var/log/secure.*",
    ]
