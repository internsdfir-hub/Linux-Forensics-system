"""cron log parser (spec category 4: persistence).

/etc/crontab tells you what is SCHEDULED; this tells you what actually RAN,
and - via the crontab(1) BEGIN EDIT / REPLACE lines - exactly when a job was
planted. On Debian those lines live in /var/log/syslog, on RHEL in
/var/log/cron, so this parser claims both.

Everything is grammar-driven (config/grammars/common.yaml) on top of
SyslogTextParser; the only Python here is the extra pass that escalates a
CMD line whose command matches the shared persistence indicators.
"""
from __future__ import annotations

import re
from pathlib import Path

from .authlog import SyslogTextParser
from .base import ParseContext
from .cron import suspicious_indicators

_CMD_RE = re.compile(r"CMD \((?P<command>.*)\)\s*$")


class CronLogParser(SyslogTextParser):
    name = "cronlog_parser"
    version = "1.0"
    artifact_category = "persistence"
    applies_to = [
        "var/log/cron", "var/log/cron.*", "var/log/cron-*", "var/log/cron.log*",
        "var/log/syslog", "var/log/syslog.*",
        "var/log/messages", "var/log/messages.*",
    ]

    def parse(self, path: Path, context: ParseContext):
        for event in super().parse(path, context):
            yield event
            if event.subcategory != "cron_command":
                continue
            match = _CMD_RE.search(event.raw_line)
            if not match:
                continue
            command = match.group("command").strip()
            reasons = suspicious_indicators(command)
            if not reasons:
                continue
            index = event.raw_line.find(command)
            yield context.build_event(
                event_kind="event",
                timestamp_utc=event.timestamp_utc,
                timestamp_local=event.timestamp_local,
                timestamp_confidence=event.timestamp_confidence,
                category="persistence",
                subcategory="suspicious_cron_command",
                actor_user=event.actor_user,
                actor_process="cron",
                description=(
                    f"Suspicious command executed by cron as "
                    f"{event.actor_user or 'unknown user'}: {command} -- "
                    + "; ".join(reasons)
                ),
                severity="high",
                # quote the command itself (with its true offset inside the
                # file) so this finding does not collide with the parent
                # event on the raw-line dedupe hash
                raw_line=command,
                raw_line_offset=event.raw_line_offset + max(index, 0),
                tool_generated_flag=event.tool_generated_flag,
                notes="derived_from:cron_command",
            )

    @staticmethod
    def _describe(rule_name: str, rule: dict, g: dict) -> str:
        sub = rule["subcategory"]
        user = g.get("user", "unknown user")
        if sub == "cron_command":
            return f"Cron ran a command as {user}: {g.get('command', '').strip()}"
        if sub == "cron_session_closed":
            return f"Scheduled (cron) session closed for {user}"
        if sub == "crontab_modified":
            action = g.get("action", "modified")
            target = g.get("target_user") or user
            verb = "replaced" if action == "REPLACE" else "deleted"
            return (f"{user} {verb} the crontab of {target} using crontab(1) "
                    f"({action})")
        if sub == "crontab_edit":
            action = g.get("action", "")
            target = g.get("target_user") or user
            return f"{user} opened the crontab of {target} in an editor ({action})"
        if sub == "cron_reload":
            return (f"cron reloaded {g.get('target', 'a crontab')} after it "
                    f"changed on disk")
        if sub == "anacron_job":
            return f"anacron job {g.get('job', '?')} {g.get('action', 'ran')}"
        return SyslogTextParser._describe(rule_name, rule, g)
