"""cron parser (spec category 4: persistence).

Covers every place a scheduled job can hide on a Debian/RHEL box:

  /etc/crontab                system crontab      -> HAS a user field
  /etc/cron.d/*               packaged fragments  -> HAS a user field
  /var/spool/cron/crontabs/*  per-user crontabs   -> NO user field, the
  /var/spool/cron/*           (RHEL layout)          username IS the filename
  /etc/cron.{hourly,daily,weekly,monthly}/*        -> run-parts shell scripts

That user-field asymmetry is the classic cron parsing trap: read a spool
crontab as if it were /etc/crontab and every command silently loses its
first word (and the "user" you report is really the program being run).

Every job is a state_finding. The file mtime goes into the description AND
into notes as an epoch, because "when was this job planted" is the question
a correlation rule asks against the incident window - the cron file itself
carries no per-job timestamps.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from .base import BaseParser, ParseContext

# Suspicious-command indicators. Shared with the systemd / startup / cron-log
# parsers so one definition drives every persistence surface. Each entry is
# (compiled pattern, plain-English reason for the report).
_INDICATORS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:curl|wget|fetch)\b[^|;]*\|\s*(?:sudo\s+)?(?:/\S*/)?"
                r"(?:ba|da|k|z)?sh\b"),
     "pipes downloaded content straight into a shell"),
    (re.compile(r"(?:curl|wget|fetch)\b[^|;]*\|\s*(?:sudo\s+)?(?:/\S*/)?"
                r"(?:python[23]?|perl|ruby)\b"),
     "pipes downloaded content straight into an interpreter"),
    (re.compile(r"\bbase64\b"),
     "uses base64 encoding/decoding to hide its payload"),
    (re.compile(r"(?:^|[\s;|&(/])(?:nc|ncat|netcat)(?:\.traditional|\.openbsd)?"
                r"(?:\s|$)"),
     "invokes netcat"),
    (re.compile(r"/dev/(?:tcp|udp)/"),
     "opens a raw network socket via /dev/tcp (reverse shell idiom)"),
    (re.compile(r"(?:^|[\s;|&(\"'=:])(?:/tmp/|/dev/shm/|/var/tmp/)"),
     "runs content from a world-writable directory (/tmp, /dev/shm, /var/tmp)"),
    (re.compile(r"/\.[A-Za-z0-9_][^/\s]*"),
     "references a hidden (dot-prefixed) filename"),
    (re.compile(r"\beval\b"),
     "uses eval, which executes constructed or decoded strings"),
    (re.compile(r"\b(?:python[23]?|perl|ruby)\s+-[ce]\b"),
     "runs an inline interpreter one-liner"),
    (re.compile(r"\bchattr\s+\+i\b"),
     "makes a file immutable (anti-removal)"),
]


def suspicious_indicators(command: str) -> list[str]:
    """Plain-English reasons a command looks like attacker persistence.
    Empty list means nothing stood out."""
    return [reason for pattern, reason in _INDICATORS if pattern.search(command)]


def mtime_iso(context: ParseContext) -> str:
    if context.artifact_mtime is None:
        return "unknown"
    return datetime.fromtimestamp(context.artifact_mtime, timezone.utc).isoformat()


def mtime_note(context: ParseContext) -> str | None:
    """Machine-readable mtime for the window-correlation rules."""
    if context.artifact_mtime is None:
        return None
    return f"file_mtime_epoch={context.artifact_mtime:.0f}"


SPECIAL_SCHEDULES = {
    "@reboot": "at every boot",
    "@yearly": "once a year",
    "@annually": "once a year",
    "@monthly": "once a month",
    "@weekly": "once a week",
    "@daily": "once a day",
    "@midnight": "once a day",
    "@hourly": "once an hour",
}

_ENV_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_MINUTE_FIELD = re.compile(r"^[0-9*/,\-]+$")
_OTHER_FIELD = re.compile(r"^[0-9A-Za-z*/,\-]+$")

_RUN_PARTS_DIRS = {
    "cron.hourly": "hourly",
    "cron.daily": "daily",
    "cron.weekly": "weekly",
    "cron.monthly": "monthly",
}


class CronParser(BaseParser):
    name = "cron_parser"
    version = "1.0"
    artifact_category = "persistence"
    applies_to = [
        "etc/crontab",
        "etc/cron.d/*",
        "var/spool/cron/crontabs/*",
        "var/spool/cron/*",
        "etc/cron.hourly/*",
        "etc/cron.daily/*",
        "etc/cron.weekly/*",
        "etc/cron.monthly/*",
    ]

    # ------------------------------------------------------------- helpers

    def _state(self, context: ParseContext, **kw):
        kw.setdefault("event_kind", "state_finding")
        kw.setdefault("timestamp_utc", None)
        kw.setdefault("timestamp_local", None)
        kw.setdefault("timestamp_confidence", "unknown")
        kw.setdefault("category", "persistence")
        kw.setdefault("notes", mtime_note(context))
        return context.build_event(**kw)

    @staticmethod
    def _layout(rel: str) -> tuple[str, str | None]:
        """('system'|'spool'|'periodic', owner-or-interval)."""
        parts = rel.split("/")
        for dirname, interval in _RUN_PARTS_DIRS.items():
            if dirname in parts:
                return "periodic", interval
        if rel.startswith("var/spool/cron"):
            return "spool", parts[-1]
        return "system", None

    # --------------------------------------------------------------- parse

    def parse(self, path: Path, context: ParseContext):
        rel = context.artifact_rel.replace("\\", "/")
        layout, extra = self._layout(rel)
        if layout == "periodic":
            yield from self._parse_run_parts_script(path, context, rel, extra)
        else:
            yield from self._parse_crontab(path, context, rel, layout, extra)

    def _parse_crontab(self, path, context, rel, layout, owner):
        stamp = mtime_iso(context)
        for offset, line in self.iter_lines(path, context):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            env = _ENV_RE.match(line)
            if env:
                name, value = env.group(1), env.group(2)
                yield self._state(
                    context,
                    subcategory="cron_env",
                    actor_user=owner if layout == "spool" else None,
                    description=(
                        f"Cron environment variable {name}={value} set in "
                        f"{rel} (file mtime {stamp})"
                    ),
                    severity="info",
                    raw_line=line,
                    raw_line_offset=offset,
                )
                continue

            parsed = self._split_job(stripped, layout, owner)
            if parsed is None:
                continue
            schedule, user, command = parsed
            # offset of the command inside the file, so a derived finding can
            # point at the command itself rather than the whole line
            cmd_offset = offset + line.rindex(command) if command in line else offset

            reasons = suspicious_indicators(command)
            if reasons:
                yield self._state(
                    context,
                    subcategory="suspicious_cron_job",
                    actor_user=user,
                    description=(
                        f"Suspicious cron job in {rel}: schedule {schedule} "
                        f"runs as {user or 'unknown user'}: {command} -- "
                        + "; ".join(reasons)
                        + f" (file mtime {stamp})"
                    ),
                    severity="high",
                    raw_line=command,
                    raw_line_offset=cmd_offset,
                )
            else:
                yield self._state(
                    context,
                    subcategory="cron_job",
                    actor_user=user,
                    description=(
                        f"Cron job in {rel}: schedule {schedule} runs as "
                        f"{user or 'unknown user'}: {command} (file mtime {stamp})"
                    ),
                    severity="info",
                    raw_line=line,
                    raw_line_offset=offset,
                )

    @staticmethod
    def _split_job(stripped: str, layout: str, owner: str | None):
        """-> (schedule_text, user, command) or None if the line is not a job.

        System crontabs (/etc/crontab, /etc/cron.d/*) carry a user field
        between the schedule and the command; per-user spool crontabs do not.
        """
        want_user = layout == "system"
        if stripped.startswith("@"):
            head = stripped.split(None, 1)[0]
            rest = stripped[len(head):].strip()
            keyword = head.lower()
            if keyword not in SPECIAL_SCHEDULES or not rest:
                return None
            schedule = f"{keyword} ({SPECIAL_SCHEDULES[keyword]})"
            if want_user:
                bits = rest.split(None, 1)
                if len(bits) < 2:
                    return None
                return schedule, bits[0], bits[1].strip()
            return schedule, owner, rest

        fields = stripped.split(None, 6 if want_user else 5)
        if len(fields) < (7 if want_user else 6):
            return None
        sched = fields[:5]
        if not _MINUTE_FIELD.match(sched[0]):
            return None
        if not all(_OTHER_FIELD.match(f) for f in sched[1:]):
            return None
        schedule = " ".join(sched)
        if want_user:
            return schedule, fields[5], fields[6].strip()
        return schedule, owner, fields[5].strip()

    # run-parts directories hold shell scripts, not crontab lines: the
    # schedule comes from the directory name and the runner is always root.
    def _parse_run_parts_script(self, path, context, rel, interval):
        stamp = mtime_iso(context)
        lines = list(self.iter_lines(path, context))
        body = [l for _, l in lines if l.strip() and not l.strip().startswith("#")]
        yield self._state(
            context,
            subcategory="cron_job",
            actor_user="root",
            description=(
                f"Scheduled script {rel} is executed {interval} as root by "
                f"run-parts ({len(body)} command lines, file mtime {stamp})"
            ),
            severity="info",
            raw_line=f"<run-parts {interval} script: {rel}>",
            raw_line_offset=0,
        )
        for offset, line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            reasons = suspicious_indicators(stripped)
            if not reasons:
                continue
            yield self._state(
                context,
                subcategory="suspicious_cron_job",
                actor_user="root",
                description=(
                    f"Suspicious command in {interval} scheduled script {rel} "
                    f"(runs as root): {stripped} -- " + "; ".join(reasons)
                    + f" (file mtime {stamp})"
                ),
                severity="high",
                raw_line=line,
                raw_line_offset=offset,
            )
