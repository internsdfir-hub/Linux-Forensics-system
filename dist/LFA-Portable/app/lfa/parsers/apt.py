"""apt history.log / term.log parser (spec category 5, software changes).

/var/log/apt/history.log is stanza-structured (blank-line separated), and it
is the ONLY package artifact that records attribution:

    Start-Date: 2024-03-10  02:30:01
    Commandline: apt-get install netcat-openbsd nmap
    Requested-By: alice (1000)
    Install: netcat-openbsd:amd64 (1.217-3), nmap:amd64 (7.93+dfsg1-1)
    End-Date: 2024-03-10  02:30:12

dpkg.log will tell you netcat arrived at 02:30. Only this file tells you that
*alice* typed *that exact command* to make it happen, which is the difference
between an observation and an attribution. So every stanza yields:

  * one `apt_transaction` event carrying the command line and the requester,
  * one `package_install` / `package_upgrade` / `package_remove` event per
    package in the stanza's lists, so package-level queries and correlation
    rules do not have to re-parse prose.

Remove: and Purge: both map to `package_remove` (the description says which);
downstream rules care that the package went away, not about dpkg's
config-file-retention distinction.

WHY term.log PRODUCES NOTHING: term.log is the raw terminal transcript of the
dpkg run - progress bars, ANSI escapes, maintainer-script chatter. Every fact
in it is already in history.log or dpkg.log in structured form, and its line
noise would swamp the timeline. We still CLAIM the file so the run's
"unparsed artifacts" list stays honest about it being seen and skipped by
choice, and we read nothing from it so malformed/binary content cannot break
the run.
"""
from __future__ import annotations

import re
from pathlib import Path

from .base import BaseParser, ParseContext
from .dpkg import classify_severity

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

# "netcat-openbsd:amd64 (1.217-3), nmap:amd64 (7.93+dfsg1-1, automatic)"
_PKG_ENTRY = re.compile(r"([^\s(),]+)\s*\(([^)]*)\)")

_REQUESTED_BY = re.compile(r"^(?P<user>\S+)\s*(?:\((?P<uid>\d+)\))?")

# apt writes "2024-03-10  02:30:01" with TWO spaces
_DATE = re.compile(r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})")

_LIST_KEYS = {
    "Install": "package_install",
    "Reinstall": "package_install",
    "Upgrade": "package_upgrade",
    "Downgrade": "package_upgrade",
    "Remove": "package_remove",
    "Purge": "package_remove",
}


class AptParser(BaseParser):
    name = "apt_parser"
    version = "1.0"
    artifact_category = "software_changes"
    applies_to = [
        "var/log/apt/history.log", "var/log/apt/history.log.*",
        "var/log/apt/term.log", "var/log/apt/term.log.*",
    ]

    def parse(self, path: Path, context: ParseContext):
        base = context.artifact_rel.replace("\\", "/").rsplit("/", 1)[-1]
        if base.startswith("term.log"):
            return  # see module docstring: claimed on purpose, parsed on purpose
        yield from self._parse_history(path, context)

    # ------------------------------------------------------------- stanzas

    def _parse_history(self, path: Path, context: ParseContext):
        stanza: dict[str, str] = {}
        key_offsets: dict[str, int] = {}
        raw_lines: list[str] = []
        start_offset = 0

        for offset, line in self.iter_lines(path, context):
            if not line.strip():
                if stanza:
                    yield from self._emit(context, stanza, key_offsets,
                                          raw_lines, start_offset)
                stanza, key_offsets, raw_lines = {}, {}, []
                continue
            if ":" not in line:
                continue  # garbage line inside a stanza: ignore, keep going
            key, _, value = line.partition(":")
            key = key.strip()
            if not stanza:
                start_offset = offset
            raw_lines.append(line)
            # a repeated key (apt never does this) keeps the first occurrence
            stanza.setdefault(key, value.strip())
            key_offsets.setdefault(key, offset)

        if stanza:  # unterminated final stanza (truncated log) still counts
            yield from self._emit(context, stanza, key_offsets, raw_lines,
                                  start_offset)

    def _emit(self, context: ParseContext, stanza: dict[str, str],
              key_offsets: dict[str, int], raw_lines: list[str],
              start_offset: int):
        ts = None
        date_match = _DATE.match(stanza.get("Start-Date", ""))
        if date_match:
            resolved = context.time_ctx.resolve_iso(
                f"{date_match.group(1)} {date_match.group(2)}"
            )
            if resolved.utc_iso is not None:
                ts = resolved

        actor_user, actor_uid, actor_note = self._actor(stanza)
        commandline = stanza.get("Commandline", "")

        package_events = []
        worst = "info"
        for key, subcategory in _LIST_KEYS.items():
            entries = stanza.get(key)
            if not entries:
                continue
            for package, versions in _PKG_ENTRY.findall(entries):
                severity, sev_note = classify_severity(
                    package, "remove" if subcategory == "package_remove" else key.lower()
                )
                if _SEVERITY_ORDER[severity] > _SEVERITY_ORDER[worst]:
                    worst = severity
                package_events.append(
                    context.build_event(
                        event_kind="event",
                        timestamp_utc=ts.utc_iso if ts else None,
                        timestamp_local=ts.local_iso if ts else None,
                        timestamp_confidence=ts.confidence if ts else "unknown",
                        category="software_changes",
                        subcategory=subcategory,
                        actor_user=actor_user,
                        actor_uid=actor_uid,
                        actor_process="apt",
                        description=self._describe_package(key, package, versions),
                        severity=severity,
                        raw_line=f"{key}: {package} ({versions})",
                        raw_line_offset=key_offsets.get(key, start_offset),
                        notes=sev_note,
                    )
                )

        notes = actor_note
        if stanza.get("Error"):
            notes = ((notes + "; ") if notes else "") + \
                f"apt reported an error: {stanza['Error']}"

        description = (
            f"apt transaction by {actor_user}: "
            f"{commandline or '(no command line recorded)'}"
        )
        touched = self._package_summary(stanza)
        if touched:
            description += f" [{touched}]"
        if stanza.get("End-Date"):
            description += f" (completed {stanza['End-Date']})"
        else:
            description += " (no End-Date: transaction did not complete or the log is truncated)"

        yield context.build_event(
            event_kind="event",
            timestamp_utc=ts.utc_iso if ts else None,
            timestamp_local=ts.local_iso if ts else None,
            timestamp_confidence=ts.confidence if ts else "unknown",
            category="software_changes",
            subcategory="apt_transaction",
            actor_user=actor_user,
            actor_uid=actor_uid,
            actor_process="apt",
            description=description,
            severity=worst,
            raw_line="\n".join(raw_lines),
            raw_line_offset=start_offset,
            notes=notes,
        )
        yield from package_events

    # ------------------------------------------------------------- helpers

    @staticmethod
    def _actor(stanza: dict[str, str]) -> tuple[str, int | None, str | None]:
        requested_by = stanza.get("Requested-By", "").strip()
        if requested_by:
            m = _REQUESTED_BY.match(requested_by)
            if m:
                uid = int(m.group("uid")) if m.group("uid") else None
                return m.group("user"), uid, None
        # apt omits Requested-By when the caller was already uid 0, i.e. a
        # root shell, cron job or unattended-upgrades - not a sudo escalation.
        return "root", 0, (
            "no Requested-By: field, so apt ran directly as root (root shell, "
            "cron or unattended-upgrades) rather than via sudo from a named user"
        )

    @staticmethod
    def _package_summary(stanza: dict[str, str]) -> str:
        parts = []
        for key in ("Install", "Reinstall", "Upgrade", "Downgrade", "Remove",
                    "Purge"):
            entries = stanza.get(key)
            if entries:
                count = len(_PKG_ENTRY.findall(entries))
                if count:
                    parts.append(f"{key.lower()} {count}")
        return ", ".join(parts)

    @staticmethod
    def _describe_package(key: str, package: str, versions: str) -> str:
        parts = [p.strip() for p in versions.split(",") if p.strip()]
        automatic = "automatic" in parts
        parts = [p for p in parts if p != "automatic"]
        if key in ("Upgrade", "Downgrade") and len(parts) >= 2:
            verb = "upgraded" if key == "Upgrade" else "downgraded"
            return (f"Package {package} {verb} from {parts[0]} to {parts[1]} "
                    f"by apt")
        version = parts[0] if parts else "unknown version"
        if key in ("Remove", "Purge"):
            verb = "removed" if key == "Remove" else (
                "purged - binaries and configuration both deleted")
            return f"Package {package} {verb} by apt (was version {version})"
        verb = "reinstalled" if key == "Reinstall" else "installed"
        suffix = " (pulled in automatically as a dependency)" if automatic else ""
        return f"Package {package} {verb} by apt (version {version}){suffix}"
