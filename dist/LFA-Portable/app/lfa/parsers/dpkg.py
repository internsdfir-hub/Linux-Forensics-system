"""dpkg.log parser - Debian-family package operations (spec category 5).

dpkg.log answers "what was installed/removed and exactly when". It does NOT
record who asked for it (that is /var/log/apt/history.log's unique value), so
this parser deliberately leaves actor_user empty rather than guessing root.

Only the four real state transitions are emitted - install, upgrade, remove,
purge. dpkg also logs `status`, `configure`, `trigproc` and `startup` lines for
every single package operation; emitting those would bury the analyst in
three-to-one noise for zero investigative gain.

Timestamps are host-LOCAL wall clock with no offset ("2024-03-10 02:30:01"),
so they are resolved through the host timezone from /etc/localtime and are
"exact" - the year is right there in the line, nothing is inferred.

Severity policy (shared with dnf_parser):
  info    ordinary package activity
  medium  the package is a recognised attacker toolkit item
  high    a security control was REMOVED or PURGED - an attacker disabling
          auditd/ufw/fail2ban is a louder signal than one installing nmap
"""
from __future__ import annotations

import re
from pathlib import Path

from .base import BaseParser, ParseContext

# Emitted actions. `status`, `configure`, `trigproc`, `startup` are noise.
REPORTABLE_ACTIONS = ("install", "upgrade", "remove", "purge")

# Dual-use/offensive tooling: not malicious by itself, but its arrival on a
# server during an incident window is worth an analyst's attention.
ATTACK_TOOL_TOKENS = {
    "netcat", "nc", "ncat", "nmap", "socat", "tcpdump", "john", "hydra",
    "masscan",
}

# Defensive controls: removing these is how an intruder goes quiet.
SECURITY_TOOL_TOKENS = {
    "auditd", "audit", "ufw", "fail2ban", "apparmor", "selinux", "clamav",
    "clamd", "rkhunter",
}

_LINE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>[a-z-]+)\s+(?P<rest>.*)$"
)

_SPLIT = re.compile(r"[-_.+]")


def package_tokens(package: str) -> set[str]:
    """Split 'netcat-openbsd:amd64' into {'netcat', 'openbsd'} so name
    matching survives Debian's suffixing habits without matching substrings
    inside unrelated names (python3-johnson must not look like john)."""
    name = package.split(":", 1)[0].lower()
    return {tok for tok in _SPLIT.split(name) if tok}


def is_attack_tool(package: str) -> bool:
    return bool(package_tokens(package) & ATTACK_TOOL_TOKENS)


def is_security_tool(package: str) -> bool:
    return bool(package_tokens(package) & SECURITY_TOOL_TOKENS)


def classify_severity(package: str, action: str) -> tuple[str, str | None]:
    """Return (severity, note). Shared by dpkg_parser and dnf_parser."""
    removing = action in ("remove", "purge", "erase", "package_remove")
    if removing and is_security_tool(package):
        return "high", (
            "a security control was removed: this reduces the host's ability "
            "to detect or block later activity"
        )
    if is_attack_tool(package):
        return "medium", (
            "package is commonly used for reconnaissance, tunnelling or "
            "credential attacks"
        )
    return "info", None


class DpkgParser(BaseParser):
    name = "dpkg_parser"
    version = "1.0"
    artifact_category = "software_changes"
    applies_to = ["var/log/dpkg.log", "var/log/dpkg.log.*"]

    def parse(self, path: Path, context: ParseContext):
        for offset, line in self.iter_lines(path, context):
            if not line.strip():
                continue
            match = _LINE.match(line.strip())
            if not match:
                continue
            action = match.group("action")
            if action not in REPORTABLE_ACTIONS:
                continue
            fields = match.group("rest").split()
            if not fields:
                continue

            package = fields[0]
            old_version = fields[1] if len(fields) > 1 else "<none>"
            new_version = fields[2] if len(fields) > 2 else "<none>"
            severity, note = classify_severity(package, action)

            ts = context.time_ctx.resolve_iso(
                f"{match.group('date')} {match.group('time')}"
            )

            yield context.build_event(
                event_kind="event",
                timestamp_utc=ts.utc_iso,
                timestamp_local=ts.local_iso,
                timestamp_confidence=ts.confidence,
                category="software_changes",
                subcategory=action,
                actor_process="dpkg",
                description=self._describe(action, package, old_version,
                                           new_version),
                severity=severity,
                raw_line=line,
                raw_line_offset=offset,
                notes=note,
            )

    @staticmethod
    def _describe(action: str, package: str, old: str, new: str) -> str:
        none = {"<none>", ""}
        if action == "install":
            version = new if new not in none else old
            return f"Package {package} installed (version {version})"
        if action == "upgrade":
            return f"Package {package} upgraded from {old} to {new}"
        if action == "remove":
            return f"Package {package} removed (was version {old})"
        if action == "purge":
            return (f"Package {package} purged - binaries and configuration "
                    f"both deleted (was version {old})")
        return f"Package {package} {action} ({old} -> {new})"
