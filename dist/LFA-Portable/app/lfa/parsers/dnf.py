"""dnf / dnf.rpm / yum log parser (spec category 5, software changes).

The RHEL-family counterpart to dpkg_parser, and it has to speak two dialects
that happen to live under the same filenames across releases:

  dnf (and dnf.rpm.log)
      2024-03-10T02:30:01+0500 SUBDEBUG Installed: netcat-1.2-3.x86_64
      ISO-8601 with a COLON-LESS UTC offset. datetime.fromisoformat has
      accepted that form only since 3.11, so the offset is normalised to
      +05:00 before parsing rather than depending on the interpreter.
      The year is present -> confidence "exact".

  yum (older RHEL/CentOS)
      Mar 10 02:30:01 Installed: netcat-1.2-3.x86_64
      Classic syslog: no year, no zone. The year comes from the artifact
      mtime (or an ISO anchor in the same file) -> "year_inferred".

Both dialects bury the interesting lines in DEBUG/DDEBUG chatter, so only the
rpm transaction verbs are emitted. Severity policy is shared with
dpkg_parser so a removed auditd scores the same on Debian and on RHEL.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..timeeng import find_anchor_year, parse_syslog_prefix
from .base import BaseParser, ParseContext
from .dpkg import classify_severity

# rpm transaction verbs -> our subcategories. "Obsoleted"/"Verified"/
# "Cleanup" say nothing about what is now on the box, so they are dropped.
ACTIONS = {
    "Installed": "package_install",
    "Reinstalled": "package_install",
    "Erased": "package_remove",
    "Removed": "package_remove",
    "Upgraded": "package_upgrade",
    "Updated": "package_upgrade",
    "Downgraded": "package_upgrade",
}

_ACTION_RE = re.compile(
    r"\b(?P<action>" + "|".join(ACTIONS) + r"):\s+(?P<package>\S+)"
)

# 2024-03-10T02:30:01+0500 / -0500 / +05:00 / Z
_ISO_PREFIX = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?)"
)


def normalise_iso(stamp: str) -> str:
    """'2024-03-10T02:30:01+0500' -> '2024-03-10T02:30:01+05:00'."""
    stamp = stamp.strip().replace(",", ".")
    if stamp.endswith("Z"):
        return stamp[:-1] + "+00:00"
    m = re.search(r"([+-])(\d{2})(\d{2})$", stamp)
    if m:
        return f"{stamp[:m.start()]}{m.group(1)}{m.group(2)}:{m.group(3)}"
    return stamp


def rpm_package_name(nevra: str) -> str:
    """'openssl-1:3.0.1-43.el9.x86_64' -> 'openssl'.

    Best effort: strip the arch, then everything from the first hyphen that
    is followed by a digit or an epoch, which is where version-release starts.
    """
    name = nevra
    for arch in (".x86_64", ".noarch", ".i686", ".aarch64", ".armv7hl",
                 ".ppc64le", ".s390x", ".src"):
        if name.endswith(arch):
            name = name[: -len(arch)]
            break
    m = re.search(r"-(?=\d|\d*:)", name)
    return name[: m.start()] if m else name


class DnfParser(BaseParser):
    name = "dnf_parser"
    version = "1.0"
    artifact_category = "software_changes"
    applies_to = [
        "var/log/dnf.log", "var/log/dnf.log.*",
        "var/log/dnf.rpm.log", "var/log/dnf.rpm.log.*",
        "var/log/yum.log", "var/log/yum.log.*",
    ]

    def parse(self, path: Path, context: ParseContext):
        sample = []
        for i, (_, line) in enumerate(self.iter_lines(path, context)):
            sample.append(line)
            if i > 200:
                break
        anchor = find_anchor_year(sample)

        for offset, line in self.iter_lines(path, context):
            if not line.strip():
                continue
            action_match = _ACTION_RE.search(line)
            if not action_match:
                continue
            action = action_match.group("action")
            nevra = action_match.group("package").rstrip(",;")
            subcategory = ACTIONS[action]

            ts = self._resolve(line, context, anchor)
            severity, note = classify_severity(
                rpm_package_name(nevra),
                "remove" if subcategory == "package_remove" else "install",
            )

            yield context.build_event(
                event_kind="event",
                timestamp_utc=ts.utc_iso if ts else None,
                timestamp_local=ts.local_iso if ts else None,
                timestamp_confidence=ts.confidence if ts else "unknown",
                category="software_changes",
                subcategory=subcategory,
                actor_process="dnf/yum",
                description=self._describe(action, nevra),
                severity=severity,
                raw_line=line,
                raw_line_offset=offset,
                notes=note,
            )

    # ------------------------------------------------------------ timestamps

    @staticmethod
    def _resolve(line: str, context: ParseContext, anchor: int | None):
        iso = _ISO_PREFIX.match(line.strip())
        if iso:
            result = context.time_ctx.resolve_iso(
                normalise_iso(iso.group("stamp"))
            )
            return result if result.utc_iso else None
        prefix, _rest = parse_syslog_prefix(line.strip())
        if prefix is not None:
            result = context.time_ctx.resolve_syslog(
                prefix, file_mtime=context.artifact_mtime, anchor_year=anchor
            )
            return result if result.utc_iso else None
        return None

    @staticmethod
    def _describe(action: str, nevra: str) -> str:
        verbs = {
            "Installed": "installed",
            "Reinstalled": "reinstalled",
            "Erased": "removed",
            "Removed": "removed",
            "Upgraded": "upgraded",
            "Updated": "updated",
            "Downgraded": "downgraded",
        }
        return f"Package {nevra} {verbs.get(action, action.lower())} (rpm)"
