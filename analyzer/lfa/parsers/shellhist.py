"""Shell history parser (spec category 8).

Handles plain bash history, bash with HISTTIMEFORMAT (#<epoch>), and
zsh extended history (: <epoch>:<elapsed>;<command>). Preserves temporal
ordering and classifies suspicious shell commands.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

_ZSH_EXTENDED_RE = re.compile(r"^:\s*(\d+):(?:\d+);(.*)$", re.S)
_BASH_EPOCH_RE = re.compile(r"^#(\d{9,12})$")

_SUSPICIOUS_HIGH_PATTERNS = [
    re.compile(r"\|\s*(?:bash|sh|zsh|dash)\b"),
    re.compile(r"\bnc(?:\.traditional)?\b.*-(?:e|c)\b"),
    re.compile(r"/dev/tcp/|/dev/udp/"),
    re.compile(r"\bhistory\s+-[cw]\b"),
    re.compile(r"\brm\s+(?:-[rf]+\s+)?~?/?(?:\.bash_history|\.zsh_history)"),
    re.compile(r">\s*~?/?(?:\.bash_history|\.zsh_history)"),
    re.compile(r"\bshred\b"),
    re.compile(r"\bchattr\s+[+-][a-zA-Z]"),
    re.compile(r"\bauthorized_keys\b"),
    re.compile(r"\buseradd\b|\badduser\b"),
    re.compile(r"\busermod\s+.*-(?:a?G|g)\s+(?:sudo|wheel|admin|root|docker)\b"),
    re.compile(r"\biptables\s+-F\b|\bufw\s+disable\b"),
    re.compile(r"\bsystemctl\s+(?:disable|stop)\s+(?:ufw|fail2ban|auditd|apparmor|selinux)\b"),
    re.compile(r"\bsetenforce\s+0\b"),
]

_SUSPICIOUS_MEDIUM_PATTERNS = [
    re.compile(r"\bbase64\s+-d\b|\|\s*base64\s+-d\b"),
    re.compile(r"\bchmod\s+\+x\b"),
    re.compile(r"\bcurl\s+https?://|\bwget\s+https?://"),
    re.compile(r"\bscp\b|\brsync\b"),
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),  # Long base64 string
]


def _extract_user_from_path(rel_path: str) -> str | None:
    norm = rel_path.replace("\\", "/").strip("/")
    parts = norm.split("/")
    if len(parts) >= 2 and parts[0] == "home":
        return parts[1]
    if len(parts) >= 1 and parts[0] == "root":
        return "root"
    return None


def _classify_command(cmd: str) -> tuple[str, str]:
    """Returns (subcategory, severity)."""
    for pat in _SUSPICIOUS_HIGH_PATTERNS:
        if pat.search(cmd):
            return "suspicious_command", "high"

    for pat in _SUSPICIOUS_MEDIUM_PATTERNS:
        if pat.search(cmd):
            return "suspicious_command", "medium"

    return "shell_command", "info"


class ShellHistParser(BaseParser):
    name = "shellhist_parser"
    version = "1.0"
    artifact_category = "user_activity"
    applies_to = [
        "home/*/.bash_history*",
        "root/.bash_history*",
        "home/*/.zsh_history*",
        "root/.zsh_history*",
        "home/*/.history*",
        "root/.history*",
        "home/*/.python_history*",
        "root/.python_history*",
        "home/*/.mysql_history*",
        "root/.mysql_history*",
    ]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return

        actor_user = _extract_user_from_path(context.artifact_rel)

        try:
            content = path.read_text(encoding="utf-8", errors="surrogateescape")
        except Exception:
            return

        lines = content.splitlines(keepends=True)
        offset = 0
        pending_epoch: int | None = None
        pending_offset: int | None = None

        for line in lines:
            line_len = len(line.encode("utf-8", errors="surrogateescape"))
            current_offset = offset
            offset += line_len

            line_stripped = line.strip()
            if not line_stripped:
                continue

            # Check for bash HISTTIMEFORMAT comment (#<epoch>)
            epoch_match = _BASH_EPOCH_RE.match(line_stripped)
            if epoch_match:
                try:
                    pending_epoch = int(epoch_match.group(1))
                    pending_offset = current_offset
                    continue
                except ValueError:
                    pending_epoch = None

            # Check for zsh extended format
            zsh_match = _ZSH_EXTENDED_RE.match(line_stripped)
            if zsh_match:
                try:
                    epoch = int(zsh_match.group(1))
                    cmd = zsh_match.group(2).strip()
                    ts = context.time_ctx.resolve_epoch(epoch)
                    subcat, severity = _classify_command(cmd)
                    yield context.build_event(
                        event_kind="event",
                        category="user_activity",
                        subcategory=subcat,
                        severity=severity,
                        timestamp_utc=ts.utc_iso,
                        timestamp_local=ts.local_iso,
                        timestamp_confidence="exact",
                        actor_user=actor_user,
                        description=f"User {actor_user or 'unknown'} executed: {cmd}",
                        raw_line=cmd,
                        raw_line_offset=current_offset,
                    )
                    continue
                except ValueError:
                    pass

            # Command line with pending bash epoch
            if pending_epoch is not None:
                cmd = line_stripped
                ts = context.time_ctx.resolve_epoch(pending_epoch)
                subcat, severity = _classify_command(cmd)
                yield context.build_event(
                    event_kind="event",
                    category="user_activity",
                    subcategory=subcat,
                    severity=severity,
                    timestamp_utc=ts.utc_iso,
                    timestamp_local=ts.local_iso,
                    timestamp_confidence="exact",
                    actor_user=actor_user,
                    description=f"User {actor_user or 'unknown'} executed: {cmd}",
                    raw_line=cmd,
                    raw_line_offset=pending_offset if pending_offset is not None else current_offset,
                )
                pending_epoch = None
                pending_offset = None
                continue

            # Plain command without timestamp
            cmd = line_stripped
            subcat, severity = _classify_command(cmd)
            yield context.build_event(
                event_kind="event",
                category="user_activity",
                subcategory=subcat,
                severity=severity,
                timestamp_utc=None,
                timestamp_local=None,
                timestamp_confidence="unknown",
                actor_user=actor_user,
                description=f"User {actor_user or 'unknown'} executed: {cmd}",
                raw_line=cmd,
                raw_line_offset=current_offset,
            )
