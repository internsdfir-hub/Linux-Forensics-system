"""known_hosts parser (spec category 8).

known_hosts is OUTBOUND evidence: every entry is a host this user's account
connected TO and accepted a key from. Entries may be hashed (|1|salt|hash),
in which case the hostname is genuinely NOT recoverable - the parser marks
this clearly.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

_MARKERS = {"@cert-authority", "@revoked"}


def _extract_user_from_path(rel_path: str) -> str | None:
    norm = rel_path.replace("\\", "/").strip("/")
    parts = norm.split("/")
    if len(parts) >= 2 and parts[0] == "home":
        return parts[1]
    if len(parts) >= 1 and parts[0] == "root":
        return "root"
    return None


def _is_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val.strip("[]"))
        return True
    except ValueError:
        return False


class KnownHostsParser(BaseParser):
    name = "knownhosts_parser"
    version = "1.0"
    artifact_category = "user_activity"
    applies_to = [
        "home/*/.ssh/known_hosts*",
        "root/.ssh/known_hosts*",
    ]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return

        actor_user = _extract_user_from_path(context.artifact_rel)

        try:
            content = path.read_text(encoding="utf-8", errors="surrogateescape")
        except Exception:
            return

        offset = 0
        for line in content.splitlines(keepends=True):
            raw_line_stripped = line.strip()
            line_len = len(line.encode("utf-8", errors="surrogateescape"))
            current_offset = offset
            offset += line_len

            if not raw_line_stripped or raw_line_stripped.startswith("#"):
                continue

            tokens = raw_line_stripped.split()
            if not tokens:
                continue

            marker = None
            if tokens[0] in _MARKERS:
                marker = tokens[0]
                tokens = tokens[1:]

            if len(tokens) < 2:
                continue

            host_spec = tokens[0]
            key_type = tokens[1]
            key_b64 = tokens[2] if len(tokens) > 2 else ""

            # Check for hashed known_hosts entry (|1|salt|hash)
            if host_spec.startswith("|1|"):
                desc = (
                    f"User {actor_user or 'unknown'} connected to remote host (Hashed entry: "
                    f"hostname is not recoverable) [{key_type}]"
                )
                if marker:
                    desc += f" {marker}"
                yield context.build_event(
                    event_kind="state_finding",
                    category="user_activity",
                    subcategory="known_host_hashed",
                    severity="info",
                    timestamp_utc=None,
                    timestamp_local=None,
                    timestamp_confidence="unknown",
                    actor_user=actor_user,
                    source_ip=None,
                    source_host=None,
                    description=desc,
                    raw_line=raw_line_stripped,
                    raw_line_offset=current_offset,
                )
                continue

            # Comma-separated host aliases
            host_parts = host_spec.split(",")
            primary = host_parts[0]
            port = None

            # Handle bracketed host [hostname_or_ip]:port
            port_match = re.match(r"^\[([^\]]+)\](?::(\d+))?$", primary)
            if port_match:
                target = port_match.group(1)
                port = port_match.group(2)
            else:
                target = primary

            src_ip = None
            src_host = None
            if _is_ip(target):
                src_ip = target
            else:
                src_host = target

            desc_parts = [f"User {actor_user or 'unknown'} connected to {target}"]
            if port:
                desc_parts.append(f"on port {port}")
            if len(host_parts) > 1:
                desc_parts.append(f"(aliases: {', '.join(host_parts[1:])})")
            desc_parts.append(f"[{key_type}]")
            if marker:
                desc_parts.append(marker)

            desc = " ".join(desc_parts)

            yield context.build_event(
                event_kind="state_finding",
                category="user_activity",
                subcategory="known_host",
                severity="info",
                timestamp_utc=None,
                timestamp_local=None,
                timestamp_confidence="unknown",
                actor_user=actor_user,
                source_ip=src_ip,
                source_host=src_host,
                description=desc,
                raw_line=raw_line_stripped,
                raw_line_offset=current_offset,
            )
