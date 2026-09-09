"""Netstat & SS parser for volatile network connections.

Extracts:
1. volatile/ss.txt
2. volatile/netstat.txt
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

# Netstat line: tcp 0 0 192.168.197.1:22 192.168.197.2:53245 ESTABLISHED 1234/sshd
_RE_NETSTAT = re.compile(
    r"^(tcp|udp)[46]?\s+\d+\s+\d+\s+"
    r"([a-fA-F0-9:.]+):([a-zA-Z0-9*]+)\s+"
    r"([a-fA-F0-9:.]+):([a-zA-Z0-9*]+)\s*"
    r"([A-Z_]+)?\s*"
    r"(?:-|\d+/([^ \n]+).*)?$"
)

# SS line: tcp ESTAB 0 0 192.168.197.1:22 192.168.197.2:53245 users:(("sshd",pid=1234,fd=3))
_RE_SS = re.compile(
    r"^(tcp|udp)[46]?\s+([A-Z_]+)\s+\d+\s+\d+\s+"
    r"([a-fA-F0-9:.]+):([a-zA-Z0-9*]+)\s+"
    r"([a-fA-F0-9:.]+):([a-zA-Z0-9*]+)\s*"
    r"(?:.*users:\(\(\"([^\"]+)\".*)?$"
)


class NetstatParser(BaseParser):
    name = "netstat_parser"
    version = "1.0"
    artifact_category = "network_connection"
    applies_to = [
        "volatile/ss.txt",
        "volatile/netstat.txt",
    ]

    def _state(self, context: ParseContext, **kw) -> NormalizedEvent:
        kw.setdefault("event_kind", "state_finding")
        kw.setdefault("timestamp_utc", None)
        kw.setdefault("timestamp_local", None)
        kw.setdefault("timestamp_confidence", "unknown")
        kw.setdefault("category", "network_config")
        return context.build_event(**kw)

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return

        rel = context.artifact_rel.replace("\\", "/")

        for offset, line in self.iter_lines(path, context):
            line_str = line.strip()
            if not line_str or line_str.startswith("Active") or line_str.startswith("Proto") or line_str.startswith("Netid"):
                continue

            proto = ""
            state = ""
            local_ip = ""
            local_port = ""
            remote_ip = ""
            remote_port = ""
            process = ""

            if "ss.txt" in rel:
                m = _RE_SS.match(line_str)
                if not m:
                    continue
                proto, state, local_ip, local_port, remote_ip, remote_port = m.group(1, 2, 3, 4, 5, 6)
                process = m.group(7) or ""
            else:
                m = _RE_NETSTAT.match(line_str)
                if not m:
                    continue
                proto, local_ip, local_port, remote_ip, remote_port = m.group(1, 2, 3, 4, 5)
                state = m.group(6) or "UNKNOWN"
                process = m.group(7) or ""

            # Normalize state
            state = state.upper()
            if state == "ESTAB":
                state = "ESTABLISHED"
            if proto.startswith("udp") and state == "UNKNOWN":
                state = "UNCONN"

            desc = f"{proto.upper()} {state}: {local_ip}:{local_port} -> {remote_ip}:{remote_port}"
            if process:
                desc += f" ({process})"

            yield self._state(
                context,
                subcategory=state.lower(),
                source_ip=remote_ip if remote_ip not in ("0.0.0.0", "*", "::") else None,
                actor_process=process if process else None,
                description=desc,
                severity="info" if state in ("LISTEN", "UNCONN", "TIME_WAIT", "CLOSE_WAIT") else "medium",
                raw_line=line_str,
                raw_line_offset=offset,
                notes=rel.split("/")[-1],
            )
