"""DNS Configuration and Query Log parser.

Extracts:
1. /etc/resolv.conf: configured nameservers and search domains.
2. /etc/hosts: static IP-to-hostname mappings.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

_RE_RESOLV_NAMESERVER = re.compile(r"^\s*nameserver\s+([a-fA-F0-9:.]+)", re.IGNORECASE)
_RE_RESOLV_SEARCH = re.compile(r"^\s*(?:search|domain)\s+(.+)", re.IGNORECASE)
_RE_HOSTS_ENTRY = re.compile(r"^\s*([a-fA-F0-9:.]+)\s+([^#\s]+.*)")


class DnsParser(BaseParser):
    name = "dns_parser"
    version = "1.0"
    artifact_category = "network_config"
    applies_to = [
        "etc/resolv.conf*",
        "etc/hosts*",
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

        if "resolv.conf" in rel:
            for offset, line in self.iter_lines(path, context):
                line_str = line.strip()
                if not line_str or line_str.startswith("#") or line_str.startswith(";"):
                    continue

                m_ns = _RE_RESOLV_NAMESERVER.match(line_str)
                if m_ns:
                    ns_ip = m_ns.group(1).strip()
                    yield self._state(
                        context,
                        subcategory="dns_nameserver",
                        source_ip=ns_ip,
                        description=f"Configured DNS nameserver resolver: {ns_ip}",
                        severity="info",
                        raw_line=line_str,
                        raw_line_offset=offset,
                        notes="resolv.conf",
                    )
                    continue

                m_search = _RE_RESOLV_SEARCH.match(line_str)
                if m_search:
                    domains = m_search.group(1).strip()
                    yield self._state(
                        context,
                        subcategory="dns_search",
                        description=f"Configured DNS search domains: {domains}",
                        severity="info",
                        raw_line=line_str,
                        raw_line_offset=offset,
                        notes="resolv.conf",
                    )

        elif "hosts" in rel:
            for offset, line in self.iter_lines(path, context):
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue

                # Strip trailing comment
                if "#" in line_str:
                    line_str = line_str.split("#", 1)[0].strip()

                m = _RE_HOSTS_ENTRY.match(line_str)
                if m:
                    ip = m.group(1).strip()
                    hostnames = " ".join(m.group(2).split())
                    yield self._state(
                        context,
                        subcategory="dns_mapping",
                        source_ip=ip,
                        source_host=hostnames.split()[0] if hostnames else None,
                        description=f"Static DNS host resolution: {ip} -> {hostnames}",
                        severity="info",
                        raw_line=line_str,
                        raw_line_offset=offset,
                        notes="etc/hosts",
                    )
