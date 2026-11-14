"""Network Interfaces parser: /etc/network/interfaces, netplan, ip addr.

Extracts network interface names, MAC addresses, operational states,
and assigned IPv4 / IPv6 addresses.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

_IP_ADDR_IFACE_RE = re.compile(
    r"^\d+:\s+([a-zA-Z0-9_.-]+)(?:@\S+)?: <([^>]+)>.*state\s+([A-Z]+)"
)
_INET_RE = re.compile(r"^\s+inet\s+([0-9.]+/\d+)")
_INET6_RE = re.compile(r"^\s+inet6\s+([0-9a-fA-F:]+/\d+)")
_LINK_ETHER_RE = re.compile(r"^\s+link/ether\s+([0-9a-fA-F:]{17})")


class NetIfacesParser(BaseParser):
    name = "netifaces_parser"
    version = "1.0"
    artifact_category = "network_config"
    applies_to = [
        "etc/network/interfaces",
        "etc/network/interfaces.d/*",
        "etc/netplan/*.yaml",
        "etc/netplan/*.yml",
        "volatile/ip_addr.txt",
        "collected/volatile/ip_addr.txt",
    ]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        rel = context.artifact_rel.replace("\\", "/")
        base = rel.rsplit("/", 1)[-1]

        if "ip_addr" in base:
            yield from self._parse_ip_addr(path, context)
        elif "netplan" in rel:
            yield from self._parse_netplan(path, context)
        else:
            yield from self._parse_interfaces(path, context)

    def _state(self, context: ParseContext, **kw) -> NormalizedEvent:
        kw.setdefault("event_kind", "state_finding")
        kw.setdefault("timestamp_utc", None)
        kw.setdefault("timestamp_local", None)
        kw.setdefault("timestamp_confidence", "unknown")
        kw.setdefault("category", "network_config")
        kw.setdefault("subcategory", "network_interface")
        return context.build_event(**kw)

    def _parse_ip_addr(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        current_iface = None
        current_state = "UNKNOWN"
        current_mac = ""
        current_ips = []
        start_offset = 0
        raw_lines = []

        for offset, line in self.iter_lines(path, context):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            iface_m = _IP_ADDR_IFACE_RE.match(line)
            if iface_m:
                if current_iface:
                    yield self._emit_iface_event(
                        context, current_iface, current_state, current_mac,
                        current_ips, start_offset, "\n".join(raw_lines[:3])
                    )
                current_iface = iface_m.group(1)
                current_state = iface_m.group(3)
                current_mac = ""
                current_ips = []
                start_offset = offset
                raw_lines = [stripped]
                continue

            raw_lines.append(stripped)
            eth_m = _LINK_ETHER_RE.match(line)
            if eth_m:
                current_mac = eth_m.group(1)
                continue

            inet_m = _INET_RE.match(line)
            if inet_m:
                current_ips.append(inet_m.group(1))
                continue

            inet6_m = _INET6_RE.match(line)
            if inet6_m:
                current_ips.append(inet6_m.group(1))
                continue

        if current_iface:
            yield self._emit_iface_event(
                context, current_iface, current_state, current_mac,
                current_ips, start_offset, "\n".join(raw_lines[:3])
            )

    def _emit_iface_event(
        self, context: ParseContext, iface: str, state: str,
        mac: str, ips: list[str], offset: int, raw_summary: str
    ) -> NormalizedEvent:
        ip_str = ", ".join(ips) if ips else "no IP assigned"
        primary_ip = ips[0].split("/")[0] if ips else None
        mac_str = f", MAC: {mac}" if mac else ""
        desc = f"Network interface {iface} (state: {state}{mac_str}, addresses: {ip_str})"
        return self._state(
            context,
            source_ip=primary_ip,
            description=desc,
            severity="info",
            raw_line=raw_summary,
            raw_line_offset=offset,
            notes=f"iface={iface}; state={state}; mac={mac}",
        )

    def _parse_interfaces(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        current_iface = None
        current_mode = ""
        current_addr = ""
        current_netmask = ""
        current_gw = ""
        start_offset = 0

        for offset, line in self.iter_lines(path, context):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            parts = stripped.split()
            if parts[0] == "iface" and len(parts) >= 4:
                if current_iface:
                    yield self._emit_legacy_iface(
                        context, current_iface, current_mode, current_addr,
                        current_netmask, current_gw, start_offset
                    )
                current_iface = parts[1]
                current_mode = parts[3]
                current_addr = ""
                current_netmask = ""
                current_gw = ""
                start_offset = offset
            elif parts[0] == "address" and len(parts) >= 2:
                current_addr = parts[1]
            elif parts[0] == "netmask" and len(parts) >= 2:
                current_netmask = parts[1]
            elif parts[0] == "gateway" and len(parts) >= 2:
                current_gw = parts[1]

        if current_iface:
            yield self._emit_legacy_iface(
                context, current_iface, current_mode, current_addr,
                current_netmask, current_gw, start_offset
            )

    def _emit_legacy_iface(
        self, context: ParseContext, iface: str, mode: str,
        addr: str, netmask: str, gw: str, offset: int
    ) -> NormalizedEvent:
        details = [f"mode: {mode}"]
        if addr:
            details.append(f"address: {addr}")
        if netmask:
            details.append(f"netmask: {netmask}")
        if gw:
            details.append(f"gateway: {gw}")
        desc = f"Network configuration for {iface} ({', '.join(details)})"
        return self._state(
            context,
            source_ip=addr or None,
            description=desc,
            severity="info",
            raw_line=f"iface {iface} {mode} address {addr}",
            raw_line_offset=offset,
            notes=f"iface={iface}; mode={mode}",
        )

    def _parse_netplan(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        try:
            import yaml
            data = yaml.safe_load(path.read_text(encoding="utf-8", errors="surrogateescape"))
        except Exception:
            return

        if not isinstance(data, dict):
            return

        ethernets = data.get("network", {}).get("ethernets", {})
        if not isinstance(ethernets, dict):
            return

        for iface_name, cfg in ethernets.items():
            if not isinstance(cfg, dict):
                continue
            addrs = cfg.get("addresses", [])
            dhcp4 = cfg.get("dhcp4", False)
            primary_ip = addrs[0].split("/")[0] if addrs else None
            desc = f"Netplan interface {iface_name} (addresses: {', '.join(addrs) or 'dhcp' if dhcp4 else 'none'})"
            yield self._state(
                context,
                source_ip=primary_ip,
                description=desc,
                severity="info",
                raw_line=f"{iface_name}: {addrs}",
                raw_line_offset=0,
                notes=f"netplan iface={iface_name}",
            )
