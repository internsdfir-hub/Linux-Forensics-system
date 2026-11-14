"""Storage & Hard Disk parser: /etc/fstab, lsblk, blkid, mount.

Extracts connected storage devices, partition layouts, mount points,
filesystems, UUIDs, and mount options.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

_BLKID_RE = re.compile(
    r"^(/dev/\S+):\s+(?:LABEL=\"([^\"]*)\"\s+)?(?:UUID=\"([^\"]*)\"\s+)?"
    r"(?:BLOCK_SIZE=\"([^\"]*)\"\s+)?(?:TYPE=\"([^\"]*)\")?"
)
_MOUNT_LINE_RE = re.compile(
    r"^(/dev/\S+)\s+on\s+(\S+)\s+type\s+(\S+)\s+\(([^)]+)\)"
)


class StorageParser(BaseParser):
    name = "storage_parser"
    version = "1.0"
    artifact_category = "environment"
    applies_to = [
        "etc/fstab",
        "volatile/lsblk.txt",
        "volatile/blkid.txt",
        "volatile/mount.txt",
        "collected/volatile/lsblk.txt",
        "collected/volatile/blkid.txt",
        "collected/volatile/mount.txt",
    ]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        rel = context.artifact_rel.replace("\\", "/")
        base = rel.rsplit("/", 1)[-1]

        if base == "fstab":
            yield from self._parse_fstab(path, context)
        elif "lsblk" in base:
            yield from self._parse_lsblk(path, context)
        elif "blkid" in base:
            yield from self._parse_blkid(path, context)
        elif "mount" in base:
            yield from self._parse_mount(path, context)

    def _state(self, context: ParseContext, **kw) -> NormalizedEvent:
        kw.setdefault("event_kind", "state_finding")
        kw.setdefault("timestamp_utc", None)
        kw.setdefault("timestamp_local", None)
        kw.setdefault("timestamp_confidence", "unknown")
        kw.setdefault("category", "environment")
        return context.build_event(**kw)

    def _parse_fstab(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        for offset, line in self.iter_lines(path, context):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            fields = stripped.split()
            if len(fields) < 3:
                continue

            fs_spec = fields[0]
            mount_point = fields[1]
            fs_type = fields[2]
            options = fields[3] if len(fields) > 3 else "defaults"
            dump_pass = " ".join(fields[4:]) if len(fields) > 4 else ""

            uuid = ""
            if fs_spec.startswith("UUID="):
                uuid = fs_spec.split("=", 1)[1].strip('"\'')
            elif fs_spec.startswith("LABEL="):
                uuid = f"LABEL:{fs_spec.split('=', 1)[1].strip('\"\'')}"

            desc = f"Static mount {mount_point} on {fs_spec} (type: {fs_type}, options: {options})"
            yield self._state(
                context,
                subcategory="storage_device",
                description=desc,
                severity="info",
                raw_line=stripped,
                raw_line_offset=offset,
                notes=f"fstab; uuid={uuid}" if uuid else "fstab",
            )

    def _parse_lsblk(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        lines = list(self.iter_lines(path, context))
        if not lines:
            return

        header_line = None
        header_idx = -1
        for i, (offset, line) in enumerate(lines):
            if "NAME" in line and ("FSTYPE" in line or "MOUNT" in line or "UUID" in line):
                header_line = line.strip().split()
                header_idx = i
                break

        if header_idx == -1:
            return

        for offset, line in lines[header_idx + 1:]:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            clean = re.sub(r"[├─└│\s]+", " ", line).strip()
            parts = clean.split()
            if not parts:
                continue

            dev_name = parts[0]
            desc = f"Storage device/partition: {dev_name} ({clean})"
            yield self._state(
                context,
                subcategory="storage_device",
                description=desc,
                severity="info",
                raw_line=stripped,
                raw_line_offset=offset,
                notes="lsblk output",
            )

    def _parse_blkid(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        for offset, line in self.iter_lines(path, context):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            m = _BLKID_RE.match(stripped)
            if m:
                dev = m.group(1)
                label = m.group(2) or ""
                uuid = m.group(3) or ""
                fstype = m.group(5) or "unknown"
                desc = f"Block device {dev} (type: {fstype}"
                if uuid:
                    desc += f", UUID: {uuid}"
                if label:
                    desc += f", Label: {label}"
                desc += ")"
                yield self._state(
                    context,
                    subcategory="storage_device",
                    description=desc,
                    severity="info",
                    raw_line=stripped,
                    raw_line_offset=offset,
                    notes=f"blkid; uuid={uuid}",
                )
            else:
                parts = stripped.split(":", 1)
                dev = parts[0]
                yield self._state(
                    context,
                    subcategory="storage_device",
                    description=f"Block device {dev} ({parts[1].strip() if len(parts) > 1 else ''})",
                    severity="info",
                    raw_line=stripped,
                    raw_line_offset=offset,
                    notes="blkid",
                )

    def _parse_mount(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        for offset, line in self.iter_lines(path, context):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            m = _MOUNT_LINE_RE.match(stripped)
            if m:
                dev = m.group(1)
                mount_pt = m.group(2)
                fstype = m.group(3)
                opts = m.group(4)
                yield self._state(
                    context,
                    subcategory="filesystem_mount",
                    description=f"Active filesystem mount: {dev} on {mount_pt} (type {fstype}, {opts})",
                    severity="info",
                    raw_line=stripped,
                    raw_line_offset=offset,
                    notes="active mount",
                )
