"""USB kernel-message parser (spec category 6, trap #9).

Stitches multi-line kernel messages by bus-port ID (e.g. usb 1-2) into
coherent connect/disconnect events, computes connection duration, and
detects removable storage.
"""
from __future__ import annotations

import gzip
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from ..timeeng import TSResult, parse_syslog_prefix
from .base import BaseParser, ParseContext

_USB_PREFIX_RE = re.compile(
    r"\busb\s+([0-9]+-[0-9]+(?:\.[0-9]+)*):\s+(.*)$"
)
_USB_STORAGE_RE = re.compile(
    r"\busb-storage\s+([0-9]+-[0-9]+(?:\.[0-9]+)*)"
)
_VENDOR_PROD_RE = re.compile(
    r"idVendor=([0-9a-fA-F]{4}),\s*idProduct=([0-9a-fA-F]{4})"
)
_PRODUCT_RE = re.compile(r"^Product:\s*(.*)$")
_MFR_RE = re.compile(r"^Manufacturer:\s*(.*)$")
_SERIAL_RE = re.compile(r"^SerialNumber:\s*(.*)$")
_DISCONNECT_RE = re.compile(r"USB disconnect,\s*device number\s*(\d+)")


def _format_duration(seconds: int) -> str:
    mins, secs = divmod(seconds, 60)
    hours, mins = divmod(mins, 60)
    if hours > 0:
        return f"{hours}h {mins}m {secs}s"
    return f"{mins}m {secs}s"


@dataclass
class _UsbDeviceState:
    port: str
    connect_ts: TSResult
    connect_raw_line: str
    connect_offset: int
    vendor_id: str = ""
    product_id: str = ""
    product_name: str = ""
    manufacturer: str = ""
    serial_number: str = ""
    is_storage: bool = False
    disconnected: bool = False
    disconnect_ts: TSResult | None = None
    disconnect_raw_line: str = ""
    disconnect_offset: int = 0


class UsbParser(BaseParser):
    name = "usb_parser"
    version = "1.0"
    artifact_category = "hardware_usb"
    applies_to = [
        "var/log/kern.log*",
        "var/log/syslog*",
        "var/log/messages*",
    ]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return

        try:
            if path.name.endswith(".gz"):
                with gzip.open(path, "rt", encoding="utf-8", errors="surrogateescape") as fh:
                    lines = fh.readlines()
            else:
                with open(path, "r", encoding="utf-8", errors="surrogateescape") as fh:
                    lines = fh.readlines()
        except Exception:
            return

        active_devices: dict[str, _UsbDeviceState] = {}
        completed_sessions: list[tuple[_UsbDeviceState, bool]] = []

        offset = 0
        for line in lines:
            line_len = len(line.encode("utf-8", errors="surrogateescape"))
            current_offset = offset
            offset += line_len

            raw_stripped = line.strip()
            if not raw_stripped:
                continue

            ts_prefix, rest = parse_syslog_prefix(raw_stripped)
            ts_result = (
                context.time_ctx.resolve_syslog(
                    ts_prefix,
                    file_mtime=context.artifact_mtime,
                )
                if ts_prefix
                else context.time_ctx._unknown()
            )

            storage_m = _USB_STORAGE_RE.search(rest)
            if storage_m:
                port = storage_m.group(1)
                if port in active_devices:
                    active_devices[port].is_storage = True
                continue

            if "Attached SCSI removable disk" in rest or "USB Mass Storage" in rest:
                for port, dev in active_devices.items():
                    if port in rest or dev.is_storage:
                        dev.is_storage = True
                continue

            usb_m = _USB_PREFIX_RE.search(rest)
            if not usb_m:
                continue

            port, msg = usb_m.group(1), usb_m.group(2).strip()

            disc_m = _DISCONNECT_RE.search(msg)
            if disc_m:
                if port in active_devices:
                    dev = active_devices.pop(port)
                    dev.disconnected = True
                    dev.disconnect_ts = ts_result
                    dev.disconnect_raw_line = raw_stripped
                    dev.disconnect_offset = current_offset
                    completed_sessions.append((dev, True))
                else:
                    yield context.build_event(
                        event_kind="event",
                        category="hardware_usb",
                        subcategory="usb_disconnect",
                        severity="info",
                        timestamp_utc=ts_result.utc_iso,
                        timestamp_local=ts_result.local_iso,
                        timestamp_confidence=ts_result.confidence,
                        description=f"USB device on port {port} disconnected ({msg})",
                        raw_line=raw_stripped,
                        raw_line_offset=current_offset,
                        notes="no matching connect event found in log",
                    )
                continue

            if "new high-speed USB device" in msg or "new full-speed USB device" in msg or "new low-speed USB device" in msg or "new SuperSpeed" in msg:
                if port in active_devices:
                    old_dev = active_devices.pop(port)
                    completed_sessions.append((old_dev, False))

                active_devices[port] = _UsbDeviceState(
                    port=port,
                    connect_ts=ts_result,
                    connect_raw_line=raw_stripped,
                    connect_offset=current_offset,
                )
                continue

            dev = active_devices.get(port)
            if not dev:
                if "New USB device found" in msg:
                    dev = _UsbDeviceState(
                        port=port,
                        connect_ts=ts_result,
                        connect_raw_line=raw_stripped,
                        connect_offset=current_offset,
                    )
                    active_devices[port] = dev
                else:
                    continue

            vp_m = _VENDOR_PROD_RE.search(msg)
            if vp_m:
                dev.vendor_id = vp_m.group(1)
                dev.product_id = vp_m.group(2)
                continue

            prod_m = _PRODUCT_RE.match(msg)
            if prod_m:
                dev.product_name = prod_m.group(1).strip()
                continue

            mfr_m = _MFR_RE.match(msg)
            if mfr_m:
                dev.manufacturer = mfr_m.group(1).strip()
                continue

            ser_m = _SERIAL_RE.match(msg)
            if ser_m:
                dev.serial_number = ser_m.group(1).strip()
                continue

        for port, dev in active_devices.items():
            completed_sessions.append((dev, False))

        for dev, has_disconnect in completed_sessions:
            dev_name_parts = []
            if dev.manufacturer:
                dev_name_parts.append(dev.manufacturer)
            if dev.product_name:
                dev_name_parts.append(dev.product_name)
            dev_title = " ".join(dev_name_parts) or f"USB device ({dev.port})"

            connect_desc_parts = [
                f"USB device attached on port {dev.port}: {dev_title}",
            ]
            if dev.vendor_id and dev.product_id:
                connect_desc_parts.append(f"idVendor={dev.vendor_id} idProduct={dev.product_id} {dev.vendor_id} {dev.product_id}")
            if dev.serial_number:
                connect_desc_parts.append(f"serial={dev.serial_number}")

            severity = "medium" if dev.is_storage else "info"
            connect_notes = []
            if dev.is_storage:
                connect_notes.append("USB Mass Storage device detected")
            if not has_disconnect:
                connect_notes.append("Device was not disconnected during log window (still attached)")

            yield context.build_event(
                event_kind="event",
                category="hardware_usb",
                subcategory="usb_connect",
                severity=severity,
                timestamp_utc=dev.connect_ts.utc_iso,
                timestamp_local=dev.connect_ts.local_iso,
                timestamp_confidence=dev.connect_ts.confidence,
                description=" ".join(connect_desc_parts),
                raw_line=dev.connect_raw_line,
                raw_line_offset=dev.connect_offset,
                notes="; ".join(connect_notes) if connect_notes else None,
            )

            if has_disconnect and dev.disconnect_ts is not None:
                duration_str = ""
                if dev.connect_ts.utc_iso and dev.disconnect_ts.utc_iso:
                    try:
                        t1 = datetime.fromisoformat(dev.connect_ts.utc_iso)
                        t2 = datetime.fromisoformat(dev.disconnect_ts.utc_iso)
                        dur_sec = int((t2 - t1).total_seconds())
                        if dur_sec >= 0:
                            duration_str = _format_duration(dur_sec)
                    except Exception:
                        pass

                disc_desc = f"USB device {dev_title} on port {dev.port} disconnected"
                if duration_str:
                    disc_desc += f" after {duration_str}"

                yield context.build_event(
                    event_kind="event",
                    category="hardware_usb",
                    subcategory="usb_disconnect",
                    severity="info",
                    timestamp_utc=dev.disconnect_ts.utc_iso,
                    timestamp_local=dev.disconnect_ts.local_iso,
                    timestamp_confidence=dev.disconnect_ts.confidence,
                    description=disc_desc,
                    raw_line=dev.disconnect_raw_line,
                    raw_line_offset=dev.disconnect_offset,
                    notes=f"Attached duration: {duration_str}" if duration_str else None,
                )
