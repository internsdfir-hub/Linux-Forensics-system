"""FTP log parser (vsftpd.log and standard xferlog).

Extracts file uploads, downloads, authenticated users, transfer sizes,
and client IP addresses.
"""
from __future__ import annotations

import gzip
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

# vsftpd standard format:
# Sun Mar 22 10:14:23 2020 [pid 1234] [user] OK LOGIN: Client "1.2.3.4"
# Sun Mar 22 10:15:10 2020 [pid 1234] [user] OK UPLOAD: Client "1.2.3.4", "/path", 123 bytes
_VSFTPD_RE = re.compile(
    r"^([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+\[pid\s+\d+\]\s+\[([^\]]+)\]\s+(OK|FAIL)\s+([A-Z]+):\s+Client\s+\"([^\"]+)\"(?:,\s+\"([^\"]*)\")?(?:,\s+(\d+)\s+bytes)?"
)

# Standard xferlog format (18 fields):
# Sun Mar 22 10:15:10 2020 1 192.168.1.50 1234 /pub/file b _ i r user ftp 0 * c
_XFERLOG_RE = re.compile(
    r"^([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+\S+\s+\S+\s+([io])\s+\S+\s+(\S+)"
)


class FtpLogParser(BaseParser):
    name = "ftplog_parser"
    version = "1.0"
    artifact_category = "user_activity"
    applies_to = [
        "var/log/vsftpd.log*",
        "var/log/xferlog*",
    ]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return

        try:
            if path.name.endswith(".gz"):
                fh = gzip.open(path, "rt", encoding="utf-8", errors="surrogateescape")
            else:
                fh = open(path, "r", encoding="utf-8", errors="surrogateescape")
        except Exception:
            return

        try:
            offset = 0
            for line in fh:
                line_len = len(line.encode("utf-8", errors="surrogateescape"))
                current_offset = offset
                offset += line_len

                stripped = line.strip()
                if not stripped:
                    continue

                vs_m = _VSFTPD_RE.match(stripped)
                if vs_m:
                    ts_str, user, status, action, ip, filepath, bytes_str = vs_m.groups()
                    ts_utc = self._parse_date(ts_str)
                    severity = "info"
                    if status == "FAIL":
                        severity = "low"
                    elif action == "UPLOAD":
                        severity = "medium"

                    desc = f"FTP {action} {status} from {ip} (user: {user}"
                    if filepath:
                        desc += f", file: {filepath}"
                    if bytes_str:
                        desc += f", {bytes_str} bytes"
                    desc += ")"

                    yield context.build_event(
                        event_kind="event",
                        timestamp_utc=ts_utc,
                        timestamp_local=None,
                        timestamp_confidence="exact" if ts_utc else "unknown",
                        category="user_activity",
                        subcategory="ftp_transfer",
                        actor_user=user,
                        source_ip=ip,
                        description=desc,
                        severity=severity,
                        raw_line=stripped,
                        raw_line_offset=current_offset,
                        notes=f"ftp action={action}; status={status}",
                    )
                    continue

                xf_m = _XFERLOG_RE.match(stripped)
                if xf_m:
                    ts_str, duration, ip, bytes_str, filepath, direction, user = xf_m.groups()
                    ts_utc = self._parse_date(ts_str)
                    act = "UPLOAD" if direction == "i" else "DOWNLOAD"
                    severity = "medium" if act == "UPLOAD" else "info"

                    desc = f"FTP {act} by {user} from {ip}: {filepath} ({bytes_str} bytes in {duration}s)"
                    yield context.build_event(
                        event_kind="event",
                        timestamp_utc=ts_utc,
                        timestamp_local=None,
                        timestamp_confidence="exact" if ts_utc else "unknown",
                        category="user_activity",
                        subcategory="ftp_transfer",
                        actor_user=user,
                        source_ip=ip,
                        description=desc,
                        severity=severity,
                        raw_line=stripped,
                        raw_line_offset=current_offset,
                        notes=f"ftp direction={direction}; bytes={bytes_str}",
                    )
        finally:
            fh.close()

    @staticmethod
    def _parse_date(dt_str: str) -> str | None:
        try:
            # "Sun Mar 22 10:14:23 2020"
            parts = dt_str.split()
            if len(parts) == 5:
                dt = datetime.strptime(dt_str, "%a %b %d %H:%M:%S %Y")
                return dt.replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            pass
        return None
