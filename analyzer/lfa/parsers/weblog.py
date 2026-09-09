"""Web server access and error log parser (Apache, Nginx, Lighttpd).

Extracts HTTP method, requested URI, client IP, response code, data bytes,
user-agent, and flags web attack patterns or suspicious scans.
"""
from __future__ import annotations

import gzip
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

# Common and Combined Log Format regex
_ACCESS_RE = re.compile(
    r"^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+\"([A-Z]+)\s+([^\s\"]+)(?:\s+HTTP/[0-9.]+)?\"\s+(\d{3})\s+(\S+)(?:\s+\"([^\"]*)\"\s+\"([^\"]*)\")?"
)

_SUSPICIOUS_WEB_PATTERNS = re.compile(
    r"(\.\./|etc/passwd|/proc/|union\s+select|<script|eval\(|\.env|\.git/|wp-config|base64|/bin/sh|/bin/bash|\bcat\s+/)",
    re.I,
)


class WebLogParser(BaseParser):
    name = "weblog_parser"
    version = "1.0"
    artifact_category = "user_activity"
    applies_to = [
        "var/log/apache2/access.log*",
        "var/log/apache2/error.log*",
        "var/log/nginx/access.log*",
        "var/log/nginx/error.log*",
        "var/log/httpd/access_log*",
        "var/log/httpd/error_log*",
    ]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return

        is_error_log = "error" in path.name.lower()
        if is_error_log:
            # Error logs can also be inspected if needed
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

                m = _ACCESS_RE.match(stripped)
                if not m:
                    continue

                ip, user, ts_str, method, uri, status, bytes_str, referer, ua = m.groups()
                auth_user = None if user == "-" else user

                ts_utc = None
                try:
                    # e.g. 10/Oct/2000:13:55:36 -0700
                    dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
                    ts_utc = dt.astimezone(timezone.utc).isoformat()
                except Exception:
                    pass

                severity = "info"
                if _SUSPICIOUS_WEB_PATTERNS.search(uri):
                    severity = "medium"
                elif status in {"401", "403"} and method in {"POST", "PUT"}:
                    severity = "low"

                desc = f"HTTP {method} {uri} -> status {status} ({bytes_str} bytes)"
                if auth_user:
                    desc += f" [user: {auth_user}]"

                ua_note = f"; ua={ua[:60]}" if ua and ua != "-" else ""
                yield context.build_event(
                    event_kind="event",
                    timestamp_utc=ts_utc,
                    timestamp_local=None,
                    timestamp_confidence="exact" if ts_utc else "unknown",
                    category="user_activity",
                    subcategory="http_request",
                    actor_user=auth_user,
                    source_ip=ip,
                    description=desc,
                    severity=severity,
                    raw_line=stripped,
                    raw_line_offset=current_offset,
                    notes=f"status={status}; bytes={bytes_str}{ua_note}",
                )
        finally:
            fh.close()
