"""/var/log/lastlog parser (spec trap #6).

lastlog is SPARSE and UID-INDEXED: the record for uid N sits at byte offset
N * 292. Reading it sequentially can yield tens of thousands of empty records,
so the parser reads UID list from collected /etc/passwd and seeks only to
those offsets.
"""
from __future__ import annotations

import ipaddress
import struct
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

LASTLOG_RECORD_SIZE = 292
_RECORD_STRUCT = "<i32s256s"


def _is_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val.strip("[]"))
        return True
    except ValueError:
        return False


def _find_passwd_uids(raw_host_dir: Path) -> dict[int, str]:
    candidates = [
        raw_host_dir / "collected/files/etc/passwd",
        raw_host_dir / "collected/files/passwd",
        raw_host_dir / "etc/passwd",
        raw_host_dir / "passwd",
    ]
    for p in candidates:
        if p.is_file():
            uids = {}
            try:
                content = p.read_text(encoding="utf-8", errors="surrogateescape")
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) >= 3:
                        try:
                            uid = int(parts[2])
                            uids[uid] = parts[0]
                        except ValueError:
                            pass
                return uids
            except Exception:
                pass
    return {}


class LastlogParser(BaseParser):
    name = "lastlog_parser"
    version = "1.0"
    artifact_category = "login_activity"
    applies_to = ["var/log/lastlog"]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return

        try:
            file_size = path.stat().st_size
        except Exception:
            return

        if file_size == 0:
            yield context.build_event(
                event_kind="state_finding",
                category="login_activity",
                subcategory="lastlog_absent_or_empty",
                severity="low",
                timestamp_utc=None,
                timestamp_local=None,
                timestamp_confidence="unknown",
                description="lastlog file is empty or contains no records",
                raw_line="[empty lastlog]",
                raw_line_offset=0,
            )
            return

        passwd_uids = _find_passwd_uids(context.raw_host_dir)
        is_fallback = len(passwd_uids) == 0

        events_found = 0
        has_truncated = False

        try:
            with open(path, "rb") as fh:
                if is_fallback:
                    max_records = min(file_size // LASTLOG_RECORD_SIZE + 1, 70000)
                    for uid in range(max_records):
                        offset = uid * LASTLOG_RECORD_SIZE
                        if offset >= file_size:
                            break
                        fh.seek(offset)
                        chunk = fh.read(LASTLOG_RECORD_SIZE)
                        if len(chunk) < LASTLOG_RECORD_SIZE:
                            if len(chunk) > 0:
                                has_truncated = True
                            break
                        try:
                            ll_time, raw_line, raw_host = struct.unpack(_RECORD_STRUCT, chunk)
                        except struct.error:
                            continue

                        if ll_time <= 0:
                            continue

                        events_found += 1
                        yield self._build_login_event(
                            context, uid, None, ll_time, raw_line, raw_host, offset, is_fallback=True
                        )
                else:
                    for uid, username in sorted(passwd_uids.items()):
                        offset = uid * LASTLOG_RECORD_SIZE
                        if offset >= file_size:
                            continue
                        fh.seek(offset)
                        chunk = fh.read(LASTLOG_RECORD_SIZE)
                        if len(chunk) < LASTLOG_RECORD_SIZE:
                            if len(chunk) > 0:
                                has_truncated = True
                            continue
                        try:
                            ll_time, raw_line, raw_host = struct.unpack(_RECORD_STRUCT, chunk)
                        except struct.error:
                            continue

                        if ll_time <= 0:
                            continue

                        events_found += 1
                        yield self._build_login_event(
                            context, uid, username, ll_time, raw_line, raw_host, offset, is_fallback=False
                        )
        except Exception:
            return

        if events_found == 0 and not has_truncated:
            yield context.build_event(
                event_kind="state_finding",
                category="login_activity",
                subcategory="lastlog_absent_or_empty",
                severity="low",
                timestamp_utc=None,
                timestamp_local=None,
                timestamp_confidence="unknown",
                description="lastlog contains only zero-filled entries (no recorded logins)",
                raw_line="[zero-filled lastlog]",
                raw_line_offset=0,
            )

        if has_truncated:
            yield context.build_event(
                event_kind="state_finding",
                category="login_activity",
                subcategory="lastlog_truncated",
                severity="medium",
                timestamp_utc=None,
                timestamp_local=None,
                timestamp_confidence="unknown",
                description="lastlog has truncated or incomplete record at end of file",
                raw_line="[truncated lastlog record]",
                raw_line_offset=file_size,
            )

    def _build_login_event(
        self,
        context: ParseContext,
        uid: int,
        username: str | None,
        ll_time: int,
        raw_line_bytes: bytes,
        raw_host_bytes: bytes,
        offset: int,
        is_fallback: bool,
    ) -> NormalizedEvent:
        line_str = raw_line_bytes.rstrip(b"\0").decode("utf-8", errors="surrogateescape").strip()
        host_str = raw_host_bytes.rstrip(b"\0").decode("utf-8", errors="surrogateescape").strip()

        ts = context.time_ctx.resolve_epoch(ll_time)

        src_ip = None
        src_host = None
        if host_str:
            if _is_ip(host_str):
                src_ip = host_str
            else:
                src_host = host_str

        actor = username if username else None
        user_label = username or f"UID {uid}"
        desc = f"Last login for {user_label} on {line_str or 'unknown-tty'}"
        if host_str:
            desc += f" from {host_str}"

        raw_line = f"lastlog uid={uid} time={ll_time} line={line_str} host={host_str}"
        notes = "uid list not available, scanned directly" if is_fallback else None

        return context.build_event(
            event_kind="event",
            category="login_activity",
            subcategory="last_login",
            severity="info",
            timestamp_utc=ts.utc_iso,
            timestamp_local=ts.local_iso,
            timestamp_confidence="exact",
            actor_user=actor,
            actor_uid=uid,
            source_ip=src_ip,
            source_host=src_host,
            description=desc,
            raw_line=raw_line,
            raw_line_offset=offset,
            notes=notes,
        )
