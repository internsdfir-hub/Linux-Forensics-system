"""Browser History & Download parser (Firefox places.sqlite and Chrome/Chromium History).

Extracts visited URLs, web page titles, visit timestamps, and downloaded files.
"""
from __future__ import annotations

import sqlite3
import tempfile
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

# WebKit epoch offset: seconds between 1601-01-01 and 1970-01-01
_WEBKIT_OFFSET = 11644473600


def _extract_user_from_path(rel_path: str) -> str | None:
    norm = rel_path.replace("\\", "/").strip("/")
    parts = norm.split("/")
    if len(parts) >= 2 and parts[0] == "home":
        return parts[1]
    if len(parts) >= 1 and parts[0] == "root":
        return "root"
    return None


class BrowserParser(BaseParser):
    name = "browser_parser"
    version = "1.0"
    artifact_category = "user_activity"
    applies_to = [
        "home/*/.mozilla/firefox/*/places.sqlite",
        "root/.mozilla/firefox/*/places.sqlite",
        "home/*/.config/google-chrome/*/History",
        "home/*/.config/chromium/*/History",
        "root/.config/google-chrome/*/History",
        "root/.config/chromium/*/History",
    ]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return

        actor_user = _extract_user_from_path(context.artifact_rel)
        rel_lower = context.artifact_rel.lower()

        # Work on a temporary copy to avoid database lock issues (trap #8)
        tmp_dir = tempfile.mkdtemp()
        tmp_db = Path(tmp_dir) / "browser_copy.sqlite"
        try:
            shutil.copyfile(path, tmp_db)
            conn = sqlite3.connect(f"file:{tmp_db.as_posix()}?immutable=1", uri=True)
            conn.row_factory = sqlite3.Row
            try:
                if "places.sqlite" in rel_lower:
                    yield from self._parse_firefox(conn, context, actor_user)
                else:
                    yield from self._parse_chrome(conn, context, actor_user)
            finally:
                conn.close()
        except Exception:
            return
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _parse_firefox(self, conn: sqlite3.Connection, context: ParseContext, user: str | None) -> Iterator[NormalizedEvent]:
        try:
            # Query moz_places and moz_historyvisits
            cur = conn.execute(
                "SELECT p.url, p.title, p.visit_count, v.visit_date "
                "FROM moz_places p "
                "JOIN moz_historyvisits v ON p.id = v.place_id "
                "WHERE p.url NOT LIKE 'about:%' AND p.url NOT LIKE 'place:%' "
                "ORDER BY v.visit_date DESC LIMIT 500"
            )
            for row in cur.fetchall():
                url = row["url"] or ""
                title = row["title"] or url
                v_date = row["visit_date"]
                ts_utc = None
                if v_date:
                    try:
                        # Firefox visit_date is microseconds since Unix epoch
                        sec = v_date / 1000000.0
                        dt = datetime.fromtimestamp(sec, tz=timezone.utc)
                        ts_utc = dt.isoformat()
                    except Exception:
                        pass

                yield context.build_event(
                    event_kind="event",
                    timestamp_utc=ts_utc,
                    timestamp_local=None,
                    timestamp_confidence="exact" if ts_utc else "unknown",
                    category="user_activity",
                    subcategory="browser_history",
                    actor_user=user,
                    description=f"Firefox visit: {title} ({url})",
                    severity="info",
                    raw_line=f"{ts_utc or ''} {url} {title}",
                    raw_line_offset=0,
                    notes="browser:firefox",
                )
        except Exception:
            pass

    def _parse_chrome(self, conn: sqlite3.Connection, context: ParseContext, user: str | None) -> Iterator[NormalizedEvent]:
        try:
            # 1. URL visits
            cur = conn.execute(
                "SELECT url, title, visit_count, last_visit_time FROM urls "
                "WHERE url NOT LIKE 'chrome://%' "
                "ORDER BY last_visit_time DESC LIMIT 500"
            )
            for row in cur.fetchall():
                url = row["url"] or ""
                title = row["title"] or url
                vt = row["last_visit_time"]
                ts_utc = None
                if vt and vt > 0:
                    try:
                        # WebKit timestamp: microseconds since 1601-01-01
                        sec = (vt / 1000000.0) - _WEBKIT_OFFSET
                        if sec > 0:
                            dt = datetime.fromtimestamp(sec, tz=timezone.utc)
                            ts_utc = dt.isoformat()
                    except Exception:
                        pass

                yield context.build_event(
                    event_kind="event",
                    timestamp_utc=ts_utc,
                    timestamp_local=None,
                    timestamp_confidence="exact" if ts_utc else "unknown",
                    category="user_activity",
                    subcategory="browser_history",
                    actor_user=user,
                    description=f"Chrome visit: {title} ({url})",
                    severity="info",
                    raw_line=f"{ts_utc or ''} {url} {title}",
                    raw_line_offset=0,
                    notes="browser:chrome",
                )
        except Exception:
            pass

        try:
            # 2. Downloads
            cur = conn.execute(
                "SELECT target_path, start_time, total_bytes, tab_url FROM downloads "
                "ORDER BY start_time DESC LIMIT 100"
            )
            for row in cur.fetchall():
                path_str = row["target_path"] or ""
                tab_url = row["tab_url"] or ""
                bytes_cnt = row["total_bytes"] or 0
                st = row["start_time"]
                ts_utc = None
                if st and st > 0:
                    try:
                        sec = (st / 1000000.0) - _WEBKIT_OFFSET
                        if sec > 0:
                            dt = datetime.fromtimestamp(sec, tz=timezone.utc)
                            ts_utc = dt.isoformat()
                    except Exception:
                        pass

                yield context.build_event(
                    event_kind="event",
                    timestamp_utc=ts_utc,
                    timestamp_local=None,
                    timestamp_confidence="exact" if ts_utc else "unknown",
                    category="user_activity",
                    subcategory="browser_download",
                    actor_user=user,
                    description=f"Downloaded file {path_str} from {tab_url} ({bytes_cnt} bytes)",
                    severity="medium",
                    raw_line=f"{ts_utc or ''} download {path_str} {tab_url}",
                    raw_line_offset=0,
                    notes=f"download bytes={bytes_cnt}",
                )
        except Exception:
            pass
