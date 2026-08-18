"""Timestamp engine (spec 2.6.2).

Classic syslog lines carry no year and no timezone. Resolution order:
  1. timezone from the collected /etc/localtime target (tz_source recorded;
     a tool that normalizes to UTC without collecting the timezone is
     silently wrong by hours),
  2. year from an ISO-8601 anchor found in the same file, else the file
     mtime as an upper bound (handles the Dec->Jan rollover),
  3. anything inferred is marked year_inferred, never presented as certain.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_SYSLOG_PREFIX = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}:\d{2}:\d{2})\s+(.*)$", re.S
)

# slack for "line newer than mtime": clock jitter and copy effects
_MTIME_SLACK = timedelta(days=2)


@dataclass
class TSResult:
    utc_iso: str | None
    local_iso: str | None
    tz_name: str
    tz_source: str
    confidence: str  # exact | year_inferred | unknown


def parse_syslog_prefix(line: str) -> tuple[str | None, str]:
    """Split 'Mar 14 02:19:07 rest...' -> ('Mar 14 02:19:07', 'rest...')."""
    m = _SYSLOG_PREFIX.match(line)
    if not m:
        return None, line
    mon, day, hms, rest = m.groups()
    if mon not in _MONTHS:
        return None, line
    return f"{mon} {day.rjust(2)} {hms}", rest


class TimeContext:
    """Host timezone context built from the collected environment."""

    def __init__(self, tz_name: str | None, tz_source: str | None):
        if tz_name:
            try:
                self.tz = ZoneInfo(tz_name)
                self.tz_name = tz_name
                self.tz_source = tz_source or "assumed_utc"
                return
            except Exception:
                pass  # unknown zone: degrade, never crash (decision D8)
        self.tz = timezone.utc
        self.tz_name = "UTC"
        self.tz_source = "assumed_utc"

    # ------------------------------------------------------------- helpers

    def _result(self, dt_aware: datetime, confidence: str) -> TSResult:
        local = dt_aware.astimezone(self.tz)
        utc = dt_aware.astimezone(timezone.utc)
        return TSResult(
            utc_iso=utc.isoformat(),
            local_iso=local.isoformat(),
            tz_name=self.tz_name,
            tz_source=self.tz_source,
            confidence=confidence,
        )

    def _unknown(self) -> TSResult:
        return TSResult(None, None, self.tz_name, self.tz_source, "unknown")

    # ------------------------------------------------------------ resolvers

    def resolve_syslog(
        self,
        prefix: str,
        *,
        file_mtime: float | None,
        anchor_year: int | None = None,
    ) -> TSResult:
        """Resolve a classic 'Mar 14 02:19:07' prefix (host-local time)."""
        m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})$",
                     prefix.strip())
        if not m or m.group(1) not in _MONTHS:
            return self._unknown()
        mon = _MONTHS[m.group(1)]
        day, hh, mm, ss = (int(m.group(i)) for i in range(2, 6))

        if anchor_year is not None:
            base_year = anchor_year
            upper = None
        elif file_mtime is not None:
            mtime_local = datetime.fromtimestamp(file_mtime, tz=self.tz)
            base_year = mtime_local.year
            upper = mtime_local + _MTIME_SLACK
        else:
            return self._unknown()

        # try base year, stepping back for future-dated lines (Dec->Jan
        # rollover) and for invalid dates (Feb 29 in a non-leap year)
        year = base_year
        for _ in range(8):
            try:
                local_dt = datetime(year, mon, day, hh, mm, ss, tzinfo=self.tz)
            except ValueError:
                year -= 1
                continue
            if upper is not None and local_dt > upper:
                year -= 1
                continue
            return self._result(local_dt, "year_inferred")
        return self._unknown()

    def resolve_iso(self, text: str) -> TSResult:
        """Resolve an ISO-8601 timestamp; naive values get the host tz."""
        try:
            dt = datetime.fromisoformat(text.strip())
        except ValueError:
            return self._unknown()
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=self.tz)
        return self._result(dt, "exact")

    def resolve_epoch(self, seconds: float) -> TSResult:
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        return self._result(dt, "exact")

    def resolve_epoch_us(self, microseconds: int) -> TSResult:
        return self.resolve_epoch(microseconds / 1_000_000)


def find_anchor_year(lines_sample: list[str]) -> int | None:
    """Scan a sample of lines for ISO-8601 timestamps (rsyslog can be
    configured either way); their year anchors classic lines in the file."""
    iso = re.compile(r"^(\d{4})-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
    for line in lines_sample:
        m = iso.match(line)
        if m:
            return int(m.group(1))
    return None
