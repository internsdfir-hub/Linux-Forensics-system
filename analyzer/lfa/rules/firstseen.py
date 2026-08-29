"""First-seen analysis (spec 2.8.1).

For every source IP and username, when did it first appear anywhere in the
dataset? Two lines of SQL, and often more useful than any threshold rule:
an address that has never been seen before in weeks of logs, appearing at
the moment things went wrong, is a better lead than any score.

Only addresses/users that first appear LATE in the collected window are
reported - everything is "first seen" at the start of a dataset, and
saying so would be noise, not analysis.
"""
from __future__ import annotations

import sqlite3

from .base import BaseRule, Finding, PlainSummary, parse_ts

NOT_OURS = "COALESCE(tool_generated_flag, 0) = 0"


class FirstSeenRule(BaseRule):
    name = "first_seen"
    version = "1.0"
    # only flag things that first appear after this fraction of the dataset
    parameters = {"late_fraction": 0.5, "min_events_in_case": 50}

    def run(self, conn, ctx):
        conn.row_factory = sqlite3.Row
        span = conn.execute(
            "SELECT MIN(timestamp_utc) AS lo, MAX(timestamp_utc) AS hi, "
            "COUNT(*) AS n FROM events WHERE timestamp_utc IS NOT NULL"
        ).fetchone()
        if not span or not span["lo"] or span["n"] < self.parameters["min_events_in_case"]:
            return
        lo, hi = parse_ts(span["lo"]), parse_ts(span["hi"])
        if lo is None or hi is None or hi <= lo:
            return
        threshold = lo + (hi - lo) * self.parameters["late_fraction"]

        for column, label in (("source_ip", "address"), ("actor_user", "username")):
            rows = conn.execute(
                f"SELECT {column} AS value, MIN(timestamp_utc) AS first_ts, "
                f"COUNT(*) AS n, MAX(timestamp_utc) AS last_ts "
                f"FROM events WHERE {column} IS NOT NULL AND timestamp_utc IS NOT NULL "
                f"AND {NOT_OURS} GROUP BY {column} ORDER BY first_ts, {column}"
            ).fetchall()
            for row in rows:
                first = parse_ts(row["first_ts"])
                if first is None or first < threshold:
                    continue
                sample = conn.execute(
                    f"SELECT event_id, host_id, description, subcategory "
                    f"FROM events WHERE {column} = ? AND timestamp_utc IS NOT NULL "
                    f"ORDER BY timestamp_utc LIMIT 25",
                    (row["value"],),
                ).fetchall()
                ids = [s["event_id"] for s in sample]
                host = sample[0]["host_id"] if sample else None

                yield Finding(
                    rule_name=self.name,
                    rule_version=self.version,
                    severity="low",
                    title=f"First appearance of {label} {row['value']}",
                    plain=PlainSummary(
                        what_happened=(
                            f"The {label} {row['value']} appears for the first "
                            f"time anywhere in the collected logs on "
                            f"{_short(row['first_ts'])}, and appears "
                            f"{row['n']} time(s) in total."
                        ),
                        why_it_matters=(
                            f"Everything else in this dataset stretches back to "
                            f"{_short(span['lo'])}. Something that shows up only "
                            f"in the recent part is either new and legitimate - "
                            f"a new employee, a new server - or it is the "
                            f"first trace of someone who was not there before."
                        ),
                        confidence="Medium",
                        check_next=(
                            f"Ask whether this {label} is expected. If it is a "
                            f"person, confirm with them; if it is an address, "
                            f"check whether it belongs to your organisation or "
                            f"a supplier."
                        ),
                    ),
                    technical_detail=(
                        f"rule={self.name} v{self.version}; field={column}; "
                        f"value={row['value']}; first seen {row['first_ts']}; "
                        f"last seen {row['last_ts']}; occurrences={row['n']}; "
                        f"dataset span {span['lo']} .. {span['hi']}; "
                        f"late-appearance threshold={threshold.isoformat()} "
                        f"(first {int(self.parameters['late_fraction'] * 100)}% "
                        f"of the span is treated as baseline)."
                    ),
                    event_ids=ids,
                    first_ts_utc=row["first_ts"],
                    last_ts_utc=row["last_ts"],
                    host_id=host,
                )


def _short(ts: str | None) -> str:
    if not ts:
        return "an unknown time"
    parsed = parse_ts(ts)
    return parsed.strftime("%Y-%m-%d %H:%M") if parsed else ts
