"""Evidence-integrity rules (spec 2.8.1).

These are the rules that make a report look professional, because they
reason about what is MISSING or INCONSISTENT rather than only about what is
present. Absence of evidence is evidence: a user with fifty recorded
sessions and an empty command history didn't just get shy - someone
deleted it.

None of these prove wrongdoing on their own. Log rotation, disk-full
events and clean reinstalls all produce the same shapes. Each finding says
so in its own plain-language layer.
"""
from __future__ import annotations

import re
import sqlite3
from collections import defaultdict
from datetime import timedelta

from .base import BaseRule, Finding, PlainSummary, parse_ts


def _rows(conn, sql, params=()):
    conn.row_factory = sqlite3.Row
    return conn.execute(sql, params).fetchall()


_COMMON_SERVICE_ACCOUNTS = frozenset({
    "lightdm", "nobody", "daemon", "messagebus", "_apt", "postgres", "mysql",
    "systemd-resolve", "systemd-network", "systemd-timesync", "systemd-coredump",
    "avahi", "colord", "geoclue", "rtkit", "syslog", "sshd", "dnsmasq", "sync",
    "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup",
    "list", "irc", "gnats", "bin", "sys", "reboot", "shutdown", "halt", "statd",
    "_rpc", "tss", "uuidd", "tcpdump", "nm-openvpn", "Debian-snmp", "speech-dispatcher",
})


class WipedHistoryRule(BaseRule):
    """A shell history that is missing or empty for a user who demonstrably
    had sessions."""

    name = "wiped_history"
    version = "1.0"
    parameters = {"min_sessions": 3}

    def run(self, conn, ctx):
        min_sessions = ctx.get("wiped_history_min_sessions",
                               self.parameters["min_sessions"])
        candidates_raw = _rows(
            conn,
            "SELECT * FROM events WHERE subcategory IN "
            "('history_missing','history_empty','history_symlinked_devnull') "
            "AND actor_user IS NOT NULL",
        )
        candidates: dict[str, dict] = {}
        for c in candidates_raw:
            clean_u = (c["actor_user"] or "").strip("'\"")
            if clean_u and clean_u not in _COMMON_SERVICE_ACCOUNTS and clean_u not in candidates:
                candidates[clean_u] = dict(c)

        # Check active users with >= min_sessions but 0 recorded shell history
        active_users = conn.execute(
            "SELECT actor_user, COUNT(*) as cnt, MIN(timestamp_utc), MAX(timestamp_utc), host_id, event_id "
            "FROM events WHERE actor_user IS NOT NULL AND subcategory IN ('successful_login','session_opened','login') "
            "GROUP BY actor_user HAVING cnt >= ?",
            (min_sessions,),
        ).fetchall()
        for u_row in active_users:
            u = (u_row[0] or "").strip("'\"")
            if not u or u in _COMMON_SERVICE_ACCOUNTS or u in candidates:
                continue
            hist_count = conn.execute(
                "SELECT COUNT(*) FROM events WHERE (actor_user = ? OR actor_user = ?) AND category = 'user_activity' "
                "AND subcategory IN ('shell_command','suspicious_command')",
                (u, f"'{u}'"),
            ).fetchone()[0]
            if hist_count == 0:
                candidates[u] = {
                    "actor_user": u,
                    "subcategory": "history_missing",
                    "source_artifact_path": f"home/{u}/.bash_history",
                    "event_id": u_row[5],
                    "host_id": u_row[4],
                }

        for user, row in candidates.items():
            sessions = conn.execute(
                "SELECT COUNT(*) FROM events WHERE (actor_user = ? OR actor_user = ?) AND "
                "subcategory IN ('successful_login','session_opened','login') "
                "AND timestamp_utc IS NOT NULL",
                (user, f"'{user}'"),
            ).fetchone()[0]
            if sessions < min_sessions:
                continue
            span = conn.execute(
                "SELECT MIN(timestamp_utc), MAX(timestamp_utc) FROM events "
                "WHERE (actor_user = ? OR actor_user = ?) AND subcategory IN "
                "('successful_login','session_opened','login')",
                (user, f"'{user}'"),
            ).fetchone()
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="high",
                title=f"Command history for {user} is missing or empty",
                plain=PlainSummary(
                    what_happened=(
                        f"The account {user} has {sessions} recorded login "
                        f"sessions, but its command history file is "
                        f"{'missing' if row['subcategory'] == 'history_missing' else 'empty'}."
                    ),
                    why_it_matters=(
                        "Someone who logs in and runs commands normally leaves a "
                        "history file behind. An account that logged in many "
                        "times but has nothing recorded usually means the "
                        "history was deleted, or the shell was started in a way "
                        "that avoids writing it. Either is a deliberate act."
                    ),
                    confidence="Medium",
                    check_next=(
                        f"Ask whether {user} is a service account that never "
                        f"uses an interactive shell - that would explain it "
                        f"innocently. If it is a person's account, treat the "
                        f"missing history as intentional and look at what else "
                        f"happened during those sessions."
                    ),
                ),
                technical_detail=(
                    f"rule={self.name} v{self.version}; threshold >= "
                    f"{min_sessions} sessions; user={user}; sessions counted="
                    f"{sessions} between {span[0]} and {span[1]}; history "
                    f"artifact={row['source_artifact_path']}; parser finding="
                    f"{row['subcategory']}."
                ),
                event_ids=[row["event_id"]],
                host_id=row["host_id"],
            )


class ZeroLengthLogRule(BaseRule):
    """wtmp/btmp/lastlog present but empty or implausibly small."""

    name = "zero_length_login_log"
    version = "1.0"

    def run(self, conn, ctx):
        rows = _rows(
            conn,
            "SELECT * FROM events WHERE subcategory IN "
            "('utmp_empty','lastlog_absent_or_empty')",
        )
        for row in rows:
            artifact = row["source_artifact_path"]
            other_logins = conn.execute(
                "SELECT COUNT(*) FROM events WHERE subcategory IN "
                "('successful_login','session_opened') AND timestamp_utc IS NOT NULL"
            ).fetchone()[0]
            severity = "high"
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity=severity,
                title=f"Login record file {artifact} is empty",
                plain=PlainSummary(
                    what_happened=(
                        f"The file {artifact}, which the system uses to record "
                        f"logins, exists but contains no usable records"
                        + (f", even though {other_logins} logins are recorded "
                           f"elsewhere in the logs." if other_logins
                           else ".")
                    ),
                    why_it_matters=(
                        "Clearing these files is a standard way of hiding that "
                        "someone logged in. They are binary, so they are usually "
                        "emptied rather than edited."
                    ),
                    confidence="High" if other_logins else "Medium",
                    check_next=(
                        "Compare against the same file's rotated copies and "
                        "against the journal, which records logins separately. "
                        "If the journal shows logins the binary file does not, "
                        "the file was cleared."
                    ),
                ),
                technical_detail=(
                    f"rule={self.name} v{self.version}; artifact={artifact}; "
                    f"parser finding={row['subcategory']}; corroborating login "
                    f"events elsewhere in the case={other_logins}; "
                    f"detail={row['description']}"
                ),
                event_ids=[row["event_id"]],
                host_id=row["host_id"],
            )


class RotationGapRule(BaseRule):
    """A rotation sequence with a missing number (auth.log.1, auth.log.3)."""

    name = "rotation_gap"
    version = "1.0"

    _ROT = re.compile(r"^(?P<base>.+?)\.(?P<num>\d+)(?P<gz>\.gz)?$")

    def run(self, conn, ctx):
        paths = [
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT source_artifact_path FROM events "
                "WHERE source_artifact_path IS NOT NULL ORDER BY source_artifact_path"
            )
        ]
        families: dict[str, set[int]] = defaultdict(set)
        for path in paths:
            m = self._ROT.match(path)
            if m:
                families[m.group("base")].add(int(m.group("num")))
            elif path in paths:
                families.setdefault(path, set())

        for base, numbers in sorted(families.items()):
            if not numbers:
                continue
            highest = max(numbers)
            missing = sorted(set(range(1, highest + 1)) - numbers)
            if not missing:
                continue
            missing_names = [f"{base}.{n}" for n in missing]
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="medium",
                title=f"Gap in the rotation sequence of {base}",
                plain=PlainSummary(
                    what_happened=(
                        f"The rotated copies of {base} skip "
                        + ", ".join(missing_names)
                        + f", although {base}.{highest} is present."
                    ),
                    why_it_matters=(
                        "Log rotation produces a numbered sequence with no "
                        "holes. A missing number means that copy was deleted, "
                        "or was never collected. Either way there is a period "
                        "of history we cannot see."
                    ),
                    confidence="Medium",
                    check_next=(
                        "Check whether the missing files exist on the machine "
                        "but were unreadable at collection time (the collection "
                        "log records that), and whether log rotation settings "
                        "were changed recently."
                    ),
                ),
                technical_detail=(
                    f"rule={self.name} v{self.version}; family={base}; present="
                    f"{sorted(numbers)}; missing={missing_names}; highest observed="
                    f"{highest}."
                ),
                event_ids=[],
                host_id=None,
            )


class TimelineGapRule(BaseRule):
    """N hours with zero events in a log that otherwise averages X/hour."""

    name = "timeline_gap"
    version = "1.0"
    parameters = {"min_gap_hours": 6, "min_events_per_hour": 1.0, "min_events": 40}

    def run(self, conn, ctx):
        min_gap = timedelta(hours=ctx.get("timeline_gap_hours",
                                          self.parameters["min_gap_hours"]))
        artifacts = [
            r[0]
            for r in conn.execute(
                "SELECT source_artifact_path FROM events WHERE timestamp_utc "
                "IS NOT NULL GROUP BY source_artifact_path "
                "HAVING COUNT(*) >= ? ORDER BY source_artifact_path",
                (self.parameters["min_events"],),
            )
        ]
        for artifact in artifacts:
            rows = _rows(
                conn,
                "SELECT event_id, timestamp_utc FROM events WHERE "
                "source_artifact_path = ? AND timestamp_utc IS NOT NULL "
                "ORDER BY timestamp_utc",
                (artifact,),
            )
            times = [parse_ts(r["timestamp_utc"]) for r in rows]
            times = [t for t in times if t]
            if len(times) < self.parameters["min_events"]:
                continue
            span_hours = (times[-1] - times[0]).total_seconds() / 3600
            if span_hours <= 0:
                continue
            rate = len(times) / span_hours
            if rate < self.parameters["min_events_per_hour"]:
                continue

            for i in range(1, len(times)):
                gap = times[i] - times[i - 1]
                if gap < min_gap:
                    continue
                yield Finding(
                    rule_name=self.name,
                    rule_version=self.version,
                    severity="medium",
                    title=f"{gap.total_seconds() / 3600:.1f}-hour silence in {artifact}",
                    plain=PlainSummary(
                        what_happened=(
                            f"{artifact} records something roughly {rate:.1f} "
                            f"times an hour, but between "
                            f"{times[i - 1].strftime('%Y-%m-%d %H:%M')} and "
                            f"{times[i].strftime('%Y-%m-%d %H:%M')} it records "
                            f"nothing at all."
                        ),
                        why_it_matters=(
                            "A busy log going completely silent usually means "
                            "the machine was off, the logging service was "
                            "stopped, or that stretch of the file was removed. "
                            "The first is innocent; the other two are not."
                        ),
                        confidence="Medium",
                        check_next=(
                            "Check whether the machine was rebooted or shut down "
                            "during that window (the boot records show this), "
                            "and whether the logging service was restarted."
                        ),
                    ),
                    technical_detail=(
                        f"rule={self.name} v{self.version}; artifact={artifact}; "
                        f"observed rate={rate:.2f} events/hour over "
                        f"{span_hours:.1f} hours; gap threshold="
                        f"{min_gap.total_seconds() / 3600:.0f}h; gap from "
                        f"{times[i - 1].isoformat()} to {times[i].isoformat()} "
                        f"({gap.total_seconds() / 3600:.2f}h)."
                    ),
                    event_ids=[rows[i - 1]["event_id"], rows[i]["event_id"]],
                    first_ts_utc=rows[i - 1]["timestamp_utc"],
                    last_ts_utc=rows[i]["timestamp_utc"],
                    host_id=None,
                )
                break  # one finding per artifact is enough to prompt a look


class BackwardsTimestampsRule(BaseRule):
    """Timestamps running backwards inside one file: the clock was changed,
    or lines were inserted."""

    name = "backwards_timestamps"
    version = "1.0"

    def run(self, conn, ctx):
        artifacts = [
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT source_artifact_path FROM events WHERE "
                "timestamp_utc IS NOT NULL AND raw_line_offset IS NOT NULL "
                "ORDER BY source_artifact_path"
            )
        ]
        for artifact in artifacts:
            rows = _rows(
                conn,
                "SELECT event_id, timestamp_utc, raw_line_offset, raw_line "
                "FROM events WHERE source_artifact_path = ? AND timestamp_utc "
                "IS NOT NULL ORDER BY raw_line_offset",
                (artifact,),
            )
            inversions = []
            previous = None
            for row in rows:
                ts = parse_ts(row["timestamp_utc"])
                if ts is None:
                    continue
                if previous is not None and ts < previous[0]:
                    inversions.append((previous, (ts, row)))
                    previous = (ts, row)
                    continue
                previous = (ts, row)
            if not inversions:
                continue

            first_bad = inversions[0]
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="medium",
                title=f"Timestamps run backwards inside {artifact}",
                plain=PlainSummary(
                    what_happened=(
                        f"In {artifact}, {len(inversions)} line(s) are dated "
                        f"earlier than the line above them - for example a "
                        f"line at "
                        f"{first_bad[1][0].strftime('%Y-%m-%d %H:%M:%S')} "
                        f"follows one at "
                        f"{first_bad[0][0].strftime('%Y-%m-%d %H:%M:%S')}."
                    ),
                    why_it_matters=(
                        "Log files are written in order, so time should only "
                        "move forwards within one file. Going backwards means "
                        "the system clock was changed, or lines were inserted "
                        "or removed by hand. It also means timestamps around "
                        "that point cannot be compared safely."
                    ),
                    confidence="High",
                    check_next=(
                        "Look for clock-change records around that time, and "
                        "check whether NTP was reconfigured. Treat the ordering "
                        "of events in this file as unreliable until explained."
                    ),
                ),
                technical_detail=(
                    f"rule={self.name} v{self.version}; artifact={artifact}; "
                    f"{len(inversions)} inversion(s) by file offset; first at "
                    f"offset {first_bad[1][1]['raw_line_offset']}: "
                    f"{first_bad[1][0].isoformat()} follows "
                    f"{first_bad[0][0].isoformat()} (offset "
                    f"{first_bad[0][1]['raw_line_offset']})."
                ),
                event_ids=[first_bad[0][1]["event_id"], first_bad[1][1]["event_id"]],
                first_ts_utc=first_bad[1][1]["timestamp_utc"],
                host_id=None,
            )


class JournaldSequenceGapRule(BaseRule):
    """Journald sequence number gap: entries were purged, deleted or rate-limited."""

    name = "journald_sequence_gap"
    version = "1.0"

    def run(self, conn, ctx):
        rows = _rows(
            conn,
            "SELECT * FROM events WHERE subcategory = 'journal_sequence_gap' "
            "ORDER BY timestamp_utc, raw_line_offset",
        )
        for row in rows:
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="high",
                title=f"Journald log sequence gap detected in {row['source_artifact_path']}",
                plain=PlainSummary(
                    what_happened=(
                        f"A jump in systemd journal sequence numbers was detected "
                        f"in {row['source_artifact_path']}: {row['description']}."
                    ),
                    why_it_matters=(
                        "Systemd journal sequence numbers (__SEQNUM) are strictly "
                        "sequential. A gap indicates that records were deleted, cleared, "
                        "or dropped, creating a blind spot in forensic visibility."
                    ),
                    confidence="High",
                    check_next=(
                        "Check whether systemd-journald restarted, check disk-full "
                        "or rate-limiting logs, and examine surrounding timestamps for "
                        "anti-forensic activity."
                    ),
                ),
                technical_detail=(
                    f"rule={self.name} v{self.version}; artifact={row['source_artifact_path']}; "
                    f"finding={row['description']}; notes={row['notes']}"
                ),
                event_ids=[row["event_id"]],
                first_ts_utc=row["timestamp_utc"],
                host_id=row["host_id"],
            )

