"""Suspicious process-execution correlation rule (scenario #6).

The execution parsers (auditd_parser, ps_parser) put "what ran" on the
timeline. This rule promotes the malicious-looking ones to scored findings.

Two layers:
  1. Command SHAPE. A reverse shell, download-piped-to-shell, encoded payload
     or a C2 beacon to a bare IP is intrinsically suspicious - it is flagged
     wherever it appears (auditd execve or the ps snapshot).
  2. CORRELATION. When such a command was executed within window_minutes of a
     login from an IP that also brute-forced the host, the finding is raised
     to high confidence: this is post-compromise execution, the payload of the
     break-in, not a one-off oddity.

No machine learning: the exact command shape that matched is always shown.
"""
from __future__ import annotations

import re
import sqlite3
from typing import Iterator

from .base import BaseRule, Finding, PlainSummary, events_within, parse_ts

# Command shapes that have no benign explanation in an execution trace.
_MALICIOUS = re.compile(
    r"""(?ix)
    (?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh                 # download piped to shell
    | (?:curl|wget)\b[^\n]*\b\d{1,3}(?:\.\d{1,3}){3}\b   # download/beacon to a bare IP
    | /dev/(?:tcp|udp)/                                   # bash pseudo-device reverse shell
    | \bnc(?:at)?\b[^\n]*\s-e\b                           # netcat with -e exec
    | \bbash\s+-i\b                                       # interactive bash to a socket
    | \bbase64\b[^\n]*\|\s*(?:ba)?sh                      # base64 decode piped to shell
    | \bmkfifo\b[^\n]*(?:nc|/dev/tcp)                     # named-pipe reverse shell
    | \bpython[0-9.]*\b[^\n]*-c[^\n]*socket               # python socket one-liner
    | \bperl\b[^\n]*-e[^\n]*socket                        # perl socket one-liner
    | \bsocat\b[^\n]*\bexec                               # socat exec reverse shell
    """
)

_EXEC_SUBCATS = ("process_execution", "running_process", "sudo_execution")


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute(sql, params).fetchall()


class SuspiciousProcessRule(BaseRule):
    name = "suspicious_process"
    version = "1.0"
    parameters = {"window_minutes": 60}

    def run(self, conn: sqlite3.Connection, ctx: dict) -> Iterator[Finding]:
        window = ctx.get("suspicious_process_window", self.parameters["window_minutes"])

        placeholders = ",".join("?" for _ in _EXEC_SUBCATS)
        candidates = _rows(
            conn,
            f"SELECT * FROM events WHERE subcategory IN ({placeholders}) "
            f"ORDER BY timestamp_utc IS NULL, timestamp_utc, event_hash",
            _EXEC_SUBCATS,
        )

        # IPs that brute-forced the host: the login half of a post-compromise
        # correlation. Computed once.
        bruteforce_ips = {
            r["source_ip"]
            for r in conn.execute(
                "SELECT source_ip FROM events WHERE subcategory IN "
                "('failed_login','invalid_user') AND source_ip IS NOT NULL "
                "GROUP BY source_ip HAVING COUNT(*) >= 5"
            )
        }

        seen: set[str] = set()
        for ev in candidates:
            command = f"{ev['description'] or ''} {ev['raw_line'] or ''}"
            if not _MALICIOUS.search(command):
                continue
            if ev["event_id"] in seen:
                continue
            seen.add(ev["event_id"])

            shown = ev["description"] or ev["raw_line"]
            correlated_login = None
            if ev["timestamp_utc"]:
                for near in events_within(conn, ev["timestamp_utc"], window,
                                          subcategory="successful_login"):
                    if near["source_ip"] in bruteforce_ips and parse_ts(
                        near["timestamp_utc"]
                    ) <= parse_ts(ev["timestamp_utc"]):
                        correlated_login = near
                        break

            if correlated_login is not None:
                confidence = "High"
                why = (
                    "This command ran shortly after a login from "
                    f"{correlated_login['source_ip']}, an address that also "
                    "brute-forced this host. That sequence - break in, then "
                    "run a reverse shell or beacon - is the payload of the "
                    "intrusion, not a coincidence."
                )
                tech_extra = (
                    f"; correlated with successful_login event_id="
                    f"{correlated_login['event_id']} from "
                    f"{correlated_login['source_ip']} at "
                    f"{correlated_login['timestamp_utc']}"
                )
                event_ids = [ev["event_id"], correlated_login["event_id"]]
            elif ev["timestamp_utc"] is None:
                confidence = "Medium"
                why = (
                    "A process matching a reverse-shell or C2 pattern was "
                    "running when evidence was collected. It has no execution "
                    "timestamp (captured from the live process list), so it "
                    "cannot be placed on the timeline - confirm it directly."
                )
                tech_extra = "; source=process snapshot (no execution timestamp)"
                event_ids = [ev["event_id"]]
            else:
                confidence = "Medium"
                why = (
                    "A command matching a reverse-shell, C2-beacon or encoded-"
                    "payload pattern was executed. Even without a matching "
                    "login it does not belong in normal operation and must be "
                    "explained."
                )
                tech_extra = ""
                event_ids = [ev["event_id"]]

            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="high",
                title=f"Suspicious command executed: {shown}",
                plain=PlainSummary(
                    what_happened=(
                        f"A process matching a known malicious command shape "
                        f"was seen: {shown}"
                    ),
                    why_it_matters=why,
                    confidence=confidence,
                    check_next=(
                        "Confirm the parent process and the user that launched "
                        "it, check for an outbound connection to the address in "
                        "the command, and preserve the binary before removing "
                        "it - it is evidence."
                    ),
                ),
                technical_detail=(
                    f"rule={self.name} v{self.version}; matched command "
                    f"'{shown}' in {ev['subcategory']} "
                    f"[{ev['source_artifact_path']}]{tech_extra}"
                ),
                event_ids=event_ids,
                first_ts_utc=ev["timestamp_utc"],
                last_ts_utc=ev["timestamp_utc"],
                host_id=ev["host_id"],
            )
