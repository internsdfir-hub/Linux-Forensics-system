"""Suspicious process-execution correlation rule (scenario #6).

The execution parsers (auditd_parser, ps_parser) put "what ran" on the
timeline and shellhist_parser puts "what was typed" there. This rule promotes
the malicious-looking ones to scored findings.

Three layers:
  1. Command SHAPE. A reverse shell, download-piped-to-shell, encoded payload
     or a C2 beacon to a bare IP is intrinsically suspicious - it is flagged
     wherever it appears (auditd execve, the ps snapshot, or shell history).
  2. CORROBORATION. The same command seen in more than one artifact is one
     finding, not three: the occurrences are merged and every source is named.
  3. CORRELATION. When such a command was executed within window_minutes of a
     login from an IP that also brute-forced the host, the finding is raised
     to high confidence: this is post-compromise execution, the payload of the
     break-in, not a one-off oddity.

Shell history is read because it is the only execution record that survives on
a host without auditd (the Metasploitable default) once the process itself has
exited. It is also the weakest: it records what was typed, not what the kernel
ran, and the account owner can edit or wipe it - so a history-only finding
says exactly that in plain English and tells the analyst to corroborate it.

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

# Subcategory -> the artifact it came from. Shell history spans two
# subcategories because shellhist_parser already grades what it reads: a line
# matching its own suspicious list becomes 'suspicious_command', everything
# else stays 'shell_command'. Both are the same artifact to this rule.
_SOURCE_KIND = {
    "process_execution": "audit",
    "sudo_execution": "audit",
    "running_process": "process_list",
    "shell_command": "history",
    "suspicious_command": "history",
}
_EXEC_SUBCATS = tuple(_SOURCE_KIND)

_SOURCE_LABEL = {
    "audit": "kernel audit trail",
    "process_list": "process snapshot",
    "history": "shell history",
}

# Each parser writes the command into `description` behind its own prefix.
# Stripping the prefix back off gives one comparable command string per
# source, so a command recorded by two parsers collapses into one finding.
_DESC_PREFIX = re.compile(
    r"""^(?:
        Process\ executed
      | Privileged\ command\ executed\ via\ sudo
      | Process\ running\ at\ collection\ time\ \(user\ [^)]*\)
      | User\ \S+\ executed
    ):\s*""",
    re.X,
)
_EXE_SUFFIX = re.compile(r"\s{2,}\(exe=[^)]*\)\s*$")


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute(sql, params).fetchall()


def _command_of(ev: sqlite3.Row) -> str:
    """The bare command line, with whichever parser prefix wrote it removed."""
    desc = (ev["description"] or "").strip()
    if desc:
        cmd = _EXE_SUFFIX.sub("", _DESC_PREFIX.sub("", desc)).strip()
        if cmd:
            return cmd
    return (ev["raw_line"] or "").strip()


class SuspiciousProcessRule(BaseRule):
    name = "suspicious_process"
    version = "1.1"
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

        # Merge occurrences of the same command on the same host. The ORDER BY
        # above puts timestamped rows first, so a group's first member is its
        # representative and carries a timestamp whenever any member does.
        groups: dict[tuple, list[sqlite3.Row]] = {}
        shown_for: dict[tuple, str] = {}
        for ev in candidates:
            haystack = f"{ev['description'] or ''} {ev['raw_line'] or ''}"
            if not _MALICIOUS.search(haystack):
                continue
            command = _command_of(ev)
            key = (ev["host_id"], command)
            groups.setdefault(key, []).append(ev)
            shown_for.setdefault(key, command or ev["raw_line"] or "(unparsed)")

        for key, members in groups.items():
            yield self._finding(shown_for[key], members, conn, bruteforce_ips, window)

    def _finding(self, shown, members, conn, bruteforce_ips, window) -> Finding:
        ev = members[0]
        kinds: list[str] = []
        for member in members:
            kind = _SOURCE_KIND[member["subcategory"]]
            if kind not in kinds:
                kinds.append(kind)
        history_only = kinds == ["history"]
        stamps = sorted(m["timestamp_utc"] for m in members if m["timestamp_utc"])
        event_ids = [m["event_id"] for m in members]

        correlated_login = None
        for member in members:
            if not member["timestamp_utc"]:
                continue
            for near in events_within(conn, member["timestamp_utc"], window,
                                      subcategory="successful_login"):
                if near["source_ip"] in bruteforce_ips and parse_ts(
                    near["timestamp_utc"]
                ) <= parse_ts(member["timestamp_utc"]):
                    correlated_login = near
                    break
            if correlated_login is not None:
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
            event_ids = event_ids + [correlated_login["event_id"]]
        elif ev["timestamp_utc"] is None and history_only:
            confidence = "Medium"
            why = (
                "A command matching a reverse-shell, C2-beacon or encoded-"
                "payload pattern is recorded in a user's shell history. The "
                "history file carries no timestamps, so the command cannot be "
                "placed on the timeline - but it does not belong in normal "
                "operation and must be explained."
            )
            tech_extra = "; source=shell history (file records no timestamps)"
        elif ev["timestamp_utc"] is None:
            confidence = "Medium"
            why = (
                "A process matching a reverse-shell or C2 pattern was "
                "running when evidence was collected. It has no execution "
                "timestamp (captured from the live process list), so it "
                "cannot be placed on the timeline - confirm it directly."
            )
            tech_extra = "; source=process snapshot (no execution timestamp)"
        else:
            confidence = "Medium"
            why = (
                "A command matching a reverse-shell, C2-beacon or encoded-"
                "payload pattern was executed. Even without a matching "
                "login it does not belong in normal operation and must be "
                "explained."
            )
            tech_extra = ""

        check_next = (
            "Confirm the parent process and the user that launched "
            "it, check for an outbound connection to the address in "
            "the command, and preserve the binary before removing "
            "it - it is evidence."
        )
        if history_only:
            why += (
                " Note the source: shell history records what was typed at an "
                "interactive shell, not what the kernel actually ran, and the "
                "account owner can edit or wipe it. Treat this as a lead to "
                "confirm rather than proof that the command executed."
            )
            check_next = (
                "Corroborate the history entry against a second artifact - "
                "auditd execve records, journald, or an outbound connection to "
                "the address in the command - before relying on it, and "
                "confirm which user's history file it came from."
            )

        sources = ", ".join(_SOURCE_LABEL[k] for k in kinds)
        subcats = ", ".join(sorted({m["subcategory"] for m in members}))
        paths = ", ".join(sorted({m["source_artifact_path"] for m in members
                                  if m["source_artifact_path"]}))
        corroboration = f" (recorded in the {sources})" if len(kinds) > 1 else ""

        return Finding(
            rule_name=self.name,
            rule_version=self.version,
            severity="high",
            title=f"Suspicious command executed: {shown}",
            plain=PlainSummary(
                what_happened=(
                    f"A process matching a known malicious command shape "
                    f"was seen: {shown}{corroboration}"
                ),
                why_it_matters=why,
                confidence=confidence,
                check_next=check_next,
            ),
            technical_detail=(
                f"rule={self.name} v{self.version}; matched command "
                f"'{shown}' in {subcats} "
                f"[{paths or ev['source_artifact_path']}]; sources={sources}; "
                f"occurrences={len(members)}{tech_extra}"
            ),
            event_ids=event_ids,
            first_ts_utc=stamps[0] if stamps else None,
            last_ts_utc=stamps[-1] if stamps else None,
            host_id=ev["host_id"],
        )
