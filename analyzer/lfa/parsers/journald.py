"""journald export parser (spec 2.3, trap #7).

The collector exported the journal with the machine's own
`journalctl -o json` because the on-disk format is undocumented and
version-unstable. Each line here is one journal entry as a JSON object.

journald is CORE, equal priority to auth.log: Debian 12 and most minimal
cloud images ship no rsyslog at all, so the journal is the ONLY source of
login evidence there.

Two kinds of output:
  - grammar matches (same YAML rules auth.log uses) -> typed events
  - everything else -> a generic `journal_message` event, because an
    analyst must still be able to see the timeline. Silently dropping
    unmatched lines would hide evidence.
"""
from __future__ import annotations

import json
from pathlib import Path

from .authlog import GRAMMAR_DIR, SyslogTextParser
from .base import BaseParser, ParseContext
from .grammar import GrammarEngine

# journal fields we surface as the acting process
_COMM_FIELDS = ("_COMM", "SYSLOG_IDENTIFIER", "_EXE")


def _decode_message(value) -> str:
    """MESSAGE is normally a string, but journalctl emits an array of byte
    values when the message is not valid UTF-8."""
    if isinstance(value, list):
        try:
            return bytes(value).decode("utf-8", errors="surrogateescape")
        except (ValueError, TypeError):
            return repr(value)
    if value is None:
        return ""
    return str(value)


class JournaldParser(BaseParser):
    name = "journald_parser"
    version = "1.0"
    artifact_category = "login_activity"
    applies_to = ["journal/*.json", "journal/*.json.gz"]

    def parse(self, path: Path, context: ParseContext):
        distro = (context.distro_profile or {}).get("distro_id", "")
        engine = GrammarEngine.load(GRAMMAR_DIR, distro)
        last_seq_num: int | None = None

        for offset, line in self.iter_lines(path, context):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                # a truncated or corrupt line must not stop the export
                continue
            if not isinstance(entry, dict):
                continue

            message = _decode_message(entry.get("MESSAGE"))
            comm = ""
            for field in _COMM_FIELDS:
                if entry.get(field):
                    comm = str(entry[field])
                    break
            pid = entry.get("_PID") or entry.get("SYSLOG_PID") or ""

            ts_utc = ts_local = None
            confidence = "unknown"
            realtime = entry.get("__REALTIME_TIMESTAMP")
            if realtime:
                try:
                    res = context.time_ctx.resolve_epoch_us(int(realtime))
                    ts_utc, ts_local = res.utc_iso, res.local_iso
                    confidence = res.confidence
                except (TypeError, ValueError):
                    pass

            # Track sequence number gaps (__SEQNUM) for anti-forensic detection
            seq_val = entry.get("__SEQNUM")
            seq_num = None
            if seq_val is not None:
                try:
                    seq_num = int(seq_val)
                except (ValueError, TypeError):
                    seq_num = None

            if last_seq_num is not None and seq_num is not None and seq_num > last_seq_num + 1:
                gap = seq_num - last_seq_num - 1
                yield context.build_event(
                    event_kind="event",
                    timestamp_utc=ts_utc,
                    timestamp_local=ts_local,
                    timestamp_confidence=confidence,
                    category="environment",
                    subcategory="journal_sequence_gap",
                    actor_process="systemd-journald",
                    description=f"Journal sequence gap detected: expected seq {last_seq_num + 1}, got {seq_num} ({gap} missing records)",
                    severity="high",
                    raw_line=line,
                    raw_line_offset=offset,
                    notes=f"SEQUENCE_GAP expected={last_seq_num + 1} actual={seq_num} gap={gap}",
                )

            if seq_num is not None:
                last_seq_num = seq_num

            notes = f"journald _COMM={comm} _PID={pid}"

            # journal MESSAGEs carry no syslog prefix, so hand the grammar a
            # reconstructed "identifier[pid]: message" line
            synthetic = f"{comm}[{pid}]: {message}" if comm else message
            matches = engine.match_line(synthetic)

            emitted = False
            for rule_name, rule, groups in matches:
                source_ip = groups.get("ip")
                uid = None
                if groups.get("uid", "").isdigit():
                    uid = int(groups["uid"])
                yield context.build_event(
                    event_kind="event",
                    timestamp_utc=ts_utc,
                    timestamp_local=ts_local,
                    timestamp_confidence=confidence,
                    category=rule["category"],
                    subcategory=rule["subcategory"],
                    actor_user=groups.get("user"),
                    actor_uid=uid,
                    actor_process=rule.get("process") or comm or None,
                    source_ip=source_ip,
                    description=SyslogTextParser._describe(rule_name, rule, groups),
                    severity=rule["severity"],
                    raw_line=line,
                    raw_line_offset=offset,
                    tool_generated_flag=context.is_tool_generated(source_ip, ts_utc),
                    notes=f"{notes} grammar:{rule_name}",
                )
                emitted = True

            if not emitted:
                yield context.build_event(
                    event_kind="event",
                    timestamp_utc=ts_utc,
                    timestamp_local=ts_local,
                    timestamp_confidence=confidence,
                    category="login_activity" if comm in {"sshd", "login", "sudo"}
                    else "environment",
                    subcategory="journal_message",
                    actor_user=entry.get("_UID") and None,
                    actor_process=comm or None,
                    description=message[:500] if message else "(empty journal entry)",
                    severity="info",
                    raw_line=line,
                    raw_line_offset=offset,
                    notes=notes,
                )
