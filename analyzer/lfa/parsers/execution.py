"""Process-execution parsers (closes scenario #6).

Two sources the collector already captures but nothing previously read:

- AuditdParser  -> /var/log/audit/audit.log
  The kernel audit trail is the only artifact that records *what actually
  ran*. execve is logged as two records sharing one serial: SYSCALL carries
  identity (uid/auid/pid/ppid/comm/exe) and EXECVE carries the argv. We
  stitch them by serial and emit one timed 'process_execution' event with
  the reconstructed command line. USER_CMD (sudo) records become
  'sudo_execution'.

- PsParser -> volatile/ps.txt
  A `ps aux` snapshot: what was running at collection time. No per-process
  timestamp, so these are timestamp-unknown state findings.

Neither has a dedicated correlation rule (consistent with the usb/netstat/
browser parsers); execution shows up on the timeline and known-malicious
command shapes are raised to a higher severity so they surface.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

# msg=audit(<epoch>.<ms>:<serial>):
_AUDIT_MSG = re.compile(r"msg=audit\((\d+)\.(\d+):(\d+)\):")
_TYPE = re.compile(r"^type=(\w+)")
# key=value or key="value"
_FIELD = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
# argv fields a0="..." a1="..." in EXECVE records
_ARGV = re.compile(r'\ba(\d+)="?([^"\s]*)"?')

# Command shapes that indicate remote code execution / reverse shells.
_SUSPICIOUS_CMD = re.compile(
    r"""(?ix)
    (?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh
    | /dev/(?:tcp|udp)/
    | \bnc(?:at)?\b[^\n]*\s-e\b
    | \bbash\s+-i\b
    | \bbase64\b[^\n]*\|\s*(?:ba)?sh
    | \bmkfifo\b
    | \b/bin/sh\b[^\n]*\b\d{1,3}(?:\.\d{1,3}){3}\b
    | \bsocat\b[^\n]*\bexec
    """
)


def _fields(text: str) -> dict:
    out = {}
    for m in _FIELD.finditer(text):
        out[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return out


class AuditdParser(BaseParser):
    name = "auditd_parser"
    version = "1.0"
    artifact_category = "user_activity"
    applies_to = ["var/log/audit/audit.log", "var/log/audit/audit.log.*"]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return
        # Records of one audit event share a serial and arrive consecutively.
        # Buffer per serial, flush when the serial changes or the file ends.
        cur_serial = None
        group: list[tuple[int, str, str, dict, str]] = []  # offset,type,epoch,fields,raw

        for offset, line in self.iter_lines(path, context):
            if not line.strip():
                continue
            mmsg = _AUDIT_MSG.search(line)
            mtype = _TYPE.match(line)
            if not mmsg or not mtype:
                continue
            epoch = f"{mmsg.group(1)}.{mmsg.group(2)}"
            serial = mmsg.group(3)
            rtype = mtype.group(1)
            body = line[mmsg.end():]

            if serial != cur_serial and group:
                ev = self._flush(context, group)
                if ev is not None:
                    yield ev
                group = []
            cur_serial = serial
            group.append((offset, rtype, epoch, _fields(body), line))

        if group:
            ev = self._flush(context, group)
            if ev is not None:
                yield ev

    def _flush(self, context, group):
        types = {rtype for _, rtype, _, _, _ in group}
        offset0, _, epoch, _, raw0 = group[0]
        ts = context.time_ctx.resolve_epoch(float(epoch))

        # sudo / privileged command via pam_exec USER_CMD
        if "USER_CMD" in types:
            rec = next(g for g in group if g[1] == "USER_CMD")
            cmd = self._user_cmd(rec[4])
            uid = _to_int(rec[3].get("auid") or rec[3].get("uid"))
            return context.build_event(
                event_kind="event",
                timestamp_utc=ts.utc_iso,
                timestamp_local=ts.local_iso,
                timestamp_tz=ts.tz_name,
                tz_source=ts.tz_source,
                timestamp_confidence="exact",
                category="privilege_escalation",
                subcategory="sudo_execution",
                actor_uid=uid,
                actor_process="sudo",
                description=f"Privileged command executed via sudo: {cmd or '(unparsed)'}",
                severity="high" if cmd and _SUSPICIOUS_CMD.search(cmd) else "medium",
                raw_line=rec[4],
                raw_line_offset=rec[0],
            )

        # execve: SYSCALL (identity) + EXECVE (argv), possibly split
        syscall = next((g for g in group if g[1] == "SYSCALL"), None)
        execve = next((g for g in group if g[1] == "EXECVE"), None)
        if syscall is None and execve is None:
            return None
        if syscall is not None:
            f = syscall[3]
            if f.get("syscall") not in _EXECVE_SYSCALLS and execve is None:
                return None
        else:
            f = {}

        cmd = self._argv(execve[4]) if execve else ""
        exe = f.get("exe", "")
        comm = f.get("comm", "")
        uid = _to_int(f.get("auid") or f.get("uid"))
        actor = comm or (exe.rsplit("/", 1)[-1] if exe else None)
        shown = cmd or exe or comm
        desc = f"Process executed: {shown}"
        if exe and cmd and exe.rsplit('/', 1)[-1] != cmd.split(' ', 1)[0]:
            desc = f"Process executed: {cmd}  (exe={exe})"
        return context.build_event(
            event_kind="event",
            timestamp_utc=ts.utc_iso,
            timestamp_local=ts.local_iso,
            timestamp_tz=ts.tz_name,
            tz_source=ts.tz_source,
            timestamp_confidence="exact",
            category="user_activity",
            subcategory="process_execution",
            actor_uid=uid,
            actor_process=actor,
            description=desc,
            severity="high" if shown and _SUSPICIOUS_CMD.search(shown) else "info",
            raw_line=(execve or syscall)[4],
            raw_line_offset=offset0,
        )

    @staticmethod
    def _argv(text: str) -> str:
        parts = sorted(
            ((int(i), v) for i, v in _ARGV.findall(text)),
            key=lambda t: t[0],
        )
        return " ".join(v for _, v in parts)

    @staticmethod
    def _user_cmd(raw: str) -> str:
        m = re.search(r'\bcmd="([^"]*)"', raw)
        return m.group(1) if m else ""


_EXECVE_SYSCALLS = {"59", "322", "11"}  # execve/execveat on x86-64 and i386


class PsParser(BaseParser):
    name = "ps_parser"
    version = "1.0"
    artifact_category = "user_activity"
    applies_to = ["volatile/ps.txt", "collected/volatile/ps.txt"]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return
        for offset, line in self.iter_lines(path, context):
            stripped = line.rstrip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.split()[:1] == ["USER"]:  # ps aux header
                continue
            # ps aux: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
            cols = stripped.split(None, 10)
            if len(cols) < 11:
                continue
            user, command = cols[0], cols[10]
            proc = command.split()[0] if command.split() else command
            suspicious = bool(_SUSPICIOUS_CMD.search(command))
            yield context.build_event(
                event_kind="state_finding",
                timestamp_utc=None,
                timestamp_local=None,
                timestamp_confidence="unknown",
                category="user_activity",
                subcategory="running_process",
                actor_user=user,
                actor_process=proc,
                description=f"Process running at collection time (user {user}): {command}",
                severity="medium" if suspicious else "info",
                raw_line=stripped,
                raw_line_offset=offset,
            )


def _to_int(val):
    try:
        n = int(val)
    except (TypeError, ValueError):
        return None
    # auid is 4294967295 (unset) for kernel/daemon-launched processes
    return None if n == 4294967295 else n
