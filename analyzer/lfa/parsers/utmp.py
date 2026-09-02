"""wtmp / btmp binary parser (spec 2.3, trap #5).

struct utmp is 384 bytes on both x86 and x86_64 because glibc pins ut_tv to
two int32 for compatibility, so we ship ONE layout rather than per-arch
offset tables. Validation instead of guesswork:
  - filesize % 384 == 0, else record unsupported-layout and parse what we can
  - decoded timestamps must land in a plausible range, else the layout is
    wrong and we say so rather than emitting fake 1970 logins

The real edge case is musl/Alpine, where wtmp/btmp are stubs and frequently
empty or absent, and containers where they are meaningless. Absence and
emptiness are recorded as findings - an empty wtmp on a machine with
recorded sessions is evidence of tampering, not a parser failure.

Layout (little-endian):
  int32  ut_type
  int32  ut_pid
  char   ut_line[32]
  char   ut_id[4]
  char   ut_user[32]
  char   ut_host[256]
  int16  e_termination
  int16  e_exit
  int32  ut_session
  int32  tv_sec
  int32  tv_usec
  int32  ut_addr_v6[4]
  char   __unused[20]
"""
from __future__ import annotations

import ipaddress
import struct
from datetime import datetime, timezone
from pathlib import Path

from .base import BaseParser, ParseContext

UTMP_RECORD_SIZE = 384
_HEADER = struct.Struct("<ii32s4s32s256s")          # through ut_host
_TAIL = struct.Struct("<hhiii")                     # e_term..tv_usec
_ADDR = struct.Struct("<iiii")

_TYPE_EMPTY = 0
_TYPE_RUN_LVL = 1
_TYPE_BOOT_TIME = 2
_TYPE_NEW_TIME = 3
_TYPE_OLD_TIME = 4
_TYPE_INIT_PROCESS = 5
_TYPE_LOGIN_PROCESS = 6
_TYPE_USER_PROCESS = 7
_TYPE_DEAD_PROCESS = 8

# A decoded timestamp outside this range means we are misreading the layout.
# tv_sec is int32, so it cannot exceed 2038-01-19 anyway; in practice a
# misaligned read shows up as a near-1970 value, which the lower bound catches.
_PLAUSIBLE_MIN = datetime(1993, 1, 1, tzinfo=timezone.utc).timestamp()
_PLAUSIBLE_MAX = 2 ** 31 - 1


def _cstr(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace").strip()


class UtmpParser(BaseParser):
    name = "utmp_parser"
    version = "1.0"
    artifact_category = "login_activity"
    applies_to = [
        "var/log/wtmp", "var/log/wtmp.*",
        "var/log/btmp", "var/log/btmp.*",
        "var/run/utmp", "run/utmp",
    ]

    def parse(self, path: Path, context: ParseContext):
        rel = context.artifact_rel.replace("\\", "/")
        is_btmp = "btmp" in rel.rsplit("/", 1)[-1]
        data = path.read_bytes()

        if len(data) == 0:
            yield self._finding(
                context,
                "utmp_empty",
                f"{rel} exists but is zero-length: no login records at all. "
                f"On a machine with recorded sessions this indicates the file "
                f"was cleared.",
                "medium",
            )
            return

        if data.startswith(b"SQLite format 3\x00"):
            yield from self._parse_sqlite_wtmp(path, context, rel)
            return

        remainder = len(data) % UTMP_RECORD_SIZE
        if remainder:
            yield self._finding(
                context,
                "utmp_unsupported_layout",
                f"{rel} is {len(data)} bytes, not a multiple of "
                f"{UTMP_RECORD_SIZE}: either truncated or written by a libc "
                f"whose utmp layout this tool does not support (musl/Alpine). "
                f"Parsing the {len(data) // UTMP_RECORD_SIZE} complete records "
                f"only.",
                "low",
            )

        emitted = 0
        implausible = 0
        for index in range(len(data) // UTMP_RECORD_SIZE):
            chunk = data[index * UTMP_RECORD_SIZE:(index + 1) * UTMP_RECORD_SIZE]
            offset = index * UTMP_RECORD_SIZE
            if not any(chunk):
                continue  # all-zero slot

            ut_type, ut_pid, line_b, _id, user_b, host_b = _HEADER.unpack_from(chunk, 0)
            tail_off = _HEADER.size
            _term, _exit, _session, tv_sec, _tv_usec = _TAIL.unpack_from(chunk, tail_off)
            addr_off = tail_off + _TAIL.size
            addr_words = _ADDR.unpack_from(chunk, addr_off)

            if not (_PLAUSIBLE_MIN <= tv_sec <= _PLAUSIBLE_MAX):
                implausible += 1
                continue

            user = _cstr(user_b)
            line = _cstr(line_b)
            host = _cstr(host_b)
            ts = context.time_ctx.resolve_epoch(tv_sec)

            source_ip = self._addr_to_ip(addr_words) or self._host_as_ip(host)
            source_host = None if source_ip else (host or None)

            if is_btmp:
                subcategory, severity, category = "failed_login", "low", "login_activity"
                description = (
                    f"Failed login attempt for {user or 'unknown user'} on "
                    f"{line or 'unknown terminal'}"
                    + (f" from {source_ip or source_host}" if (source_ip or source_host) else "")
                )
            elif ut_type == _TYPE_BOOT_TIME:
                subcategory, severity, category = "system_boot", "info", "environment"
                description = f"System boot (kernel {host})" if host else "System boot"
                user = user or "reboot"
            elif ut_type == _TYPE_RUN_LVL:
                subcategory, severity, category = "runlevel_change", "info", "environment"
                description = f"Runlevel change recorded on {line or 'system'}"
            elif ut_type == _TYPE_DEAD_PROCESS:
                subcategory, severity, category = "logout", "info", "login_activity"
                description = (
                    f"Session ended on {line or 'unknown terminal'}"
                    + (f" (user {user})" if user else "")
                )
            elif ut_type == _TYPE_USER_PROCESS:
                subcategory, severity, category = "login", "info", "login_activity"
                description = (
                    f"Login: {user or 'unknown user'} on {line or 'unknown terminal'}"
                    + (f" from {source_ip or source_host}" if (source_ip or source_host) else " (local)")
                )
            elif ut_type in (_TYPE_LOGIN_PROCESS, _TYPE_INIT_PROCESS):
                subcategory, severity, category = "login_prompt", "info", "login_activity"
                description = f"Login prompt started on {line or 'unknown terminal'}"
            elif ut_type in (_TYPE_NEW_TIME, _TYPE_OLD_TIME):
                subcategory, severity, category = "clock_change", "medium", "environment"
                description = (
                    "System clock was changed - timestamps around this point "
                    "may not be comparable"
                )
            else:
                subcategory, severity, category = "utmp_record", "info", "login_activity"
                description = f"utmp record type {ut_type} for {user or 'unknown'}"

            yield context.build_event(
                event_kind="event",
                timestamp_utc=ts.utc_iso,
                timestamp_local=ts.local_iso,
                timestamp_confidence=ts.confidence,
                category=category,
                subcategory=subcategory,
                actor_user=user or None,
                actor_process=None,
                source_ip=source_ip,
                source_host=source_host,
                description=description,
                severity=severity,
                raw_line=(
                    f"type={ut_type} pid={ut_pid} line={line} user={user} "
                    f"host={host} tv_sec={tv_sec}"
                ),
                raw_line_offset=offset,
                tool_generated_flag=context.is_tool_generated(source_ip, ts.utc_iso),
                notes=f"utmp record index {index}",
            )
            emitted += 1

        if implausible:
            yield self._finding(
                context,
                "utmp_unsupported_layout",
                f"{implausible} record(s) in {rel} decoded to timestamps "
                f"outside a plausible range. This normally means the file uses "
                f"a utmp layout this tool does not support; those records were "
                f"NOT reported as logins rather than presenting invented dates.",
                "medium",
            )
        if emitted == 0 and not implausible:
            yield self._finding(
                context,
                "utmp_empty",
                f"{rel} contains no usable login records. On a machine with "
                f"recorded sessions elsewhere this suggests the file was "
                f"cleared or the platform does not maintain it (musl, "
                f"containers).",
                "medium",
            )

    def _parse_sqlite_wtmp(self, path: Path, context: ParseContext, rel: str):
        """Parse modern wtmpdb SQLite databases (common on systemd / Debian / Kali / Ubuntu)."""
        import sqlite3
        try:
            conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        except Exception:
            try:
                conn = sqlite3.connect(str(path))
            except Exception as e:
                yield self._finding(context, "utmp_sqlite_error", f"Could not open {rel} as SQLite database: {e}", "low")
                return

        try:
            cursor = conn.cursor()
            table_check = cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='wtmp'").fetchone()
            if not table_check:
                yield self._finding(context, "utmp_sqlite_no_wtmp", f"{rel} is an SQLite database without a wtmp table", "low")
                return

            rows = cursor.execute("SELECT ID, Type, User, Login, Logout, TTY, RemoteHost, Service FROM wtmp ORDER BY ID ASC").fetchall()
            if not rows:
                yield self._finding(context, "utmp_empty", f"{rel} SQLite database contains no session records", "medium")
                return

            for row in rows:
                id_val, type_val, user, login_us, logout_us, tty, remote_host, service = row
                user = (user or "").strip()
                tty = (tty or "").strip()
                remote_host = (remote_host or "").strip()
                service = (service or "").strip()

                source_ip = self._host_as_ip(remote_host)
                source_host = None if source_ip else (remote_host or None)

                # Process Login
                if login_us:
                    login_sec = float(login_us) / 1_000_000.0
                    if _PLAUSIBLE_MIN <= login_sec <= _PLAUSIBLE_MAX:
                        ts = context.time_ctx.resolve_epoch(login_sec)
                        desc = f"User login: {user or 'unknown user'} on {tty or 'unknown terminal'}"
                        if service:
                            desc += f" via {service}"
                        if source_ip or source_host:
                            desc += f" from {source_ip or source_host}"
                        else:
                            desc += " (local)"

                        yield context.build_event(
                            event_kind="event",
                            timestamp_utc=ts.utc_iso,
                            timestamp_local=ts.local_iso,
                            timestamp_confidence=ts.confidence,
                            category="login_activity",
                            subcategory="login",
                            actor_user=user or None,
                            actor_process=service or None,
                            source_ip=source_ip,
                            source_host=source_host,
                            description=desc,
                            severity="info",
                            raw_line=f"id={id_val} type={type_val} user={user} tty={tty} host={remote_host} service={service} login={login_us}",
                            raw_line_offset=int(id_val or 0),
                            tool_generated_flag=context.is_tool_generated(source_ip, ts.utc_iso),
                            notes=f"wtmpdb record id {id_val}",
                        )

                # Process Logout
                if logout_us:
                    logout_sec = float(logout_us) / 1_000_000.0
                    if _PLAUSIBLE_MIN <= logout_sec <= _PLAUSIBLE_MAX:
                        ts_out = context.time_ctx.resolve_epoch(logout_sec)
                        desc_out = f"Session closed for {user or 'unknown user'} on {tty or 'unknown terminal'}"
                        if service:
                            desc_out += f" via {service}"

                        yield context.build_event(
                            event_kind="event",
                            timestamp_utc=ts_out.utc_iso,
                            timestamp_local=ts_out.local_iso,
                            timestamp_confidence=ts_out.confidence,
                            category="login_activity",
                            subcategory="logout",
                            actor_user=user or None,
                            actor_process=service or None,
                            source_ip=source_ip,
                            source_host=source_host,
                            description=desc_out,
                            severity="info",
                            raw_line=f"id={id_val} type={type_val} user={user} tty={tty} host={remote_host} service={service} logout={logout_us}",
                            raw_line_offset=int(id_val or 0),
                            tool_generated_flag=context.is_tool_generated(source_ip, ts_out.utc_iso),
                            notes=f"wtmpdb logout id {id_val}",
                        )
        finally:
            conn.close()

    @staticmethod
    def _addr_to_ip(words) -> str | None:
        if not any(words):
            return None
        if not any(words[1:]):  # IPv4 lives in the first word
            try:
                return str(ipaddress.IPv4Address(
                    struct.pack("<i", words[0])
                ))
            except (ipaddress.AddressValueError, struct.error):
                return None
        try:
            return str(ipaddress.IPv6Address(struct.pack("<iiii", *words)))
        except (ipaddress.AddressValueError, struct.error):
            return None

    @staticmethod
    def _host_as_ip(host: str) -> str | None:
        if not host:
            return None
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return None

    @staticmethod
    def _finding(context: ParseContext, subcategory: str, description: str,
                 severity: str):
        return context.build_event(
            event_kind="state_finding",
            timestamp_utc=None,
            timestamp_local=None,
            timestamp_confidence="unknown",
            category="login_activity",
            subcategory=subcategory,
            description=description,
            severity=severity,
            raw_line=f"[{subcategory}] {context.artifact_rel}",
            raw_line_offset=0,
        )
