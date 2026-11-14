"""/etc/sudoers and /etc/sudoers.d/* (spec category 3).

sudoers answers the question the auth log cannot: who is ALLOWED to become
root, and do they have to prove who they are first. Everything emitted here
is a state_finding - a fact about the machine's configuration at collection
time, not something that happened at a point in time.

What is parsed
  Defaults lines           -> subcategory "sudo_defaults"
  *_Alias definitions      -> subcategory "sudo_alias"
  privilege spec lines     -> subcategory "sudo_privilege"
  #includedir / @includedir-> subcategory "includedir"

Findings that matter
  NOPASSWD granting ALL commands  -> "passwordless_sudo", severity high.
      The named principal becomes root with no password at all: stealing the
      account (a key, a session, a reused password) is stealing root.
  NOPASSWD with a restricted command list -> "passwordless_sudo", medium.
  Defaults !authenticate          -> "passwordless_sudo", severity high.
      The same thing applied globally: sudo stops asking for a password for
      everyone the ruleset permits.
  A spec line granting ALL commands to a principal that is not root and not
  one of the conventional admin groups (%sudo/%wheel/%admin) -> medium.

Syntax details that a naive line-by-line reader gets wrong
  - backslash line continuations: a Cmnd_Alias or a command list routinely
    spans several physical lines. They are joined before matching, and the
    event carries the offset of the FIRST physical line.
  - '#' starts a comment EXCEPT for '#include' / '#includedir', which are
    directives. The includedir event is emitted so the report can show that
    /etc/sudoers.d was in scope (an empty drop-in directory and an
    uncollected one look identical otherwise).
  - a user list may hold several principals ('alice, bob ALL=...'); one
    event per principal, each with a distinct raw_line so the DB's
    event_hash dedupe does not silently drop all but the first.
"""
from __future__ import annotations

import re
from pathlib import Path

from .base import BaseParser, ParseContext

# groups conventionally used to hand out full administrative rights; a full
# grant to these is normal, a full grant to anything else is worth a look
CONVENTIONAL_ADMINS = {"root", "%sudo", "%wheel", "%admin"}

_ALIAS = re.compile(
    r"^(?P<kind>User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\s+"
    r"(?P<name>[A-Z0-9_]+)\s*=\s*(?P<value>.*)$"
)
_DEFAULTS = re.compile(r"^Defaults\b(?P<scope>[:@>!][^\s]+)?\s*(?P<body>.*)$")
_INCLUDE = re.compile(r"^[#@](?P<directive>includedir|include)\s+(?P<target>\S+)\s*$")
_SPEC = re.compile(
    r"^(?P<who>[^\s=,]+(?:\s*,\s*[^\s=,]+)*)\s+(?P<hosts>[^=]+?)\s*=\s*(?P<rest>.*)$"
)
_RUNAS = re.compile(r"^\(\s*(?P<runas>[^)]*)\)\s*")
_TAG = re.compile(
    r"^(?P<tag>NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|"
    r"NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT|FOLLOW|NOFOLLOW|MAIL|NOMAIL)"
    r"\s*:\s*",
    re.IGNORECASE,
)


def _logical_lines(path: Path, context: ParseContext):
    """Yield (offset_of_first_physical_line, joined_line) with backslash
    continuations resolved."""
    buffer = ""
    start = 0
    for offset, line in BaseParser.iter_lines(path, context):
        stripped = line.strip()
        if buffer:
            buffer = f"{buffer} {stripped}"
        else:
            start, buffer = offset, stripped
        if buffer.endswith("\\"):
            buffer = buffer[:-1].rstrip()
            continue
        if buffer:
            yield start, buffer
        buffer = ""
    if buffer:
        yield start, buffer


def _split_tags(rest: str) -> tuple[str | None, list[str], str]:
    """'(root) NOPASSWD: /bin/ls' -> ('root', ['NOPASSWD'], '/bin/ls')"""
    runas = None
    tags: list[str] = []
    text = rest.strip()
    while True:
        m = _RUNAS.match(text)
        if m and runas is None:
            runas = m.group("runas").strip()
            text = text[m.end():]
            continue
        m = _TAG.match(text)
        if m:
            tags.append(m.group("tag").upper())
            text = text[m.end():]
            continue
        break
    return runas, tags, text.strip()


def _grants_all(commands: str) -> bool:
    return any(part.strip().upper() == "ALL"
               for part in commands.split(",") if part.strip())


class SudoersParser(BaseParser):
    name = "sudoers_parser"
    version = "1.0"
    artifact_category = "privilege_escalation"
    applies_to = ["etc/sudoers", "etc/sudoers.d/*", "etc/sudoers.dist"]

    # ------------------------------------------------------------- helpers

    def _finding(self, context: ParseContext, **kw):
        kw.setdefault("event_kind", "state_finding")
        kw.setdefault("timestamp_utc", None)
        kw.setdefault("timestamp_local", None)
        kw.setdefault("timestamp_confidence", "unknown")
        kw.setdefault("category", "privilege_escalation")
        return context.build_event(**kw)

    # --------------------------------------------------------------- parse

    def parse(self, path: Path, context: ParseContext):
        for offset, line in _logical_lines(path, context):
            inc = _INCLUDE.match(line)
            if inc:
                target = inc.group("target")
                directive = inc.group("directive")
                yield self._finding(
                    context,
                    subcategory="includedir",
                    description=(
                        f"sudoers pulls in additional rules via "
                        f"{directive} {target}: every file under {target} is "
                        f"part of the effective sudo policy"
                    ),
                    severity="info",
                    raw_line=line,
                    raw_line_offset=offset,
                )
                continue

            if line.startswith("#"):
                continue

            m = _DEFAULTS.match(line)
            if m:
                yield self._defaults_event(context, offset, line, m)
                continue

            m = _ALIAS.match(line)
            if m:
                yield self._finding(
                    context,
                    subcategory="sudo_alias",
                    description=(
                        f"{m.group('kind')} {m.group('name')} defined as: "
                        f"{m.group('value').strip()}"
                    ),
                    severity="info",
                    raw_line=line,
                    raw_line_offset=offset,
                )
                continue

            m = _SPEC.match(line)
            if m:
                yield from self._spec_events(context, offset, line, m)
                continue

            yield self._finding(
                context,
                subcategory="sudoers_unparsed",
                description=(
                    "sudoers line could not be interpreted by this parser; "
                    "it is reported verbatim so nothing is silently dropped"
                ),
                severity="low",
                raw_line=line,
                raw_line_offset=offset,
            )

    # ------------------------------------------------------------ Defaults

    def _defaults_event(self, context: ParseContext, offset: int, line: str, m):
        scope = (m.group("scope") or "").strip()
        body = (m.group("body") or "").strip()
        where = f" (scoped to {scope})" if scope else ""
        if re.search(r"!\s*authenticate\b", line):
            return self._finding(
                context,
                subcategory="passwordless_sudo",
                description=(
                    f"Defaults !authenticate is set{where}: sudo does not ask "
                    f"for a password at all, so every principal the ruleset "
                    f"permits can become root with no password"
                ),
                severity="high",
                raw_line=line,
                raw_line_offset=offset,
            )
        return self._finding(
            context,
            subcategory="sudo_defaults",
            description=f"Defaults setting: {body or line}{where}",
            severity="info",
            raw_line=line,
            raw_line_offset=offset,
        )

    # -------------------------------------------------------- privilege spec

    def _spec_events(self, context: ParseContext, offset: int, line: str, m):
        hosts = m.group("hosts").strip()
        runas, tags, commands = _split_tags(m.group("rest"))
        principals = [p.strip() for p in m.group("who").split(",") if p.strip()]
        nopasswd = "NOPASSWD" in tags
        everything = _grants_all(commands)
        multi = len(principals) > 1

        for who in principals:
            conventional = who in CONVENTIONAL_ADMINS
            if nopasswd:
                subcategory = "passwordless_sudo"
                severity = "high" if everything else "medium"
            else:
                subcategory = "sudo_privilege"
                severity = "medium" if (everything and not conventional) else "info"

            kind = "group" if who.startswith("%") else "user"
            target = runas or "root"
            what = commands or "(no command list)"
            description = (
                f"sudoers: {kind} {who} may run {what} as {target} on {hosts}"
            )
            if nopasswd and everything:
                description += (
                    " WITHOUT a password - this account can run any command as "
                    "root with no password at all, so control of the account is "
                    "control of root"
                )
            elif nopasswd:
                description += " without being asked for a password"
            elif everything and not conventional:
                description += (
                    " - a full grant to a principal that is neither root nor a "
                    "conventional admin group (%sudo/%wheel/%admin)"
                )
            if tags:
                description += f" [tags: {', '.join(tags)}]"

            yield self._finding(
                context,
                subcategory=subcategory,
                actor_user=who,
                description=description,
                severity=severity,
                # keep hashes distinct when one line names several principals
                raw_line=f"[{who}] {line}" if multi else line,
                raw_line_offset=offset,
                notes=f"runas={target} hosts={hosts}",
            )
