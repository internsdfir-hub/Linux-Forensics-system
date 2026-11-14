"""ld.so.preload and shell-startup persistence parsers.

The collector preserves /etc/ld.so.preload and the shell rc/profile files,
but nothing parsed them, so LdPreloadRule (queries subcategory
'ld_preload_set') was a dead rule and PersistenceAfterLoginRule never saw a
'suspicious_startup_line' anchor.

- LdPreloadParser: any active preload library is high severity - the file is
  empty on a clean system and is a classic rootkit hook point.
- StartupScriptParser: emits an event only for lines that match a known
  command-injection / reverse-shell shape. Benign startup lines are left as
  preserved raw evidence rather than flooded into the timeline.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

# Command shapes that have no business in a login shell's startup file.
_SUSPICIOUS = re.compile(
    r"""(?ix)
    (?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh   # download piped straight to a shell
    | /dev/(?:tcp|udp)/                    # bash pseudo-device reverse shell
    | \bnc(?:at)?\b[^\n]*\s-e\b            # netcat with -e exec
    | \bbash\s+-i\b                        # interactive bash to a socket
    | \bbase64\b[^\n]*\|\s*(?:ba)?sh       # base64 decode piped to shell
    | \bmkfifo\b[^\n]*\|\s*(?:ba)?sh       # named-pipe reverse shell
    | \bpython[0-9.]*\b[^\n]*-c[^\n]*socket # python one-liner socket shell
    | \bLD_PRELOAD\s*=                     # inline preload injection
    """
)


class LdPreloadParser(BaseParser):
    name = "ld_preload_parser"
    version = "1.0"
    artifact_category = "persistence"
    applies_to = ["etc/ld.so.preload"]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return
        for offset, line in self.iter_lines(path, context):
            lib = line.strip()
            if not lib or lib.startswith("#"):
                continue
            yield context.build_event(
                event_kind="state_finding",
                timestamp_utc=None,
                timestamp_local=None,
                timestamp_confidence="unknown",
                category="persistence",
                subcategory="ld_preload_set",
                description=(
                    f"/etc/ld.so.preload forces the dynamic linker to preload "
                    f"'{lib}' into every executed process - a classic rootkit "
                    f"hook used to hide files, processes and connections"
                ),
                severity="high",
                raw_line=lib,
                raw_line_offset=offset,
            )


class StartupScriptParser(BaseParser):
    name = "startup_script_parser"
    version = "1.0"
    artifact_category = "persistence"
    applies_to = [
        "etc/profile",
        "etc/profile.d/*",
        "etc/rc.local",
        "home/*/.bashrc",
        "home/*/.profile",
        "home/*/.bash_profile",
        "home/*/.bash_login",
        "root/.bashrc",
        "root/.profile",
        "root/.bash_profile",
        "root/.bash_login",
    ]

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return
        for offset, line in self.iter_lines(path, context):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not _SUSPICIOUS.search(stripped):
                continue
            yield context.build_event(
                event_kind="state_finding",
                timestamp_utc=None,
                timestamp_local=None,
                timestamp_confidence="unknown",
                category="persistence",
                subcategory="suspicious_startup_line",
                description=(
                    "A shell startup file runs a command that looks like "
                    "remote code execution or a reverse shell - it executes "
                    "automatically every time the shell starts"
                ),
                severity="high",
                raw_line=stripped,
                raw_line_offset=offset,
            )
