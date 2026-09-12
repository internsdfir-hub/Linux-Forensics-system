"""sshd_config risk parser (revives the sshd_config_risk rule).

The collector preserves /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*
as evidence, but nothing turned them into events, so SshdConfigRule -
which queries for subcategory='sshd_setting' - could never fire.

This parser emits a 'sshd_setting' state_finding for the *risky* directives
only. Safe values (PermitRootLogin no / prohibit-password, commented lines)
emit nothing, so the rule never flags a hardened host. The raw file is still
preserved verbatim as evidence regardless.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent
from .base import BaseParser, ParseContext

# "Key Value" with optional leading whitespace; sshd_config is case-insensitive
# on keywords and allows '=' or whitespace as the separator.
_DIRECTIVE = re.compile(r"^\s*([A-Za-z]\w*)\s*[=\s]\s*(.+?)\s*$")


class SshdConfigParser(BaseParser):
    name = "sshd_config_parser"
    version = "1.0"
    artifact_category = "persistence"
    applies_to = [
        "etc/ssh/sshd_config",
        "etc/ssh/sshd_config.d/*",
    ]

    # keyword (lowercased) -> (risky_value_predicate, severity, why)
    def _risk(self, keyword: str, value: str):
        v = value.strip().lower().split()[0] if value.strip() else ""
        if keyword == "permitrootlogin" and v == "yes":
            return ("high",
                    "PermitRootLogin yes - the SSH daemon permits direct root "
                    "login, so the root account can be attacked over the "
                    "network with no user attribution")
        if keyword == "permitemptypasswords" and v == "yes":
            return ("high",
                    "PermitEmptyPasswords yes - accounts with an empty "
                    "password may log in over SSH without any credential")
        if keyword == "passwordauthentication" and v == "yes":
            return ("medium",
                    "PasswordAuthentication yes - password logins are allowed, "
                    "which exposes every account to brute-force attempts")
        return None

    def _state(self, context: ParseContext, **kw) -> NormalizedEvent:
        kw.setdefault("event_kind", "state_finding")
        kw.setdefault("timestamp_utc", None)
        kw.setdefault("timestamp_local", None)
        kw.setdefault("timestamp_confidence", "unknown")
        kw.setdefault("category", "persistence")
        return context.build_event(**kw)

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        if not path.is_file():
            return
        for offset, line in self.iter_lines(path, context):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = _DIRECTIVE.match(stripped)
            if not m:
                continue
            keyword = m.group(1).lower()
            value = m.group(2)
            risk = self._risk(keyword, value)
            if not risk:
                continue
            severity, why = risk
            yield self._state(
                context,
                subcategory="sshd_setting",
                description=why,
                severity=severity,
                raw_line=stripped,
                raw_line_offset=offset,
            )
