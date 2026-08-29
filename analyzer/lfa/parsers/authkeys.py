"""authorized_keys parser (spec category 4: persistence).

One line here is passwordless login, forever, for whoever holds the private
key - and unlike a cron job it leaves no execution trace until it is used.
So every key gets its own event with the fingerprint an analyst can compare
against known-good inventory (`ssh-keygen -lf` prints exactly this form:
SHA256:<unpadded base64 of the sha256 of the decoded key blob>).

Two details matter for the write-up:
  * the leading options field (command=, from=, no-pty, ...) is quoted text
    that can contain spaces and commas, so it is tokenised quote-aware
    rather than split() on whitespace;
  * a `command="..."` forced command is how a legitimate backup key is
    restricted AND how a backdoor pins itself to a payload, so it is
    reported at medium and never silently.

The file mtime is carried in the description and, as an epoch, in notes -
a key added inside the incident window is the finding, not the key itself.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from pathlib import Path

from .base import BaseParser, ParseContext
from .cron import mtime_iso, mtime_note

_KEY_TYPE_RE = re.compile(
    r"^(?:sk-)?(?:ssh-(?:rsa|dss|ed25519|ed448)"
    r"|ecdsa-sha2-nistp\d+"
    r"|rsa-sha2-\d+)"
    r"(?:-cert-v0\d)?(?:@openssh\.com)?$"
)
_FORCED_COMMAND_RE = re.compile(r'(?:^|,)\s*command\s*=', re.IGNORECASE)


def fingerprint(blob_b64: str) -> str | None:
    """SHA256:<base64, unpadded> over the DECODED key blob, like ssh-keygen."""
    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not blob:
        return None
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _tokenize(line: str) -> list[tuple[int, str]]:
    """(start_index, token) honouring double-quoted, backslash-escaped
    option values so `command="do a thing"` stays one token."""
    tokens: list[tuple[int, str]] = []
    i, n = 0, len(line)
    while i < n:
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break
        start = i
        in_quotes = False
        while i < n and (in_quotes or not line[i].isspace()):
            char = line[i]
            if char == "\\" and in_quotes and i + 1 < n:
                i += 2
                continue
            if char == '"':
                in_quotes = not in_quotes
            i += 1
        tokens.append((start, line[start:i]))
    return tokens


def split_key_line(line: str):
    """-> (options, key_type, blob_b64, comment) or None when the line is not
    a usable public key entry."""
    tokens = _tokenize(line)
    for index, (start, token) in enumerate(tokens):
        if not _KEY_TYPE_RE.match(token):
            continue
        if index + 1 >= len(tokens):
            return None
        blob_start, blob = tokens[index + 1]
        options = line[:start].strip().rstrip(",")
        comment = line[blob_start + len(blob):].strip()
        return options, token, blob, comment
    return None


class AuthKeysParser(BaseParser):
    name = "authkeys_parser"
    version = "1.0"
    artifact_category = "persistence"
    applies_to = [
        "home/*/.ssh/authorized_keys*",
        "root/.ssh/authorized_keys*",
    ]

    @staticmethod
    def _owner(rel: str) -> str | None:
        parts = rel.split("/")
        if parts[0] == "root":
            return "root"
        if parts[0] == "home" and len(parts) > 1:
            return parts[1]
        return None

    def _state(self, context: ParseContext, **kw):
        kw.setdefault("event_kind", "state_finding")
        kw.setdefault("timestamp_utc", None)
        kw.setdefault("timestamp_local", None)
        kw.setdefault("timestamp_confidence", "unknown")
        kw.setdefault("category", "persistence")
        kw.setdefault("notes", mtime_note(context))
        return context.build_event(**kw)

    def parse(self, path: Path, context: ParseContext):
        rel = context.artifact_rel.replace("\\", "/")
        user = self._owner(rel)
        stamp = mtime_iso(context)
        line_no = 0

        for offset, line in self.iter_lines(path, context):
            line_no += 1
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            parsed = split_key_line(line)
            print_ok = parsed is not None
            digest = fingerprint(parsed[2]) if print_ok else None
            if not print_ok or digest is None:
                # never drop a line from this file silently: an entry we
                # cannot decode is itself worth an analyst's attention
                yield self._state(
                    context,
                    subcategory="unparsable_key_line",
                    actor_user=user,
                    description=(
                        f"Line {line_no} of {rel} is not a decodable SSH public "
                        f"key entry (kept verbatim in raw_line) "
                        f"(file mtime {stamp})"
                    ),
                    severity="low",
                    raw_line=line,
                    raw_line_offset=offset,
                )
                continue

            options, key_type, _blob, comment = parsed
            forced = bool(_FORCED_COMMAND_RE.search(options))
            yield self._state(
                context,
                subcategory="authorized_key",
                actor_user=user,
                description=(
                    f"{key_type} key authorized for login as "
                    f"{user or 'unknown user'}: fingerprint {digest}"
                    + (f" comment {comment!r}" if comment else " (no comment)")
                    + (f" options {options}" if options else "")
                    + (" [forced command: this key can only run that command, "
                       "and only that command runs when it is used]" if forced
                       else "")
                    + f" (file mtime {stamp})"
                ),
                severity="medium" if forced else "info",
                raw_line=line,
                raw_line_offset=offset,
            )
