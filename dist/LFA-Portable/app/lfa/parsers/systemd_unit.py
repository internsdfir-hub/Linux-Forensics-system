"""systemd unit parser (spec category 4: persistence).

systemd is where modern persistence lives: a .service with Restart=always
survives every kill, a .timer replaces cron without touching a crontab, and
a unit under ~/.config/systemd/user needs no root at all (it starts with the
user's session, or at boot if lingering is enabled).

Covered:
  etc/systemd/system/**              system units and their .wants/ links
  home/*/.config/systemd/user/**     per-user units
  root/.config/systemd/user/**

.wants/ and .requires/ directories hold symlinks; depending on how the
bundle was collected they arrive as dangling symlinks dumped to text, as
copies of the target, or as empty files. All three are handled: the
enablement fact is reported either way, and a body is only parsed if one
is actually there.
"""
from __future__ import annotations

import re
from pathlib import Path

from .base import BaseParser, ParseContext
from .cron import mtime_iso, mtime_note, suspicious_indicators

_SECTION_RE = re.compile(r"^\[([^]]+)\]\s*$")

# directives worth putting in front of an analyst, in report order
_REPORTED = (
    "Description",
    "Type",
    "User",
    "Group",
    "ExecStartPre",
    "ExecStart",
    "ExecStartPost",
    "ExecStop",
    "ExecReload",
    "Restart",
    "OnCalendar",
    "OnBootSec",
    "OnUnitActiveSec",
    "OnStartupSec",
    "Persistent",
    "Unit",
    "ListenStream",
    "ListenDatagram",
    "Accept",
    "WantedBy",
    "RequiredBy",
    "Also",
)
_EXEC_KEYS = {"ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop",
              "ExecReload"}

_UNIT_LABELS = {
    ".service": "systemd service unit",
    ".timer": "systemd timer unit",
    ".socket": "systemd socket unit",
    ".path": "systemd path unit",
    ".mount": "systemd mount unit",
    ".target": "systemd target unit",
}


class SystemdUnitParser(BaseParser):
    name = "systemd_unit_parser"
    version = "1.0"
    artifact_category = "persistence"
    applies_to = [
        "etc/systemd/system/**",
        "home/*/.config/systemd/user/**",
        "root/.config/systemd/user/**",
    ]

    # ------------------------------------------------------------- helpers

    def _state(self, context: ParseContext, **kw):
        kw.setdefault("event_kind", "state_finding")
        kw.setdefault("timestamp_utc", None)
        kw.setdefault("timestamp_local", None)
        kw.setdefault("timestamp_confidence", "unknown")
        kw.setdefault("category", "persistence")
        kw.setdefault("notes", mtime_note(context))
        return context.build_event(**kw)

    @staticmethod
    def _owner(rel: str) -> str | None:
        parts = rel.split("/")
        if parts[0] == "root":
            return "root"
        if parts[0] == "home" and len(parts) > 1:
            return parts[1]
        return None

    def _logical_lines(self, path: Path, context: ParseContext):
        """Yield (offset, line) with systemd's backslash continuations joined
        back into single logical directives."""
        buf: str | None = None
        buf_offset = 0
        for offset, line in self.iter_lines(path, context):
            raw = line.rstrip()
            if buf is None:
                buf, buf_offset = raw, offset
            else:
                buf = f"{buf} {raw.strip()}"
            if buf.endswith("\\"):
                buf = buf[:-1].rstrip()
                continue
            yield buf_offset, buf
            buf = None
        if buf is not None:
            yield buf_offset, buf

    # --------------------------------------------------------------- parse

    def parse(self, path: Path, context: ParseContext):
        rel = context.artifact_rel.replace("\\", "/")
        parts = rel.split("/")
        basename = parts[-1]
        stamp = mtime_iso(context)
        owner = self._owner(rel)
        is_user_unit = "/systemd/user/" in rel
        link_dir = next(
            (p for p in parts[:-1] if p.endswith((".wants", ".requires"))), None
        )

        entries: list[tuple[str, str, str, int, str]] = []  # section,k,v,off,line
        for offset, line in self._logical_lines(path, context):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            if _SECTION_RE.match(stripped):
                section = _SECTION_RE.match(stripped).group(1)
                entries.append((section, "", "", offset, line))
                continue
            key, sep, value = stripped.partition("=")
            key = key.strip()
            if not sep or not key or " " in key:
                continue
            section = next((s for s, k, _v, _o, _l in reversed(entries) if not k),
                           "")
            entries.append((section, key, value.strip(), offset, line))

        directives = [e for e in entries if e[1]]

        if link_dir:
            first_body = next((l for _s, _k, _v, _o, l in directives), "")
            target = first_body
            if not target:
                target = next(
                    (l.strip() for _o, l in self._logical_lines(path, context)
                     if l.strip()),
                    "",
                )
            yield self._state(
                context,
                subcategory="systemd_enabled_link",
                actor_user=owner,
                description=(
                    f"Unit {basename} is enabled: {rel} links it into "
                    f"{link_dir.rsplit('.', 1)[0]}"
                    + (f" (link target {target})" if target else "")
                    + f" (file mtime {stamp})"
                ),
                severity="info",
                raw_line=target or f"<enablement symlink {rel}>",
                raw_line_offset=0,
            )

        if not directives:
            return

        values: dict[str, list[str]] = {}
        for _section, key, value, _offset, _line in directives:
            values.setdefault(key, []).append(value)

        suffix = basename[basename.rfind("."):] if "." in basename else ""
        label = _UNIT_LABELS.get(suffix, "systemd unit")
        subcategory = "systemd_timer" if suffix == ".timer" else "systemd_unit"

        shown = []
        for key in _REPORTED:
            for value in values.get(key, []):
                shown.append(f"{key}={value}")
        if not shown:
            shown = [f"{k}={v[0]}" for k, v in list(values.items())[:5]]

        run_as = (values.get("User") or [None])[0] or owner or "root"
        scope = f" (user unit for {owner})" if is_user_unit and owner else ""

        yield self._state(
            context,
            subcategory=subcategory,
            actor_user=run_as,
            description=(
                f"{label} {rel}{scope} runs as {run_as}: "
                + " ".join(shown)
                + f" (file mtime {stamp})"
            ),
            severity="info",
            raw_line=f"<systemd unit file {rel}: {len(directives)} directives>",
            raw_line_offset=0,
        )

        for _section, key, value, offset, line in directives:
            if key not in _EXEC_KEYS:
                continue
            reasons = suspicious_indicators(value)
            if not reasons:
                continue
            yield self._state(
                context,
                subcategory="suspicious_systemd_unit",
                actor_user=run_as,
                description=(
                    f"Suspicious {key} in {label.replace('systemd ', '')} "
                    f"{rel} (runs as {run_as}): {value} -- "
                    + "; ".join(reasons)
                    + f" (file mtime {stamp})"
                ),
                severity="high",
                raw_line=line.strip(),
                raw_line_offset=offset,
            )
