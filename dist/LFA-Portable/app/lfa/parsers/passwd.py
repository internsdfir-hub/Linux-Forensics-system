"""User account files: /etc/passwd, /etc/shadow, /etc/group and their
backup variants (spec category 1).

Everything here is a state_finding (a fact about the machine's configuration
at collection time). The quietly useful part: diffing the live files against
their '-' backups shows exactly what changed recently, for free.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from .base import BaseParser, ParseContext

# groups whose membership is effectively privileged (docker ~ root because
# a member can mount / into a container)
PRIVILEGED_GROUPS = {"sudo", "wheel", "adm", "docker", "root"}

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _days_to_date(days_str: str) -> str | None:
    try:
        days = int(days_str)
    except (TypeError, ValueError):
        return None
    if days <= 0:
        return None
    # trap #10: shadow stores DAYS since epoch, not seconds
    return (_EPOCH + timedelta(days=days)).date().isoformat()


def _read_colon_file(path: Path, context: ParseContext):
    for offset, line in BaseParser.iter_lines(path, context):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split(":")
        yield offset, line, fields


class PasswdParser(BaseParser):
    name = "passwd_parser"
    version = "1.0"
    artifact_category = "user_accounts"
    applies_to = [
        "etc/passwd", "etc/passwd-",
        "etc/shadow", "etc/shadow-",
        "etc/group", "etc/group-",
        "etc/gshadow", "etc/gshadow-",
    ]

    def parse(self, path: Path, context: ParseContext):
        rel = context.artifact_rel.replace("\\", "/")
        base = rel.rsplit("/", 1)[-1]
        if base == "passwd":
            yield from self._parse_passwd(path, context)
        elif base == "passwd-":
            yield from self._diff_passwd_backup(path, context)
        elif base in {"shadow", "shadow-"}:
            yield from self._parse_shadow(path, context)
        elif base == "group":
            yield from self._parse_group(path, context)
        elif base == "group-":
            yield from self._diff_group_backup(path, context)
        # gshadow adds nothing beyond group for our purposes; ignore quietly

    # ------------------------------------------------------------- passwd

    def _state(self, context, **kw):
        kw.setdefault("event_kind", "state_finding")
        kw.setdefault("timestamp_utc", None)
        kw.setdefault("timestamp_local", None)
        kw.setdefault("timestamp_confidence", "unknown")
        kw.setdefault("category", "user_accounts")
        return context.build_event(**kw)

    def _parse_passwd(self, path: Path, context: ParseContext):
        for offset, line, f in _read_colon_file(path, context):
            if len(f) < 7:
                continue
            user, _pw, uid_s, gid_s, gecos, home, shell = f[:7]
            if not user:
                continue
            try:
                uid = int(uid_s)
            except ValueError:
                uid = None
            login_capable = shell not in {
                "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"
            }
            yield self._state(
                context,
                subcategory="account",
                actor_user=user,
                actor_uid=uid,
                description=(
                    f"Account {user}: uid={uid_s} gid={gid_s} home={home} "
                    f"shell={shell}"
                    + ("" if login_capable else " (login disabled)")
                ),
                severity="info",
                raw_line=line,
                raw_line_offset=offset,
            )
            if uid == 0 and user != "root":
                yield self._state(
                    context,
                    subcategory="uid0_account",
                    actor_user=user,
                    actor_uid=0,
                    description=(
                        f"Account {user} has UID 0: full root privileges under "
                        f"a different name"
                    ),
                    severity="high",
                    raw_line=line,
                    raw_line_offset=offset,
                )

    def _load_accounts(self, path: Path, context: ParseContext) -> dict[str, str]:
        accounts = {}
        if path.exists():
            for _, line, f in _read_colon_file(path, context):
                if len(f) >= 7 and f[0]:
                    accounts[f[0]] = line
        return accounts

    def _diff_passwd_backup(self, path: Path, context: ParseContext):
        live_path = context.raw_host_dir / "collected/files/etc/passwd"
        backup = self._load_accounts(path, context)
        live = self._load_accounts(live_path, context)
        for user in sorted(set(live) - set(backup)):
            yield self._state(
                context,
                subcategory="account_added_since_backup",
                actor_user=user,
                description=(
                    f"Account {user} exists in /etc/passwd but not in the "
                    f"backup /etc/passwd- : created since the backup was written"
                ),
                severity="medium",
                raw_line=live[user],
                raw_line_offset=0,
            )
        for user in sorted(set(backup) - set(live)):
            yield self._state(
                context,
                subcategory="account_removed_since_backup",
                actor_user=user,
                description=(
                    f"Account {user} exists in the backup /etc/passwd- but not "
                    f"in /etc/passwd : removed since the backup was written"
                ),
                severity="medium",
                raw_line=backup[user],
                raw_line_offset=0,
            )

    # ------------------------------------------------------------- shadow

    def _parse_shadow(self, path: Path, context: ParseContext):
        for offset, line, f in _read_colon_file(path, context):
            if len(f) < 2 or not f[0]:
                continue
            user, pw = f[0], f[1]
            changed = _days_to_date(f[2]) if len(f) > 2 else None
            if pw == "":
                yield self._state(
                    context,
                    subcategory="passwordless_account",
                    actor_user=user,
                    description=(
                        f"Account {user} has NO password set: anyone can log "
                        f"in as this user without credentials"
                    ),
                    severity="high",
                    raw_line=f"{user}::<aging fields redacted from event>",
                    raw_line_offset=offset,
                )
            elif pw in {"!", "*", "!!"} or pw.startswith("!"):
                yield self._state(
                    context,
                    subcategory="locked_account",
                    actor_user=user,
                    description=f"Account {user} is locked (cannot authenticate by password)",
                    severity="info",
                    raw_line=f"{user}:{pw[:2]}...",
                    raw_line_offset=offset,
                )
            if changed:
                yield self._state(
                    context,
                    subcategory="password_state",
                    actor_user=user,
                    description=f"Password for {user} last changed {changed}",
                    severity="info",
                    raw_line=f"{user}:<hash omitted>:{f[2]}",
                    raw_line_offset=offset,
                )

    # -------------------------------------------------------------- group

    def _load_groups(self, path: Path, context: ParseContext) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = {}
        if path.exists():
            for _, line, f in _read_colon_file(path, context):
                if len(f) >= 4 and f[0]:
                    members = [m for m in f[3].split(",") if m]
                    groups[f[0]] = members
        return groups

    def _parse_group(self, path: Path, context: ParseContext):
        for offset, line, f in _read_colon_file(path, context):
            if len(f) < 4 or not f[0]:
                continue
            group = f[0]
            members = [m for m in f[3].split(",") if m]
            for member in members:
                yield self._state(
                    context,
                    subcategory="group_membership",
                    actor_user=member,
                    description=f"User {member} is a member of group {group}",
                    severity="info",
                    raw_line=line,
                    raw_line_offset=offset,
                )
                if group in PRIVILEGED_GROUPS:
                    extra = (" (docker group membership is equivalent to root)"
                             if group == "docker" else "")
                    yield self._state(
                        context,
                        subcategory="privileged_group_member",
                        actor_user=member,
                        description=(
                            f"User {member} belongs to privileged group "
                            f"{group}{extra}"
                        ),
                        severity="low",
                        raw_line=line,
                        raw_line_offset=offset,
                    )

    def _diff_group_backup(self, path: Path, context: ParseContext):
        live_path = context.raw_host_dir / "collected/files/etc/group"
        backup = self._load_groups(path, context)
        live = self._load_groups(live_path, context)
        for group in sorted(live):
            before = set(backup.get(group, []))
            after = set(live[group])
            for member in sorted(after - before):
                yield self._state(
                    context,
                    subcategory="group_member_added_since_backup",
                    actor_user=member,
                    description=(
                        f"User {member} was added to group {group} since the "
                        f"/etc/group- backup was written"
                    ),
                    severity="medium" if group in PRIVILEGED_GROUPS else "low",
                    raw_line=f"{group}: +{member}",
                    raw_line_offset=0,
                )
            for member in sorted(before - after):
                yield self._state(
                    context,
                    subcategory="group_member_removed_since_backup",
                    actor_user=member,
                    description=(
                        f"User {member} was removed from group {group} since "
                        f"the /etc/group- backup was written"
                    ),
                    severity="low",
                    raw_line=f"{group}: -{member}",
                    raw_line_offset=0,
                )
