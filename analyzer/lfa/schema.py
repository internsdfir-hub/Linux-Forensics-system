"""The frozen NormalizedEvent schema (spec section 2.5).

This is the week-1 contract for the entire pipeline. Every parser emits
NormalizedEvent, the DB stores exactly these fields, rules and the report
consume them. Do not change field names or enums without logging a
justification in docs/superpowers/plans/2026-08-18-linux-forensic-tool.md.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, fields
from datetime import datetime

# uuid5 namespace for deterministic event ids (decision D2: random uuid4
# would break the byte-identical canonical export guarantee).
NAMESPACE_LFA = uuid.UUID("6c1f0a52-9d0b-4e6a-8f3e-2b7a1c9d4e10")

RAW_LINE_MAX_BYTES = 2048

EVENT_KINDS = frozenset({"event", "state_finding"})
TZ_SOURCES = frozenset({"etc_localtime", "etc_timezone", "log_offset", "assumed_utc"})
TIMESTAMP_CONFIDENCES = frozenset({"exact", "year_inferred", "unknown"})
SEVERITIES = frozenset({"info", "low", "medium", "high"})
CATEGORIES = frozenset(
    {
        "user_accounts",
        "login_activity",
        "privilege_escalation",
        "persistence",
        "software_changes",
        "hardware_usb",
        "network_config",
        "user_activity",
        "environment",
    }
)

_ENUMS = {
    "event_kind": EVENT_KINDS,
    "tz_source": TZ_SOURCES,
    "timestamp_confidence": TIMESTAMP_CONFIDENCES,
    "severity": SEVERITIES,
    "category": CATEGORIES,
}

_REQUIRED_STR = (
    "event_id",
    "case_id",
    "host_id",
    "event_hash",
    "event_kind",
    "tz_source",
    "timestamp_confidence",
    "category",
    "subcategory",
    "description",
    "severity",
    "source_artifact_path",
    "source_artifact_sha256",
    "parser_name",
    "parser_version",
)


@dataclass
class NormalizedEvent:
    event_id: str
    case_id: str
    host_id: str
    event_hash: str
    event_kind: str
    timestamp_utc: str | None
    timestamp_local: str | None
    timestamp_tz: str
    tz_source: str
    timestamp_confidence: str
    category: str
    subcategory: str
    actor_user: str | None
    actor_uid: int | None
    actor_process: str | None
    source_ip: str | None
    source_host: str | None
    description: str
    severity: str
    source_artifact_path: str
    source_artifact_sha256: str
    raw_line: str
    raw_line_offset: int
    parser_name: str
    parser_version: str
    tool_generated_flag: bool
    notes: str | None


FIELD_NAMES = tuple(f.name for f in fields(NormalizedEvent))


def compute_event_hash(host_id: str, source_path: str, offset: int, raw_line: str) -> str:
    """Dedupe key: hash(host_id, source_path, offset, raw_line) per spec 2.5."""
    material = "\x1f".join((host_id, source_path, str(offset), raw_line))
    return hashlib.sha256(material.encode("utf-8", errors="surrogateescape")).hexdigest()


def event_id_for(event_hash: str) -> str:
    """Deterministic uuid5 derived from the event hash (decision D2)."""
    return str(uuid.uuid5(NAMESPACE_LFA, event_hash))


def _truncate_raw_line(raw_line: str) -> str:
    data = raw_line.encode("utf-8", errors="surrogateescape")
    if len(data) <= RAW_LINE_MAX_BYTES:
        return raw_line
    return data[:RAW_LINE_MAX_BYTES].decode("utf-8", errors="ignore")


def make_event(**kwargs) -> NormalizedEvent:
    """Factory: computes event_hash/event_id and truncates raw_line at 2 KB.

    The hash is computed over the ORIGINAL raw line before truncation so
    dedupe stays honest for long lines.
    """
    raw_line = kwargs.get("raw_line", "")
    event_hash = compute_event_hash(
        kwargs["host_id"],
        kwargs["source_artifact_path"],
        kwargs.get("raw_line_offset", 0),
        raw_line,
    )
    kwargs["raw_line"] = _truncate_raw_line(raw_line)
    kwargs.setdefault("raw_line_offset", 0)
    kwargs["event_hash"] = event_hash
    kwargs["event_id"] = event_id_for(event_hash)
    return NormalizedEvent(**kwargs)


def _valid_iso8601(value: str) -> bool:
    try:
        datetime.fromisoformat(value)
        return True
    except ValueError:
        return False


def validate(event: NormalizedEvent) -> list[str]:
    """Return a list of problems; empty list means the event is valid."""
    errors: list[str] = []

    for name in _REQUIRED_STR:
        value = getattr(event, name)
        if not isinstance(value, str) or not value:
            errors.append(f"{name}: required non-empty string, got {value!r}")

    for name, allowed in _ENUMS.items():
        value = getattr(event, name)
        if value not in allowed:
            errors.append(f"{name}: {value!r} not in {sorted(allowed)}")

    for name in ("timestamp_utc", "timestamp_local"):
        value = getattr(event, name)
        if value is not None:
            if not isinstance(value, str) or not _valid_iso8601(value):
                errors.append(f"{name}: {value!r} is not ISO-8601")

    if (
        event.event_kind == "event"
        and event.timestamp_utc is None
        and event.timestamp_confidence != "unknown"
    ):
        errors.append(
            "timestamp_utc: null on an 'event' requires timestamp_confidence=unknown"
        )

    if event.actor_uid is not None and not isinstance(event.actor_uid, int):
        errors.append(f"actor_uid: {event.actor_uid!r} is not an int")
    if not isinstance(event.raw_line_offset, int) or event.raw_line_offset < 0:
        errors.append(f"raw_line_offset: {event.raw_line_offset!r} invalid")
    if not isinstance(event.tool_generated_flag, bool):
        errors.append("tool_generated_flag: must be bool")
    if len(event.raw_line.encode("utf-8", errors="surrogateescape")) > RAW_LINE_MAX_BYTES:
        errors.append("raw_line: exceeds 2 KB")
    # The stored hash may differ from a recomputation when raw_line was
    # truncated (hash covers the original line), so only check the shape.
    try:
        if len(event.event_hash) != 64 or int(event.event_hash, 16) < 0:
            errors.append("event_hash: not a sha256 hex digest")
    except (ValueError, TypeError):
        errors.append("event_hash: not a sha256 hex digest")

    return errors
