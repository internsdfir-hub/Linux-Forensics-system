"""Correlation rule framework (spec 2.8.1).

Same plugin pattern as parsers, but operating on the DB instead of files.
One shared helper does the generic work - "return all events within +/-N
minutes of this event" - and every rule is built on top of it. Less code,
more rules.

The hard contract: every rule returns BOTH a technical_detail and a
plain_summary carrying the four questions from spec 1.7 (what happened,
why it matters, how confident we are, what to check next). A rule that
cannot produce a plain-English line does not ship, and that is enforced
here in the interface rather than in review.

Deliberately no machine learning: if the tool says something is
suspicious, we must be able to state precisely which rule fired and on
which evidence.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import pkgutil
import sqlite3
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

SEVERITIES = {"info", "low", "medium", "high"}

# Confidence is a word an analyst can defend in a report, not a number we
# cannot justify. Spec 1.7 shows "High. This is recorded in two separate
# logs that agree with each other."
CONFIDENCE_WORDS = {"High", "Medium", "Low"}


@dataclass(frozen=True)
class PlainSummary:
    """The four questions every finding must answer in plain language."""

    what_happened: str
    why_it_matters: str
    confidence: str
    check_next: str

    def __post_init__(self):
        missing = [
            name
            for name in ("what_happened", "why_it_matters", "confidence", "check_next")
            if not str(getattr(self, name)).strip()
        ]
        if missing:
            raise ValueError(
                f"plain summary is missing required field(s): {', '.join(missing)}. "
                f"A rule that cannot explain itself in plain English does not ship."
            )
        if self.confidence not in CONFIDENCE_WORDS:
            raise ValueError(
                f"confidence must be one of {sorted(CONFIDENCE_WORDS)}, "
                f"got {self.confidence!r} - state a defensible word, not a number"
            )


@dataclass
class Finding:
    rule_name: str
    rule_version: str
    severity: str
    title: str
    plain: PlainSummary
    technical_detail: str
    event_ids: list[str] = field(default_factory=list)
    first_ts_utc: str | None = None
    last_ts_utc: str | None = None
    host_id: str | None = None
    finding_id: str = ""

    def __post_init__(self):
        if not str(self.technical_detail).strip():
            raise ValueError(
                "technical_detail is required: the report's technical layer "
                "must be able to show how this finding was reached"
            )
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity {self.severity!r} not in {sorted(SEVERITIES)}")
        if not self.finding_id:
            material = "\x1f".join(
                [
                    self.rule_name,
                    self.rule_version,
                    self.title,
                    self.host_id or "",
                    "\x1e".join(sorted(self.event_ids)),
                ]
            )
            self.finding_id = hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


class BaseRule:
    name: str = ""
    version: str = ""
    # documented so the report's methodology section can list thresholds
    parameters: dict = {}

    def run(self, conn: sqlite3.Connection, ctx: dict) -> Iterator[Finding]:
        raise NotImplementedError


# ------------------------------------------------------------------ helpers

def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def events_within(conn: sqlite3.Connection, anchor_ts: str, minutes: float,
                  **filters) -> list[sqlite3.Row]:
    """The generic join every correlation rule is built on: all events
    within +/-N minutes of a point in time, optionally filtered."""
    anchor = parse_ts(anchor_ts)
    if anchor is None:
        return []
    lo = (anchor - timedelta(minutes=minutes)).isoformat()
    hi = (anchor + timedelta(minutes=minutes)).isoformat()

    where = ["timestamp_utc IS NOT NULL", "timestamp_utc >= ?", "timestamp_utc <= ?"]
    params: list = [lo, hi]
    for key, value in filters.items():
        if value is None:
            continue
        if key.endswith("__in"):
            column = key[:-4]
            placeholders = ",".join("?" for _ in value)
            where.append(f"{column} IN ({placeholders})")
            params.extend(value)
        else:
            where.append(f"{key} = ?")
            params.append(value)

    sql = (
        "SELECT * FROM events WHERE " + " AND ".join(where)
        + " ORDER BY timestamp_utc, event_hash"
    )
    conn.row_factory = sqlite3.Row
    return conn.execute(sql, params).fetchall()


def discover_rules() -> list[BaseRule]:
    pkg_name = __package__ or "lfa.rules"
    pkg = importlib.import_module(pkg_name)

    rules: list[BaseRule] = []
    for modinfo in pkgutil.iter_modules(pkg.__path__):
        if modinfo.name == "base":
            continue
        module = importlib.import_module(f"{pkg_name}.{modinfo.name}")
        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and issubclass(obj, BaseRule)
                and obj is not BaseRule
                and obj.__module__ == module.__name__
                and obj.name
            ):
                rules.append(obj())
    rules.sort(key=lambda r: r.name)
    return rules


class RuleRun:
    """Runs rules with the same error isolation the parser engine uses."""

    def __init__(self, rules: list[BaseRule], errors_log: Path):
        self.rules = rules
        self.errors_log = Path(errors_log)
        self.stats = {r.name: {"success": 0, "fail": 0, "findings": 0}
                      for r in rules}

    def run_all(self, conn: sqlite3.Connection, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            try:
                produced = list(rule.run(conn, ctx))
            except Exception as exc:
                self.errors_log.parent.mkdir(parents=True, exist_ok=True)
                with open(self.errors_log, "a", encoding="utf-8") as fh:
                    fh.write(
                        f"=== {datetime.now(timezone.utc).isoformat()} "
                        f"rule={rule.name}\n"
                    )
                    fh.write("".join(traceback.format_exception(exc)))
                    fh.write("\n")
                self.stats[rule.name]["fail"] += 1
                continue
            self.stats[rule.name]["success"] += 1
            self.stats[rule.name]["findings"] += len(produced)
            findings.extend(produced)
        # deterministic order: severity desc, then time, then id
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        findings.sort(
            key=lambda f: (order[f.severity], f.first_ts_utc or "9999",
                           f.finding_id)
        )
        return findings


def save_findings(conn: sqlite3.Connection, findings: list[Finding],
                  case_id: str) -> None:
    conn.execute("DELETE FROM findings WHERE case_id = ?", (case_id,))
    conn.executemany(
        """
        INSERT OR IGNORE INTO findings
            (finding_id, case_id, rule_name, rule_version, severity, title,
             what_happened, why_it_matters, confidence, check_next,
             technical_detail, first_ts_utc, last_ts_utc, host_id, event_ids)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        [
            (
                f.finding_id, case_id, f.rule_name, f.rule_version, f.severity,
                f.title, f.plain.what_happened, f.plain.why_it_matters,
                f.plain.confidence, f.plain.check_next, f.technical_detail,
                f.first_ts_utc, f.last_ts_utc, f.host_id,
                json.dumps(sorted(f.event_ids)),
            )
            for f in findings
        ],
    )
    conn.commit()
