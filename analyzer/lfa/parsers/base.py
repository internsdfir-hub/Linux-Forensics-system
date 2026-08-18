"""Parser plugin framework (spec 2.6.1).

Every parser translates one artifact format into NormalizedEvents. Parsers
are auto-discovered from this package, each runs inside its own try/except
boundary, failures write a full traceback to parser_errors.log and the
engine continues. The run's success/fail/skip counts feed the report's
methodology section - analysts need to know what WASN'T processed.
"""
from __future__ import annotations

import fnmatch
import importlib
import pkgutil
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ..schema import NormalizedEvent, make_event
from ..timeeng import TimeContext


@dataclass
class ParseContext:
    """Everything a parser needs beyond the file itself. build_event() fills
    all provenance fields so parsers only supply what they actually parsed."""

    case_id: str
    host_id: str
    raw_host_dir: Path
    time_ctx: TimeContext
    distro_profile: dict
    artifact_rel: str = ""
    artifact_sha256: str = ""
    tool_generated_flag: bool = False
    parser_name: str = ""
    parser_version: str = ""
    had_decode_errors: bool = False
    contamination: dict = field(default_factory=dict)

    def build_event(self, **kwargs) -> NormalizedEvent:
        kwargs.setdefault("case_id", self.case_id)
        kwargs.setdefault("host_id", self.host_id)
        kwargs.setdefault("timestamp_tz", self.time_ctx.tz_name)
        kwargs.setdefault("tz_source", self.time_ctx.tz_source)
        kwargs.setdefault("source_artifact_path", self.artifact_rel)
        kwargs.setdefault("source_artifact_sha256", self.artifact_sha256)
        kwargs.setdefault("parser_name", self.parser_name)
        kwargs.setdefault("parser_version", self.parser_version)
        kwargs.setdefault("tool_generated_flag", self.tool_generated_flag)
        kwargs.setdefault("actor_user", None)
        kwargs.setdefault("actor_uid", None)
        kwargs.setdefault("actor_process", None)
        kwargs.setdefault("source_ip", None)
        kwargs.setdefault("source_host", None)
        kwargs.setdefault("subcategory", "unspecified")
        kwargs.setdefault("notes", None)
        return make_event(**kwargs)


class BaseParser:
    name: str = ""
    version: str = ""
    artifact_category: str = ""
    applies_to: list[str] = []  # glob patterns over bundle-relative paths

    def can_parse(self, rel_path: str, distro_profile: dict) -> bool:
        rel = rel_path.replace("\\", "/")
        return any(fnmatch.fnmatch(rel, pat) for pat in self.applies_to)

    def parse(self, path: Path, context: ParseContext) -> Iterator[NormalizedEvent]:
        raise NotImplementedError

    # helper shared by text parsers: stream lines with byte offsets and the
    # mandatory surrogateescape handling (spec: naive open() loses data)
    @staticmethod
    def iter_lines(path: Path, context: ParseContext):
        offset = 0
        with open(path, "rb") as fh:
            for raw in fh:
                try:
                    line = raw.decode("utf-8")
                except UnicodeDecodeError:
                    line = raw.decode("utf-8", errors="surrogateescape")
                    context.had_decode_errors = True
                yield offset, line.rstrip("\r\n")
                offset += len(raw)


def discover_parsers() -> list[BaseParser]:
    """Instantiate every BaseParser subclass found in lfa.parsers.*"""
    import lfa.parsers as pkg

    parsers: list[BaseParser] = []
    for modinfo in pkgutil.iter_modules(pkg.__path__):
        if modinfo.name in {"base"}:
            continue
        module = importlib.import_module(f"lfa.parsers.{modinfo.name}")
        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and issubclass(obj, BaseParser)
                and obj is not BaseParser
                and obj.__module__ == module.__name__
                and obj.name
            ):
                parsers.append(obj())
    parsers.sort(key=lambda p: p.name)
    return parsers


class ParserRun:
    """Drives parsers over artifacts with error isolation and stats."""

    def __init__(self, parsers: list[BaseParser], errors_log: Path):
        self.parsers = parsers
        self.errors_log = Path(errors_log)
        self.stats: dict[str, dict[str, int]] = {
            p.name: {"success": 0, "fail": 0, "events": 0} for p in parsers
        }
        self.skipped: list[str] = []
        self.artifact_results: list[dict] = []

    def _log_error(self, parser: BaseParser, rel_path: str, exc: BaseException) -> None:
        self.errors_log.parent.mkdir(parents=True, exist_ok=True)
        with open(self.errors_log, "a", encoding="utf-8") as fh:
            fh.write(
                f"=== {datetime.now(timezone.utc).isoformat()} "
                f"parser={parser.name} artifact={rel_path}\n"
            )
            fh.write("".join(traceback.format_exception(exc)))
            fh.write("\n")

    def parse_artifact(self, path: Path, rel_path: str,
                       context: ParseContext) -> list[NormalizedEvent]:
        claimed = [p for p in self.parsers
                   if p.can_parse(rel_path, context.distro_profile)]
        if not claimed:
            self.skipped.append(rel_path)
            self.artifact_results.append(
                {"artifact": rel_path, "parser": None, "status": "skip", "events": 0}
            )
            return []

        events: list[NormalizedEvent] = []
        for parser in claimed:
            context.parser_name = parser.name
            context.parser_version = parser.version
            context.artifact_rel = rel_path
            context.had_decode_errors = False
            try:
                produced = list(parser.parse(path, context))
            except Exception as exc:  # isolation boundary: never fail the run
                self._log_error(parser, rel_path, exc)
                self.stats[parser.name]["fail"] += 1
                self.artifact_results.append(
                    {"artifact": rel_path, "parser": parser.name,
                     "status": "fail", "events": 0, "error": repr(exc)}
                )
                continue
            events.extend(produced)
            self.stats[parser.name]["success"] += 1
            self.stats[parser.name]["events"] += len(produced)
            self.artifact_results.append(
                {"artifact": rel_path, "parser": parser.name,
                 "status": "success", "events": len(produced),
                 "had_decode_errors": context.had_decode_errors}
            )
        return events
