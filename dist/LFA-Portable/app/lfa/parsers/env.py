"""Environment parser: os-release, machine-id, timezone.

Feeds everything else (DistroProfile / TimeContext are built from the
collector manifest at pipeline level); also emits state findings so the
report's environment section is traceable to evidence."""
from __future__ import annotations

from pathlib import Path

from .base import BaseParser, ParseContext


class EnvParser(BaseParser):
    name = "env_parser"
    version = "1.0"
    artifact_category = "environment"
    applies_to = ["etc/os-release", "etc/machine-id", "etc/timezone",
                  "etc/redhat-release", "etc/debian_version"]

    def parse(self, path: Path, context: ParseContext):
        rel = context.artifact_rel
        if rel.endswith("os-release"):
            fields = {}
            for offset, line in self.iter_lines(path, context):
                if "=" in line and not line.startswith("#"):
                    key, _, value = line.partition("=")
                    fields[key.strip()] = value.strip().strip('"')
            pretty = fields.get("PRETTY_NAME") or fields.get("ID", "unknown")
            yield context.build_event(
                event_kind="state_finding",
                timestamp_utc=None,
                timestamp_local=None,
                timestamp_confidence="unknown",
                category="environment",
                subcategory="os_identity",
                description=f"Operating system: {pretty}",
                severity="info",
                raw_line=" ".join(f"{k}={v}" for k, v in sorted(fields.items())),
                raw_line_offset=0,
            )
        elif rel.endswith("machine-id"):
            for offset, line in self.iter_lines(path, context):
                if line.strip():
                    yield context.build_event(
                        event_kind="state_finding",
                        timestamp_utc=None,
                        timestamp_local=None,
                        timestamp_confidence="unknown",
                        category="environment",
                        subcategory="machine_id",
                        description=f"Machine id: {line.strip()}",
                        severity="info",
                        raw_line=line,
                        raw_line_offset=offset,
                    )
                    break
        elif rel.endswith("timezone"):
            for offset, line in self.iter_lines(path, context):
                if line.strip():
                    yield context.build_event(
                        event_kind="state_finding",
                        timestamp_utc=None,
                        timestamp_local=None,
                        timestamp_confidence="unknown",
                        category="environment",
                        subcategory="timezone",
                        description=f"Configured timezone: {line.strip()}",
                        severity="info",
                        raw_line=line,
                        raw_line_offset=offset,
                    )
                    break
        else:  # redhat-release / debian_version
            for offset, line in self.iter_lines(path, context):
                if line.strip():
                    yield context.build_event(
                        event_kind="state_finding",
                        timestamp_utc=None,
                        timestamp_local=None,
                        timestamp_confidence="unknown",
                        category="environment",
                        subcategory="os_identity",
                        description=f"OS release file {rel}: {line.strip()}",
                        severity="info",
                        raw_line=line,
                        raw_line_offset=offset,
                    )
                    break
