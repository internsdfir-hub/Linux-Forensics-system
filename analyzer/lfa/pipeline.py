"""Pipeline orchestration: ingested evidence -> parsers -> case DB.

Walks each host's verified raw tree, offers every artifact to the parser
registry, validates the resulting events and inserts them with dedupe.
Per-artifact status (success / fail / skip) is persisted so the report's
methodology section can state exactly what was NOT processed - analysts
need to know that, not only what was.

Quarantined files (raw/<host>/_integrity_failed/) are never parsed: their
contents no longer match what was collected, so anything derived from them
would be unattributable.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import db
from .parsers.base import ParseContext, ParserRun, discover_parsers
from .timeeng import TimeContext


@dataclass
class PipelineStats:
    artifacts_seen: int = 0
    events_inserted: int = 0
    events_deduped: int = 0
    events_invalid: int = 0
    skipped: list[str] = field(default_factory=list)
    parser_stats: dict = field(default_factory=dict)


def _load_case_metadata(case_dir: Path) -> dict:
    path = case_dir / "case_metadata.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"hosts": {}}


def _artifact_rows(host_dir: Path) -> dict[str, dict]:
    """hash_manifest rows keyed by the bundle-relative stored path."""
    from .ingest import stored_rel_path

    rows: dict[str, dict] = {}
    manifest = host_dir / "hash_manifest.csv"
    if not manifest.exists():
        return rows
    with open(manifest, encoding="utf-8", errors="surrogateescape", newline="") as fh:
        for row in csv.DictReader(fh):
            rows[stored_rel_path(row["original_path"])] = row
    return rows


def parse_case(conn, case_dir: str | Path, case_id: str) -> PipelineStats:
    case_dir = Path(case_dir)
    meta = _load_case_metadata(case_dir)
    parsers = discover_parsers()
    run = ParserRun(parsers=parsers, errors_log=case_dir / "parser_errors.log")
    stats = PipelineStats()

    raw_root = case_dir / "raw"
    if not raw_root.is_dir():
        return stats

    for host_dir in sorted(p for p in raw_root.iterdir() if p.is_dir()):
        host_id = host_dir.name
        host_meta = meta.get("hosts", {}).get(host_id, {})
        collector_manifest = host_meta.get("collector_manifest", {})
        host_info = collector_manifest.get("host", {})

        time_ctx = TimeContext(
            tz_name=host_info.get("timezone") or None,
            tz_source=host_info.get("timezone_source") or None,
        )
        distro_profile = {
            "distro_id": host_info.get("distro_id", ""),
            "version_id": host_info.get("version_id", ""),
            "init_system": host_info.get("init_system", ""),
        }
        contamination = collector_manifest.get("contamination", {})

        manifest_rows = _artifact_rows(host_dir)
        collected_root = host_dir / "collected"
        if not collected_root.is_dir():
            continue

        for path in sorted(collected_root.rglob("*")):
            if not path.is_file():
                continue
            rel_in_bundle = path.relative_to(host_dir).as_posix()
            # bundle-relative -> artifact-relative (what parsers glob against)
            if rel_in_bundle.startswith("collected/files/"):
                artifact_rel = rel_in_bundle[len("collected/files/"):]
            elif rel_in_bundle.startswith("collected/"):
                artifact_rel = rel_in_bundle[len("collected/"):]
            else:
                artifact_rel = rel_in_bundle

            row = manifest_rows.get(rel_in_bundle, {})
            stats.artifacts_seen += 1

            context = ParseContext(
                case_id=case_id,
                host_id=host_id,
                raw_host_dir=host_dir,
                time_ctx=time_ctx,
                distro_profile=distro_profile,
                artifact_rel=artifact_rel,
                artifact_sha256=row.get("sha256") or "",
                artifact_mtime=_as_float(row.get("mtime")),
                contamination=contamination,
            )

            before_skips = len(run.skipped)
            events = run.parse_artifact(path, artifact_rel, context)
            was_skipped = len(run.skipped) > before_skips

            if events:
                insert = db.insert_events(conn, events)
                stats.events_inserted += insert.inserted
                stats.events_deduped += insert.deduped
                stats.events_invalid += insert.invalid

            _record_artifact(
                conn,
                host_id=host_id,
                row=row,
                artifact_rel=artifact_rel,
                status="skip" if was_skipped else ("success" if events or not was_skipped else "fail"),
                events=len(events),
                had_decode_errors=context.had_decode_errors,
            )

    stats.skipped = list(run.skipped)
    stats.parser_stats = run.stats
    db.set_meta(conn, "parser_stats", json.dumps(run.stats, sort_keys=True))
    db.set_meta(conn, "parser_artifacts",
                json.dumps(run.artifact_results, sort_keys=True))
    db.set_meta(conn, "parser_skipped", json.dumps(sorted(run.skipped)))
    conn.commit()
    return stats


def _as_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _record_artifact(conn, *, host_id: str, row: dict, artifact_rel: str,
                     status: str, events: int, had_decode_errors: bool) -> None:
    original = row.get("original_path") or f"/{artifact_rel}"
    conn.execute(
        """
        INSERT INTO artifacts (host_id, original_path, stored_path, sha256, size,
                               mode, owner, atime, mtime, ctime,
                               source_was_active, status, verified_sha256,
                               integrity, had_decode_errors, parse_status,
                               parse_events)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(host_id, original_path) DO UPDATE SET
            parse_status=excluded.parse_status,
            parse_events=excluded.parse_events,
            had_decode_errors=excluded.had_decode_errors
        """,
        (
            host_id,
            original,
            artifact_rel,
            row.get("sha256"),
            row.get("size"),
            row.get("mode"),
            row.get("owner"),
            row.get("atime"),
            row.get("mtime"),
            row.get("ctime"),
            1 if row.get("source_was_active") == "1" else 0,
            row.get("status"),
            row.get("sha256"),
            "verified" if row.get("sha256") else "unknown",
            1 if had_decode_errors else 0,
            status,
            events,
        ),
    )


def run_analysis_pipeline(
    case_dir: str | Path,
    bundles: list[str | Path],
    case_id: str | None = None,
    examiner: str = "Forensic Examiner",
    business_hours: str = "08-18",
) -> dict[str, Any]:
    """Execute the complete ingestion -> parse -> correlate -> report pipeline."""
    from . import canonical, ingest
    from .report.render import render_report
    from .rules.base import RuleRun, discover_rules

    case_dir = Path(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    c_id = case_id or case_dir.name

    conn = db.open_case(case_dir / "case.db")
    db.set_case_meta(conn, "case_id", c_id)
    db.set_case_meta(conn, "examiner", examiner)
    db.set_case_meta(conn, "business_hours", business_hours)

    verified_total = 0
    hosts_ingested: list[str] = []
    for b in bundles:
        p = Path(b)
        if not p.exists():
            continue
        res = ingest.ingest_bundle(p, case_dir, examiner)
        verified_total += res.verified
        hosts_ingested.append(res.host_id)

    stats = parse_case(conn, case_dir, c_id)

    from .rules.base import RuleRun, discover_rules, save_findings

    # Correlation rules
    rules = discover_rules()
    rule_runner = RuleRun(rules=rules, errors_log=case_dir / "rule_errors.log")
    b_start, b_end = 8, 18
    if business_hours:
        try:
            parts = business_hours.split("-")
            b_start, b_end = int(parts[0]), int(parts[1])
        except Exception:
            pass

    findings = rule_runner.run_all(conn, ctx={"business_hours": (b_start, b_end)})
    save_findings(conn, findings, c_id)

    # Self-contained offline report
    report_path = case_dir / "report.html"
    render_report(conn, case_dir, report_path)

    # Canonical exports
    export_dir = case_dir / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    json_hash = canonical.export_json(conn, export_dir / "events.json")
    csv_hashes = canonical.export_csv_per_category(conn, export_dir / "csv")

    conn.close()
    return {
        "case_id": c_id,
        "case_dir": str(case_dir),
        "hosts": hosts_ingested,
        "verified_files": verified_total,
        "events_inserted": stats.events_inserted,
        "findings_count": len(findings),
        "report_path": str(report_path),
        "json_hash": json_hash,
        "csv_hashes": csv_hashes,
    }
