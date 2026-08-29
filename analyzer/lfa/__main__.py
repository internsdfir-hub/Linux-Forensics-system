"""LFA (Linux Forensic Analyzer) CLI entrypoint (spec Task 6.6).

Subcommands:
  analyse  - Ingest bundle(s), parse artifacts, run threat correlation, and generate HTML report.
  verify   - Verify evidence integrity and hash manifests against ingested raw artifacts.
  export   - Export canonical byte-deterministic JSON and CSV event datasets.
  report   - Re-render offline HTML report from an existing case database.
  synth    - Generate a synthetic test case database with scripted incident patterns.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import canonical, db, ingest, pipeline
from .report.render import render_report
from .rules.base import RuleRun, discover_rules


def cmd_analyse(args) -> int:
    case_dir = Path(args.case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    case_id = args.case_id or case_dir.name
    examiner = args.examiner or "Forensic Examiner"

    print(f"[*] Initializing case '{case_id}' in '{case_dir}'")
    conn = db.open_case(case_dir / "case.db")
    db.set_case_meta(conn, "case_id", case_id)
    db.set_case_meta(conn, "examiner", examiner)
    db.set_case_meta(conn, "business_hours", args.business_hours or "08-18")

    # Ingest bundle(s)
    for bundle_path in args.bundles:
        p = Path(bundle_path)
        if not p.exists():
            print(f"[!] Bundle not found: {p}", file=sys.stderr)
            continue
        print(f"[*] Ingesting evidence bundle: {p.name}")
        ingest_res = ingest.ingest_bundle(
            bundle_path=p,
            case_dir=case_dir,
            examiner=examiner,
        )
        print(f"[+] Ingested host '{ingest_res.host_id}' successfully (verified: {ingest_res.verified} files)")

    # Sync artifact metadata into DB
    db.sync_artifacts_from_disk(conn, case_dir)

    # Parse artifacts
    print("[*] Running parser suite across collected artifacts...")
    stats = pipeline.parse_case(conn, case_dir, case_id)
    print(
        f"[+] Parsed {stats.artifacts_seen} artifacts: {stats.events_inserted} events inserted, "
        f"{stats.events_deduped} deduped, {stats.events_invalid} invalid"
    )

    # Run correlation rules
    print("[*] Executing threat correlation & integrity rules...")
    rules = discover_rules()
    rule_runner = RuleRun(rules=rules, errors_log=case_dir / "rule_errors.log")
    b_start, b_end = 8, 18
    if args.business_hours:
        try:
            parts = args.business_hours.split("-")
            b_start, b_end = int(parts[0]), int(parts[1])
        except Exception:
            pass

    findings = rule_runner.run_all(conn, ctx={"business_hours": (b_start, b_end)})
    db.insert_findings(conn, findings, case_id)
    print(f"[+] Correlation engine completed: {len(findings)} threat/state findings recorded")

    # Render HTML report
    report_path = case_dir / "report.html"
    print(f"[*] Rendering self-contained HTML forensic report -> {report_path.name}")
    render_report(conn, case_dir, report_path)
    print(f"[+] Report generated: {report_path.resolve()}")

    # Canonical exports
    export_dir = case_dir / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    json_hash = canonical.export_json(conn, export_dir / "events.json")
    csv_hashes = canonical.export_csv_per_category(conn, export_dir / "csv")
    print(f"[+] Canonical exports saved (JSON SHA-256: {json_hash[:16]}...)")

    conn.close()
    print("[+] Analysis pipeline completed successfully.")
    return 0


def cmd_verify(args) -> int:
    case_dir = Path(args.case_dir)
    print(f"[*] Verifying evidence integrity in '{case_dir}'")
    mismatches = ingest.verify_raw(case_dir)
    if mismatches:
        print(f"[!] INTEGRITY FAILURE: {len(mismatches)} artifact(s) failed hash verification!", file=sys.stderr)
        for m in mismatches:
            print(f"    - {m}", file=sys.stderr)
        return 1
    print("[+] All raw evidence artifacts verified clean against collection manifests.")
    return 0


def cmd_export(args) -> int:
    case_dir = Path(args.case_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    conn = db.open_case(case_dir / "case.db")
    j_hash = canonical.export_json(conn, out_dir / "events.json")
    c_hashes = canonical.export_csv_per_category(conn, out_dir / "csv")
    conn.close()
    print(f"[+] Canonical JSON export: {out_dir / 'events.json'} (SHA-256: {j_hash})")
    print(f"[+] Canonical CSV exports: {len(c_hashes)} category files in {out_dir / 'csv'}")
    return 0


def cmd_report(args) -> int:
    case_dir = Path(args.case_dir)
    out_path = Path(args.out) if args.out else case_dir / "report.html"
    conn = db.open_case(case_dir / "case.db")
    render_report(conn, case_dir, out_path)
    conn.close()
    print(f"[+] HTML Report generated: {out_path.resolve()}")
    return 0


def cmd_synth(args) -> int:
    from tools.make_synthetic_case import build_case
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    seed = args.seed if args.seed is not None else 42
    print(f"[*] Generating synthetic forensic case -> {out_path} (seed={seed})")
    gt = build_case(out_path, seed=seed)
    print(f"[+] Synthetic case created with {len(gt)} ground-truth attack indicators.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="lfa",
        description="LFA — Linux Forensic Log Processing & Correlation System",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyse
    p_analyse = subparsers.add_parser("analyse", help="Ingest bundles, parse logs, run correlation and report")
    p_analyse.add_argument("bundles", nargs="+", help="Path(s) to collected .tar.gz evidence bundles")
    p_analyse.add_argument("--case-dir", required=True, help="Destination case working directory")
    p_analyse.add_argument("--case-id", help="Optional case reference ID")
    p_analyse.add_argument("--examiner", help="Forensic examiner name/badge")
    p_analyse.add_argument("--business-hours", default="08-18", help="Expected business hours (default: 08-18)")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify integrity of raw evidence in case directory")
    p_verify.add_argument("case_dir", help="Path to case directory")

    # export
    p_export = subparsers.add_parser("export", help="Export canonical JSON and CSV event datasets")
    p_export.add_argument("case_dir", help="Path to case directory")
    p_export.add_argument("--out-dir", required=True, help="Output directory for exports")

    # report
    p_report = subparsers.add_parser("report", help="Render offline HTML forensic report")
    p_report.add_argument("case_dir", help="Path to case directory")
    p_report.add_argument("--out", help="Output HTML file path (default: <case_dir>/report.html)")

    # synth
    p_synth = subparsers.add_parser("synth", help="Generate synthetic test case with ground truth")
    p_synth.add_argument("--out", required=True, help="Output SQLite DB path")
    p_synth.add_argument("--seed", type=int, default=42, help="RNG seed for deterministic generation")

    args = parser.parse_args(argv)

    if args.command == "analyse":
        return cmd_analyse(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "export":
        return cmd_export(args)
    elif args.command == "report":
        return cmd_report(args)
    elif args.command == "synth":
        return cmd_synth(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
