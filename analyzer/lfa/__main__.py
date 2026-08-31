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
    case_id = args.case_id or case_dir.name
    examiner = args.examiner or "Forensic Examiner"

    print(f"[*] Initializing case '{case_id}' in '{case_dir}'")
    res = pipeline.run_analysis_pipeline(
        case_dir=case_dir,
        bundles=args.bundles,
        case_id=case_id,
        examiner=examiner,
        business_hours=args.business_hours or "08-18",
    )
    print(f"[+] Ingested hosts: {', '.join(res['hosts']) or 'None'} (verified: {res['verified_files']} files)")
    print(f"[+] Parsed and inserted {res['events_inserted']} events")
    print(f"[+] Correlation engine completed: {res['findings_count']} threat/state findings recorded")
    print(f"[+] Report generated: {res['report_path']}")
    print(f"[+] Canonical exports saved (JSON SHA-256: {res['json_hash'][:16]}...)")
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


def cmd_serve(args) -> int:
    from .server import run_server
    run_server(
        host=args.host,
        port=args.port,
        cases_dir=args.cases_dir,
        token=args.token,
        auto_analyse=not args.no_auto_analyse,
        cert_file=args.cert,
        key_file=args.key,
        business_hours=args.business_hours,
        examiner=args.examiner or "Remote Investigator",
    )
    return 0


def cmd_remote(args) -> int:
    """Acquire evidence from a remote target over SSH stream and analyse."""
    import subprocess
    collector_sh = Path(__file__).resolve().parents[2] / "collector" / "collect.sh"
    if not collector_sh.exists():
        print(f"[!] Collector script not found at {collector_sh}", file=sys.stderr)
        return 1

    case_dir = Path(args.case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    case_id = args.case_id or case_dir.name
    bundle_path = case_dir / "bundle.tar.gz"

    ssh_target = f"{args.user}@{args.host}" if args.user else args.host
    port_args = ["-p", str(args.port)] if args.port else []
    key_args = ["-i", args.key] if args.key else []

    print(f"[*] Connecting to remote target '{ssh_target}' to acquire live evidence...")
    print("[*] Executing in-memory collection and streaming directly over SSH pipe...")

    collect_script = collector_sh.read_bytes()
    remote_cmd = ["ssh", *port_args, *key_args, ssh_target, "sudo sh -s -- -M -S -z"]

    try:
        proc = subprocess.Popen(
            remote_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
        )
        stdout_data, _ = proc.communicate(input=collect_script)

        if proc.returncode != 0:
            print(f"[!] Remote acquisition failed with return code {proc.returncode}", file=sys.stderr)
            return proc.returncode

        bundle_path.write_bytes(stdout_data)
        print(f"[+] Remote acquisition stream saved: {len(stdout_data)} bytes -> {bundle_path}")

        pipeline.run_analysis_pipeline(
            case_dir=case_dir,
            bundles=[bundle_path],
            case_id=case_id,
            examiner=args.examiner or "Remote Investigator",
            business_hours=args.business_hours,
        )
        print(f"[+] Remote analysis complete! Report: {case_dir / 'report.html'}")
        return 0
    except Exception as ex:
        print(f"[!] Remote SSH error: {ex}", file=sys.stderr)
        return 1


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

    # serve (Central Ingestion & Dashboard Server)
    p_serve = subparsers.add_parser("serve", help="Start Central Forensic Streaming Ingestion & Investigation Server")
    p_serve.add_argument("--host", default="0.0.0.0", help="Listen host address (default: 0.0.0.0)")
    p_serve.add_argument("--port", type=int, default=8443, help="Listen port (default: 8443)")
    p_serve.add_argument("--cases-dir", default="cases", help="Directory where ingested cases are stored")
    p_serve.add_argument("--token", help="Bearer authentication token for secure ingestion")
    p_serve.add_argument("--no-auto-analyse", action="store_true", help="Disable automatic analysis pipeline trigger")
    p_serve.add_argument("--cert", help="Path to TLS certificate file")
    p_serve.add_argument("--key", help="Path to TLS private key file")
    p_serve.add_argument("--examiner", default="Remote Investigator", help="Examiner name for ingested cases")
    p_serve.add_argument("--business-hours", default="08-18", help="Expected business hours")

    # remote (Agentless SSH Pull Streaming)
    p_remote = subparsers.add_parser("remote", help="Acquire evidence remotely over SSH stream and analyze in memory")
    p_remote.add_argument("--host", required=True, help="Remote host IP or hostname")
    p_remote.add_argument("--user", help="SSH username (e.g. root or sudo user)")
    p_remote.add_argument("--port", type=int, help="SSH port (default 22)")
    p_remote.add_argument("--key", help="Path to SSH private key")
    p_remote.add_argument("--case-dir", required=True, help="Destination case working directory")
    p_remote.add_argument("--case-id", help="Optional case ID")
    p_remote.add_argument("--examiner", help="Examiner name")
    p_remote.add_argument("--business-hours", default="08-18", help="Expected business hours")

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
    elif args.command == "serve":
        return cmd_serve(args)
    elif args.command == "remote":
        return cmd_remote(args)
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
