"""Ingest and integrity verification (spec 2.5 ingest workflow).

extract bundle -> cases/<case>/raw/<host>/ -> re-hash every file against
hash_manifest.csv -> mismatches moved to raw/<host>/_integrity_failed/ and
logged, analysis continues -> case_metadata.json merges the collector
manifest with examiner name, ingest time, analyzer version.

raw/ is read-only IN CODE: everything in this package opens evidence via
open_raw() ('rb' only). chmod 444 is applied best-effort (no-op on Windows).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .schema import clean_surrogates

# statuses in hash_manifest.csv that carry no verifiable file
_NO_FILE_STATUSES = {"unreadable", "redacted", "copy_failed", "stat_failed"}


def _rmtree(path: Path) -> None:
    """Recursively remove a directory tree, clearing read-only flags on Windows."""
    def _remove_readonly(func, p, exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_remove_readonly)
    else:
        shutil.rmtree(path, onerror=_remove_readonly)


@dataclass
class IngestResult:
    host_id: str
    verified: int = 0
    failed: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)


@dataclass
class VerifyReport:
    reverified: int = 0
    mismatches: list[str] = field(default_factory=list)


def open_raw(path: str | Path):
    """The only sanctioned way to read evidence: binary, read-only."""
    return open(path, "rb")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open_raw(path) as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stored_rel_path(original_path: str) -> str:
    """Map a hash_manifest original_path to its location inside the bundle."""
    if original_path.startswith("/"):
        return f"collected/files{original_path}"
    return f"collected/{original_path}"


def _read_hash_manifest(raw_host: Path) -> list[dict]:
    import csv

    manifest = raw_host / "hash_manifest.csv"
    if not manifest.exists():
        return []
    with open(manifest, encoding="utf-8", errors="surrogateescape", newline="") as fh:
        return list(csv.DictReader(fh))


def ingest_bundle(bundle_path: str | Path, case_dir: str | Path,
                  examiner: str) -> IngestResult:
    bundle_path = Path(bundle_path)
    case_dir = Path(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)

    # --- extract to a temp area first so we can name the host dir afterwards
    tmp_extract = case_dir / "_extracting"
    if tmp_extract.exists():
        _rmtree(tmp_extract)
    tmp_extract.mkdir(parents=True)

    mode = "r:gz" if bundle_path.name.endswith(".gz") else "r"
    with tarfile.open(bundle_path, mode) as tf:
        tf.extractall(tmp_extract, filter="data")

    collector_manifest = {}
    manifest_file = tmp_extract / "manifest.json"
    if manifest_file.exists():
        collector_manifest = json.loads(
            manifest_file.read_text(encoding="utf-8", errors="surrogateescape")
        )

    host = collector_manifest.get("host", {})
    host_id = host.get("machine_id") or host.get("hostname") or "unknown-host"
    host_id = host_id.strip() or "unknown-host"

    raw_host = case_dir / "raw" / host_id
    if raw_host.exists():
        _rmtree(raw_host)
    raw_host.parent.mkdir(parents=True, exist_ok=True)
    tmp_extract.rename(raw_host)

    # --- verify every hashed file against the collection-time manifest
    result = IngestResult(host_id=host_id)
    quarantine = raw_host / "_integrity_failed"
    verified_hashes: dict[str, str] = {}

    for row in _read_hash_manifest(raw_host):
        status = row.get("status", "")
        original = row.get("original_path", "")
        expected = (row.get("sha256") or "").strip()
        if status in _NO_FILE_STATUSES:
            result.skipped.append({"original_path": original, "status": status})
            continue
        rel = stored_rel_path(original)
        stored = raw_host / rel
        if not stored.exists():
            result.failed.append(
                {"original_path": original, "reason": "listed in manifest but absent from bundle"}
            )
            continue
        actual = _sha256_file(stored)
        if expected and actual != expected:
            dest = quarantine / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(stored), str(dest))
            result.failed.append(
                {
                    "original_path": original,
                    "reason": "hash mismatch",
                    "expected": expected,
                    "actual": actual,
                }
            )
            continue
        verified_hashes[rel] = actual
        result.verified += 1

    # record verified hashes for the final re-verification pass
    (raw_host / "_verified_hashes.json").write_text(
        json.dumps(verified_hashes, indent=0, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="surrogateescape",
    )

    # best-effort read-only marking (no-op on Windows)
    for p in raw_host.rglob("*"):
        if p.is_file():
            try:
                p.chmod(0o444)
            except OSError:
                pass

    # --- case_metadata.json (merge across multiple ingested hosts)
    meta_path = case_dir / "case_metadata.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8", errors="surrogateescape"))
    else:
        meta = {"examiner": examiner, "analyzer_version": __version__, "hosts": {}}
    meta["examiner"] = examiner
    meta["analyzer_version"] = __version__
    meta["hosts"][host_id] = {
        "bundle": bundle_path.name,
        "ingest_time_utc": datetime.now(timezone.utc).isoformat(),
        "verified": result.verified,
        "integrity_failed": result.failed,
        "skipped_no_content": result.skipped,
        "collector_manifest": collector_manifest,
    }
    meta_path.write_text(
        json.dumps(meta, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="surrogateescape",
    )
    return result


def verify_raw(case_dir: str | Path) -> VerifyReport:
    """Final re-verification: prove nothing under raw/ changed since ingest."""
    case_dir = Path(case_dir)
    report = VerifyReport()
    for host_dir in sorted((case_dir / "raw").iterdir()):
        record = host_dir / "_verified_hashes.json"
        if not record.exists():
            continue
        expected = json.loads(record.read_text(encoding="utf-8"))
        for rel, digest in expected.items():
            stored = host_dir / rel
            if not stored.exists():
                report.mismatches.append(f"{host_dir.name}:{rel}: missing")
                continue
            if _sha256_file(stored) != digest:
                report.mismatches.append(f"{host_dir.name}:{rel}: modified after ingest")
            else:
                report.reverified += 1
    return report
