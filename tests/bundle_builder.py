"""Programmatic bundle builder for ingest tests.

Produces the same on-disk shape as collector/collect.sh (P5 seal) without
paying the cost of shelling out: collected/files/..., manifest.json,
hash_manifest.csv, collector.log, all inside bundle.tar.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import tarfile
from pathlib import Path


def build_bundle(
    out_dir: Path,
    files: dict[str, bytes],
    *,
    machine_id: str = "1234abcd1234abcd1234abcd1234abcd",
    hostname: str = "testhost",
    case_id: str = "CASE-ING",
    tamper: set[str] = frozenset(),
    gzip_it: bool = False,
) -> Path:
    """files maps original_path (e.g. "/etc/passwd" or "journal/boot-0.json")
    to content bytes. Paths in `tamper` get a wrong sha256 in the manifest,
    simulating post-collection modification."""
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    payload: dict[str, bytes] = {}
    for orig, content in files.items():
        if orig.startswith("/"):
            arcname = f"collected/files{orig}"
        else:
            arcname = f"collected/{orig}"
        payload[arcname] = content
        digest = hashlib.sha256(content).hexdigest()
        if orig in tamper:
            digest = "0" * 64
        status = "journald_export" if orig.startswith("journal/") else "collected"
        rows.append(
            {
                "original_path": orig,
                "sha256": digest,
                "size": str(len(content)),
                "mode": "644",
                "owner": "0:0",
                "atime": "1710000000",
                "mtime": "1710000001",
                "ctime": "1710000002",
                "source_was_active": "0",
                "status": status,
            }
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    payload["hash_manifest.csv"] = buf.getvalue().encode()

    manifest = {
        "collector_version": "1.0.0",
        "case_id": case_id,
        "operator": "builder",
        "collection_start_utc": "2024-03-14T00:00:00Z",
        "collection_end_utc": "2024-03-14T00:01:00Z",
        "root": "/",
        "redact_mode": False,
        "host": {
            "distro_id": "debian",
            "version_id": "12",
            "pretty_name": "Debian 12",
            "kernel": "6.1.0",
            "hostname": hostname,
            "machine_id": machine_id,
            "timezone": "Asia/Karachi",
            "timezone_source": "etc_timezone",
            "init_system": "systemd",
        },
        "privilege": {"euid": "0", "is_root": True, "warnings": ""},
        "contamination": {
            "operator_user": "builder",
            "source_ip": "10.0.0.99",
            "tty": "pts/9",
            "pid": "4242",
            "start_utc": "2024-03-14T00:00:00Z",
            "end_utc": "2024-03-14T00:01:00Z",
        },
        "journald": {"available": False, "persistent": False, "exported_boots": 0},
        "volatile_captured": False,
        "collected_files": len(files),
        "hasher": "sha256sum",
        "stat_mode": "gnu",
        "missing": [],
        "degradations": [],
    }
    payload["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    payload["collector.log"] = b"builder bundle\n"

    tar_path = out_dir / "bundle.tar"
    with tarfile.open(tar_path, "w") as tf:
        for arcname in sorted(payload):
            data = payload[arcname]
            info = tarfile.TarInfo(arcname)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

    if gzip_it:
        import gzip as gz

        gz_path = out_dir / "bundle.tar.gz"
        gz_path.write_bytes(gz.compress(tar_path.read_bytes()))
        return gz_path
    return tar_path
