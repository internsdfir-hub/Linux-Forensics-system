"""CLI entrypoint tests (analyzer/lfa/__main__.py).

The CLI had no test coverage at all, which is how `lfa verify` shipped
completely broken while 284 other tests passed.
"""
import json
from pathlib import Path

import pytest

from lfa.__main__ import main

from bundle_builder import build_bundle


def _analysed_case(tmp_path: Path) -> Path:
    """Ingest a tiny bundle so there is a real case directory to verify."""
    bundle = build_bundle(
        tmp_path / "src",
        {
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n",
            "/etc/os-release": b'ID=debian\nVERSION_ID="12"\n',
        },
    )
    case_dir = tmp_path / "case"
    rc = main([
        "analyse", str(bundle),
        "--case-dir", str(case_dir),
        "--examiner", "Test Examiner",
    ])
    assert rc == 0
    return case_dir


def test_verify_returns_zero_on_clean_case(tmp_path, capsys):
    case_dir = _analysed_case(tmp_path)

    rc = main(["verify", str(case_dir)])

    assert rc == 0
    assert "verified" in capsys.readouterr().out.lower()


def test_verify_returns_one_when_evidence_modified(tmp_path, capsys):
    case_dir = _analysed_case(tmp_path)

    # Tamper with a file after ingest; verify_raw must notice.
    target = next((case_dir / "raw").rglob("passwd"))
    target.chmod(0o644)
    target.write_bytes(b"root:x:0:0:root:/root:/bin/bash\nevil:x:0:0::/root:/bin/sh\n")

    rc = main(["verify", str(case_dir)])

    assert rc == 1
    assert "INTEGRITY FAILURE" in capsys.readouterr().err


def test_verify_handles_case_with_no_raw_directory(tmp_path, capsys):
    empty_case = tmp_path / "empty"
    empty_case.mkdir()

    rc = main(["verify", str(empty_case)])

    assert rc == 0
    assert "no raw evidence" in capsys.readouterr().out.lower()
