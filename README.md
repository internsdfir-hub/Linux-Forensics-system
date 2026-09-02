# Linux Forensic Analyzer (LFA)

LFA is a high-fidelity, deterministic forensic log collection, ingestion, correlation, and analysis engine for Linux environments.

The architecture is strictly separated into two sides:
1. **Collector (`collector/collect.sh`)** — Runs on the target/investigated Linux host (POSIX `sh`, minimal dependencies, zero Python/rsync required, tamper-evident).
2. **Analyzer / Server (`analyzer/lfa`)** — Runs on the forensic examiner / SOC workstation or central server (Python 3.11+, timeline reconstruction, threat correlation rules, interactive web dashboard, and offline HTML reports).

---

## Architecture Overview

```
                      TARGET / LIVE LINUX HOST
    +-------------------------------------------------------------+
    |  collector/collect.sh (POSIX sh, zero-install, in-memory)   |
    +-------------------------------------------------------------+
              |                                 |
              | (Direct HTTPS Stream / SSH)     | (Manual Tarball Transfer)
              v                                 v
    +-------------------------------------------------------------+
    |                     EXAMINER / SOC SERVER                   |
    |                                                             |
    |  1. Central Server:   python -m lfa serve                   |
    |  2. CLI Pipeline:     python -m lfa analyse <bundles...>    |
    |  3. Remote Ingest:    python -m lfa remote --host <target>  |
    |  4. Integrity Verify: python -m lfa verify <case_dir>       |
    |  5. Web UI & Report:  Interactive Dashboard & Offline HTML  |
    +-------------------------------------------------------------+
```

---

## Prerequisites & Installation

### 1. Collector (Target Side)
- Any Linux system (Debian/Ubuntu, RHEL/CentOS, Arch, Alpine, BusyBox, etc.)
- Standard POSIX shell (`/bin/sh`, `dash`, `bash`) and coreutils (`tar`, `sha256sum`, `cp`, `stat`).
- Root / sudo privileges for full artifact collection (`/etc/shadow`, `/var/log/*`, memory snapshots).

### 2. Analyzer (Examiner Side)
- Python 3.11+
- Install dependencies:
```bash
# In the repository root:
pip install -e ./analyzer
# Or install required packages directly:
pip install PyYAML Jinja2
```

---

## 1. Running the Collector (Target Host)

The collector script is located at [`collector/collect.sh`](file:///collector/collect.sh).

### Basic Collection (Standard Archive)
Collect artifacts from the live system and save a compressed bundle:
```bash
sudo sh collector/collect.sh -o /tmp/output -c CASE-001 -p "Examiner Name" -z
```
*Output: `/tmp/output/lfa_CASE-001_<hostname>_<timestamp>.tar.gz` and `manifest.txt` with SHA-256 hashes.*

### In-Memory / RAM Mode (Zero Disk Forensics)
Stages collection in `/dev/shm` to avoid touching the target disk:
```bash
sudo sh collector/collect.sh -M -o /tmp -c CASE-001 -z
```

### Direct Streaming Ingestion over HTTPS
Stream evidence directly to a running LFA Central Server without saving the tarball to disk:
```bash
sudo sh collector/collect.sh -M -s "http://soc-server.corp.local:8443" -T "SECRET_SOC_TOKEN" -c CASE-001
```

### Full Volatile Snapshot Mode
Collect volatile memory state (`/proc`, open network connections, running process tree) first before file collection:
```bash
sudo sh collector/collect.sh -V -z -o /tmp -c CASE-001
```

### Redacted Secrets Mode
Exclude credentials and hash content (`/etc/shadow`, `/etc/gshadow`) when handling sensitive environments:
```bash
sudo sh collector/collect.sh -R -z -o /tmp -c CASE-001
```

---

## 2. Running the Analyzer (Examiner / SOC Side)

The analyzer CLI is invoked using `python -m lfa <subcommand>`.

### Option A: Local Bundle Analysis (CLI Pipeline)
Ingests one or more collected `.tar.gz` bundles, parses artifacts, executes correlation rules, and generates an offline HTML report:
```bash
python -m lfa analyse /path/to/lfa_CASE-001_bundle.tar.gz --case-dir cases/CASE-001 --examiner "Jane Doe"
```
**Output generated in `cases/CASE-001/`:**
- `case.db` — SQLite database with normalized forensic events & findings.
- `report.html` — Self-contained, offline interactive HTML forensic report with SVG charts.
- `canonical/events.json` — SHA-256 verifiable canonical JSON timeline.
- `canonical/csv/` — Per-category CSV exports.

### Option B: Central Server & Live SOC Dashboard
Start the central ingestion server that accepts streaming uploads from collectors and serves the SOC web dashboard:
```bash
# Start server on port 8443 with token authentication
python -m lfa serve --host 0.0.0.0 --port 8443 --token "SECRET_SOC_TOKEN" --cases-dir cases/
```
- Open browser at `http://localhost:8443` for the interactive case dashboard and timeline explorer.
- When target hosts upload bundles, the server automatically verifies hashes, parses logs, and creates case reports.

### Option C: Agentless Remote Acquisition via SSH
Stream and analyze evidence directly from a remote target over SSH in a single command (no script saved on target disk):
```bash
python -m lfa remote --host 192.168.1.50 --user root --case-dir cases/REMOTE-001 --examiner "Jane Doe"
```

---

## 3. Evidence Verification & Re-Reporting

### Verify Raw Evidence Integrity
Re-verify all raw collected files against the tamper-evident SHA-256 hashes in the manifest:
```bash
python -m lfa verify cases/CASE-001
```

### Re-render Forensic Report
Re-generate the HTML report from an existing SQLite case database (e.g. after rule updates):
```bash
python -m lfa report cases/CASE-001 --out cases/CASE-001/updated_report.html
```

### Export Canonical Datasets
Export deterministic JSON and CSV datasets for external SIEM / data science analysis:
```bash
python -m lfa export cases/CASE-001 --out-dir exports/CASE-001
```

---

## 4. End-to-End Workflow Examples

### Example 1: Offline Manual Triage
1. **On Target Linux Host:**
   ```bash
   sudo sh collect.sh -o /mnt/usb -c INCIDENT-42 -p "Alice" -z
   ```
2. **Transfer the bundle to Examiner Workstation.**
3. **On Examiner Workstation:**
   ```bash
   python -m lfa analyse /mnt/usb/lfa_INCIDENT-42_server1.tar.gz --case-dir cases/INCIDENT-42 --examiner "Bob"
   # Open the report in your browser:
   # cases/INCIDENT-42/report.html
   ```

### Example 2: Live Ingest & Remote Investigation
1. **Start Central LFA Server:**
   ```bash
   python -m lfa serve --port 8443 --token "supersecret123"
   ```
2. **Trigger Remote Push on Target:**
   ```bash
   sudo sh collect.sh -M -s "http://192.168.1.100:8443" -T "supersecret123" -c INCIDENT-99
   ```
3. **View Results:**
   - Navigate to `http://192.168.1.100:8443` to explore timeline events, threat detections, and forensic artifacts in real time.

---

## Running the Test Suite

Run the full automated test suite (250+ unit and integration tests):
```bash
python -m pytest
```

Score detections against attack ground truth:
```bash
python tools/score_detection.py --case-dir cases/SYNTH-001 --ground-truth testlab/ground_truth.json
```
