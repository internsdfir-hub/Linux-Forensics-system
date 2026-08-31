# PROJECT_MEMORY.md — Linux Forensic Log Processing System (`LFA`)

> **CRITICAL REPOSITORY MEMORY FILE**  
> This file contains the complete persistent context, architectural decisions, strict constraints, testing environments, credentials, and project directions for all current and future AI agent sessions.

---

## 1. Project Identity & Purpose
- **Repository Name:** `Linux-Forensics-system` (`internsdfir-hub/Linux-Forensics-system`)
- **Package Name:** `lfa` (Linux Forensic Analyzer)
- **Goal:** A zero-dependency, forensic-grade Linux forensic collection and analysis system.
- **Core Philosophy:**
  1. **Strict Evidence Integrity & Non-Contamination:** Standard forensic principles (RFC 3227 Order of Volatility). Collector runs POSIX `sh` on target without Python or heavy dependencies; copies first, hashes the copy, verifies SHA-256 against manifest.
  2. **Frozen Unified Event Model:** All parsers output standardized `NormalizedEvent` instances validated against `analyzer/lfa/schema.py`.
  3. **Deterministic & Offline:** Identical evidence input always yields byte-identical JSON/CSV canonical exports. Reports are 100% self-contained HTML with inlined CSS, JS, and pure-Python SVG density charts (zero external network/CDN calls).
  4. **Explainable Dual-Layer Rules (No ML):** Every correlation rule produces both a Plain-English summary (answering: What happened? Why it matters? Confidence? Recommended action?) for investigators and a Technical Details drawer for examiners.

---

## 2. Testing Environment & Credentials
- **WSL Linux Testing:**
  - Distribution: `kali-linux` (WSL2)
  - Username: `kali`
  - Password: `kali`
  - Sudo Command Pattern: `echo kali | sudo -S <command>`
  - Secondary WSL Distribution: `Ubuntu-24.04` (WSL2)
- **Python Environment:** Python 3.11+ stdlib + `PyYAML`, `Jinja2` (+ `tzdata` on Windows).

---

## 3. Directory Map & File Architecture
```
Linux-Forensics-system/
├── collector/
│   └── collect.sh                    # POSIX sh live evidence collector (embedded artifact table)
├── config/
│   ├── artifacts.yaml                # Single source of truth for artifact catalogue
│   ├── grammars/                     # Syslog regex grammar YAML definitions (common, debian, rhel)
│   └── usb_vendors.csv               # Bundled offline USB vendor-ID database
├── analyzer/
│   ├── pyproject.toml                # Package definition (lfa)
│   └── lfa/
│       ├── __init__.py               # Version definition
│       ├── __main__.py               # CLI entrypoint (analyse, verify, export, report, synth)
│       ├── schema.py                 # NormalizedEvent schema & validation contract
│       ├── db.py                     # SQLite case database & indexing
│       ├── canonical.py              # Byte-deterministic JSON & CSV export engine
│       ├── ingest.py                 # Evidence bundle unpacker & SHA-256 integrity verifier
│       ├── timeeng.py                # Timezone resolution & syslog year inference engine
│       ├── pipeline.py               # Ingestion -> Parser execution orchestration
│       ├── parsers/                  # Complete parser suite (authlog, journald, utmp, passwd,
│       │                             # lastlog, shellhist, knownhosts, usb, cron, apt/dpkg/dnf,
│       │                             # sudoers, systemd_unit, authkeys, etc.)
│       ├── rules/                    # Correlation engine (attack, integrity, state, firstseen)
│       └── report/                   # Reporting engine (data, chart, narrative, render, templates)
├── testlab/
│   ├── scenario.sh                   # WSL Kali attack simulation script
│   └── ground_truth.json             # Ground truth indicators injected by scenario.sh
├── tools/
│   ├── gen_artifact_table.py         # Syncs artifacts.yaml into collect.sh embedded table
│   ├── make_synthetic_case.py        # Seeded deterministic synthetic case generator
│   └── score_detection.py            # Automated scorecard comparing detections vs ground truth
├── tests/                            # Comprehensive pytest test suite (240+ unit/integration tests)
├── PROJECT_MEMORY.md                 # Persistent project context and directions
└── AGENTS.md                         # Agent instructions and rules
```

---

## 4. Key Technical Decisions & Invariants
- **D1 (Artifact Table Sync):** `config/artifacts.yaml` is the source of truth; `tools/gen_artifact_table.py` embeds the table into `collector/collect.sh`. `tests/test_artifact_table_sync.py` enforces sync.
- **D2 (Event ID Determinism):** `event_id = uuid5(NAMESPACE_LFA, event_hash)`. Never use random `uuid4()`.
- **D3 (Pure-Python SVG Charts):** No matplotlib. Pure-Python SVG generation in `analyzer/lfa/report/chart.py` ensures deterministic output and zero native wheel dependencies.
- **D4 (Lightweight Schema Validation):** `analyzer/lfa/schema.py` enforces frozen field types without heavy jsonschema dependencies.
- **D6 (WSL Validation):** Tested in WSL Kali (`kali:kali`).
- **D8 (Windows Timezone):** Platform-aware timezone handling with fallback to UTC; never crash on invalid timezone names.
- **D9 (CLI Naming):** Package is `lfa`; invoked via `python -m lfa <subcommand>`.
- **D10 (Streaming Log Parsing):** Always stream lines lazily (never `.readlines()` large files) to handle gigabyte logs cleanly.

---

## 5. Standard CLI Operations
### Analyse Evidence Bundle:
```powershell
python -m lfa analyse cases/bundle.tar.gz --case-dir cases/case_01 --examiner "Investigator"
```

### Verify Case Evidence Hashes:
```powershell
python -m lfa verify cases/case_01
```

### Export Canonical Deterministic Dataset:
```powershell
python -m lfa export cases/case_01 --out-dir cases/case_01/exports
```

### Re-render Offline HTML Report:
```powershell
python -m lfa report cases/case_01 --out cases/case_01/report.html
```

### Generate Synthetic Test Case:
```powershell
python -m lfa synth --out cases/synth/case.db --seed 42
```

### Start Central Forensic Streaming Ingestion & Investigation Server:
```powershell
python -m lfa serve --host 0.0.0.0 --port 8443 --cases-dir cases --token "secret-key"
```

### Acquire Evidence Remotely over SSH Stream (Agentless Pull):
```powershell
python -m lfa remote --host 192.168.1.50 --user kali --case-dir cases/kali_01 --examiner "Investigator"
```

### Stream Live Target Evidence Directly to Central Server in RAM (Zero Disk Writes):
```bash
# On target machine:
sudo sh collect.sh -s http://<server-ip>:8443/api/v1/ingest -T "secret-key" -c CASE_REMOTE_01 -V -z
```

---

## 6. Testing & Development Roadmap for Future Turns
1. **Running Full Test Suite:** `python -m pytest`
2. **Executing WSL Kali Attack Simulation & Live Collection:**
   ```powershell
   # 1. Run attack simulation in Kali WSL:
   wsl -d kali-linux -u kali bash -c "cd /mnt/d/C/Git/Linux-Forensics-system && echo kali | sudo -S bash testlab/scenario.sh"
   
   # 2. Run POSIX collector in Kali WSL:
   wsl -d kali-linux -u kali bash -c "cd /mnt/d/C/Git/Linux-Forensics-system && echo kali | sudo -S sh collector/collect.sh -r / -o /mnt/d/C/Git/Linux-Forensics-system/cases/wsl_kali -c CASE_KALI_01 -p kali -V -z"
   
   # 3. Ingest & analyse evidence bundle:
   python -m lfa analyse cases/wsl_kali/*.tar.gz --case-dir cases/kali_case --examiner "Fahad"
   
   # 4. Score detections against ground truth:
   python tools/score_detection.py --case-dir cases/kali_case --ground-truth testlab/ground_truth.json
   ```
3. **Future Feature Enhancements:**
   - Extended parsers (browser history WebKit timestamps, `faillog`, `fstimeline`).
   - Extended Sigma rule converter to LFA rule generator.
   - Multi-host timeline cross-correlation for lateral movement mapping.
