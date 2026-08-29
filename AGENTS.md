# AGENTS.md — Agent Guidelines & Repository Memory for Linux-Forensics-system

This workspace contains **LFA (Linux Forensic Analyzer)**, a high-fidelity, deterministic forensic log collection and correlation engine for Linux environments.

## Essential Context & Rules for Agents
- **Master Plan & Architecture:** Refer to [docs/superpowers/plans/2026-08-18-linux-forensic-tool.md](file:///d:/C/Git/Linux-Forensics-system/docs/superpowers/plans/2026-08-18-linux-forensic-tool.md) and [PROJECT_MEMORY.md](file:///d:/C/Git/Linux-Forensics-system/PROJECT_MEMORY.md).
- **Core Contract:** All parsers output `NormalizedEvent` records validated against [analyzer/lfa/schema.py](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/schema.py).
- **Offline & Determinism:** No external network or CDN calls in HTML reports. Charts are pure-Python SVG in [analyzer/lfa/report/chart.py](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/report/chart.py).
- **Dual-Layer Rules:** Every correlation rule must return both `technical_detail` and a four-question `plain_summary` (what happened, why it matters, confidence, check next).
- **WSL Test Environment:**
  - Distribution: `kali-linux`
  - User: `kali` (Password: `kali`)
  - Sudo syntax: `echo kali | sudo -S <command>`

## Quick Reference Commands
- Run test suite: `python -m pytest`
- Run analysis CLI: `python -m lfa analyse <bundles...> --case-dir <dir> --examiner <name>`
- Verify raw evidence integrity: `python -m lfa verify <case-dir>`
- Score detections against attack ground truth: `python tools/score_detection.py --case-dir <case-dir> --ground-truth testlab/ground_truth.json`
