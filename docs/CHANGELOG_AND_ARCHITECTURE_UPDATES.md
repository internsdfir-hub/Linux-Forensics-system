# LFA System Updates & Feature Changelog

This document provides a comprehensive technical breakdown of all architectural enhancements, bug fixes, forensic tuning, and new interactive forensic capabilities implemented in the **Linux Forensic Analyzer (LFA)**.

---

## 1. Executive Summary of Changes

| Category | Component / Files | Description |
| :--- | :--- | :--- |
| **New Feature** | [`analyzer/lfa/explorer.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/explorer.py)<br>[`analyzer/lfa/server.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/server.py) | **Autopsy & FTK-Style Interactive Forensic Explorer:** Single-page investigation interface with real-time log search, faceted filters, raw evidence tree viewer, and 1-click SOC threat pivots. |
| **API Endpoints** | [`analyzer/lfa/server.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/server.py) | Added REST query endpoints (`/events`, `/artifacts`, `/artifact-content`, `/findings`) supporting pagination, sorting, full-text search, and cryptographic hash verification. |
| **Ingest & Parser Fix** | [`analyzer/lfa/parsers/utmp.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/parsers/utmp.py) | Added native SQLite 3 parsing for modern Linux `/var/log/wtmp.db` (Debian 12+, Kali 2024+, Ubuntu 24.04+). |
| **Crash Protection** | [`analyzer/lfa/schema.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/schema.py)<br>[`analyzer/lfa/db.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/db.py)<br>[`analyzer/lfa/pipeline.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/pipeline.py) | Implemented `clean_surrogates()` to sanitize non-UTF-8 binary surrogates (`\udcxx`) and prevent SQLite database driver crashes. |
| **Windows OS Cleanup** | [`analyzer/lfa/ingest.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/ingest.py) | Added `_rmtree()` with read-only file attribute stripping to eliminate `PermissionError` on Windows during temporary bundle extraction. |
| **Rule & Report Tuning** | [`analyzer/lfa/rules/integrity.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/rules/integrity.py)<br>[`analyzer/lfa/rules/base.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/rules/base.py)<br>[`analyzer/lfa/report/narrative.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/report/narrative.py) | Filtered non-interactive service accounts (e.g. `lightdm`) from missing history alerts, cleared stale findings upon case re-analysis, and auto-numbered narrative action items. |
| **Dynamic Reflection** | [`analyzer/lfa/parsers/base.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/parsers/base.py)<br>[`analyzer/lfa/rules/base.py`](file:///d:/C/Git/Linux-Forensics-system/analyzer/lfa/rules/base.py) | Updated `discover_parsers()` and `discover_rules()` to use dynamic package resolution `__package__`. |
| **Test Verification** | [`tests/test_server_stream.py`](file:///d:/C/Git/Linux-Forensics-system/tests/test_server_stream.py)<br>[`tests/test_utmp_parser.py`](file:///d:/C/Git/Linux-Forensics-system/tests/test_utmp_parser.py) | Added unit and integration tests covering SQLite wtmpdb, explorer APIs, and streaming ingest (251 tests passing). |

---

## 2. Interactive Forensic Log & Artifact Explorer

### Background & Goal
Traditional forensic suites (Autopsy, FTK) allow examiners to navigate the directory tree of an acquired filesystem and view file content, while modern SIEM tools (Splunk, Elastic) allow rapid searching and timeline sorting of normalized events.

The new **LFA Explorer** bridges this gap inside the central investigation web interface:
- **Zero Dependencies / Zero CDN:** Operates entirely offline with inline Vanilla CSS and Vanilla JS, adhering to strict air-gapped forensic standards.
- **Sub-10ms Query Speed:** Direct indexed SQLite queries across tens of thousands of records.

### Interface Tabs & Architecture

```
                               ┌──────────────────────────────────────────────┐
                               │     LFA Single-Page Forensic Workspace       │
                               └──────────────────────┬───────────────────────┘
                                                      │
         ┌────────────────────────────────────────────┼────────────────────────────────────────────┐
         │                                            │                                            │
         ▼                                            ▼                                            ▼
┌─────────────────────────────────┐        ┌─────────────────────────────────┐        ┌─────────────────────────────────┐
│     Tab 1: Event Timeline       │        │     Tab 2: Evidence Tree        │        │     Tab 3: Threat Findings      │
├─────────────────────────────────┤        ├─────────────────────────────────┤        ├─────────────────────────────────┤
│ • Full-text keyword search      │        │ • Folder tree (/etc, /var/log)  │        │ • Correlated threat detections  │
│ • Category & severity filters   │        │ • File size & integrity badges  │        │ • 4-question plain summary      │
│ • Actor User dropdown           │        │ • Line-numbered code viewer     │        │ • Technical provenance          │
│ • Expandable raw log drawer     │        │ • In-file string search         │        │ • "Pivot to Events" button:     │
│ • 1-Click Copy Raw Line / JSON  │        │ • Cryptographic SHA-256 copy    │        │   Jumps into Tab 1 with exact   │
│ • "Jump to Artifact" button     │        │ • Permissions & owner metadata  │        │   event IDs pre-filtered        │
└─────────────────────────────────┘        └─────────────────────────────────┘        └─────────────────────────────────┘
```

### New Server Endpoints (`server.py`)

1. **`GET /cases/<case_id>/explorer`**
   - Serves the self-contained Single-Page Application generated by `analyzer/lfa/explorer.py`.
2. **`GET /api/v1/cases/<case_id>/events`**
   - Query Parameters: `q` (search string), `category`, `severity`, `user`, `host`, `from_ts`, `to_ts`, `ids` (comma-separated event IDs), `limit` (default 50), `offset`, `sort`, `order`.
   - Returns: JSON object containing total counts, filtered counts, distinct users, and array of normalized event dicts.
3. **`GET /api/v1/cases/<case_id>/artifacts`**
   - Returns: JSON list of all ingested artifacts with original path, stored path, SHA-256 checksum, size, mode, owner, integrity status, and parsed event counts.
4. **`GET /api/v1/cases/<case_id>/artifact-content?path=<original_path>`**
   - Query Parameters: `path` (file path with path traversal protection).
   - Returns: JSON object containing line-numbered text content, file size, line count, and real-time SHA-256 checksum.
5. **`GET /api/v1/cases/<case_id>/findings`**
   - Returns: JSON list of all correlated SOC threat findings with plain summaries and linked event IDs.

---

## 3. Bug Fixes & Forensic Engine Tuning

### A. SQLite `wtmpdb` Support (`analyzer/lfa/parsers/utmp.py`)
- **Root Cause:** Modern Linux distros (Debian 12+, Kali 2024+) replace raw C-struct utmp files with SQLite databases (`/var/log/wtmp.db`). The legacy parser attempted to read 384-byte C structs from the SQLite binary database, producing surrogate Unicode garbage (`\udcb9`) that crashed database transactions.
- **Solution:** Added a header check (`b"SQLite format 3\x00"`). When detected, the parser directly queries the SQLite `log` table, extracting user, TTY/line, host, timestamp, and login/logout status cleanly.

### B. Unicode Surrogate Decode Sanitization (`analyzer/lfa/schema.py`, `analyzer/lfa/db.py`)
- **Root Cause:** Non-UTF-8 corrupted log lines with surrogateescape code points (`\udc80`–`\udcff`) caused Python's SQLite driver to raise `UnicodeEncodeError: 'utf-8' codec can't encode character... surrogates not allowed`.
- **Solution:** Added `clean_surrogates()`:
  ```python
  def clean_surrogates(val: Any) -> Any:
      if isinstance(val, str):
          return val.encode("utf-8", "replace").decode("utf-8")
      return val
  ```
  Applied across `make_event()`, `db.insert_events()`, and `pipeline._record_artifact()`.

### C. False-Positive Rule Tuning (`analyzer/lfa/rules/integrity.py`)
- **Issue:** Service/daemon accounts (`lightdm`, `nobody`, `daemon`, `systemd-*`) were triggering `wiped_history` alerts because they lack interactive shell histories.
- **Solution:** Added `_COMMON_SERVICE_ACCOUNTS` filter to bypass non-human system accounts while strictly auditing human users (`root`, `kali`, etc.).

### D. Idempotent Re-Analysis (`analyzer/lfa/rules/base.py`)
- **Issue:** Re-running the analysis pipeline on an existing case appended duplicate finding rows into the `findings` table.
- **Solution:** Added `DELETE FROM findings WHERE case_id = ?` before inserting new findings in `save_findings()`.

### E. Executive Narrative Auto-Numbering (`analyzer/lfa/report/narrative.py`)
- **Issue:** Action items rendered as `1. ... 1. ... 1. ...`.
- **Solution:** Dynamically numbered recommendations `1., 2., 3., ...` and deduplicated identical remediation directives.

---

## 4. Test Verification & Metrics

- **Unit & Integration Test Suite:**
  - Ran `python -m pytest` across all 18 test files.
  - **Result:** `251 passed, 10 skipped in 11.86s` (0 failures, 0 regressions).
- **Live Incident Dataset (Case 103):**
  - Total Events: `53,059`
  - Ingested Evidence Artifacts: `111`
  - Threat Findings: `6`
  - Query latency for full-text search: `< 5ms`
