"""Central Forensic Ingestion & Investigation Server for LFA.

Provides:
  - Streaming Evidence Ingestion API (`POST /api/v1/ingest`) with in-flight SHA-256 validation.
  - Token-based Bearer Authentication (`--token`).
  - Automated analysis pipeline trigger upon stream reception (`--auto-analyse`).
  - Modern, responsive dark-themed SOC Investigation Web Dashboard (`GET /`).
  - Native offline report and export serving (`GET /cases/<case_id>/report.html`).
  - Zero external dependencies (uses Python standard library http.server, ssl, threading).
"""
from __future__ import annotations

import hashlib
import http.server
import json
import secrets
import socketserver
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__, db
from .pipeline import run_analysis_pipeline


class LFAServerHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Request Handler for LFA Streaming Ingest and Investigation Dashboard."""

    server_version = f"LFAServer/{__version__}"

    @property
    def cases_dir(self) -> Path:
        return Path(getattr(self.server, "cases_dir", "cases"))

    @property
    def auth_token(self) -> str | None:
        return getattr(self.server, "auth_token", None)

    @property
    def auto_analyse(self) -> bool:
        return getattr(self.server, "auto_analyse", True)

    @property
    def examiner(self) -> str:
        return getattr(self.server, "examiner", "Remote Investigator")

    @property
    def business_hours(self) -> str:
        return getattr(self.server, "business_hours", "08-18")

    def _check_auth(self) -> bool:
        """Verify token authentication if configured on server."""
        if not self.auth_token:
            return True
        auth_header = self.headers.get("Authorization", "")
        token_header = self.headers.get("X-LFA-Token", "")

        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif token_header:
            token = token_header.strip()

        return secrets.compare_digest(token, self.auth_token)

    def _send_json(self, status_code: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, status_code: int, html_content: str) -> None:
        payload = html_content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Case-ID, X-Examiner, X-Bundle-SHA256, X-LFA-Token")
        self.end_headers()

    def do_GET(self) -> None:
        """Serve Dashboard, Reports, and JSON APIs."""
        path = self.path.split("?")[0].rstrip("/")
        if path == "":
            path = "/"

        # 1. Health / Status API
        if path in ("/api/v1/health", "/api/v1/status"):
            cases = self._list_cases()
            self._send_json(200, {
                "status": "online",
                "service": "Linux Forensic Analyzer Ingestion Server",
                "version": __version__,
                "cases_count": len(cases),
                "server_time_utc": datetime.now(timezone.utc).isoformat(),
            })
            return

        # 2. Case List JSON API
        if path == "/api/v1/cases":
            cases = self._list_cases()
            self._send_json(200, {"cases": cases})
            return

        # 3. Main SOC Web Dashboard
        if path == "/" or path == "/dashboard":
            cases = self._list_cases()
            html = self._render_dashboard_html(cases)
            self._send_html(200, html)
            return

        # 4. Report / Static file serving: /cases/<case_id>/report.html or exports
        if path.startswith("/cases/"):
            rel_path = path[len("/cases/"):]
            parts = Path(rel_path).parts
            if not parts or ".." in parts:
                self._send_json(400, {"error": "Invalid path navigation"})
                return

            target_file = self.cases_dir / rel_path
            if target_file.is_file() and target_file.exists():
                try:
                    content_type = "text/html; charset=utf-8" if target_file.suffix == ".html" else "application/octet-stream"
                    if target_file.suffix == ".json":
                        content_type = "application/json; charset=utf-8"
                    elif target_file.suffix == ".csv":
                        content_type = "text/csv; charset=utf-8"

                    with open(target_file, "rb") as fh:
                        content = fh.read()

                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                    return
                except Exception as ex:
                    self._send_json(500, {"error": f"Failed reading file: {ex}"})
                    return

        self._send_json(404, {"error": "Endpoint or resource not found", "path": self.path})

    def do_POST(self) -> None:
        """Handle Streaming Evidence Ingestion."""
        path = self.path.split("?")[0].rstrip("/")

        if path != "/api/v1/ingest":
            self._send_json(404, {"error": "Unknown POST endpoint"})
            return

        if not self._check_auth():
            self._send_json(401, {"error": "Unauthorized: Invalid or missing authentication token"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            content_length = 0

        if content_length <= 0:
            self._send_json(400, {"error": "Missing or empty Content-Length header for streaming ingest"})
            return

        # Case Identification
        case_id = self.headers.get("X-Case-ID")
        if not case_id or not case_id.strip():
            timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            case_id = f"stream_case_{timestamp_str}"
        case_id = "".join(c for c in case_id if c.isalnum() or c in ("-", "_", "."))

        examiner = self.headers.get("X-Examiner") or self.examiner
        expected_sha256 = self.headers.get("X-Bundle-SHA256", "").strip().lower()

        case_dir = self.cases_dir / case_id
        case_dir.mkdir(parents=True, exist_ok=True)

        bundle_path = case_dir / "bundle.tar.gz"

        print(f"[*] [LFA-Server] Receiving incoming stream for case '{case_id}' ({content_length} bytes)...")
        hasher = hashlib.sha256()
        bytes_read = 0
        chunk_size = 1024 * 1024  # 1MB buffer

        try:
            with open(bundle_path, "wb") as out_fh:
                remaining = content_length
                while remaining > 0:
                    read_len = min(chunk_size, remaining)
                    chunk = self.rfile.read(read_len)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    out_fh.write(chunk)
                    bytes_read += len(chunk)
                    remaining -= len(chunk)

            computed_sha256 = hasher.hexdigest()
            print(f"[+] [LFA-Server] Stream received: {bytes_read} bytes. SHA-256: {computed_sha256}")

            # Verify client provided hash if present
            if expected_sha256 and expected_sha256 != computed_sha256:
                print(f"[!] [LFA-Server] SHA-256 hash mismatch! Expected: {expected_sha256}, Got: {computed_sha256}")
                bundle_path.unlink(missing_ok=True)
                self._send_json(400, {
                    "status": "error",
                    "error": "Integrity validation failure: Bundle SHA-256 checksum does not match stream header.",
                    "expected_sha256": expected_sha256,
                    "computed_sha256": computed_sha256,
                })
                return

            # Save stream sha256 checksum file
            (case_dir / "bundle.tar.gz.sha256").write_text(f"{computed_sha256}  bundle.tar.gz\n", encoding="utf-8")

            # Execute automated analysis pipeline if enabled
            if self.auto_analyse:
                print(f"[*] [LFA-Server] Auto-analysis triggered for case '{case_id}'...")
                analysis_res = run_analysis_pipeline(
                    case_dir=case_dir,
                    bundles=[bundle_path],
                    case_id=case_id,
                    examiner=examiner,
                    business_hours=self.business_hours,
                )
                print(f"[+] [LFA-Server] Case '{case_id}' analyzed: {analysis_res.get('events_inserted', 0)} events, {analysis_res.get('findings_count', 0)} findings.")

                self._send_json(200, {
                    "status": "success",
                    "case_id": case_id,
                    "bundle_sha256": computed_sha256,
                    "bytes_received": bytes_read,
                    "analysed": True,
                    "verified_files": analysis_res.get("verified_files", 0),
                    "events_inserted": analysis_res.get("events_inserted", 0),
                    "findings_count": analysis_res.get("findings_count", 0),
                    "report_url": f"/cases/{case_id}/report.html",
                })
            else:
                self._send_json(200, {
                    "status": "success",
                    "case_id": case_id,
                    "bundle_sha256": computed_sha256,
                    "bytes_received": bytes_read,
                    "analysed": False,
                    "bundle_path": str(bundle_path),
                })

        except Exception as ex:
            print(f"[!] [LFA-Server] Error during stream processing: {ex}", file=sys.stderr)
            self._send_json(500, {"status": "error", "error": str(ex)})

    def _list_cases(self) -> list[dict[str, Any]]:
        """Scan cases directory and summarize metadata, findings, and reports."""
        cases = []
        if not self.cases_dir.exists():
            return cases

        for item in sorted(self.cases_dir.iterdir(), reverse=True):
            if not item.is_dir():
                continue
            case_id = item.name
            db_path = item / "case.db"
            report_path = item / "report.html"
            meta_path = item / "case_metadata.json"

            case_info: dict[str, Any] = {
                "case_id": case_id,
                "path": str(item),
                "has_db": db_path.exists(),
                "has_report": report_path.exists(),
                "report_url": f"/cases/{case_id}/report.html" if report_path.exists() else None,
                "hosts": [],
                "examiner": "Unknown",
                "events_count": 0,
                "findings_count": 0,
                "high_findings": 0,
                "ingest_time": None,
            }

            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    case_info["hosts"] = list(meta.get("hosts", {}).keys())
                    case_info["examiner"] = meta.get("examiner", "Unknown")
                    case_info["ingest_time"] = meta.get("ingest_time_utc")
                except Exception:
                    pass

            if db_path.exists():
                try:
                    conn = db.open_case(db_path)
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM events")
                    case_info["events_count"] = cur.fetchone()[0]

                    cur.execute("SELECT COUNT(*) FROM findings")
                    case_info["findings_count"] = cur.fetchone()[0]

                    cur.execute("SELECT COUNT(*) FROM findings WHERE severity = 'high'")
                    case_info["high_findings"] = cur.fetchone()[0]

                    if case_info["examiner"] == "Unknown":
                        case_info["examiner"] = db.get_case_meta(conn, "examiner", "Unknown")

                    conn.close()
                except Exception:
                    pass

            cases.append(case_info)

        return cases

    def _render_dashboard_html(self, cases: list[dict[str, Any]]) -> str:
        """Generate a sleek, dark-mode SOC dashboard for the examiner."""
        total_cases = len(cases)
        total_events = sum(c["events_count"] for c in cases)
        total_findings = sum(c["findings_count"] for c in cases)
        total_high = sum(c["high_findings"] for c in cases)

        rows_html = ""
        if not cases:
            rows_html = """
            <tr>
              <td colspan="7" class="empty-state">
                <div class="empty-icon">📡</div>
                <p>No forensic streams received yet.</p>
                <span class="subtext">Run <code>collect.sh --stream-to http://&lt;server-ip&gt;:&lt;port&gt;/api/v1/ingest</code> on the target machine.</span>
              </td>
            </tr>
            """
        else:
            for c in cases:
                hosts_str = ", ".join(c["hosts"]) if c["hosts"] else "—"
                badge_high = f'<span class="badge badge-high">{c["high_findings"]} High</span>' if c["high_findings"] > 0 else ""
                badge_total = f'<span class="badge badge-neutral">{c["findings_count"]} Total</span>'

                report_btn = f'<a href="{c["report_url"]}" target="_blank" class="btn btn-primary">🔍 View Report</a>' if c["has_report"] else '<span class="btn btn-disabled">Pending</span>'

                ingest_str = c["ingest_time"][:19].replace("T", " ") if c["ingest_time"] else "—"

                rows_html += f"""
                <tr>
                  <td><strong class="case-title">{c["case_id"]}</strong></td>
                  <td><span class="mono-tag">{hosts_str}</span></td>
                  <td>{c["examiner"]}</td>
                  <td class="num">{c["events_count"]:,}</td>
                  <td>{badge_high} {badge_total}</td>
                  <td class="subtext">{ingest_str}</td>
                  <td>{report_btn}</td>
                </tr>
                """

        token_arg = f'--token "{self.auth_token}"' if self.auth_token else ''

        server_port = self.server.server_address[1] if hasattr(self.server, "server_address") else 8443

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LFA Central Ingestion & Investigation Console</title>
  <style>
    :root {{
      --bg: #0b0f19;
      --card-bg: #131b2e;
      --card-border: #1e293b;
      --text: #e2e8f0;
      --text-dim: #94a3b8;
      --primary: #38bdf8;
      --primary-hover: #0284c7;
      --accent: #6366f1;
      --high: #ef4444;
      --med: #f59e0b;
      --low: #10b981;
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font);
      line-height: 1.5;
      padding: 2rem 3rem;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 1.5rem;
    }}
    .logo-group {{
      display: flex;
      align-items: center;
      gap: 1rem;
    }}
    .logo-icon {{
      font-size: 2.2rem;
      background: linear-gradient(135deg, var(--primary), var(--accent));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }}
    h1 {{
      font-size: 1.75rem;
      font-weight: 700;
      letter-spacing: -0.025em;
    }}
    .status-badge {{
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.2);
      padding: 0.35rem 0.85rem;
      border-radius: 9999px;
      font-size: 0.875rem;
      font-weight: 600;
    }}
    .pulse-dot {{
      width: 8px;
      height: 8px;
      background: #34d399;
      border-radius: 50%;
      box-shadow: 0 0 8px #34d399;
    }}
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2rem;
    }}
    .stat-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.25rem;
    }}
    .stat-label {{
      color: var(--text-dim);
      font-size: 0.875rem;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .stat-value {{
      font-size: 2rem;
      font-weight: 700;
      margin-top: 0.25rem;
      color: #fff;
    }}
    .stat-value.high {{ color: var(--high); }}
    .stat-value.primary {{ color: var(--primary); }}
    
    .panel {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 2rem;
    }}
    .panel-header {{
      padding: 1.25rem 1.5rem;
      border-bottom: 1px solid var(--card-border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .panel-title {{
      font-size: 1.15rem;
      font-weight: 600;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }}
    th {{
      background: #0d1424;
      color: var(--text-dim);
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 0.85rem 1.5rem;
      border-bottom: 1px solid var(--card-border);
    }}
    td {{
      padding: 1rem 1.5rem;
      border-bottom: 1px solid var(--card-border);
      font-size: 0.925rem;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
    
    .case-title {{ color: #fff; font-size: 1rem; }}
    .mono-tag {{
      font-family: var(--font-mono);
      background: rgba(255, 255, 255, 0.05);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.85rem;
    }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.55rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
    }}
    .badge-high {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
    .badge-neutral {{ background: rgba(148, 163, 184, 0.15); color: #cbd5e1; }}
    .subtext {{ color: var(--text-dim); font-size: 0.85rem; }}
    .num {{ font-family: var(--font-mono); }}

    .btn {{
      display: inline-block;
      padding: 0.45rem 0.95rem;
      border-radius: 6px;
      font-size: 0.85rem;
      font-weight: 600;
      text-decoration: none;
      transition: all 0.15s ease;
      cursor: pointer;
    }}
    .btn-primary {{
      background: var(--primary);
      color: #0b0f19;
    }}
    .btn-primary:hover {{
      background: var(--primary-hover);
      color: #fff;
    }}
    .btn-disabled {{
      background: rgba(255, 255, 255, 0.05);
      color: var(--text-dim);
      cursor: not-allowed;
    }}

    .command-box {{
      background: #080c14;
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1.25rem;
      font-family: var(--font-mono);
      font-size: 0.875rem;
      color: #38bdf8;
      overflow-x: auto;
    }}
    .empty-state {{
      text-align: center;
      padding: 4rem 2rem !important;
      color: var(--text-dim);
    }}
    .empty-icon {{ font-size: 2.5rem; margin-bottom: 0.5rem; }}
  </style>
</head>
<body>
  <header>
    <div class="logo-group">
      <div class="logo-icon">🛡️</div>
      <div>
        <h1>LFA Forensic Ingestion Console</h1>
        <p class="subtext">Central Acquisition & Correlation Server v{__version__}</p>
      </div>
    </div>
    <div class="status-badge">
      <span class="pulse-dot"></span> Ingest API Online
    </div>
  </header>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Active Cases</div>
      <div class="stat-value primary">{total_cases}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Normalized Events</div>
      <div class="stat-value">{total_events:,}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Threat Findings</div>
      <div class="stat-value">{total_findings:,}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">High Severity Alerts</div>
      <div class="stat-value high">{total_high}</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">Forensic Cases & Evidence Streams</div>
      <div><button onclick="location.reload()" class="btn btn-primary">↻ Refresh</button></div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Case ID</th>
          <th>Host(s)</th>
          <th>Examiner</th>
          <th>Events</th>
          <th>Findings</th>
          <th>Ingest Time (UTC)</th>
          <th>Report Action</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>

  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">📡 Target Machine Streaming Quickstart (Zero Disk Footprint)</div>
    </div>
    <div style="padding: 1.5rem;">
      <p class="subtext" style="margin-bottom: 0.75rem;">Run this command on the target Linux system to collect artifacts strictly in RAM and stream directly to this server without touching target physical disk:</p>
      <div class="command-box">
sudo sh collect.sh -s http://&lt;THIS-SERVER-IP&gt;:{server_port}/api/v1/ingest {token_arg}
      </div>
    </div>
  </div>
</body>
</html>
"""


def run_server(
    host: str = "0.0.0.0",
    port: int = 8443,
    cases_dir: str | Path = "cases",
    token: str | None = None,
    auto_analyse: bool = True,
    cert_file: str | None = None,
    key_file: str | None = None,
    business_hours: str = "08-18",
    examiner: str = "Remote Investigator",
) -> None:
    """Start the central LFA streaming ingestion and investigation server."""
    cases_path = Path(cases_dir)
    cases_path.mkdir(parents=True, exist_ok=True)

    class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    server = ThreadedServer((host, port), LFAServerHandler)
    server.cases_dir = cases_path  # type: ignore[attr-defined]
    server.auth_token = token  # type: ignore[attr-defined]
    server.auto_analyse = auto_analyse  # type: ignore[attr-defined]
    server.business_hours = business_hours  # type: ignore[attr-defined]
    server.examiner = examiner  # type: ignore[attr-defined]

    protocol = "http"
    if cert_file and key_file:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        protocol = "https"

    print("=" * 70)
    print(f"[*] LFA Central Forensic Ingestion & Investigation Server v{__version__}")
    print(f"[*] Listening on: {protocol}://{host}:{port}/")
    print(f"[*] Cases Directory: {cases_path.resolve()}")
    print(f"[*] Authentication: {'Token Enabled' if token else 'None (Open)'}")
    print(f"[*] Auto-Analyze Stream: {'ENABLED' if auto_analyse else 'DISABLED'}")
    print(f"[*] Console Dashboard: {protocol}://127.0.0.1:{port}/")
    print("=" * 70)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down LFA Central Server cleanly...")
    finally:
        server.server_close()
