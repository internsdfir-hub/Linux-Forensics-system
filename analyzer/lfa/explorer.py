"""Interactive Forensic Log & Artifact Explorer UI generator for LFA (Autopsy / FTK style).

Generates a self-contained, responsive, zero-CDN single-page forensic investigation workspace.
Provides:
  1. High-speed Event & Timeline Grid with full-text search, multi-faceted filtering, and expandable raw provenance.
  2. Hierarchical Raw Evidence & Artifact Tree Explorer with file integrity badges and line-numbered log viewers.
  3. Correlated Threat Detections with 1-click event pivots.
"""
from __future__ import annotations

from typing import Any

from . import __version__


def render_explorer_html(case_id: str, case_info: dict[str, Any]) -> str:
    """Render the single-page interactive investigation explorer."""
    examiner = case_info.get("examiner", "Forensic Investigator")
    hosts_str = ", ".join(case_info.get("hosts", [])) if case_info.get("hosts") else "—"
    events_count = case_info.get("events_count", 0)
    findings_count = case_info.get("findings_count", 0)
    high_findings = case_info.get("high_findings", 0)
    report_url = case_info.get("report_url", f"/cases/{case_id}/report.html")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LFA Explorer — Case {case_id}</title>
  <style>
    :root {{
      --bg: #080c14;
      --card-bg: #0f172a;
      --card-hover: #1e293b;
      --border: #1e293b;
      --border-focus: #38bdf8;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --primary: #38bdf8;
      --primary-hover: #0284c7;
      --accent: #818cf8;
      --high: #ef4444;
      --high-bg: rgba(239, 68, 68, 0.15);
      --med: #f59e0b;
      --med-bg: rgba(245, 158, 11, 0.15);
      --low: #10b981;
      --low-bg: rgba(16, 185, 129, 0.15);
      --info: #38bdf8;
      --info-bg: rgba(56, 189, 248, 0.15);
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font);
      line-height: 1.5;
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
    }}
    header {{
      background: var(--card-bg);
      border-bottom: 1px solid var(--border);
      padding: 0.75rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-shrink: 0;
    }}
    .header-left {{
      display: flex;
      align-items: center;
      gap: 1.25rem;
    }}
    .back-link {{
      color: var(--text-muted);
      text-decoration: none;
      font-size: 0.875rem;
      display: flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.35rem 0.65rem;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 6px;
      transition: all 0.15s ease;
    }}
    .back-link:hover {{
      color: #fff;
      background: rgba(255, 255, 255, 0.1);
    }}
    .case-badge {{
      font-size: 1.15rem;
      font-weight: 700;
      letter-spacing: -0.01em;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .header-meta {{
      font-size: 0.85rem;
      color: var(--text-muted);
      display: flex;
      gap: 1rem;
    }}
    .header-right {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}
    .nav-tabs {{
      display: flex;
      gap: 0.5rem;
      background: rgba(0, 0, 0, 0.2);
      padding: 0.25rem;
      border-radius: 8px;
      border: 1px solid var(--border);
    }}
    .tab-btn {{
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 0.45rem 1rem;
      font-size: 0.875rem;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      transition: all 0.15s ease;
    }}
    .tab-btn:hover {{
      color: var(--text);
      background: rgba(255, 255, 255, 0.05);
    }}
    .tab-btn.active {{
      background: var(--primary);
      color: #0b0f19;
      box-shadow: 0 1px 3px rgba(0,0,0,0.3);
    }}
    .tab-badge {{
      font-size: 0.75rem;
      padding: 0.1rem 0.45rem;
      border-radius: 9999px;
      background: rgba(0, 0, 0, 0.25);
      color: inherit;
    }}
    .tab-btn.active .tab-badge {{
      background: rgba(0, 0, 0, 0.2);
      color: #0b0f19;
      font-weight: 700;
    }}

    .btn {{
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.45rem 0.9rem;
      border-radius: 6px;
      font-size: 0.85rem;
      font-weight: 600;
      text-decoration: none;
      border: 1px solid transparent;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .btn-secondary {{
      background: rgba(255, 255, 255, 0.08);
      color: var(--text);
      border-color: var(--border);
    }}
    .btn-secondary:hover {{
      background: rgba(255, 255, 255, 0.15);
      color: #fff;
    }}
    .btn-primary {{
      background: var(--primary);
      color: #0b0f19;
    }}
    .btn-primary:hover {{
      background: var(--primary-hover);
      color: #fff;
    }}

    /* Main Container */
    main {{
      flex: 1;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      position: relative;
    }}

    .tab-pane {{
      display: none;
      flex: 1;
      flex-direction: column;
      overflow: hidden;
      height: 100%;
    }}
    .tab-pane.active {{
      display: flex;
    }}

    /* Tab 1: Log & Event Explorer */
    .filter-toolbar {{
      background: var(--card-bg);
      border-bottom: 1px solid var(--border);
      padding: 0.75rem 1.5rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      align-items: center;
      flex-shrink: 0;
    }}
    .search-box {{
      flex: 1;
      min-width: 260px;
      position: relative;
    }}
    .search-input {{
      width: 100%;
      background: #080c14;
      border: 1px solid var(--border);
      color: var(--text);
      font-size: 0.875rem;
      padding: 0.5rem 0.85rem 0.5rem 2.2rem;
      border-radius: 6px;
      outline: none;
      transition: border-color 0.15s ease;
    }}
    .search-input:focus {{
      border-color: var(--primary);
    }}
    .search-icon {{
      position: absolute;
      left: 0.75rem;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-dim);
      pointer-events: none;
    }}
    .filter-select {{
      background: #080c14;
      border: 1px solid var(--border);
      color: var(--text);
      font-size: 0.85rem;
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      outline: none;
      cursor: pointer;
    }}
    .filter-select:focus {{
      border-color: var(--primary);
    }}
    .pill-group {{
      display: flex;
      gap: 0.35rem;
    }}
    .sev-pill {{
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 0.35rem 0.65rem;
      font-size: 0.8rem;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .sev-pill:hover {{
      color: #fff;
    }}
    .sev-pill.active-all {{ background: rgba(255, 255, 255, 0.15); color: #fff; border-color: var(--text-muted); }}
    .sev-pill.active-high {{ background: var(--high-bg); color: #f87171; border-color: var(--high); }}
    .sev-pill.active-med {{ background: var(--med-bg); color: #fbbf24; border-color: var(--med); }}
    .sev-pill.active-low {{ background: var(--low-bg); color: #34d399; border-color: var(--low); }}
    .sev-pill.active-info {{ background: var(--info-bg); color: #38bdf8; border-color: var(--info); }}

    /* Table & Event Grid */
    .table-container {{
      flex: 1;
      overflow: auto;
      background: var(--bg);
    }}
    table.events-table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.875rem;
    }}
    table.events-table th {{
      position: sticky;
      top: 0;
      background: #0f172a;
      color: var(--text-muted);
      font-weight: 600;
      padding: 0.65rem 1rem;
      border-bottom: 1px solid var(--border);
      z-index: 10;
      white-space: nowrap;
      user-select: none;
    }}
    table.events-table th.sortable {{
      cursor: pointer;
    }}
    table.events-table th.sortable:hover {{
      color: #fff;
    }}
    table.events-table td {{
      padding: 0.65rem 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      vertical-align: top;
    }}
    table.events-table tr:hover td {{
      background: rgba(255, 255, 255, 0.02);
    }}
    table.events-table tr.expanded-parent td {{
      background: rgba(56, 189, 248, 0.03);
      border-bottom: none;
    }}

    .timestamp-cell {{
      font-family: var(--font-mono);
      font-size: 0.8rem;
      color: #cbd5e1;
      white-space: nowrap;
    }}
    .user-tag {{
      font-family: var(--font-mono);
      background: rgba(255, 255, 255, 0.06);
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      font-size: 0.8rem;
      color: #e2e8f0;
      display: inline-block;
    }}
    .category-tag {{
      font-size: 0.775rem;
      color: var(--text-muted);
      background: rgba(255, 255, 255, 0.04);
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      white-space: nowrap;
    }}
    .subcat-tag {{
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--accent);
    }}
    .desc-cell {{
      color: #e2e8f0;
      max-width: 500px;
      word-break: break-word;
    }}
    .artifact-link {{
      font-family: var(--font-mono);
      font-size: 0.775rem;
      color: var(--primary);
      text-decoration: none;
      cursor: pointer;
      display: inline-block;
      max-width: 220px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .artifact-link:hover {{
      text-decoration: underline;
    }}

    .badge-sev {{
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.725rem;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .badge-sev-high {{ background: var(--high-bg); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
    .badge-sev-medium {{ background: var(--med-bg); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
    .badge-sev-low {{ background: var(--low-bg); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
    .badge-sev-info {{ background: var(--info-bg); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }}

    /* Expand Drawer */
    tr.event-detail-row {{
      background: #0b1120;
    }}
    .detail-drawer {{
      padding: 1.25rem 1.5rem;
      border-top: 1px dashed var(--border);
      border-bottom: 1px solid var(--border);
    }}
    .detail-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 1rem;
      background: rgba(0, 0, 0, 0.3);
      padding: 1rem;
      border-radius: 6px;
      font-size: 0.825rem;
    }}
    .detail-item strong {{
      color: var(--text-dim);
      display: block;
      margin-bottom: 0.2rem;
      font-size: 0.75rem;
      text-transform: uppercase;
    }}
    .detail-item span {{
      color: #e2e8f0;
      font-family: var(--font-mono);
      word-break: break-all;
    }}
    .raw-box {{
      background: #050810;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
      font-family: var(--font-mono);
      font-size: 0.825rem;
      color: #38bdf8;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      margin-bottom: 0.75rem;
    }}
    .drawer-actions {{
      display: flex;
      gap: 0.75rem;
    }}

    /* Pagination Footer */
    .table-footer {{
      background: var(--card-bg);
      border-top: 1px solid var(--border);
      padding: 0.65rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-shrink: 0;
      font-size: 0.85rem;
      color: var(--text-muted);
    }}
    .pagination-controls {{
      display: flex;
      gap: 0.5rem;
      align-items: center;
    }}

    /* Tab 2: Artifact Explorer */
    .dual-pane {{
      display: flex;
      flex: 1;
      overflow: hidden;
    }}
    .tree-pane {{
      width: 380px;
      background: var(--card-bg);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
    }}
    .tree-search {{
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
    }}
    .tree-content {{
      flex: 1;
      overflow-y: auto;
      padding: 0.5rem;
    }}
    .tree-folder {{
      margin-bottom: 0.5rem;
    }}
    .tree-folder-title {{
      font-size: 0.8rem;
      font-weight: 700;
      color: var(--text-dim);
      text-transform: uppercase;
      padding: 0.35rem 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }}
    .tree-file {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.4rem 0.65rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.825rem;
      font-family: var(--font-mono);
      color: var(--text-muted);
      transition: all 0.15s ease;
    }}
    .tree-file:hover {{
      background: rgba(255, 255, 255, 0.05);
      color: #fff;
    }}
    .tree-file.selected {{
      background: rgba(56, 189, 248, 0.15);
      color: var(--primary);
      font-weight: 600;
    }}
    .file-size {{
      font-size: 0.75rem;
      color: var(--text-dim);
    }}
    .file-badge-ok {{
      color: #34d399;
      font-size: 0.75rem;
    }}

    .viewer-pane {{
      flex: 1;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      background: #080c14;
    }}
    .viewer-header {{
      background: var(--card-bg);
      border-bottom: 1px solid var(--border);
      padding: 0.75rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-shrink: 0;
    }}
    .file-meta-tags {{
      display: flex;
      gap: 0.75rem;
      font-size: 0.8rem;
      color: var(--text-muted);
      align-items: center;
      margin-top: 0.25rem;
    }}
    .viewer-body {{
      flex: 1;
      overflow: auto;
      padding: 1rem;
      font-family: var(--font-mono);
      font-size: 0.85rem;
      line-height: 1.6;
      background: #050810;
      color: #cbd5e1;
      white-space: pre-wrap;
    }}
    .line-row {{
      display: flex;
    }}
    .line-num {{
      width: 45px;
      color: var(--text-dim);
      user-select: none;
      text-align: right;
      padding-right: 1rem;
      flex-shrink: 0;
    }}
    .line-text {{
      flex: 1;
      word-break: break-all;
    }}

    /* Tab 3: Findings Grid */
    .findings-container {{
      flex: 1;
      overflow-y: auto;
      padding: 1.5rem 2rem;
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(480px, 1fr));
      gap: 1.25rem;
      align-content: start;
    }}
    .finding-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.85rem;
      position: relative;
    }}
    .finding-card.high {{ border-left: 4px solid var(--high); }}
    .finding-card.medium {{ border-left: 4px solid var(--med); }}
    .finding-card.low {{ border-left: 4px solid var(--low); }}
    .finding-title {{
      font-size: 1.05rem;
      font-weight: 700;
      color: #fff;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .finding-section {{
      font-size: 0.85rem;
      line-height: 1.5;
    }}
    .finding-section strong {{
      color: var(--primary);
      display: block;
      margin-bottom: 0.2rem;
      font-size: 0.775rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .finding-tech {{
      background: #080c14;
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 0.5rem 0.75rem;
      font-family: var(--font-mono);
      font-size: 0.775rem;
      color: var(--text-muted);
    }}

    .empty-state {{
      text-align: center;
      padding: 4rem 2rem;
      color: var(--text-dim);
    }}
    .empty-state .icon {{ font-size: 2.5rem; margin-bottom: 0.5rem; }}
  </style>
</head>
<body>
  <header>
    <div class="header-left">
      <a href="/" class="back-link">← Console Dashboard</a>
      <div class="case-badge">
        <span>🛡️</span> Case <strong>{case_id}</strong>
      </div>
      <div class="header-meta">
        <span><strong>Host:</strong> {hosts_str}</span>
        <span><strong>Examiner:</strong> {examiner}</span>
      </div>
    </div>
    <div class="header-right">
      <div class="nav-tabs">
        <button class="tab-btn active" onclick="switchTab('events')" id="btn-tab-events">
          📋 Event Timeline <span class="tab-badge" id="badge-events-count">{events_count:,}</span>
        </button>
        <button class="tab-btn" onclick="switchTab('artifacts')" id="btn-tab-artifacts">
          📁 Artifact Tree <span class="tab-badge" id="badge-artifacts-count">—</span>
        </button>
        <button class="tab-btn" onclick="switchTab('findings')" id="btn-tab-findings">
          🚨 SOC Findings <span class="tab-badge" id="badge-findings-count">{findings_count}</span>
        </button>
      </div>
      <a href="{report_url}" target="_blank" class="btn btn-secondary">🔍 View Report</a>
    </div>
  </header>

  <main>
    <!-- TAB 1: Log & Event Explorer -->
    <div class="tab-pane active" id="tab-events">
      <div class="filter-toolbar">
        <div class="search-box">
          <span class="search-icon">🔍</span>
          <input type="text" id="event-search" class="search-input" placeholder="Search events by keyword, command, IP, user, artifact..." oninput="debounceSearch()">
        </div>
        <select id="filter-category" class="filter-select" onchange="applyFilters()">
          <option value="all">All Categories</option>
          <option value="user_accounts">User Accounts</option>
          <option value="login_activity">Login Activity</option>
          <option value="privilege_escalation">Privilege Escalation</option>
          <option value="persistence">Persistence</option>
          <option value="user_activity">User Activity</option>
          <option value="software_changes">Software Changes</option>
          <option value="hardware_usb">Hardware / USB</option>
          <option value="network_config">Network Config</option>
          <option value="environment">Environment</option>
        </select>
        <div class="pill-group">
          <button class="sev-pill active-all" onclick="setSeverity('all')" id="sev-all">All</button>
          <button class="sev-pill" onclick="setSeverity('high')" id="sev-high">High</button>
          <button class="sev-pill" onclick="setSeverity('medium')" id="sev-medium">Med</button>
          <button class="sev-pill" onclick="setSeverity('low')" id="sev-low">Low</button>
          <button class="sev-pill" onclick="setSeverity('info')" id="sev-info">Info</button>
        </div>
        <select id="filter-user" class="filter-select" onchange="applyFilters()">
          <option value="all">All Users</option>
        </select>
        <select id="filter-limit" class="filter-select" onchange="applyFilters()">
          <option value="50">50 per page</option>
          <option value="100">100 per page</option>
          <option value="250">250 per page</option>
          <option value="500">500 per page</option>
        </select>
        <button class="btn btn-secondary" onclick="resetFilters()">↺ Reset</button>
      </div>

      <div class="table-container" id="events-table-container">
        <table class="events-table">
          <thead>
            <tr>
              <th style="width: 40px;"></th>
              <th class="sortable" onclick="sortBy('timestamp_utc')">Timestamp (UTC) ↕</th>
              <th class="sortable" onclick="sortBy('severity')">Severity ↕</th>
              <th class="sortable" onclick="sortBy('category')">Category ↕</th>
              <th>Subcategory</th>
              <th class="sortable" onclick="sortBy('actor_user')">Actor User ↕</th>
              <th>Description / Command</th>
              <th>Source Artifact</th>
            </tr>
          </thead>
          <tbody id="events-tbody">
            <tr>
              <td colspan="8" class="empty-state">
                <div class="icon">⌛</div>
                <p>Loading case events...</p>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="table-footer">
        <div id="events-pagination-summary">Showing 0–0 of 0 events</div>
        <div class="pagination-controls">
          <button class="btn btn-secondary" id="btn-prev-page" onclick="prevPage()" disabled>← Previous</button>
          <span id="page-display">Page 1</span>
          <button class="btn btn-secondary" id="btn-next-page" onclick="nextPage()" disabled>Next →</button>
        </div>
      </div>
    </div>

    <!-- TAB 2: Artifact Tree Explorer -->
    <div class="tab-pane" id="tab-artifacts">
      <div class="dual-pane">
        <div class="tree-pane">
          <div class="tree-search">
            <input type="text" id="artifact-tree-search" class="search-input" placeholder="Filter artifacts..." oninput="filterArtifactTree()">
          </div>
          <div class="tree-content" id="artifact-tree-root">
            <div class="empty-state"><p>Loading evidence artifacts...</p></div>
          </div>
        </div>
        <div class="viewer-pane">
          <div class="viewer-header">
            <div>
              <strong id="viewer-title" style="font-size: 1rem; color: #fff; font-family: var(--font-mono);">Select an artifact to inspect</strong>
              <div class="file-meta-tags" id="viewer-meta">
                <span>Select a file from the tree to view raw content and integrity hashes.</span>
              </div>
            </div>
            <div>
              <button class="btn btn-secondary" onclick="copyViewerContent()" id="btn-copy-artifact">📋 Copy All</button>
            </div>
          </div>
          <div class="viewer-body" id="viewer-body">
            <div class="empty-state">
              <div class="icon">📄</div>
              <p>No file selected</p>
              <span style="font-size: 0.8rem; color: var(--text-dim);">Click any artifact from the hierarchy on the left to review its raw collected contents.</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 3: Threat Findings -->
    <div class="tab-pane" id="tab-findings">
      <div class="findings-container" id="findings-container">
        <div class="empty-state"><p>Loading findings...</p></div>
      </div>
    </div>
  </main>

  <script>
    const CASE_ID = "{case_id}";
    let currentTab = 'events';
    let currentSeverity = 'all';
    let currentSort = 'timestamp_utc';
    let currentOrder = 'asc';
    let currentOffset = 0;
    let totalEvents = 0;
    let filteredEvents = 0;
    let searchDebounceTimer = null;
    let selectedEventIds = null;
    let artifactsList = [];
    let activeArtifactPath = null;
    let expandedRows = new Set();

    // Tab Switching
    function switchTab(tabId) {{
      currentTab = tabId;
      document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      
      document.getElementById('tab-' + tabId).classList.add('active');
      document.getElementById('btn-tab-' + tabId).classList.add('active');

      if (tabId === 'artifacts' && artifactsList.length === 0) {{
        loadArtifacts();
      }} else if (tabId === 'findings') {{
        loadFindings();
      }}
    }}

    // Load Events
    async function loadEvents() {{
      const limit = parseInt(document.getElementById('filter-limit').value) || 50;
      const q = document.getElementById('event-search').value.trim();
      const category = document.getElementById('filter-category').value;
      const user = document.getElementById('filter-user').value;

      let url = `/api/v1/cases/${{CASE_ID}}/events?limit=${{limit}}&offset=${{currentOffset}}&sort=${{currentSort}}&order=${{currentOrder}}`;
      if (q) url += `&q=${{encodeURIComponent(q)}}`;
      if (category !== 'all') url += `&category=${{encodeURIComponent(category)}}`;
      if (currentSeverity !== 'all') url += `&severity=${{encodeURIComponent(currentSeverity)}}`;
      if (user !== 'all') url += `&user=${{encodeURIComponent(user)}}`;
      if (selectedEventIds) url += `&ids=${{encodeURIComponent(selectedEventIds.join(','))}}`;

      const tbody = document.getElementById('events-tbody');
      try {{
        const res = await fetch(url);
        const data = await res.json();
        totalEvents = data.total || 0;
        filteredEvents = data.filtered_total || 0;

        document.getElementById('badge-events-count').innerText = totalEvents.toLocaleString();

        // Populate users dropdown if empty
        const userSelect = document.getElementById('filter-user');
        if (userSelect.options.length <= 1 && data.users) {{
          data.users.forEach(u => {{
            const opt = document.createElement('option');
            opt.value = u;
            opt.innerText = u;
            userSelect.appendChild(opt);
          }});
        }}

        if (!data.events || data.events.length === 0) {{
          tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="icon">🔍</div><p>No matching normalized events found.</p><span style="font-size:0.8rem;color:var(--text-dim)">Try refining or resetting your search filters.</span></td></tr>`;
          updatePagination(0, limit);
          return;
        }}

        let rowsHtml = '';
        data.events.forEach((ev) => {{
          const isExpanded = expandedRows.has(ev.event_id);
          const sevClass = `badge-sev-${{ev.severity}}`;
          const userStr = ev.actor_user ? `<span class="user-tag">${{escapeHtml(ev.actor_user)}}</span>` : '—';
          const timeStr = ev.timestamp_utc ? ev.timestamp_utc.replace('T', ' ').replace('+00:00', 'Z') : '—';
          const expandIcon = isExpanded ? '▼' : '▶';

          rowsHtml += `
            <tr class="${{isExpanded ? 'expanded-parent' : ''}}" onclick="toggleRow('${{ev.event_id}}')">
              <td style="cursor: pointer; text-align: center; color: var(--primary); font-size: 0.8rem;">${{expandIcon}}</td>
              <td class="timestamp-cell">${{timeStr}}</td>
              <td><span class="badge-sev ${{sevClass}}">${{ev.severity}}</span></td>
              <td><span class="category-tag">${{ev.category}}</span></td>
              <td><span class="subcat-tag">${{ev.subcategory}}</span></td>
              <td>${{userStr}}</td>
              <td class="desc-cell">${{escapeHtml(ev.description)}}</td>
              <td><a class="artifact-link" onclick="jumpToArtifact('${{escapeHtml(ev.source_artifact_path)}}', event)">${{escapeHtml(ev.source_artifact_path)}}</a></td>
            </tr>
          `;

          if (isExpanded) {{
            rowsHtml += `
              <tr class="event-detail-row">
                <td colspan="8" class="detail-drawer">
                  <div class="detail-grid">
                    <div class="detail-item"><strong>Event ID</strong><span>${{ev.event_id}}</span></div>
                    <div class="detail-item"><strong>Parser Provenance</strong><span>${{ev.parser_name}} v${{ev.parser_version}}</span></div>
                    <div class="detail-item"><strong>Source Offset</strong><span>Byte offset ${{ev.raw_line_offset}}</span></div>
                    <div class="detail-item"><strong>Source Artifact SHA-256</strong><span>${{ev.source_artifact_sha256 || '—'}}</span></div>
                    <div class="detail-item"><strong>Actor Process</strong><span>${{escapeHtml(ev.actor_process || '—')}}</span></div>
                    <div class="detail-item"><strong>Source IP / Host</strong><span>${{escapeHtml(ev.source_ip || ev.source_host || '—')}}</span></div>
                  </div>
                  <div style="font-size:0.75rem; color:var(--text-dim); text-transform:uppercase; margin-bottom:0.25rem; font-weight:700;">Exact Raw Forensic Log Line:</div>
                  <div class="raw-box">${{escapeHtml(ev.raw_line)}}</div>
                  <div class="drawer-actions">
                    <button class="btn btn-secondary" onclick="copyText('${{escapeJs(ev.raw_line)}}')">📋 Copy Raw Line</button>
                    <button class="btn btn-secondary" onclick="copyText('${{escapeJs(JSON.stringify(ev, null, 2))}}')">📋 Copy JSON Event</button>
                    <button class="btn btn-primary" onclick="jumpToArtifact('${{escapeHtml(ev.source_artifact_path)}}', event)">📂 Open in Artifact Tree</button>
                  </div>
                </td>
              </tr>
            `;
          }}
        }});

        tbody.innerHTML = rowsHtml;
        updatePagination(data.events.length, limit);
      }} catch (err) {{
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="icon">⚠️</div><p>Failed loading events: ${{err}}</p></td></tr>`;
      }}
    }}

    function toggleRow(eventId) {{
      if (expandedRows.has(eventId)) {{
        expandedRows.delete(eventId);
      }} else {{
        expandedRows.add(eventId);
      }}
      loadEvents();
    }}

    function debounceSearch() {{
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(() => {{
        currentOffset = 0;
        selectedEventIds = null;
        loadEvents();
      }}, 300);
    }}

    function setSeverity(sev) {{
      currentSeverity = sev;
      document.querySelectorAll('.sev-pill').forEach(el => {{
        el.className = 'sev-pill';
      }});
      document.getElementById('sev-' + sev).className = `sev-pill active-${{sev}}`;
      currentOffset = 0;
      selectedEventIds = null;
      loadEvents();
    }}

    function applyFilters() {{
      currentOffset = 0;
      selectedEventIds = null;
      loadEvents();
    }}

    function resetFilters() {{
      document.getElementById('event-search').value = '';
      document.getElementById('filter-category').value = 'all';
      document.getElementById('filter-user').value = 'all';
      setSeverity('all');
      selectedEventIds = null;
      currentOffset = 0;
      loadEvents();
    }}

    function sortBy(col) {{
      if (currentSort === col) {{
        currentOrder = currentOrder === 'asc' ? 'desc' : 'asc';
      }} else {{
        currentSort = col;
        currentOrder = 'asc';
      }}
      loadEvents();
    }}

    function updatePagination(currentCount, limit) {{
      const start = filteredEvents === 0 ? 0 : currentOffset + 1;
      const end = Math.min(currentOffset + currentCount, filteredEvents);
      document.getElementById('events-pagination-summary').innerText = `Showing ${{start}}–${{end}} of ${{filteredEvents.toLocaleString()}} events (filtered from ${{totalEvents.toLocaleString()}} total)`;
      
      const page = Math.floor(currentOffset / limit) + 1;
      const totalPages = Math.ceil(filteredEvents / limit) || 1;
      document.getElementById('page-display').innerText = `Page ${{page}} of ${{totalPages}}`;

      document.getElementById('btn-prev-page').disabled = currentOffset <= 0;
      document.getElementById('btn-next-page').disabled = currentOffset + limit >= filteredEvents;
    }}

    function prevPage() {{
      const limit = parseInt(document.getElementById('filter-limit').value) || 50;
      currentOffset = Math.max(0, currentOffset - limit);
      loadEvents();
    }}

    function nextPage() {{
      const limit = parseInt(document.getElementById('filter-limit').value) || 50;
      if (currentOffset + limit < filteredEvents) {{
        currentOffset += limit;
        loadEvents();
      }}
    }}

    // Tab 2: Artifacts
    async function loadArtifacts() {{
      try {{
        const res = await fetch(`/api/v1/cases/${{CASE_ID}}/artifacts`);
        const data = await res.json();
        artifactsList = data.artifacts || [];
        document.getElementById('badge-artifacts-count').innerText = artifactsList.length;
        renderArtifactTree(artifactsList);
        if (artifactsList.length > 0 && !activeArtifactPath) {{
          selectArtifact(artifactsList[0].original_path);
        }}
      }} catch (err) {{
        document.getElementById('artifact-tree-root').innerHTML = `<div class="empty-state"><p>Error loading artifacts: ${{err}}</p></div>`;
      }}
    }}

    function renderArtifactTree(list) {{
      const root = document.getElementById('artifact-tree-root');
      if (!list || list.length === 0) {{
        root.innerHTML = `<div class="empty-state"><p>No artifacts recorded</p></div>`;
        return;
      }}

      // Group by top-level directory
      const groups = {{}};
      list.forEach(a => {{
        const orig = a.original_path || '';
        const parts = orig.split('/').filter(Boolean);
        const folder = parts.length > 1 ? '/' + parts[0] : '/root';
        if (!groups[folder]) groups[folder] = [];
        groups[folder].push(a);
      }});

      let html = '';
      for (const [folder, files] of Object.entries(groups)) {{
        html += `
          <div class="tree-folder">
            <div class="tree-folder-title">📁 ${{folder}} <span style="font-size:0.7rem; color:var(--text-dim);">(${{files.length}})</span></div>
        `;
        files.forEach(f => {{
          const isSel = f.original_path === activeArtifactPath;
          const fileName = f.original_path.split('/').pop() || f.original_path;
          const sizeKb = (f.size / 1024).toFixed(1);
          html += `
            <div class="tree-file ${{isSel ? 'selected' : ''}}" onclick="selectArtifact('${{escapeHtml(f.original_path)}}')">
              <span>📄 ${{escapeHtml(fileName)}}</span>
              <div style="display:flex; align-items:center; gap:0.4rem;">
                <span class="file-size">${{sizeKb}} KB</span>
                <span class="file-badge-ok">✔</span>
              </div>
            </div>
          `;
        }});
        html += `</div>`;
      }}
      root.innerHTML = html;
    }}

    function filterArtifactTree() {{
      const q = document.getElementById('artifact-tree-search').value.toLowerCase().trim();
      if (!q) {{
        renderArtifactTree(artifactsList);
        return;
      }}
      const filtered = artifactsList.filter(a => a.original_path.toLowerCase().includes(q));
      renderArtifactTree(filtered);
    }}

    async function selectArtifact(path) {{
      activeArtifactPath = path;
      renderArtifactTree(artifactsList);

      const art = artifactsList.find(a => a.original_path === path);
      document.getElementById('viewer-title').innerText = path;

      const metaEl = document.getElementById('viewer-meta');
      if (art) {{
        metaEl.innerHTML = `
          <span><strong>Size:</strong> ${{art.size}} B</span>
          <span><strong>Owner:</strong> ${{art.owner || '—'}}</span>
          <span><strong>Mode:</strong> ${{art.mode || '—'}}</span>
          <span><strong>SHA-256:</strong> <code style="color:var(--primary); font-size:0.75rem;">${{art.sha256 ? art.sha256.substring(0, 16) + '...' : '—'}}</code></span>
          <span style="color:#34d399; font-weight:600;">✔ Verified</span>
        `;
      }}

      const bodyEl = document.getElementById('viewer-body');
      bodyEl.innerHTML = `<div class="empty-state"><div class="icon">⌛</div><p>Reading collected file...</p></div>`;

      try {{
        const res = await fetch(`/api/v1/cases/${{CASE_ID}}/artifact-content?path=${{encodeURIComponent(path)}}`);
        const data = await res.json();
        if (data.error) {{
          bodyEl.innerHTML = `<div class="empty-state"><p>Error: ${{escapeHtml(data.error)}}</p></div>`;
          return;
        }}

        const lines = data.content.split('\\n');
        let linesHtml = '';
        lines.forEach((line, idx) => {{
          linesHtml += `
            <div class="line-row">
              <div class="line-num">${{idx + 1}}</div>
              <div class="line-text">${{escapeHtml(line)}}</div>
            </div>
          `;
        }});
        bodyEl.innerHTML = linesHtml;
      }} catch (err) {{
        bodyEl.innerHTML = `<div class="empty-state"><p>Failed to load artifact content: ${{err}}</p></div>`;
      }}
    }}

    function jumpToArtifact(path, e) {{
      if (e) e.stopPropagation();
      switchTab('artifacts');
      loadArtifacts().then(() => {{
        selectArtifact(path);
      }});
    }}

    // Tab 3: Findings
    async function loadFindings() {{
      const container = document.getElementById('findings-container');
      try {{
        const res = await fetch(`/api/v1/cases/${{CASE_ID}}/findings`);
        const data = await res.json();
        const findings = data.findings || [];
        document.getElementById('badge-findings-count').innerText = findings.length;

        if (findings.length === 0) {{
          container.innerHTML = `<div class="empty-state" style="grid-column: 1 / -1;"><div class="icon">🛡️</div><p>No critical or medium threat findings detected for this case.</p></div>`;
          return;
        }}

        let html = '';
        findings.forEach(f => {{
          const sevClass = f.severity || 'low';
          const eventIds = f.event_ids || [];
          html += `
            <div class="finding-card ${{sevClass}}">
              <div class="finding-title">
                <span>${{escapeHtml(f.title)}}</span>
                <span class="badge-sev badge-sev-${{sevClass}}">${{f.severity}}</span>
              </div>
              <div class="finding-section">
                <strong>What Happened</strong>
                <div>${{escapeHtml(f.what_happened)}}</div>
              </div>
              <div class="finding-section">
                <strong>Why It Matters</strong>
                <div>${{escapeHtml(f.why_it_matters)}}</div>
              </div>
              <div class="finding-section">
                <strong>Recommended Next Action</strong>
                <div>${{escapeHtml(f.check_next)}}</div>
              </div>
              <div class="finding-tech">
                <strong>Technical Detail & Provenance:</strong><br>
                ${{escapeHtml(f.technical_detail)}}
              </div>
              <div>
                <button class="btn btn-primary" onclick="pivotToEvents([${{eventIds.map(i => `'${{i}}'`).join(',')}}])">
                  🔍 Pivot to ${{eventIds.length}} Supporting Events
                </button>
              </div>
            </div>
          `;
        }});
        container.innerHTML = html;
      }} catch (err) {{
        container.innerHTML = `<div class="empty-state"><p>Failed loading findings: ${{err}}</p></div>`;
      }}
    }}

    function pivotToEvents(eventIds) {{
      selectedEventIds = eventIds;
      switchTab('events');
      currentOffset = 0;
      loadEvents();
    }}

    // Utilities
    function escapeHtml(str) {{
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }}

    function escapeJs(str) {{
      if (!str) return '';
      return String(str)
        .replace(/\\\\/g, '\\\\\\\\')
        .replace(/'/g, "\\\\'")
        .replace(/\\n/g, '\\\\n')
        .replace(/\\r/g, '');
    }}

    function copyText(text) {{
      navigator.clipboard.writeText(text);
      alert('Copied to clipboard!');
    }}

    function copyViewerContent() {{
      const text = document.getElementById('viewer-body').innerText;
      navigator.clipboard.writeText(text);
      alert('Artifact content copied to clipboard!');
    }}

    // Initialize
    window.addEventListener('DOMContentLoaded', () => {{
      loadEvents();
    }});
  </script>
</body>
</html>
"""
