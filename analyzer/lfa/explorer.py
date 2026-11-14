"""Interactive Forensic Log & Artifact Explorer UI generator for LFA (CrowdStrike / Timesketch / Velociraptor style).

Generates a self-contained, responsive, zero-CDN single-page forensic investigation workspace.
Provides:
  1. High-Density Event & Timeline Studio with dynamic SVG activity histogram scrubber, full-text search, and multi-faceted filtering.
  2. Slide-Out Master-Detail Inspector Drawer with 1-click forensic pivots, raw provenance, syntax-highlighted JSON, and correlated threats.
  3. Hierarchical Evidence & Artifact Explorer with line-numbered viewer, cryptographic verification stamps, and dual-mode Hex/ASCII dump.
  4. Correlated Threat Detections & MITRE ATT&CK Matrix with 1-click event pivots.
  5. Keyboard ergonomics (j/k navigation, / search focus, Esc dismiss) and micro-interactions (radar pulse, toast notifications).
"""
from __future__ import annotations

import html
import json
from typing import Any

from . import __version__


def render_explorer_html(case_id: str, case_info: dict[str, Any]) -> str:
    """Render the single-page interactive investigation explorer."""
    case_id_raw = str(case_id)
    case_id_js = json.dumps(case_id_raw).replace("<", "\\u003c").replace(">", "\\u003e")
    case_id = html.escape(case_id_raw, quote=True)
    examiner = html.escape(
        str(case_info.get("examiner", "Forensic Investigator")), quote=True
    )
    hosts_str = html.escape(
        ", ".join(str(h) for h in case_info.get("hosts", []))
        if case_info.get("hosts")
        else "—",
        quote=True,
    )
    events_count = case_info.get("events_count", 0)
    findings_count = case_info.get("findings_count", 0)
    high_findings = case_info.get("high_findings", 0)
    report_url = html.escape(
        str(case_info.get("report_url", f"/cases/{case_id}/report.html")), quote=True
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LFA Explorer — Case {case_id}</title>
  <style>
    :root {{
      /* Cosmic Slate Palette */
      --bg-base: #070a0f;
      --bg-panel: #0c1017;
      --bg-card: #121824;
      --bg-card-hover: #192233;
      --bg-active: #1e293b;
      --bg-subtle: rgba(255, 255, 255, 0.03);

      /* Hairline Borders */
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-medium: rgba(255, 255, 255, 0.16);
      --border-focus: #38bdf8;

      /* High-Precision Typography */
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --text-bright: #ffffff;

      /* Forensic Telemetry & Accents */
      --accent-cyan: #38bdf8;
      --accent-blue: #3b82f6;
      --accent-violet: #a855f7;

      /* Strict Threat Semantics */
      --sev-high: #ff4d6d;
      --sev-high-bg: rgba(255, 77, 109, 0.14);
      --sev-high-border: rgba(255, 77, 109, 0.4);
      --sev-med: #f59e0b;
      --sev-med-bg: rgba(245, 158, 11, 0.14);
      --sev-med-border: rgba(245, 158, 11, 0.4);
      --sev-low: #10b981;
      --sev-low-bg: rgba(16, 185, 129, 0.14);
      --sev-low-border: rgba(16, 185, 129, 0.4);
      --sev-info: #0ea5e9;
      --sev-info-bg: rgba(14, 165, 233, 0.14);
      --sev-info-border: rgba(14, 165, 233, 0.4);

      /* Fonts */
      --font-sans: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
      --font-mono: ui-monospace, "Cascadia Code", "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;

      /* Elevation & Shadows */
      --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.4);
      --shadow-md: 0 4px 14px rgba(0, 0, 0, 0.5);
      --shadow-drawer: -12px 0 40px rgba(0, 0, 0, 0.7);
      --shadow-toast: 0 12px 28px rgba(0, 0, 0, 0.6);
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    /* Custom Modern Scrollbars */
    ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
    ::-webkit-scrollbar-track {{ background: var(--bg-base); }}
    ::-webkit-scrollbar-thumb {{
      background: rgba(255, 255, 255, 0.12);
      border-radius: 4px;
      border: 2px solid var(--bg-base);
    }}
    ::-webkit-scrollbar-thumb:hover {{ background: rgba(255, 255, 255, 0.22); }}

    body {{
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: var(--font-sans);
      line-height: 1.5;
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
      -webkit-font-smoothing: antialiased;
      user-select: none;
    }}

    /* ======================================================== */
    /* 1. TOP HEADER HUD                                        */
    /* ======================================================== */
    header.studio-header {{
      background: var(--bg-panel);
      border-bottom: 1px solid var(--border-subtle);
      padding: 0 1.5rem;
      height: 56px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-shrink: 0;
      z-index: 30;
    }}

    .header-left {{
      display: flex;
      align-items: center;
      gap: 1.25rem;
    }}

    .brand-group {{
      display: flex;
      align-items: center;
      gap: 0.6rem;
      text-decoration: none;
      color: inherit;
    }}
    .brand-logo {{
      font-weight: 800;
      font-size: 1rem;
      letter-spacing: -0.03em;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }}
    .brand-logo span {{
      color: var(--accent-cyan);
    }}

    /* Radar Pulse Indicator */
    .radar-indicator {{
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      background: rgba(16, 185, 129, 0.08);
      border: 1px solid rgba(16, 185, 129, 0.25);
      padding: 0.15rem 0.55rem;
      border-radius: 9999px;
      font-size: 0.7rem;
      font-weight: 600;
      color: #34d399;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }}
    .pulse-dot {{
      width: 6px;
      height: 6px;
      background: #10b981;
      border-radius: 50%;
      position: relative;
    }}
    .pulse-dot::after {{
      content: '';
      position: absolute;
      top: -3px;
      left: -3px;
      right: -3px;
      bottom: -3px;
      border-radius: 50%;
      border: 1.5px solid #10b981;
      animation: pulse-ring 2s cubic-bezier(0.215, 0.61, 0.355, 1) infinite;
    }}
    @keyframes pulse-ring {{
      0% {{ transform: scale(0.6); opacity: 0.9; }}
      100% {{ transform: scale(2.4); opacity: 0; }}
    }}

    .case-chip {{
      font-family: var(--font-mono);
      font-size: 0.8rem;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border-subtle);
      padding: 0.25rem 0.65rem;
      border-radius: 6px;
      color: var(--text-bright);
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.15s ease;
    }}
    .case-chip:hover {{
      border-color: var(--accent-cyan);
      background: rgba(56, 189, 248, 0.06);
    }}

    .header-nav {{
      display: flex;
      align-items: center;
      gap: 0.35rem;
      background: rgba(0, 0, 0, 0.35);
      padding: 0.25rem;
      border-radius: 8px;
      border: 1px solid var(--border-subtle);
    }}
    .nav-btn {{
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 0.35rem 0.9rem;
      font-size: 0.8rem;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 0.45rem;
      transition: all 0.15s ease;
    }}
    .nav-btn:hover {{
      color: var(--text-bright);
      background: rgba(255, 255, 255, 0.05);
    }}
    .nav-btn.active {{
      background: var(--bg-card);
      color: var(--accent-cyan);
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.5);
    }}
    .nav-badge {{
      font-size: 0.7rem;
      padding: 0.1rem 0.45rem;
      border-radius: 9999px;
      background: rgba(255, 255, 255, 0.08);
      color: inherit;
    }}
    .nav-btn.active .nav-badge {{
      background: rgba(56, 189, 248, 0.18);
      color: var(--accent-cyan);
    }}
    .nav-badge.danger {{
      background: var(--sev-high-bg);
      color: var(--sev-high);
      border: 1px solid var(--sev-high-border);
    }}

    .header-actions {{
      display: flex;
      align-items: center;
      gap: 0.65rem;
    }}

    .btn {{
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.4rem 0.85rem;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 600;
      text-decoration: none;
      border: 1px solid transparent;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .btn-secondary {{
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-main);
      border-color: var(--border-subtle);
    }}
    .btn-secondary:hover {{
      background: rgba(255, 255, 255, 0.09);
      border-color: var(--border-medium);
      color: #fff;
    }}
    .btn-primary {{
      background: var(--accent-blue);
      color: #fff;
    }}
    .btn-primary:hover {{
      background: #2563eb;
      box-shadow: 0 0 12px rgba(59, 130, 246, 0.45);
    }}
    .btn-hotkey {{
      padding: 0.35rem 0.6rem;
      color: var(--text-dim);
      font-family: var(--font-mono);
      font-size: 0.75rem;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-subtle);
      border-radius: 5px;
      cursor: pointer;
    }}
    .btn-hotkey:hover {{
      color: var(--text-main);
      border-color: var(--border-medium);
    }}

    /* ======================================================== */
    /* 2. MAIN WORKSPACE PANES                                  */
    /* ======================================================== */
    main.studio-workspace {{
      flex: 1;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      position: relative;
    }}

    .view-pane {{
      display: none;
      flex: 1;
      flex-direction: column;
      overflow: hidden;
      height: 100%;
    }}
    .view-pane.active {{
      display: flex;
    }}

    /* ======================================================== */
    /* 3. TIMELINE & EVENT EXPLORER VIEW                        */
    /* ======================================================== */

    /* Activity Histogram Bar */
    .histogram-bar-wrap {{
      background: var(--bg-panel);
      border-bottom: 1px solid var(--border-subtle);
      padding: 0.4rem 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
      flex-shrink: 0;
    }}
    .histogram-meta {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.7rem;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 600;
    }}
    .histogram-svg-container {{
      width: 100%;
      height: 38px;
    }}
    .histogram-svg-container svg {{
      width: 100%;
      height: 100%;
      overflow: visible;
    }}
    .hist-rect {{
      fill: rgba(56, 189, 248, 0.3);
      transition: fill 0.15s, height 0.2s;
      cursor: pointer;
    }}
    .hist-rect:hover {{
      fill: #38bdf8;
    }}
    .hist-rect.has-threat {{
      fill: rgba(255, 77, 109, 0.5);
    }}
    .hist-rect.has-threat:hover {{
      fill: #ff4d6d;
    }}

    /* Command / Filter Toolbar */
    .command-toolbar {{
      background: var(--bg-panel);
      border-bottom: 1px solid var(--border-subtle);
      padding: 0.65rem 1.5rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      align-items: center;
      flex-shrink: 0;
      z-index: 10;
    }}
    .search-wrapper {{
      flex: 1;
      min-width: 260px;
      position: relative;
    }}
    .search-input {{
      width: 100%;
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      color: var(--text-main);
      font-size: 0.825rem;
      border-radius: 6px;
      padding: 0.45rem 1.75rem 0.45rem 2.2rem;
      outline: none;
      transition: all 0.15s ease;
    }}
    .search-input:focus {{
      border-color: var(--accent-cyan);
      box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.18);
    }}
    .search-icon {{
      position: absolute;
      left: 0.75rem;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-dim);
      font-size: 0.85rem;
      pointer-events: none;
    }}
    .search-kbd {{
      position: absolute;
      right: 0.6rem;
      top: 50%;
      transform: translateY(-50%);
      font-family: var(--font-mono);
      font-size: 0.65rem;
      color: var(--text-dim);
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-subtle);
      padding: 0.1rem 0.35rem;
      border-radius: 4px;
      pointer-events: none;
    }}

    .filter-select {{
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      color: var(--text-main);
      font-size: 0.8rem;
      border-radius: 6px;
      padding: 0.45rem 0.75rem;
      outline: none;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .filter-select:focus {{
      border-color: var(--accent-cyan);
    }}

    .pill-group {{
      display: flex;
      gap: 0.25rem;
      background: rgba(0, 0, 0, 0.3);
      padding: 0.2rem;
      border-radius: 6px;
      border: 1px solid var(--border-subtle);
    }}
    .filter-pill {{
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 0.25rem 0.65rem;
      font-size: 0.75rem;
      font-weight: 600;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .filter-pill:hover {{
      color: #fff;
      background: rgba(255, 255, 255, 0.05);
    }}
    .filter-pill.active-all {{ background: rgba(255, 255, 255, 0.1); color: #fff; }}
    .filter-pill.active-high {{ background: var(--sev-high-bg); color: var(--sev-high); border: 1px solid var(--sev-high-border); }}
    .filter-pill.active-medium {{ background: var(--sev-med-bg); color: var(--sev-med); border: 1px solid var(--sev-med-border); }}
    .filter-pill.active-low {{ background: var(--sev-low-bg); color: var(--sev-low); border: 1px solid var(--sev-low-border); }}
    .filter-pill.active-info {{ background: var(--sev-info-bg); color: var(--sev-info); border: 1px solid var(--sev-info-border); }}

    /* Table Container & High-Density Grid */
    .events-workspace {{
      flex: 1;
      display: flex;
      position: relative;
      overflow: hidden;
    }}

    .table-scroll-container {{
      flex: 1;
      overflow: auto;
      background: var(--bg-base);
    }}

    table.events-table {{
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      text-align: left;
      font-size: 0.8rem;
    }}

    table.events-table th {{
      position: sticky;
      top: 0;
      background: rgba(12, 16, 23, 0.94);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      color: var(--text-dim);
      font-weight: 700;
      padding: 0.65rem 1rem;
      border-bottom: 1px solid var(--border-medium);
      z-index: 10;
      white-space: nowrap;
      text-transform: uppercase;
      font-size: 0.7rem;
      letter-spacing: 0.06em;
    }}
    table.events-table th.sortable {{
      cursor: pointer;
      transition: color 0.15s;
    }}
    table.events-table th.sortable:hover {{
      color: var(--text-main);
    }}
    table.events-table th.sorted {{
      color: var(--accent-cyan);
    }}

    table.events-table td {{
      padding: 0.55rem 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.03);
      vertical-align: middle;
      user-select: text;
      transition: background 0.1s ease;
    }}
    table.events-table tbody tr {{
      cursor: pointer;
      transition: background 0.12s ease;
    }}
    table.events-table tbody tr:hover td {{
      background: rgba(255, 255, 255, 0.025);
    }}
    table.events-table tbody tr.selected-row td {{
      background: rgba(56, 189, 248, 0.08) !important;
    }}
    table.events-table tbody tr.selected-row td:first-child {{
      box-shadow: inset 3px 0 0 var(--accent-cyan);
    }}

    .cell-time {{
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--text-muted);
      white-space: nowrap;
      font-variant-numeric: tabular-nums;
    }}
    .badge-sev {{
      font-size: 0.68rem;
      font-weight: 700;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      display: inline-block;
      white-space: nowrap;
    }}
    .badge-sev.high {{ background: var(--sev-high-bg); color: var(--sev-high); border: 1px solid var(--sev-high-border); }}
    .badge-sev.medium {{ background: var(--sev-med-bg); color: var(--sev-med); border: 1px solid var(--sev-med-border); }}
    .badge-sev.low {{ background: var(--sev-low-bg); color: var(--sev-low); border: 1px solid var(--sev-low-border); }}
    .badge-sev.info {{ background: var(--sev-info-bg); color: var(--sev-info); border: 1px solid var(--sev-info-border); }}

    .cell-user {{
      font-family: var(--font-mono);
      font-size: 0.75rem;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border-subtle);
      padding: 0.1rem 0.45rem;
      border-radius: 4px;
      color: var(--text-main);
      display: inline-block;
    }}
    .cell-cat {{
      font-size: 0.72rem;
      color: var(--text-muted);
      background: rgba(255, 255, 255, 0.03);
      padding: 0.1rem 0.45rem;
      border-radius: 4px;
      text-transform: capitalize;
    }}
    .cell-subcat {{
      font-family: var(--font-mono);
      font-size: 0.72rem;
      color: var(--accent-cyan);
    }}
    .cell-desc {{
      color: var(--text-bright);
      font-weight: 500;
      max-width: 480px;
      word-break: break-word;
    }}
    .cell-artifact {{
      font-family: var(--font-mono);
      font-size: 0.72rem;
      color: var(--text-dim);
      white-space: nowrap;
      max-width: 200px;
      overflow: hidden;
      text-overflow: ellipsis;
    }}

    /* Pagination Bar */
    .table-footer {{
      background: var(--bg-panel);
      border-top: 1px solid var(--border-subtle);
      padding: 0.5rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-shrink: 0;
      font-size: 0.75rem;
      color: var(--text-dim);
    }}
    .pagination-actions {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}

    /* ======================================================== */
    /* 4. SLIDE-OUT MASTER-DETAIL INSPECTOR DRAWER              */
    /* ======================================================== */
    .inspector-drawer {{
      position: absolute;
      top: 0;
      right: 0;
      bottom: 0;
      width: 500px;
      background: #0b0f17;
      border-left: 1px solid var(--border-medium);
      box-shadow: var(--shadow-drawer);
      z-index: 40;
      display: flex;
      flex-direction: column;
      transform: translateX(100%);
      transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1);
    }}
    .inspector-drawer.open {{
      transform: translateX(0);
    }}

    .drawer-header {{
      padding: 0.9rem 1.25rem;
      background: var(--bg-card);
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-shrink: 0;
    }}
    .drawer-title {{
      font-size: 0.85rem;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .drawer-close-btn {{
      background: transparent;
      border: none;
      color: var(--text-dim);
      font-size: 1.2rem;
      cursor: pointer;
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      line-height: 1;
      transition: all 0.15s ease;
    }}
    .drawer-close-btn:hover {{
      color: #fff;
      background: rgba(255, 255, 255, 0.08);
    }}

    .drawer-nav-tabs {{
      display: flex;
      background: rgba(0, 0, 0, 0.3);
      border-bottom: 1px solid var(--border-subtle);
      flex-shrink: 0;
    }}
    .drawer-tab {{
      flex: 1;
      text-align: center;
      padding: 0.5rem;
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--text-dim);
      background: transparent;
      border: none;
      cursor: pointer;
      transition: all 0.15s ease;
      border-bottom: 2px solid transparent;
    }}
    .drawer-tab:hover {{
      color: var(--text-main);
    }}
    .drawer-tab.active {{
      color: var(--accent-cyan);
      border-bottom-color: var(--accent-cyan);
      background: rgba(255, 255, 255, 0.02);
    }}

    .drawer-body {{
      flex: 1;
      overflow-y: auto;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
      user-select: text;
    }}

    .prop-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.775rem;
    }}
    .prop-table tr {{
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }}
    .prop-table td {{
      padding: 0.45rem 0.2rem;
    }}
    .prop-label {{
      width: 38%;
      color: var(--text-dim);
      font-weight: 600;
    }}
    .prop-value {{
      color: var(--text-main);
      font-family: var(--font-mono);
      word-break: break-all;
    }}
    .prop-actions {{
      margin-left: 0.4rem;
      display: inline-flex;
      gap: 0.25rem;
    }}
    .mini-pivot-btn {{
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-subtle);
      color: var(--text-dim);
      padding: 0.05rem 0.3rem;
      border-radius: 3px;
      font-size: 0.65rem;
      cursor: pointer;
      transition: all 0.12s;
    }}
    .mini-pivot-btn:hover {{
      color: var(--accent-cyan);
      border-color: var(--accent-cyan);
      background: rgba(56, 189, 248, 0.1);
    }}

    .code-box {{
      background: #06090e;
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 0.75rem;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      line-height: 1.5;
      color: #cbd5e1;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 180px;
      overflow-y: auto;
      user-select: text;
    }}

    .json-viewer {{
      background: #06090e;
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 0.75rem;
      font-family: var(--font-mono);
      font-size: 0.725rem;
      line-height: 1.5;
      overflow-x: auto;
      max-height: 400px;
    }}
    .json-key {{ color: #38bdf8; }}
    .json-string {{ color: #34d399; }}
    .json-number {{ color: #fbbf24; }}
    .json-bool {{ color: #c084fc; }}
    .json-null {{ color: #94a3b8; }}

    /* ======================================================== */
    /* 5. ARTIFACT & RAW EVIDENCE TREE VIEW                     */
    /* ======================================================== */
    .dual-pane {{
      flex: 1;
      display: flex;
      overflow: hidden;
    }}
    .tree-pane {{
      width: 320px;
      background: var(--bg-panel);
      border-right: 1px solid var(--border-subtle);
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
    }}
    .tree-search-wrap {{
      padding: 0.75rem;
      border-bottom: 1px solid var(--border-subtle);
    }}
    .tree-content {{
      flex: 1;
      overflow-y: auto;
      padding: 0.5rem 0.4rem;
    }}
    .tree-folder {{
      margin-bottom: 0.4rem;
    }}
    .tree-folder-title {{
      font-size: 0.72rem;
      font-weight: 700;
      color: var(--text-dim);
      padding: 0.35rem 0.6rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .tree-file {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.35rem 0.65rem;
      border-radius: 5px;
      font-size: 0.78rem;
      color: var(--text-muted);
      cursor: pointer;
      transition: all 0.12s ease;
    }}
    .tree-file:hover {{
      background: rgba(255, 255, 255, 0.04);
      color: #fff;
    }}
    .tree-file.selected {{
      background: rgba(56, 189, 248, 0.12);
      color: var(--accent-cyan);
      font-weight: 600;
    }}

    .viewer-pane {{
      flex: 1;
      display: flex;
      flex-direction: column;
      background: var(--bg-base);
      overflow: hidden;
    }}
    .viewer-header {{
      background: var(--bg-panel);
      border-bottom: 1px solid var(--border-subtle);
      padding: 0.75rem 1.25rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-shrink: 0;
    }}
    .viewer-title {{
      font-family: var(--font-mono);
      font-size: 0.85rem;
      color: #fff;
      font-weight: 600;
    }}
    .viewer-meta-chips {{
      display: flex;
      gap: 0.6rem;
      margin-top: 0.25rem;
      font-size: 0.72rem;
      color: var(--text-dim);
    }}
    .viewer-content-wrap {{
      flex: 1;
      overflow: auto;
      background: #05080d;
      padding: 0.5rem 0;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      user-select: text;
    }}
    .line-row {{
      display: flex;
      line-height: 1.6;
    }}
    .line-row:hover {{
      background: rgba(255, 255, 255, 0.03);
    }}
    .line-num {{
      width: 55px;
      color: #475569;
      text-align: right;
      padding-right: 1.25rem;
      user-select: none;
      flex-shrink: 0;
    }}
    .line-text {{
      flex: 1;
      color: #cbd5e1;
      white-space: pre;
    }}

    /* Hex Dump View Mode */
    .hex-row {{
      display: flex;
      line-height: 1.6;
      padding: 0 0.75rem;
    }}
    .hex-row:hover {{
      background: rgba(255, 255, 255, 0.03);
    }}
    .hex-offset {{
      width: 90px;
      color: #64748b;
      user-select: none;
      flex-shrink: 0;
    }}
    .hex-bytes-col {{
      width: 380px;
      color: var(--accent-cyan);
      user-select: text;
      flex-shrink: 0;
      letter-spacing: 0.05em;
    }}
    .hex-ascii-col {{
      flex: 1;
      color: #94a3b8;
      border-left: 1px solid var(--border-subtle);
      padding-left: 1rem;
      white-space: pre;
      user-select: text;
    }}

    /* ======================================================== */
    /* 6. THREAT FINDINGS VIEW                                  */
    /* ======================================================== */
    .findings-workspace {{
      flex: 1;
      overflow-y: auto;
      padding: 1.5rem;
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(460px, 1fr));
      gap: 1.25rem;
      align-content: start;
    }}

    .finding-card {{
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.85rem;
      transition: all 0.15s ease;
      position: relative;
    }}
    .finding-card:hover {{
      border-color: var(--border-medium);
      box-shadow: var(--shadow-md);
      transform: translateY(-2px);
    }}
    .finding-card.high {{ border-top: 3px solid var(--sev-high); }}
    .finding-card.medium {{ border-top: 3px solid var(--sev-med); }}
    .finding-card.low {{ border-top: 3px solid var(--sev-low); }}

    .finding-head {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 0.75rem;
    }}
    .finding-title {{
      font-size: 0.95rem;
      font-weight: 700;
      color: #fff;
    }}
    .finding-section {{
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
      font-size: 0.8rem;
    }}
    .finding-section strong {{
      color: var(--text-dim);
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .finding-tech-box {{
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--border-subtle);
      border-radius: 5px;
      padding: 0.65rem;
      font-family: var(--font-mono);
      font-size: 0.725rem;
      color: var(--text-muted);
      line-height: 1.4;
    }}

    /* ======================================================== */
    /* 7. MITRE ATT&CK MATRIX VIEW                              */
    /* ======================================================== */
    .matrix-workspace {{
      flex: 1;
      overflow: auto;
      padding: 1.5rem;
    }}
    .matrix-grid {{
      display: grid;
      grid-template-columns: repeat(10, minmax(130px, 1fr));
      gap: 0.75rem;
      min-width: 1400px;
    }}
    .matrix-tactic-col {{
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }}
    .matrix-tactic-head {{
      background: rgba(255, 255, 255, 0.03);
      padding: 0.5rem 0.65rem;
      border-bottom: 1px solid var(--border-subtle);
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-bright);
    }}
    .matrix-tech-list {{
      padding: 0.5rem;
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
    }}
    .matrix-tech-cell {{
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-subtle);
      padding: 0.45rem;
      border-radius: 4px;
      font-size: 0.7rem;
      color: var(--text-muted);
      line-height: 1.3;
      transition: all 0.12s;
    }}
    .matrix-tech-cell.detected {{
      background: var(--sev-high-bg);
      border-color: var(--sev-high-border);
      color: #fff;
      font-weight: 600;
      box-shadow: 0 0 8px rgba(255, 77, 109, 0.2);
    }}

    /* ======================================================== */
    /* 8. TOAST NOTIFICATIONS & MODALS                          */
    /* ======================================================== */
    #toast-container {{
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 9999;
      display: flex;
      flex-direction: column;
      gap: 8px;
      pointer-events: none;
    }}
    .toast {{
      display: flex;
      align-items: center;
      gap: 10px;
      background: #151d2c;
      color: #f8fafc;
      border: 1px solid rgba(255, 255, 255, 0.15);
      padding: 9px 16px;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 500;
      box-shadow: var(--shadow-toast);
      pointer-events: auto;
      animation: toast-in 0.2s cubic-bezier(0.16, 1, 0.3, 1), toast-out 0.25s ease 2.2s forwards;
    }}
    @keyframes toast-in {{
      from {{ opacity: 0; transform: translateY(12px) scale(0.96); }}
      to {{ opacity: 1; transform: translateY(0) scale(1); }}
    }}
    @keyframes toast-out {{
      from {{ opacity: 1; transform: translateY(0) scale(1); }}
      to {{ opacity: 0; transform: translateY(8px) scale(0.96); }}
    }}

    /* Empty States */
    .empty-state {{
      text-align: center;
      padding: 3.5rem 1.5rem;
      color: var(--text-dim);
    }}
    .empty-state .icon {{
      font-size: 2rem;
      margin-bottom: 0.5rem;
      opacity: 0.6;
    }}

    /* Modal Sheet */
    .modal-backdrop {{
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(6px);
      z-index: 100;
      align-items: center;
      justify-content: center;
    }}
    .modal-backdrop.open {{ display: flex; }}
    .modal-card {{
      background: var(--bg-card);
      border: 1px solid var(--border-medium);
      border-radius: 8px;
      width: 500px;
      max-width: 90vw;
      box-shadow: var(--shadow-drawer);
      overflow: hidden;
    }}
    .modal-head {{
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-weight: 700;
      color: #fff;
      font-size: 0.9rem;
    }}
    .modal-content {{
      padding: 1.25rem;
      font-size: 0.825rem;
      color: var(--text-main);
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }}
    .hotkey-row {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.35rem 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }}
    .kbd-chip {{
      font-family: var(--font-mono);
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid var(--border-subtle);
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      color: var(--accent-cyan);
    }}
  </style>
</head>
<body>

  <!-- 1. TOP HEADER HUD -->
  <header class="studio-header">
    <div class="header-left">
      <a href="/" class="brand-group" title="Back to Central SOC Console">
        <div class="brand-logo">LFA<span>STUDIO</span></div>
      </a>
      <div class="radar-indicator">
        <span class="pulse-dot"></span> Engine Online
      </div>
      <div class="case-chip" onclick="copyText('{case_id}', 'Case ID copied!')" title="Click to copy Case ID">
        Case: <strong>{case_id}</strong> 📋
      </div>
      <div class="header-meta" style="font-size:0.75rem; color:var(--text-dim); display:flex; gap:0.75rem; border-left:1px solid var(--border-subtle); padding-left:0.75rem;">
        <span>Examiner: <strong style="color:var(--text-main);">{examiner}</strong></span>
        <span>Host(s): <strong style="color:var(--text-main);">{hosts_str}</strong></span>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <nav class="header-nav">
      <button class="nav-btn active" id="btn-tab-events" onclick="switchTab('events')">
        ⏱️ Timeline Grid <span class="nav-badge" id="badge-events-count">{events_count:,}</span>
      </button>
      <button class="nav-btn" id="btn-tab-findings" onclick="switchTab('findings')">
        🛡️ Detections <span class="nav-badge {'danger' if high_findings > 0 else ''}" id="badge-findings-count">{findings_count}</span>
      </button>
      <button class="nav-btn" id="btn-tab-artifacts" onclick="switchTab('artifacts')">
        📁 Raw Evidence <span class="nav-badge" id="badge-artifacts-count">—</span>
      </button>
      <button class="nav-btn" id="btn-tab-matrix" onclick="switchTab('matrix')">
        🎯 MITRE Matrix
      </button>
    </nav>

    <!-- Header Right Actions -->
    <div class="header-actions">
      <a href="{report_url}" target="_blank" class="btn btn-secondary">📄 Offline Report</a>
      <button class="btn-hotkey" onclick="toggleHotkeysModal()" title="Keyboard Shortcuts (?)">?</button>
    </div>
  </header>

  <!-- 2. MAIN WORKSPACE -->
  <main class="studio-workspace">

    <!-- VIEW 1: TIMELINE & EVENTS EXPLORER -->
    <div class="view-pane active" id="tab-events">
      <!-- Activity Histogram Scrubber -->
      <div class="histogram-bar-wrap">
        <div class="histogram-meta">
          <span>Event Density & Activity Timeline</span>
          <span id="hist-time-range">Computing chronological spread...</span>
        </div>
        <div class="histogram-svg-container" id="histogram-container">
          <!-- Rendered via JS -->
        </div>
      </div>

      <!-- Command Filter Toolbar -->
      <div class="command-toolbar">
        <div class="search-wrapper">
          <span class="search-icon">🔍</span>
          <input type="text" id="event-search" class="search-input" placeholder="Search events, commands, users, hashes, IPs, or paths..." oninput="debounceSearch()">
          <span class="search-kbd">/</span>
        </div>

        <!-- Severity Filter Pills -->
        <div class="pill-group">
          <button class="filter-pill active-all" onclick="setSeverity('all')" id="sev-all">All</button>
          <button class="filter-pill" onclick="setSeverity('high')" id="sev-high">High</button>
          <button class="filter-pill" onclick="setSeverity('medium')" id="sev-medium">Med</button>
          <button class="filter-pill" onclick="setSeverity('low')" id="sev-low">Low</button>
          <button class="filter-pill" onclick="setSeverity('info')" id="sev-info">Info</button>
        </div>

        <!-- Category Dropdown -->
        <select id="filter-category" class="filter-select" onchange="applyFilters()">
          <option value="all">All Categories</option>
          <option value="execution">Execution</option>
          <option value="authentication">Authentication</option>
          <option value="persistence">Persistence</option>
          <option value="network">Network</option>
          <option value="storage">Storage & USB</option>
          <option value="integrity">System Integrity</option>
          <option value="configuration">Configuration</option>
        </select>

        <!-- User Dropdown -->
        <select id="filter-user" class="filter-select" onchange="applyFilters()">
          <option value="all">All Actors</option>
        </select>

        <!-- Page Limit -->
        <select id="filter-limit" class="filter-select" onchange="applyFilters()">
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
          <option value="250">250 / page</option>
          <option value="500">500 / page</option>
        </select>

        <button class="btn btn-secondary" onclick="resetFilters()">↺ Reset</button>
      </div>

      <!-- Data Table Workspace with Slide-Out Drawer -->
      <div class="events-workspace">
        <div class="table-scroll-container" id="events-table-container">
          <table class="events-table">
            <thead>
              <tr>
                <th style="width: 32px;">#</th>
                <th class="sortable" onclick="sortBy('timestamp_utc')">Timestamp (UTC) ↕</th>
                <th class="sortable" onclick="sortBy('severity')">Severity ↕</th>
                <th class="sortable" onclick="sortBy('category')">Category ↕</th>
                <th>Subcategory</th>
                <th class="sortable" onclick="sortBy('actor_user')">Actor ↕</th>
                <th>Forensic Description & Activity</th>
                <th>Artifact Source</th>
              </tr>
            </thead>
            <tbody id="events-tbody">
              <tr>
                <td colspan="8" class="empty-state">
                  <div class="icon">⌛</div>
                  <p>Initializing high-speed event grid...</p>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Master-Detail Slide-Out Inspector Drawer -->
        <aside class="inspector-drawer" id="inspector-drawer">
          <div class="drawer-header">
            <div class="drawer-title">
              <span>🔬 Event Inspector</span>
              <span id="drawer-sev-badge" class="badge-sev info">INFO</span>
            </div>
            <button class="drawer-close-btn" onclick="closeDrawer()" title="Close (Esc)">×</button>
          </div>
          <div class="drawer-nav-tabs">
            <button class="drawer-tab active" id="dtab-btn-attr" onclick="switchDrawerTab('attr')">Attributes</button>
            <button class="drawer-tab" id="dtab-btn-raw" onclick="switchDrawerTab('raw')">Raw Log</button>
            <button class="drawer-tab" id="dtab-btn-json" onclick="switchDrawerTab('json')">JSON Tree</button>
          </div>
          <div class="drawer-body" id="drawer-content">
            <!-- Dynamically populated -->
          </div>
        </aside>
      </div>

      <!-- Pagination Footer -->
      <div class="table-footer">
        <div id="events-pagination-summary">Showing 0–0 of 0 events</div>
        <div class="pagination-actions">
          <button class="btn btn-secondary" id="btn-prev-page" onclick="prevPage()" disabled>← Prev</button>
          <span id="page-display" style="font-weight:600; color:var(--text-main);">Page 1</span>
          <button class="btn btn-secondary" id="btn-next-page" onclick="nextPage()" disabled>Next →</button>
        </div>
      </div>
    </div>

    <!-- VIEW 2: THREAT FINDINGS -->
    <div class="view-pane" id="tab-findings">
      <div class="findings-workspace" id="findings-container">
        <div class="empty-state"><p>Loading correlated threat detections...</p></div>
      </div>
    </div>

    <!-- VIEW 3: ARTIFACT & RAW EVIDENCE TREE -->
    <div class="view-pane" id="tab-artifacts">
      <div class="dual-pane">
        <!-- Tree Left Rail -->
        <div class="tree-pane">
          <div class="tree-search-wrap">
            <input type="text" id="artifact-tree-search" class="search-input" placeholder="Filter artifact paths..." oninput="filterArtifactTree()">
          </div>
          <div class="tree-content" id="artifact-tree-root">
            <div class="empty-state"><p>Reading evidentiary manifest...</p></div>
          </div>
        </div>
        <!-- Right Inspector View -->
        <div class="viewer-pane">
          <div class="viewer-header">
            <div>
              <div class="viewer-title" id="viewer-title">Select an artifact to examine</div>
              <div class="viewer-meta-chips" id="viewer-meta">
                <span>Cryptographically verified read-only forensic artifacts</span>
              </div>
            </div>
            <div style="display:flex; gap:0.5rem; align-items:center;">
              <select id="viewer-mode-select" class="filter-select" onchange="toggleViewerMode()">
                <option value="text">Line Numbers (Text)</option>
                <option value="hex">Forensic Hex Dump</option>
              </select>
              <button class="btn btn-secondary" onclick="copyViewerContent()">📋 Copy Content</button>
            </div>
          </div>
          <div class="viewer-content-wrap" id="viewer-body">
            <div class="empty-state">
              <div class="icon">📄</div>
              <p>Select an artifact from the evidence tree to inspect raw content.</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- VIEW 4: MITRE ATT&CK MATRIX -->
    <div class="view-pane" id="tab-matrix">
      <div class="matrix-workspace">
        <div style="margin-bottom: 1rem; color: var(--text-dim); font-size: 0.8rem;">
          Enterprise ATT&CK Framework mapping generated deterministically from correlated evidence rules.
        </div>
        <div class="matrix-grid" id="mitre-matrix-grid">
          <!-- Populated via JS -->
        </div>
      </div>
    </div>

  </main>

  <!-- TOAST CONTAINER -->
  <div id="toast-container"></div>

  <!-- KEYBOARD SHORTCUTS MODAL -->
  <div class="modal-backdrop" id="modal-hotkeys" onclick="if(event.target===this) toggleHotkeysModal()">
    <div class="modal-card">
      <div class="modal-head">
        <span>⌨️ Forensic Studio Hotkeys</span>
        <button class="drawer-close-btn" onclick="toggleHotkeysModal()">×</button>
      </div>
      <div class="modal-content">
        <div class="hotkey-row"><span>Focus Command Search</span><span class="kbd-chip">/</span></div>
        <div class="hotkey-row"><span>Next Event in Grid</span><span class="kbd-chip">j  or  ↓</span></div>
        <div class="hotkey-row"><span>Previous Event in Grid</span><span class="kbd-chip">k  or  ↑</span></div>
        <div class="hotkey-row"><span>Inspect Selected Event</span><span class="kbd-chip">Enter  or  Space</span></div>
        <div class="hotkey-row"><span>Close Drawer / Modal</span><span class="kbd-chip">Esc</span></div>
        <div class="hotkey-row"><span>Switch to Timeline</span><span class="kbd-chip">1</span></div>
        <div class="hotkey-row"><span>Switch to Detections</span><span class="kbd-chip">2</span></div>
        <div class="hotkey-row"><span>Switch to Raw Artifacts</span><span class="kbd-chip">3</span></div>
        <div class="hotkey-row"><span>Switch to MITRE Matrix</span><span class="kbd-chip">4</span></div>
      </div>
    </div>
  </div>

  <!-- SCRIPT ENGINE -->
  <script>
    const CASE_ID = {case_id_js};
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
    let currentArtifactData = null;
    let currentViewerMode = 'text';

    // Interactive Grid State
    let loadedEvents = [];
    let selectedEventIndex = -1;
    let currentInspectedEvent = null;
    let currentDrawerTab = 'attr';

    // Toast Notification System
    function showToast(message) {{
      const container = document.getElementById('toast-container');
      const toast = document.createElement('div');
      toast.className = 'toast';
      toast.innerHTML = `<span>✔</span> <span>${{escapeHtml(message)}}</span>`;
      container.appendChild(toast);
      setTimeout(() => {{
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }}, 2400);
    }}

    function copyText(text, toastMsg) {{
      navigator.clipboard.writeText(text).then(() => {{
        showToast(toastMsg || 'Copied to clipboard!');
      }}).catch(() => {{
        showToast('Copied to clipboard!');
      }});
    }}

    // Tab Navigation
    function switchTab(tabId) {{
      currentTab = tabId;
      document.querySelectorAll('.view-pane').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));

      const pane = document.getElementById('tab-' + tabId);
      const btn = document.getElementById('btn-tab-' + tabId);
      if (pane) pane.classList.add('active');
      if (btn) btn.classList.add('active');

      if (tabId === 'artifacts' && artifactsList.length === 0) {{
        loadArtifacts();
      }} else if (tabId === 'findings') {{
        loadFindings();
      }} else if (tabId === 'matrix') {{
        loadMitreMatrix();
      }}
    }}

    // ----------------------------------------------------
    // Load Events & Histogram Scrubber
    // ----------------------------------------------------
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
        loadedEvents = data.events || [];

        document.getElementById('badge-events-count').innerText = totalEvents.toLocaleString();

        // Populate users dropdown
        const userSelect = document.getElementById('filter-user');
        if (userSelect.options.length <= 1 && data.users) {{
          data.users.forEach(u => {{
            const opt = document.createElement('option');
            opt.value = u;
            opt.innerText = u;
            userSelect.appendChild(opt);
          }});
        }}

        if (loadedEvents.length === 0) {{
          tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="icon">🔍</div><p>No matching normalized events found.</p><span style="font-size:0.75rem;color:var(--text-dim)">Try refining your query or resetting filters.</span></td></tr>`;
          updatePagination(0, limit);
          renderHistogram([]);
          return;
        }}

        let rowsHtml = '';
        loadedEvents.forEach((ev, idx) => {{
          const isSelected = selectedEventIndex === idx;
          const sev = ev.severity || 'info';
          const userStr = ev.actor_user ? `<span class="cell-user" title="Filter by user" onclick="filterByField('user', '${{escapeJs(ev.actor_user)}}', event)">${{escapeHtml(ev.actor_user)}}</span>` : '—';
          const timeStr = ev.timestamp_utc ? ev.timestamp_utc.replace('T', ' ').replace('+00:00', 'Z') : '—';

          rowsHtml += `
            <tr class="${{isSelected ? 'selected-row' : ''}}" id="row-ev-${{idx}}" onclick="selectEventRow(${{idx}})">
              <td style="color:var(--text-dim); font-size:0.7rem; font-family:var(--font-mono);">${{currentOffset + idx + 1}}</td>
              <td class="cell-time">${{timeStr}}</td>
              <td><span class="badge-sev ${{sev}}">${{sev}}</span></td>
              <td><span class="cell-cat" onclick="filterByField('category', '${{escapeJs(ev.category)}}', event)">${{escapeHtml(ev.category)}}</span></td>
              <td><span class="cell-subcat">${{escapeHtml(ev.subcategory)}}</span></td>
              <td>${{userStr}}</td>
              <td class="cell-desc">${{escapeHtml(ev.description)}}</td>
              <td><span class="cell-artifact" title="${{escapeHtml(ev.source_artifact_path)}}">${{escapeHtml(ev.source_artifact_path)}}</span></td>
            </tr>
          `;
        }});

        tbody.innerHTML = rowsHtml;
        updatePagination(loadedEvents.length, limit);
        renderHistogram(loadedEvents);

      }} catch (err) {{
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="icon">⚠️</div><p>Failed loading events: ${{escapeHtml(err)}}</p></td></tr>`;
      }}
    }}

    // Dynamic Activity Histogram Scrubber (SVG)
    function renderHistogram(events) {{
      const container = document.getElementById('histogram-container');
      const timeRangeEl = document.getElementById('hist-time-range');

      if (!events || events.length === 0) {{
        container.innerHTML = '<div style="color:var(--text-dim);font-size:0.7rem;padding-top:8px;">No temporal distribution data available.</div>';
        timeRangeEl.innerText = '—';
        return;
      }}

      // Parse timestamps
      const timestamps = events
        .map(e => e.timestamp_utc ? new Date(e.timestamp_utc).getTime() : null)
        .filter(t => t && !isNaN(t))
        .sort((a, b) => a - b);

      if (timestamps.length === 0) {{
        container.innerHTML = '';
        return;
      }}

      const minT = timestamps[0];
      const maxT = timestamps[timestamps.length - 1];
      const span = Math.max(maxT - minT, 1000);

      timeRangeEl.innerText = `${{new Date(minT).toISOString().slice(0, 19).replace('T', ' ')}} → ${{new Date(maxT).toISOString().slice(0, 19).replace('T', ' ')}} UTC`;

      const numBuckets = Math.min(48, Math.max(16, Math.floor(container.clientWidth / 24)));
      const buckets = new Array(numBuckets).fill(0);
      const threatBuckets = new Array(numBuckets).fill(0);

      events.forEach(e => {{
        if (!e.timestamp_utc) return;
        const t = new Date(e.timestamp_utc).getTime();
        if (isNaN(t)) return;
        let bIdx = Math.floor(((t - minT) / span) * (numBuckets - 1));
        bIdx = Math.max(0, Math.min(numBuckets - 1, bIdx));
        buckets[bIdx]++;
        if (e.severity === 'high' || e.severity === 'medium') {{
          threatBuckets[bIdx]++;
        }}
      }});

      const maxCount = Math.max(...buckets, 1);
      const barWidth = 100 / numBuckets;

      let rects = '';
      buckets.forEach((count, i) => {{
        const heightPct = Math.max(8, (count / maxCount) * 95);
        const y = 100 - heightPct;
        const hasThreat = threatBuckets[i] > 0;
        const cls = hasThreat ? 'hist-rect has-threat' : 'hist-rect';
        rects += `<rect class="${{cls}}" x="${{i * barWidth + 0.5}}%" y="${{y}}%" width="${{barWidth - 1}}%" height="${{heightPct}}%" rx="2"><title>Bucket ${{i+1}}: ${{count}} events (${{threatBuckets[i]}} threats)</title></rect>`;
      }});

      container.innerHTML = `<svg preserveAspectRatio="none" viewBox="0 0 100 100">${{rects}}</svg>`;
    }}

    // Row Selection & Slide-Out Inspector
    function selectEventRow(index) {{
      if (index < 0 || index >= loadedEvents.length) return;
      selectedEventIndex = index;
      currentInspectedEvent = loadedEvents[index];

      // Update row active state
      document.querySelectorAll('.events-table tbody tr').forEach(r => r.classList.remove('selected-row'));
      const row = document.getElementById('row-ev-' + index);
      if (row) row.classList.add('selected-row');

      renderDrawerContent();
      openDrawer();
    }}

    function openDrawer() {{
      const drawer = document.getElementById('inspector-drawer');
      drawer.classList.add('open');
    }}

    function closeDrawer() {{
      const drawer = document.getElementById('inspector-drawer');
      drawer.classList.remove('open');
    }}

    function switchDrawerTab(tab) {{
      currentDrawerTab = tab;
      document.querySelectorAll('.drawer-tab').forEach(b => b.classList.remove('active'));
      const btn = document.getElementById('dtab-btn-' + tab);
      if (btn) btn.classList.add('active');
      renderDrawerContent();
    }}

    function renderDrawerContent() {{
      const ev = currentInspectedEvent;
      if (!ev) return;

      const badgeEl = document.getElementById('drawer-sev-badge');
      badgeEl.className = `badge-sev ${{ev.severity || 'info'}}`;
      badgeEl.innerText = (ev.severity || 'info').toUpperCase();

      const container = document.getElementById('drawer-content');

      if (currentDrawerTab === 'attr') {{
        container.innerHTML = `
          <div>
            <div style="font-size:0.7rem; color:var(--text-dim); text-transform:uppercase; font-weight:700; margin-bottom:0.4rem;">
              Normalized Telemetry Attributes
            </div>
            <table class="prop-table">
              <tr>
                <td class="prop-label">Event ID</td>
                <td class="prop-value">
                  ${{ev.event_id}}
                  <span class="prop-actions"><button class="mini-pivot-btn" onclick="copyText('${{ev.event_id}}', 'Event ID copied')">Copy</button></span>
                </td>
              </tr>
              <tr>
                <td class="prop-label">Timestamp (UTC)</td>
                <td class="prop-value">${{ev.timestamp_utc || '—'}}</td>
              </tr>
              <tr>
                <td class="prop-label">Actor User</td>
                <td class="prop-value">
                  ${{escapeHtml(ev.actor_user || '—')}}
                  ${{ev.actor_user ? `<span class="prop-actions"><button class="mini-pivot-btn" onclick="filterByField('user', '${{escapeJs(ev.actor_user)}}')">[+ Filter]</button></span>` : ''}}
                </td>
              </tr>
              <tr>
                <td class="prop-label">Actor Process</td>
                <td class="prop-value">${{escapeHtml(ev.actor_process || '—')}}</td>
              </tr>
              <tr>
                <td class="prop-label">Source Host / IP</td>
                <td class="prop-value">
                  ${{escapeHtml(ev.source_ip || ev.source_host || '—')}}
                  ${{ev.source_ip ? `<span class="prop-actions"><button class="mini-pivot-btn" onclick="copyText('${{escapeJs(ev.source_ip)}}', 'IP copied')">Copy</button></span>` : ''}}
                </td>
              </tr>
              <tr>
                <td class="prop-label">Category / Sub</td>
                <td class="prop-value">${{escapeHtml(ev.category)}} / ${{escapeHtml(ev.subcategory)}}</td>
              </tr>
              <tr>
                <td class="prop-label">Parser Provenance</td>
                <td class="prop-value">${{escapeHtml(ev.parser_name)}} v${{escapeHtml(ev.parser_version)}}</td>
              </tr>
              <tr>
                <td class="prop-label">Source Artifact</td>
                <td class="prop-value">
                  <a style="color:var(--accent-cyan); text-decoration:none; cursor:pointer;" onclick="jumpToArtifact('${{escapeJs(ev.source_artifact_path)}}')">
                    ${{escapeHtml(ev.source_artifact_path)}}
                  </a>
                </td>
              </tr>
              <tr>
                <td class="prop-label">Source Offset</td>
                <td class="prop-value">Byte ${{ev.raw_line_offset || 0}}</td>
              </tr>
              <tr>
                <td class="prop-label">Artifact SHA-256</td>
                <td class="prop-value">
                  <span style="font-size:0.7rem;">${{ev.source_artifact_sha256 ? ev.source_artifact_sha256.substring(0, 16) + '...' : '—'}}</span>
                  ${{ev.source_artifact_sha256 ? `<span class="prop-actions"><button class="mini-pivot-btn" onclick="copyText('${{escapeJs(ev.source_artifact_sha256)}}', 'SHA-256 copied')">Copy</button></span>` : ''}}
                </td>
              </tr>
            </table>
          </div>

          <div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span style="font-size:0.7rem; color:var(--text-dim); text-transform:uppercase; font-weight:700;">Exact Raw Log Provenance</span>
              <button class="mini-pivot-btn" onclick="copyText('${{escapeJs(ev.raw_line)}}', 'Raw log line copied!')">📋 Copy Line</button>
            </div>
            <div class="code-box">${{escapeHtml(ev.raw_line)}}</div>
          </div>
        `;
      }} else if (currentDrawerTab === 'raw') {{
        container.innerHTML = `
          <div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
              <span style="font-size:0.7rem; color:var(--text-dim); text-transform:uppercase; font-weight:700;">Complete Raw Evidence Record</span>
              <button class="btn btn-secondary" onclick="copyText('${{escapeJs(ev.raw_line)}}', 'Copied raw line')">📋 Copy</button>
            </div>
            <div class="code-box" style="max-height: 500px; font-size:0.8rem;">${{escapeHtml(ev.raw_line)}}</div>
          </div>
        `;
      }} else if (currentDrawerTab === 'json') {{
        const jsonFormatted = formatSyntaxJson(ev);
        container.innerHTML = `
          <div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
              <span style="font-size:0.7rem; color:var(--text-dim); text-transform:uppercase; font-weight:700;">Full Normalized JSON Record</span>
              <button class="btn btn-secondary" onclick="copyText('${{escapeJs(JSON.stringify(ev, null, 2))}}', 'Normalized JSON copied')">📋 Copy JSON</button>
            </div>
            <div class="json-viewer">${{jsonFormatted}}</div>
          </div>
        `;
      }}
    }}

    // Syntax-Highlighted JSON Formatter
    function formatSyntaxJson(obj) {{
      const json = JSON.stringify(obj, null, 2);
      return json.replace(/("(\\\\u[a-zA-Z0-9]{{4}}|\\\\[^u]|[^\\\\"])*"(\\\\s*:)?|\\b(true|false|null)\\b|-?\\d+(?:\\.\\d*)?(?:[eE][+\\\\-]?\\d+)?)/g, function (match) {{
        let cls = 'json-number';
        if (/^"/.test(match)) {{
          if (/:$/.test(match)) {{
            cls = 'json-key';
          }} else {{
            cls = 'json-string';
          }}
        }} else if (/true|false/.test(match)) {{
          cls = 'json-bool';
        }} else if (/null/.test(match)) {{
          cls = 'json-null';
        }}
        return '<span class="' + cls + '">' + escapeHtml(match) + '</span>';
      }});
    }}

    // Quick In-Line Pivot Filters
    function filterByField(field, val, e) {{
      if (e) e.stopPropagation();
      if (field === 'user') {{
        const sel = document.getElementById('filter-user');
        sel.value = val;
        applyFilters();
        showToast(`Filtered by actor: ${{val}}`);
      }} else if (field === 'category') {{
        const sel = document.getElementById('filter-category');
        sel.value = val;
        applyFilters();
        showToast(`Filtered by category: ${{val}}`);
      }}
    }}

    // Search & Filter Controllers
    function debounceSearch() {{
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(() => {{
        currentOffset = 0;
        selectedEventIds = null;
        loadEvents();
      }}, 260);
    }}

    function setSeverity(sev) {{
      currentSeverity = sev;
      document.querySelectorAll('.filter-pill').forEach(el => {{
        el.className = 'filter-pill';
      }});
      const pill = document.getElementById('sev-' + sev);
      if (pill) pill.className = `filter-pill active-${{sev}}`;
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
      selectedEventIndex = -1;
      closeDrawer();
      loadEvents();
      showToast('Filters cleared');
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
      document.getElementById('events-pagination-summary').innerText =
        `Showing ${{start}}–${{end}} of ${{filteredEvents.toLocaleString()}} events (total: ${{totalEvents.toLocaleString()}})`;

      const page = Math.floor(currentOffset / limit) + 1;
      const totalPages = Math.ceil(filteredEvents / limit) || 1;
      document.getElementById('page-display').innerText = `Page ${{page}} / ${{totalPages}}`;

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

    // ----------------------------------------------------
    // Tab 2: Threat Findings & Detections
    // ----------------------------------------------------
    async function loadFindings() {{
      const container = document.getElementById('findings-container');
      try {{
        const res = await fetch(`/api/v1/cases/${{CASE_ID}}/findings`);
        const data = await res.json();
        const findings = data.findings || [];
        document.getElementById('badge-findings-count').innerText = findings.length;

        if (findings.length === 0) {{
          container.innerHTML = `<div class="empty-state" style="grid-column: 1 / -1;"><div class="icon">🛡️</div><p>No critical or suspicious security alerts triggered for this case.</p></div>`;
          return;
        }}

        let html = '';
        findings.forEach(f => {{
          const sevClass = f.severity || 'low';
          const eventIds = f.event_ids || [];
          html += `
            <div class="finding-card ${{sevClass}}">
              <div class="finding-head">
                <span class="finding-title">${{escapeHtml(f.title)}}</span>
                <span class="badge-sev ${{sevClass}}">${{sevClass.toUpperCase()}}</span>
              </div>
              <div class="finding-section">
                <strong>What Happened</strong>
                <div style="color:var(--text-bright); font-weight:500;">${{escapeHtml(f.what_happened)}}</div>
              </div>
              <div class="finding-section">
                <strong>Why It Matters</strong>
                <div>${{escapeHtml(f.why_it_matters)}}</div>
              </div>
              <div class="finding-section">
                <strong>Recommended Next Action</strong>
                <div>${{escapeHtml(f.check_next)}}</div>
              </div>
              <div class="finding-section">
                <strong>Technical Details & Rule Provenance</strong>
                <div class="finding-tech-box">
                  <div>Rule: ${{escapeHtml(f.rule_name)}} (v${{escapeHtml(f.rule_version)}})</div>
                  <div>Confidence: ${{escapeHtml(f.confidence)}} | Timestamps: ${{escapeHtml(f.first_ts_utc || '—')}} → ${{escapeHtml(f.last_ts_utc || '—')}}</div>
                  <div style="margin-top:0.3rem;">${{escapeHtml(f.technical_detail)}}</div>
                </div>
              </div>
              <div style="margin-top:0.4rem;">
                <button class="btn btn-primary" onclick="pivotToEvents([${{eventIds.map(i => `'${{i}}'`).join(',')}}])">
                  🔍 Pivot to ${{eventIds.length}} Supporting Events
                </button>
              </div>
            </div>
          `;
        }});
        container.innerHTML = html;
      }} catch (err) {{
        container.innerHTML = `<div class="empty-state"><p>Failed loading threat findings: ${{escapeHtml(err)}}</p></div>`;
      }}
    }}

    function pivotToEvents(eventIds) {{
      selectedEventIds = eventIds;
      switchTab('events');
      currentOffset = 0;
      loadEvents();
      showToast(`Pivoted to ${{eventIds.length}} threat events`);
    }}

    // ----------------------------------------------------
    // Tab 3: Artifacts & Evidence Tree (Text + Hex Modes)
    // ----------------------------------------------------
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
        document.getElementById('artifact-tree-root').innerHTML = `<div class="empty-state"><p>Error loading artifacts: ${{escapeHtml(err)}}</p></div>`;
      }}
    }}

    function renderArtifactTree(list) {{
      const root = document.getElementById('artifact-tree-root');
      if (!list || list.length === 0) {{
        root.innerHTML = `<div class="empty-state"><p>No artifacts recorded</p></div>`;
        return;
      }}

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
            <div class="tree-folder-title">📁 ${{folder}} (${{files.length}})</div>
        `;
        files.forEach(f => {{
          const isSel = f.original_path === activeArtifactPath;
          const fileName = f.original_path.split('/').pop() || f.original_path;
          const sizeKb = (f.size / 1024).toFixed(1);
          html += `
            <div class="tree-file ${{isSel ? 'selected' : ''}}" onclick="selectArtifact('${{escapeJs(f.original_path)}}')">
              <span>📄 ${{escapeHtml(fileName)}}</span>
              <div style="display:flex; align-items:center; gap:0.4rem;">
                <span style="font-size:0.7rem; color:var(--text-dim);">${{sizeKb}} KB</span>
                <span style="color:#10b981; font-size:0.75rem;">✔</span>
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
          <span>Size: <strong>${{art.size}} B</strong></span>
          <span>Owner: <strong>${{art.owner || '—'}}</strong></span>
          <span>Mode: <strong>${{art.mode || '—'}}</strong></span>
          <span>SHA-256: <code style="color:var(--accent-cyan);">${{art.sha256 ? art.sha256.substring(0, 16) + '...' : '—'}}</code></span>
          <span style="color:#10b981; font-weight:600;">✔ Verified Read-Only</span>
        `;
      }}

      const bodyEl = document.getElementById('viewer-body');
      bodyEl.innerHTML = `<div class="empty-state"><div class="icon">⌛</div><p>Fetching collected file...</p></div>`;

      try {{
        const res = await fetch(`/api/v1/cases/${{CASE_ID}}/artifact-content?path=${{encodeURIComponent(path)}}`);
        const data = await res.json();
        if (data.error) {{
          bodyEl.innerHTML = `<div class="empty-state"><p>Error: ${{escapeHtml(data.error)}}</p></div>`;
          return;
        }}
        currentArtifactData = data;
        renderViewerContent();
      }} catch (err) {{
        bodyEl.innerHTML = `<div class="empty-state"><p>Failed to load artifact content: ${{escapeHtml(err)}}</p></div>`;
      }}
    }}

    function toggleViewerMode() {{
      currentViewerMode = document.getElementById('viewer-mode-select').value;
      renderViewerContent();
    }}

    function renderViewerContent() {{
      if (!currentArtifactData) return;
      const bodyEl = document.getElementById('viewer-body');
      const content = currentArtifactData.content || '';

      if (currentViewerMode === 'hex') {{
        // Build Hex Dump View (Offset | 16 Hex Bytes | ASCII)
        let hexRows = '';
        const encoder = new TextEncoder();
        const bytes = encoder.encode(content);
        const limitBytes = Math.min(bytes.length, 32768); // First 32KB

        for (let i = 0; i < limitBytes; i += 16) {{
          const offsetStr = i.toString(16).padStart(8, '0');
          let hexCol = '';
          let asciiCol = '';

          for (let j = 0; j < 16; j++) {{
            if (i + j < limitBytes) {{
              const b = bytes[i + j];
              hexCol += b.toString(16).padStart(2, '0') + ' ';
              asciiCol += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
            }} else {{
              hexCol += '   ';
              asciiCol += ' ';
            }}
          }}

          hexRows += `
            <div class="hex-row">
              <span class="hex-offset">${{offsetStr}}</span>
              <span class="hex-bytes-col">${{hexCol}}</span>
              <span class="hex-ascii-col">${{escapeHtml(asciiCol)}}</span>
            </div>
          `;
        }}

        bodyEl.innerHTML = hexRows;
      }} else {{
        // Text Mode with Line Numbers
        const lines = content.split('\\n');
        let linesHtml = '';
        lines.forEach((line, idx) => {{
          const cleanLine = line.replace(/\\r$/, '');
          linesHtml += `<div class="line-row"><div class="line-num">${{idx + 1}}</div><div class="line-text">${{escapeHtml(cleanLine) || '&nbsp;'}}</div></div>`;
        }});
        bodyEl.innerHTML = linesHtml;
      }}
    }}

    function jumpToArtifact(path) {{
      switchTab('artifacts');
      loadArtifacts().then(() => {{
        selectArtifact(path);
      }});
    }}

    function copyViewerContent() {{
      if (!currentArtifactData || !currentArtifactData.content) return;
      copyText(currentArtifactData.content, 'Artifact content copied!');
    }}

    // ----------------------------------------------------
    // Tab 4: MITRE ATT&CK Matrix View
    // ----------------------------------------------------
    const TACTICS_MAP = [
      {{ id: 'initial-access', name: 'Initial Access', techniques: ['T1078 Valid Accounts', 'T1190 Exploit Public App'] }},
      {{ id: 'execution', name: 'Execution', techniques: ['T1059 Command & Scripting', 'T1204 User Execution'] }},
      {{ id: 'persistence', name: 'Persistence', techniques: ['T1053 Scheduled Task/Cron', 'T1543 Systemd Service'] }},
      {{ id: 'priv-esc', name: 'Priv Escalation', techniques: ['T1548 Abuse Elevation', 'T1068 Exploitation'] }},
      {{ id: 'defense-evasion', name: 'Defense Evasion', techniques: ['T1070 Indicator Removal', 'T1036 Masquerading'] }},
      {{ id: 'cred-access', name: 'Credential Access', techniques: ['T1003 OS Credential Dump', 'T1110 Brute Force'] }},
      {{ id: 'discovery', name: 'Discovery', techniques: ['T1082 System Info Discovery', 'T1083 File Discovery'] }},
      {{ id: 'lateral-move', name: 'Lateral Move', techniques: ['T1021 Remote Services (SSH)', 'T1072 Software Deployment'] }},
      {{ id: 'collection', name: 'Collection', techniques: ['T1005 Data from Local Drive', 'T1056 Input Capture'] }},
      {{ id: 'exfiltration', name: 'Exfiltration', techniques: ['T1048 Exfil Over Alt Protocol', 'T1041 Exfil Over C2'] }},
    ];

    async function loadMitreMatrix() {{
      const grid = document.getElementById('mitre-matrix-grid');
      let findings = [];
      try {{
        const res = await fetch(`/api/v1/cases/${{CASE_ID}}/findings`);
        const data = await res.json();
        findings = data.findings || [];
      }} catch (err) {{}}

      let html = '';
      TACTICS_MAP.forEach(t => {{
        html += `
          <div class="matrix-tactic-col">
            <div class="matrix-tactic-head">${{t.name}}</div>
            <div class="matrix-tech-list">
        `;
        t.techniques.forEach(tech => {{
          const isTriggered = findings.some(f =>
            (f.technical_detail && f.technical_detail.toLowerCase().includes(tech.split(' ')[0].toLowerCase())) ||
            (f.title && f.title.toLowerCase().includes(tech.split(' ')[0].toLowerCase()))
          );
          html += `
            <div class="matrix-tech-cell ${{isTriggered ? 'detected' : ''}}">
              ${{escapeHtml(tech)}}
              ${{isTriggered ? '<div style="font-size:0.6rem; color:#fca5a5; margin-top:2px;">DETECTED IN CASE</div>' : ''}}
            </div>
          `;
        }});
        html += `</div></div>`;
      }});
      grid.innerHTML = html;
    }}

    // ----------------------------------------------------
    // Keyboard Ergonomics & Modal
    // ----------------------------------------------------
    function toggleHotkeysModal() {{
      const modal = document.getElementById('modal-hotkeys');
      modal.classList.toggle('open');
    }}

    window.addEventListener('keydown', (e) => {{
      // Ignore hotkeys when typing in search or inputs
      if (['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement.tagName)) {{
        if (e.key === 'Escape') {{
          document.activeElement.blur();
        }}
        return;
      }}

      if (e.key === '/') {{
        e.preventDefault();
        document.getElementById('event-search').focus();
      }} else if (e.key === 'Escape') {{
        closeDrawer();
        const modal = document.getElementById('modal-hotkeys');
        if (modal.classList.contains('open')) modal.classList.remove('open');
      }} else if (e.key === 'j' || e.key === 'ArrowDown') {{
        e.preventDefault();
        if (currentTab === 'events' && loadedEvents.length > 0) {{
          selectEventRow(Math.min(loadedEvents.length - 1, selectedEventIndex + 1));
        }}
      }} else if (e.key === 'k' || e.key === 'ArrowUp') {{
        e.preventDefault();
        if (currentTab === 'events' && loadedEvents.length > 0) {{
          selectEventRow(Math.max(0, selectedEventIndex - 1));
        }}
      }} else if (e.key === 'Enter' || e.key === ' ') {{
        if (currentTab === 'events' && selectedEventIndex >= 0) {{
          e.preventDefault();
          openDrawer();
        }}
      }} else if (e.key === '1') {{
        switchTab('events');
      }} else if (e.key === '2') {{
        switchTab('findings');
      }} else if (e.key === '3') {{
        switchTab('artifacts');
      }} else if (e.key === '4') {{
        switchTab('matrix');
      }} else if (e.key === '?') {{
        toggleHotkeysModal();
      }}
    }});

    // Helper Escapes
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

    // Initialization
    window.addEventListener('DOMContentLoaded', () => {{
      loadEvents();
    }});
  </script>
</body>
</html>
"""
