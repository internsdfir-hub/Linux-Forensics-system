"""Report rendering engine.

Compiles data, deterministic SVG charts, executive narrative, inlined CSS/JS,
and Jinja2 templates into a completely self-contained offline HTML forensic report.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .chart import generate_density_svg
from .data import (
    get_artifacts_data,
    get_case_summary,
    get_categorized_intel,
    get_events_sample,
    get_findings_data,
)
from .narrative import generate_executive_summary


def render_report(conn: sqlite3.Connection, case_dir: Path | str, out_html_path: Path | str) -> Path:
    case_dir = Path(case_dir)
    out_path = Path(out_html_path)

    meta_path = case_dir / "case_metadata.json"
    case_meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}

    summary = get_case_summary(conn, case_meta)
    findings = get_findings_data(conn)
    artifacts = get_artifacts_data(conn)
    events = get_events_sample(conn, limit=1500)
    intel = get_categorized_intel(conn)

    svg_chart = generate_density_svg(conn)
    narrative = generate_executive_summary(summary, findings)

    tpl_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(loader=FileSystemLoader(str(tpl_dir)), autoescape=True)

    css_path = tpl_dir / "style.css"
    js_path = tpl_dir / "tables.js"

    inline_css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""
    inline_js = js_path.read_text(encoding="utf-8") if js_path.exists() else ""

    template = env.get_template("report.html.j2")
    html_content = template.render(
        summary=summary,
        findings=findings,
        artifacts=artifacts,
        events=events,
        intel=intel,
        svg_chart=svg_chart,
        narrative=narrative,
        inline_css=inline_css,
        inline_js=inline_js,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_content, encoding="utf-8")
    return out_path
