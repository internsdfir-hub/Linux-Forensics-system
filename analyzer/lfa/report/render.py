"""Report rendering engine.

Compiles data, deterministic SVG charts, executive narrative, inlined CSS/JS,
and Jinja2 templates into a completely self-contained offline HTML forensic report.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..ui import assets
from .chart import (
    auth_failure_bursts_svg,
    generate_density_svg,
    severity_breakdown_svg,
    user_activity_svg,
)
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
    severity_chart = severity_breakdown_svg(conn)
    user_chart = user_activity_svg(conn)
    failures_chart = auth_failure_bursts_svg(conn)
    narrative = generate_executive_summary(summary, findings)

    env = Environment(
        loader=FileSystemLoader(str(assets.TEMPLATE_DIR)), autoescape=True
    )

    inline_css = assets.load_styles("base")
    inline_js = assets.load_script("report")

    template = env.get_template("report.html.j2")
    html_content = template.render(
        summary=summary,
        findings=findings,
        artifacts=artifacts,
        events=events,
        intel=intel,
        svg_chart=svg_chart,
        severity_chart=severity_chart,
        user_chart=user_chart,
        failures_chart=failures_chart,
        narrative=narrative,
        inline_css=inline_css,
        inline_js=inline_js,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_content, encoding="utf-8")
    return out_path
