"""Pure-Python SVG event density chart generator (spec Decision D3).

Generates a clean, zero-dependency, self-contained SVG histogram showing event
density and suspicious activity over the case timeline.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


def generate_density_svg(conn: sqlite3.Connection, width: int = 900, height: int = 240) -> str:
    rows = conn.execute(
        "SELECT timestamp_utc, severity FROM events WHERE timestamp_utc IS NOT NULL ORDER BY timestamp_utc"
    ).fetchall()

    if not rows:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="{height}">'
            f'<rect width="{width}" height="{height}" fill="#181824" rx="8"/>'
            f'<text x="{width/2}" y="{height/2}" fill="#8b949e" font-family="sans-serif" font-size="14" text-anchor="middle">'
            f'No timestamped events available for timeline visualization</text></svg>'
        )

    timestamps = []
    severities = []
    for r in rows:
        try:
            ts = datetime.fromisoformat(r[0].replace("Z", "+00:00"))
            timestamps.append(ts.timestamp())
            severities.append(r[1])
        except Exception:
            continue

    if not timestamps:
        return '<svg xmlns="http://www.w3.org/2000/svg" width="100%" height="200"></svg>'

    min_t, max_t = min(timestamps), max(timestamps)
    if max_t == min_t:
        max_t = min_t + 3600  # 1 hour window default

    num_bins = min(50, max(10, int((max_t - min_t) // 300) + 1))
    bin_width_sec = (max_t - min_t) / num_bins

    bins = [0] * num_bins
    high_bins = [0] * num_bins

    for t, sev in zip(timestamps, severities):
        b = min(int((t - min_t) / bin_width_sec), num_bins - 1)
        bins[b] += 1
        if sev in ("high", "medium"):
            high_bins[b] += 1

    max_count = max(bins) if bins else 1
    if max_count == 0:
        max_count = 1

    pad_left = 60
    pad_right = 30
    pad_top = 30
    pad_bottom = 50
    chart_w = width - pad_left - pad_right
    chart_h = height - pad_top - pad_bottom

    bar_w = max(4.0, (chart_w / num_bins) - 3.0)

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="{height}">',
        f'<rect width="{width}" height="{height}" fill="#161b22" rx="8" stroke="#30363d"/>',
        f'<text x="{pad_left}" y="20" fill="#c9d1d9" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif" font-size="12" font-weight="600">Event Density &amp; Threat Distribution Timeline</text>',
        f'<line x1="{pad_left}" y1="{pad_top + chart_h}" x2="{pad_left + chart_w}" y2="{pad_top + chart_h}" stroke="#30363d" stroke-width="1"/>',
    ]

    for i in range(num_bins):
        x = pad_left + i * (chart_w / num_bins)
        h = (bins[i] / max_count) * chart_h
        y = pad_top + chart_h - h

        high_h = (high_bins[i] / max_count) * chart_h
        high_y = pad_top + chart_h - high_h

        # Total bar (blue/teal)
        svg_parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" fill="#238636" rx="2" opacity="0.85">'
            f'<title>Bin {i+1}: {bins[i]} events ({high_bins[i]} suspicious)</title></rect>'
        )

        # High/suspicious bar overlay (red/orange)
        if high_bins[i] > 0:
            svg_parts.append(
                f'<rect x="{x:.1f}" y="{high_y:.1f}" width="{bar_w:.1f}" height="{high_h:.1f}" fill="#da3633" rx="2">'
                f'<title>High/Med: {high_bins[i]} events</title></rect>'
            )

    t1_str = datetime.fromtimestamp(min_t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    t2_str = datetime.fromtimestamp(max_t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    svg_parts.append(
        f'<text x="{pad_left}" y="{height - 15}" fill="#8b949e" font-family="sans-serif" font-size="11">{t1_str}</text>'
    )
    svg_parts.append(
        f'<text x="{width - pad_right}" y="{height - 15}" fill="#8b949e" font-family="sans-serif" font-size="11" text-anchor="end">{t2_str}</text>'
    )
    svg_parts.append(
        f'<text x="{pad_left - 10}" y="{pad_top + 10}" fill="#8b949e" font-family="sans-serif" font-size="10" text-anchor="end">{max_count}</text>'
    )
    svg_parts.append(
        f'<text x="{pad_left - 10}" y="{pad_top + chart_h}" fill="#8b949e" font-family="sans-serif" font-size="10" text-anchor="end">0</text>'
    )

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)
