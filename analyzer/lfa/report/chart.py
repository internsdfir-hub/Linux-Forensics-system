"""Deterministic pure-Python SVG charts (project decision D3: no matplotlib).

Every function returns one complete <svg> element, ready to inline. Colour
comes from the design-token layer via var(), never from a literal, so charts
re-theme with the rest of the page. Each chart is accessible: role="img" plus
a <title> and <desc> that state what it shows.

Determinism is a hard requirement. Identical evidence must produce identical
bytes, so every query is explicitly ordered and nothing here reads the clock.
"""
from __future__ import annotations

import hashlib
import sqlite3
from xml.sax.saxutils import escape

_PAD_LEFT = 56
_PAD_RIGHT = 16
_PAD_TOP = 28
_PAD_BOTTOM = 40

_SEVERITY_ORDER = ("high", "medium", "low", "info")


def _open(width: int, height: int, title: str, desc: str) -> list[str]:
    ident = "lfa-" + hashlib.sha256(title.encode("utf-8")).hexdigest()[:8]
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" aria-labelledby="{ident}" '
        f'class="lfa-chart">',
        f'<title id="{ident}">{escape(title)}</title>',
        f"<desc>{escape(desc)}</desc>",
    ]


def _empty(width: int, height: int, title: str) -> str:
    parts = _open(width, height, title, "No data available for this chart.")
    parts.append(
        f'<text x="{width // 2}" y="{height // 2}" text-anchor="middle" '
        f'fill="var(--text-muted)" font-size="14">No data available</text>'
    )
    parts.append("</svg>")
    return "\n".join(parts)


def _axes(width: int, height: int) -> list[str]:
    """Baseline and left rule, drawn from tokens."""
    x0, y0 = _PAD_LEFT, height - _PAD_BOTTOM
    return [
        f'<line x1="{x0}" y1="{y0}" x2="{width - _PAD_RIGHT}" y2="{y0}" '
        f'stroke="var(--border-strong)" stroke-width="1"/>',
        f'<line x1="{x0}" y1="{_PAD_TOP}" x2="{x0}" y2="{y0}" '
        f'stroke="var(--border-strong)" stroke-width="1"/>',
    ]


def _gridlines(width: int, height: int, steps: int, top_value: int) -> list[str]:
    out = []
    x0, x1 = _PAD_LEFT, width - _PAD_RIGHT
    plot_h = height - _PAD_TOP - _PAD_BOTTOM
    for i in range(steps + 1):
        y = _PAD_TOP + plot_h - (plot_h * i / steps)
        value = round(top_value * i / steps)
        out.append(
            f'<line x1="{x0}" y1="{y:.1f}" x2="{x1}" y2="{y:.1f}" '
            f'stroke="var(--border-subtle)" stroke-width="1"/>'
        )
        out.append(
            f'<text x="{x0 - 8}" y="{y + 4:.1f}" text-anchor="end" '
            f'fill="var(--text-muted)" font-size="11">{value}</text>'
        )
    return out


def _bar(x: float, y: float, w: float, h: float, token: str, label: str) -> str:
    return (
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
        f'fill="var({token})" rx="2"><title>{escape(label)}</title></rect>'
    )


def _label(x: float, y: float, text: str, anchor: str = "middle",
           size: int = 11, token: str = "--text-muted") -> str:
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}" '
        f'fill="var({token})" font-size="{size}">{escape(text)}</text>'
    )


def generate_density_svg(conn: sqlite3.Connection, width: int = 900,
                         height: int = 240) -> str:
    """Event volume over time, bucketed by day."""
    rows = conn.execute(
        "SELECT substr(timestamp_utc, 1, 10) AS day, COUNT(*) AS n "
        "FROM events WHERE timestamp_utc IS NOT NULL "
        "GROUP BY day ORDER BY day"
    ).fetchall()
    if not rows:
        return _empty(width, height, "Event density over time")

    top = max(r[1] for r in rows)
    parts = _open(
        width, height,
        "Event density over time",
        f"Bar chart of event counts per day across {len(rows)} day(s); "
        f"peak {top} events.",
    )
    parts += _gridlines(width, height, 4, top)
    parts += _axes(width, height)

    plot_w = width - _PAD_LEFT - _PAD_RIGHT
    plot_h = height - _PAD_TOP - _PAD_BOTTOM
    slot = plot_w / len(rows)
    bar_w = max(1.0, slot * 0.7)

    for i, (day, count) in enumerate(rows):
        h = (count / top) * plot_h if top else 0
        x = _PAD_LEFT + slot * i + (slot - bar_w) / 2
        y = _PAD_TOP + plot_h - h
        parts.append(_bar(x, y, bar_w, h, "--accent-primary", f"{day}: {count} events"))

    # Label first, middle and last day only, so the axis never collides.
    for idx in sorted({0, len(rows) // 2, len(rows) - 1}):
        x = _PAD_LEFT + slot * idx + slot / 2
        parts.append(_label(x, height - _PAD_BOTTOM + 16, rows[idx][0]))

    parts.append("</svg>")
    return "\n".join(parts)


def severity_breakdown_svg(conn: sqlite3.Connection, width: int = 900,
                           height: int = 200) -> str:
    """How many findings sit at each severity."""
    counts = dict(
        conn.execute(
            "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
        ).fetchall()
    )
    ordered = [(s, counts.get(s, 0)) for s in _SEVERITY_ORDER]
    if not any(n for _, n in ordered):
        return _empty(width, height, "Findings by severity")

    top = max(n for _, n in ordered)
    parts = _open(
        width, height,
        "Findings by severity",
        "Horizontal bar chart of finding counts at each severity level: "
        + ", ".join(f"{s} {n}" for s, n in ordered) + ".",
    )

    row_h = (height - _PAD_TOP - _PAD_BOTTOM) / len(ordered)
    plot_w = width - _PAD_LEFT - _PAD_RIGHT

    for i, (sev, n) in enumerate(ordered):
        y = _PAD_TOP + row_h * i + row_h * 0.15
        h = row_h * 0.7
        w = (n / top) * plot_w if top else 0
        parts.append(_bar(_PAD_LEFT, y, w, h, f"--severity-{sev}",
                          f"{sev}: {n} finding(s)"))
        parts.append(_label(_PAD_LEFT - 8, y + h / 2 + 4, sev, anchor="end",
                            token="--text-secondary"))
        parts.append(_label(_PAD_LEFT + w + 8, y + h / 2 + 4, str(n),
                            anchor="start", token="--text-secondary"))

    parts.append("</svg>")
    return "\n".join(parts)


def user_activity_svg(conn: sqlite3.Connection, width: int = 900,
                      height: int = 280, limit: int = 10) -> str:
    """Which accounts generated the most recorded activity."""
    rows = conn.execute(
        "SELECT actor_user, COUNT(*) AS n FROM events "
        "WHERE actor_user IS NOT NULL AND actor_user != '' "
        "GROUP BY actor_user ORDER BY n DESC, actor_user ASC LIMIT ?",
        (limit,),
    ).fetchall()
    if not rows:
        return _empty(width, height, "Activity by account")

    top = max(r[1] for r in rows)
    parts = _open(
        width, height,
        "Activity by account",
        f"Horizontal bar chart of event counts for the {len(rows)} most "
        f"active account(s); highest {top} events.",
    )

    row_h = (height - _PAD_TOP - _PAD_BOTTOM) / len(rows)
    plot_w = width - _PAD_LEFT - _PAD_RIGHT

    for i, (user, n) in enumerate(rows):
        y = _PAD_TOP + row_h * i + row_h * 0.15
        h = row_h * 0.7
        w = (n / top) * plot_w if top else 0
        parts.append(_bar(_PAD_LEFT, y, w, h, "--accent-primary",
                          f"{user}: {n} events"))
        parts.append(_label(_PAD_LEFT - 8, y + h / 2 + 4, user, anchor="end",
                            token="--text-secondary"))
        parts.append(_label(_PAD_LEFT + w + 8, y + h / 2 + 4, str(n),
                            anchor="start", token="--text-secondary"))

    parts.append("</svg>")
    return "\n".join(parts)


def auth_failure_bursts_svg(conn: sqlite3.Connection, width: int = 900,
                            height: int = 240) -> str:
    """Failed authentication attempts per hour - the shape of a brute force."""
    rows = conn.execute(
        "SELECT substr(timestamp_utc, 1, 13) AS hour, COUNT(*) AS n "
        "FROM events WHERE timestamp_utc IS NOT NULL "
        "AND subcategory IN ('failed_login','invalid_user','auth_failure') "
        "GROUP BY hour ORDER BY hour"
    ).fetchall()
    if not rows:
        return _empty(width, height, "Authentication failures over time")

    top = max(r[1] for r in rows)
    parts = _open(
        width, height,
        "Authentication failures over time",
        f"Bar chart of failed authentication attempts per hour across "
        f"{len(rows)} hour(s); peak {top} in a single hour.",
    )
    parts += _gridlines(width, height, 4, top)
    parts += _axes(width, height)

    plot_w = width - _PAD_LEFT - _PAD_RIGHT
    plot_h = height - _PAD_TOP - _PAD_BOTTOM
    slot = plot_w / len(rows)
    bar_w = max(1.0, slot * 0.7)

    for i, (hour, count) in enumerate(rows):
        h = (count / top) * plot_h if top else 0
        x = _PAD_LEFT + slot * i + (slot - bar_w) / 2
        y = _PAD_TOP + plot_h - h
        parts.append(_bar(x, y, bar_w, h, "--severity-high",
                          f"{hour}:00 - {count} failure(s)"))

    for idx in sorted({0, len(rows) // 2, len(rows) - 1}):
        x = _PAD_LEFT + slot * idx + slot / 2
        parts.append(_label(x, height - _PAD_BOTTOM + 16,
                            rows[idx][0].replace("T", " ") + ":00"))

    parts.append("</svg>")
    return "\n".join(parts)
