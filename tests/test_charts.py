"""Chart vocabulary: pure-Python SVG, deterministic, accessible.

No matplotlib and no charting library - decision D3 of the original project.
Determinism matters because a chart that changes between runs on identical
evidence undermines the tool's central claim.
"""
import re
import sqlite3

import pytest

from lfa import db
from lfa.report import chart

CHART_FUNCS = [
    chart.generate_density_svg,
    chart.severity_breakdown_svg,
    chart.user_activity_svg,
    chart.auth_failure_bursts_svg,
]


@pytest.fixture
def case(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "case.db")
    events = []
    for hour in range(6):
        for n in range(hour + 1):
            events.append(
                event_factory(
                    timestamp_utc=f"2024-03-14T{hour:02d}:{n:02d}:00+00:00",
                    actor_user=f"user{n % 3}",
                    subcategory="failed_login" if n % 2 else "successful_login",
                    severity=["info", "low", "medium", "high"][n % 4],
                    raw_line=f"line {hour}-{n}",
                )
            )
    db.insert_events(conn, events)
    conn.execute(
        "INSERT INTO findings (finding_id, case_id, rule_name, rule_version, "
        "severity, title, what_happened, why_it_matters, confidence, "
        "check_next, technical_detail, event_ids) "
        "VALUES ('f1','CASE-001','brute_force','1.0','high','T','w','y','High','c','t','[]')"
    )
    conn.commit()
    yield conn
    conn.close()


@pytest.mark.parametrize("func", CHART_FUNCS, ids=lambda f: f.__name__)
def test_chart_returns_a_complete_svg_element(case, func):
    svg = func(case)
    assert svg.lstrip().startswith("<svg")
    assert svg.rstrip().endswith("</svg>")


@pytest.mark.parametrize("func", CHART_FUNCS, ids=lambda f: f.__name__)
def test_chart_is_deterministic(case, func):
    assert func(case) == func(case)


def test_chart_output_is_stable_across_processes(case, tmp_path):
    """Determinism must hold across RUNS, not just within one process.

    Python salts str hashing per process and the salt is fixed for that
    process's lifetime, so comparing two calls inside one interpreter
    cannot catch a hash()-based id. Only a separate process can.
    """
    import subprocess
    import sys

    db_path = tmp_path / "case.db"

    script = (
        "import sqlite3, sys;"
        "from lfa.report import chart;"
        "conn = sqlite3.connect(sys.argv[1]);"
        "print(chart.generate_density_svg(conn))"
    )
    runs = [
        subprocess.run(
            [sys.executable, "-c", script, str(db_path)],
            capture_output=True, text=True, check=True,
        ).stdout
        for _ in range(2)
    ]
    assert runs[0] == runs[1]
    assert runs[0].strip(), "subprocess produced no SVG"


@pytest.mark.parametrize("func", CHART_FUNCS, ids=lambda f: f.__name__)
def test_chart_is_accessible(case, func):
    svg = func(case)
    assert 'role="img"' in svg
    assert "<title" in svg and "</title>" in svg
    assert "<desc" in svg and "</desc>" in svg


@pytest.mark.parametrize("func", CHART_FUNCS, ids=lambda f: f.__name__)
def test_chart_contains_no_raw_colour_literal(case, func):
    """Charts take colour from the token layer like everything else."""
    svg = func(case)
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", svg), (
        "charts must use var(--token) or currentColor, not hardcoded colour"
    )


@pytest.mark.parametrize("func", CHART_FUNCS, ids=lambda f: f.__name__)
def test_chart_survives_an_empty_case(tmp_path, func):
    conn = db.open_case(tmp_path / "empty.db")
    svg = func(conn)
    conn.close()
    assert svg.lstrip().startswith("<svg")
    assert "No data" in svg or "no data" in svg


def test_density_chart_labels_its_axis(case):
    svg = chart.generate_density_svg(case)
    assert "2024-03-14" in svg, "expected a dated axis label"


def test_severity_breakdown_labels_each_band(case):
    svg = chart.severity_breakdown_svg(case)
    for label in ("high", "medium", "low", "info"):
        assert label in svg.lower()


def test_user_activity_respects_its_limit(case):
    """One bar per account, never more than the limit."""
    svg = chart.user_activity_svg(case, limit=2)
    assert svg.count("<rect") == 2, "expected exactly one bar per account"


# --- Real-evidence defects (found in Task 8's inspection) --------------------
#
# The bar charts reserved a fixed 56px left gutter, which was sized for the
# short numeric y-axis labels of the time-series charts. The horizontal bar
# charts reuse that gutter for arbitrary-length account names, so on the real
# WSL/Kali bundle `backdooruser` - the one account an examiner most needs to
# read - was right-anchored at x=48 and ran off the left edge of the canvas.

def _end_anchored_labels(svg):
    """Every category label, as (anchor_x, text). These extend LEFTWARD."""
    return [
        (float(x), text)
        for x, text in re.findall(
            r'<text[^>]*\sx="([\d.]+)"[^>]*text-anchor="end"[^>]*>([^<]*)</text>',
            svg,
        )
    ]


@pytest.fixture
def long_name_case(tmp_path, event_factory):
    """One account whose name is far wider than the old fixed gutter."""
    conn = db.open_case(tmp_path / "case.db")
    db.insert_events(conn, [
        event_factory(
            timestamp_utc=f"2024-03-14T00:{n:02d}:00+00:00",
            actor_user="backdooruser" if n % 2 else "root",
            raw_line=f"line {n}",
        )
        for n in range(10)
    ])
    conn.commit()
    yield conn
    conn.close()


def test_text_width_estimate_grows_with_the_string():
    assert chart._text_width("backdooruser") > chart._text_width("root")
    # A sanity floor: no real sans font is narrower than 5px/char at size 11,
    # so an estimate below this would under-reserve the gutter.
    assert chart._text_width("backdooruser") >= 5 * len("backdooruser")


def test_account_labels_are_not_clipped_off_the_left_edge(long_name_case):
    svg = chart.user_activity_svg(long_name_case)
    for x, text in _end_anchored_labels(svg):
        assert x - chart._text_width(text) >= 0, (
            f"label {text!r} anchored at x={x} runs off the left edge"
        )


def test_severity_labels_are_not_clipped_off_the_left_edge(case):
    svg = chart.severity_breakdown_svg(case)
    for x, text in _end_anchored_labels(svg):
        assert x - chart._text_width(text) >= 0


def test_a_pathological_account_name_does_not_starve_the_bars(tmp_path,
                                                              event_factory):
    """A 32-char name is legal on Linux. The gutter must cap, not consume."""
    conn = db.open_case(tmp_path / "case.db")
    db.insert_events(conn, [
        event_factory(timestamp_utc="2024-03-14T00:00:00+00:00",
                      actor_user="a" * 32, raw_line="x")
    ])
    conn.commit()
    svg = chart.user_activity_svg(conn, width=900)
    conn.close()

    origins = [float(x) for x in re.findall(r'<rect[^>]*\sx="([\d.]+)"', svg)]
    assert origins, "the chart must still draw a bar"
    assert max(origins) <= 900 * 0.5, (
        "the label gutter must be capped so bars keep at least half the canvas"
    )


def test_an_over_long_label_is_truncated_but_survives_in_the_tooltip(
        tmp_path, event_factory):
    conn = db.open_case(tmp_path / "case.db")
    db.insert_events(conn, [
        event_factory(timestamp_utc="2024-03-14T00:00:00+00:00",
                      actor_user="a" * 60, raw_line="x")
    ])
    conn.commit()
    svg = chart.user_activity_svg(conn, width=900)
    conn.close()

    labels = [t for _, t in _end_anchored_labels(svg)]
    assert any(t.endswith("…") for t in labels), "expected an ellipsis"
    assert "a" * 60 in svg, "the untruncated name must remain in the <title>"
