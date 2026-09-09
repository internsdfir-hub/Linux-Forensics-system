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
