"""Attack-behaviour rules (spec 2.8.1) exercised against the synthetic
case, which contains a scripted incident with known ground truth."""
import pytest

from lfa import db
from lfa.rules.base import RuleRun, discover_rules
from tools.make_synthetic_case import build_case

ATTACKER_IP = "203.0.113.9"


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    base = tmp_path_factory.mktemp("attackcase")
    path = base / "case.db"
    ground_truth = build_case(path, seed=7)
    conn = db.open_case(path)
    rules = discover_rules()
    run = RuleRun(rules=rules, errors_log=base / "rule_errors.log")
    findings = run.run_all(conn, ctx={"business_hours": (8, 18)})
    yield conn, findings, ground_truth, run
    conn.close()


def by_rule(findings, name):
    return [f for f in findings if f.rule_name == name]


def test_no_rule_crashed(case):
    _, _, _, run = case
    failures = {n: s for n, s in run.stats.items() if s["fail"]}
    assert failures == {}, f"rules crashed: {failures}"


def test_brute_force_detected_with_username_list(case):
    _, findings, _, _ = case
    hits = by_rule(findings, "brute_force")
    assert hits, "brute force burst not detected"
    hit = next(f for f in hits if ATTACKER_IP in f.technical_detail)
    assert hit.severity in {"medium", "high"}
    assert "admin" in hit.technical_detail
    assert "47" in hit.technical_detail or "47" in hit.plain.what_happened
    # the plain layer must be readable by a manager
    assert ATTACKER_IP in hit.plain.what_happened
    assert hit.plain.confidence in {"High", "Medium", "Low"}
    assert len(hit.event_ids) >= 5


def test_successful_login_after_burst_is_high_severity(case):
    _, findings, _, _ = case
    hits = by_rule(findings, "brute_force_success")
    assert hits, "successful login after brute force not detected"
    hit = hits[0]
    assert hit.severity == "high"
    assert ATTACKER_IP in hit.plain.what_happened
    assert "guess" in hit.plain.why_it_matters.lower()


def test_new_account_then_privilege_grant(case):
    _, findings, gt, _ = case
    hits = by_rule(findings, "new_account_privilege_grant")
    assert hits
    assert "svc-backup" in hits[0].plain.what_happened
    assert hits[0].severity == "high"


def test_persistence_near_suspicious_login(case):
    _, findings, _, _ = case
    hits = by_rule(findings, "persistence_after_login")
    assert hits, "persistence created near a suspicious login not detected"
    detail = hits[0].technical_detail
    assert "cron" in detail.lower() or "authorized_key" in detail.lower()


def test_off_hours_privileged_activity(case):
    _, findings, _, _ = case
    hits = by_rule(findings, "off_hours_privileged")
    assert hits, "off-hours privileged activity not detected"
    assert "outside" in hits[0].plain.why_it_matters.lower() or \
           "hours" in hits[0].plain.why_it_matters.lower()


def test_first_seen_flags_the_attacker_ip(case):
    _, findings, _, _ = case
    hits = by_rule(findings, "first_seen")
    assert hits
    ips = {f.technical_detail for f in hits}
    assert any(ATTACKER_IP in d for d in ips)


def test_every_finding_carries_both_layers(case):
    _, findings, _, _ = case
    assert findings
    for f in findings:
        assert f.technical_detail.strip()
        assert f.plain.what_happened.strip()
        assert f.plain.why_it_matters.strip()
        assert f.plain.check_next.strip()
        assert f.plain.confidence in {"High", "Medium", "Low"}


def test_findings_are_deterministic(tmp_path):
    """Same case analysed twice must produce identical finding ids."""
    p1, p2 = tmp_path / "a.db", tmp_path / "b.db"
    build_case(p1, seed=11)
    build_case(p2, seed=11)
    out = []
    for p in (p1, p2):
        conn = db.open_case(p)
        run = RuleRun(rules=discover_rules(), errors_log=tmp_path / "e.log")
        out.append([f.finding_id for f in run.run_all(conn, ctx={})])
        conn.close()
    assert out[0] == out[1]


def test_tool_generated_events_are_never_findings(tmp_path, event_factory):
    """The collector's own session must not be reported as an intrusion."""
    conn = db.open_case(tmp_path / "case.db")
    events = []
    for i in range(12):
        events.append(
            event_factory(
                raw_line=f"tool fail {i}",
                raw_line_offset=i,
                subcategory="failed_login",
                source_ip="10.9.9.9",
                timestamp_utc=f"2024-03-14T02:{i:02d}:00+00:00",
                tool_generated_flag=True,
            )
        )
    db.insert_events(conn, events)
    run = RuleRun(rules=discover_rules(), errors_log=tmp_path / "e.log")
    findings = run.run_all(conn, ctx={})
    assert not [f for f in findings if "10.9.9.9" in f.technical_detail]
    conn.close()
