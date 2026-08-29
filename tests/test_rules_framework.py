"""Rule framework (spec 2.8.1).

Every rule returns BOTH technical_detail and a plain_summary with the four
keys from spec 1.7. A rule that cannot produce a plain-English line does
not ship - and that is enforced by the interface, not by review."""
import pytest

from lfa import db
from lfa.rules.base import BaseRule, Finding, PlainSummary, RuleRun, discover_rules


def test_plain_summary_requires_all_four_fields():
    with pytest.raises(ValueError):
        PlainSummary(what_happened="", why_it_matters="b", confidence="High",
                     check_next="d")
    with pytest.raises(ValueError):
        PlainSummary(what_happened="a", why_it_matters="", confidence="High",
                     check_next="d")
    with pytest.raises(ValueError):
        PlainSummary(what_happened="a", why_it_matters="b", confidence="",
                     check_next="d")
    with pytest.raises(ValueError):
        PlainSummary(what_happened="a", why_it_matters="b", confidence="High",
                     check_next="")
    ok = PlainSummary("a", "b", "High", "d")
    assert ok.confidence == "High"


def test_confidence_must_be_a_defensible_word():
    with pytest.raises(ValueError):
        PlainSummary("a", "b", "87.4%", "d")


def test_finding_requires_technical_detail():
    summary = PlainSummary("a", "b", "High", "d")
    with pytest.raises(ValueError):
        Finding(rule_name="r", rule_version="1", severity="high", title="t",
                plain=summary, technical_detail="", event_ids=["x"])


def test_finding_id_is_deterministic():
    summary = PlainSummary("a", "b", "High", "d")
    kwargs = dict(rule_name="r", rule_version="1", severity="high", title="t",
                  plain=summary, technical_detail="detail", event_ids=["b", "a"])
    f1 = Finding(**kwargs)
    f2 = Finding(**kwargs)
    assert f1.finding_id == f2.finding_id
    # event id ordering must not change the identity
    f3 = Finding(**{**kwargs, "event_ids": ["a", "b"]})
    assert f1.finding_id == f3.finding_id


def test_severity_validated():
    summary = PlainSummary("a", "b", "High", "d")
    with pytest.raises(ValueError):
        Finding(rule_name="r", rule_version="1", severity="catastrophic",
                title="t", plain=summary, technical_detail="d", event_ids=[])


def test_rules_are_discovered():
    rules = discover_rules()
    assert rules, "no rules discovered"
    names = {r.name for r in rules}
    assert "brute_force" in names
    for rule in rules:
        assert rule.name and rule.version


def test_rule_errors_are_isolated(tmp_path, event_factory):
    class _Boom(BaseRule):
        name = "boom_rule"
        version = "1.0"

        def run(self, conn, ctx):
            raise RuntimeError("rule exploded")
            yield  # pragma: no cover

    class _Fine(BaseRule):
        name = "fine_rule"
        version = "1.0"

        def run(self, conn, ctx):
            yield Finding(
                rule_name=self.name, rule_version=self.version, severity="low",
                title="ok", plain=PlainSummary("a", "b", "High", "d"),
                technical_detail="d", event_ids=[],
            )

    conn = db.open_case(tmp_path / "case.db")
    run = RuleRun(rules=[_Boom(), _Fine()], errors_log=tmp_path / "rule_errors.log")
    findings = run.run_all(conn, ctx={})
    assert [f.rule_name for f in findings] == ["fine_rule"]
    assert "rule exploded" in (tmp_path / "rule_errors.log").read_text()
    assert run.stats["boom_rule"]["fail"] == 1
    conn.close()


def test_findings_persist_and_reload(tmp_path):
    conn = db.open_case(tmp_path / "case.db")
    finding = Finding(
        rule_name="r", rule_version="1", severity="high", title="t",
        plain=PlainSummary("what", "why", "High", "next"),
        technical_detail="detail", event_ids=["e1", "e2"],
        first_ts_utc="2024-03-14T02:19:07+00:00", host_id="H1",
    )
    from lfa.rules.base import save_findings

    save_findings(conn, [finding], case_id="C1")
    save_findings(conn, [finding], case_id="C1")  # idempotent
    rows = conn.execute("SELECT rule_name, severity, what_happened, event_ids "
                        "FROM findings").fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "r"
    assert rows[0][2] == "what"
    assert "e1" in rows[0][3]
    conn.close()
