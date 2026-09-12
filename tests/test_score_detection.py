"""Tests for tools/score_detection.py.

Ground-truth files now mix two kinds of threat: rule-backed (expected_rule
is a rule name) and evidence-only (expected_rule is null — e.g. USB insertion
or process execution, which the analyzer surfaces on the timeline but has no
dedicated finding for). Evidence-only items must not be scored as MISSED.
"""
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.score_detection import score_case


def _make_case(tmp_path, fired_rules):
    db = tmp_path / "case.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE findings (rule_name TEXT)")
    conn.executemany("INSERT INTO findings VALUES (?)",
                     [(r,) for r in fired_rules])
    conn.commit()
    conn.close()
    return tmp_path


def _gt(tmp_path, threats):
    p = tmp_path / "gt.json"
    p.write_text(json.dumps({"scenario_name": "t", "injected_threats": threats}),
                 encoding="utf-8")
    return p


def test_all_rule_backed_detected_returns_zero(tmp_path, capsys):
    case = _make_case(tmp_path, ["brute_force"])
    gt = _gt(tmp_path, [
        {"threat_id": "a", "expected_rule": "brute_force"},
    ])
    rc = score_case(case, gt)
    assert rc == 0


def test_evidence_only_item_is_not_a_miss(tmp_path, capsys):
    # expected_rule is null -> evidence layer -> must not fail the run
    case = _make_case(tmp_path, ["brute_force"])
    gt = _gt(tmp_path, [
        {"threat_id": "a", "expected_rule": "brute_force"},
        {"threat_id": "b", "expected_rule": None},
    ])
    rc = score_case(case, gt)
    out = capsys.readouterr().out
    assert rc == 0                      # evidence item did not fail the run
    assert "EVIDENCE" in out            # reported as its own class
    assert "MISS" not in out            # and NOT as a miss


def test_genuine_rule_miss_returns_one(tmp_path, capsys):
    case = _make_case(tmp_path, ["brute_force"])
    gt = _gt(tmp_path, [
        {"threat_id": "a", "expected_rule": "wiped_history"},  # not fired
    ])
    rc = score_case(case, gt)
    assert rc == 1
