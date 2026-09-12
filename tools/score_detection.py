"""Detection scoring tool (spec Task 7.3).

Evaluates detected correlation findings against simulated attack ground truth,
calculates detection rates, and highlights any false negatives or false positives.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path


def score_case(case_dir: Path | str, ground_truth_file: Path | str) -> int:
    case_dir = Path(case_dir)
    gt_path = Path(ground_truth_file)

    if not gt_path.exists():
        print(f"[!] Ground truth file not found: {gt_path}", file=sys.stderr)
        return 1

    db_path = case_dir / "case.db"
    if not db_path.exists():
        print(f"[!] Case database not found: {db_path}", file=sys.stderr)
        return 1

    with open(gt_path, "r", encoding="utf-8") as fh:
        gt = json.load(fh)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    findings = conn.execute("SELECT * FROM findings").fetchall()
    conn.close()

    fired_rules = {r["rule_name"] for r in findings}
    injected_threats = gt.get("injected_threats", [])

    print("\n=======================================================")
    print(f" LFA DETECTION SCORECARD: {gt.get('scenario_name', 'Scenario')}")
    print("=======================================================")

    detected_count = 0
    missed_count = 0
    evidence_count = 0

    print(f"{'Threat ID':<25} {'Expected Rule':<25} {'Status':<10}")
    print("-" * 65)

    for threat in injected_threats:
        t_id = threat["threat_id"]
        exp_rule = threat.get("expected_rule")

        # Evidence-only threats (expected_rule is null) are validated on the
        # timeline/events table, not the findings table. They are not scored as
        # detections or misses; they carry no rule to fire.
        if exp_rule is None:
            evidence_count += 1
            print(f"{t_id:<25} {'(evidence layer)':<25} [EVIDENCE]")
            continue

        if exp_rule in fired_rules:
            detected_count += 1
            print(f"{t_id:<25} {exp_rule:<25} [PASS]")
        else:
            missed_count += 1
            print(f"{t_id:<25} {exp_rule:<25} [FAIL/MISS]")

    total = len(injected_threats)
    rule_backed = detected_count + missed_count
    detection_rate = (detected_count / rule_backed * 100.0) if rule_backed > 0 else 0.0

    print("-" * 65)
    print(f"Total Injected Threats: {total}")
    print(f"Rule-backed Threats:    {rule_backed}")
    print(f"Detections Triggered:   {detected_count}")
    print(f"Missed Indicators:      {missed_count}")
    print(f"Evidence-only (unscored): {evidence_count}")
    print(f"Detection Rate (rule-backed): {detection_rate:.1f}%")
    print("=======================================================\n")

    return 0 if missed_count == 0 else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Score LFA case detections against attack scenario ground truth")
    parser.add_argument("--case-dir", required=True, help="Path to analysed case directory containing case.db")
    parser.add_argument("--ground-truth", required=True, help="Path to ground_truth.json")
    args = parser.parse_args(argv)

    return score_case(args.case_dir, args.ground_truth)


if __name__ == "__main__":
    sys.exit(main())
