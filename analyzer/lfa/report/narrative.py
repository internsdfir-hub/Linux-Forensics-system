"""Deterministic narrative timeline and executive summary generator (spec Task 6.4).

Synthesizes plain-language findings into a readable executive briefing and structured
chronological incident narrative without stochastic LLM dependencies.
"""
from __future__ import annotations

import sqlite3


def generate_executive_summary(summary: dict, findings: list[dict]) -> str:
    high_count = summary["severity_counts"]["high"]
    med_count = summary["severity_counts"]["medium"]
    low_count = summary["severity_counts"]["low"]
    total_events = summary["event_count"]
    total_findings = summary["finding_count"]

    paragraphs = []

    # Opening statement
    if high_count > 0:
        paragraphs.append(
            f"Forensic examination of case **{summary['case_id']}** identified **{high_count} critical/high-severity security finding(s)** "
            f"and **{med_count} medium-severity indicator(s)** across {total_events:,} ingested log and system artifacts. "
            f"Evidence indicates targeted adversarial activity or significant security misconfigurations requiring immediate investigative remediation."
        )
    elif med_count > 0:
        paragraphs.append(
            f"Forensic examination of case **{summary['case_id']}** identified **{med_count} medium-severity security indicator(s)** "
            f"across {total_events:,} normalized system events. No confirmed high-severity compromise was detected, but abnormal activity warrants analyst review."
        )
    else:
        paragraphs.append(
            f"Forensic analysis of case **{summary['case_id']}** processed {total_events:,} events. "
            f"No high or medium-severity adversarial indicators were identified within the collected evidence artifacts."
        )

    # Key findings breakdown
    high_findings = [f for f in findings if f["severity"] == "high"]
    if high_findings:
        bullets = []
        for f in high_findings[:5]:
            bullets.append(f"- **{f['title']}**: {f['what_happened']} ({f['why_it_matters']})")
        paragraphs.append("**Key Critical Observations:**\n" + "\n".join(bullets))

    # Recommended next steps summary
    next_steps = set()
    for f in findings:
        if f["severity"] in ("high", "medium") and f.get("check_next"):
            next_steps.add(f["check_next"])

    if next_steps:
        steps_list = [f"1. {step}" for step in sorted(next_steps)[:4]]
        paragraphs.append("**Immediate Recommended Actions:**\n" + "\n".join(steps_list))

    return "\n\n".join(paragraphs)
