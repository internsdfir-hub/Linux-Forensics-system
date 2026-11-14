"""Executive summary as structured data (spec Task 6.4, revised).

Returns fields the template renders with escaping on. The previous version
emitted Markdown into an autoescaped template, so generated reports displayed
literal asterisks - **CASE-205** rather than a bold case id.

Deterministic by construction: no clock, no randomness, and findings are
consumed in the order the data layer produced them.
"""
from __future__ import annotations

_ACTIONABLE = ("high", "medium")
_MAX_OBSERVATIONS = 5
_MAX_ACTIONS = 5


def _observations(findings: list[dict], severity: str) -> list[dict]:
    return [
        {
            "title": f["title"],
            "what_happened": f["what_happened"],
            "why_it_matters": f["why_it_matters"],
        }
        for f in findings
        if f["severity"] == severity
    ][:_MAX_OBSERVATIONS]


def generate_executive_summary(summary: dict, findings: list[dict]) -> dict:
    """Build the executive summary block.

    Returns a dict with 'headline', 'key_observations' and
    'recommended_actions'. No field contains markup of any kind.
    """
    counts = summary["severity_counts"]
    high, medium = counts["high"], counts["medium"]
    events = summary["event_count"]
    case_id = summary["case_id"]

    if high:
        headline = (
            f"Examination of case {case_id} identified {high} high-severity "
            f"finding(s) and {medium} medium-severity indicator(s) across "
            f"{events:,} normalised events. The evidence points to targeted "
            f"activity or a significant misconfiguration, and warrants "
            f"immediate review."
        )
    elif medium:
        headline = (
            f"Examination of case {case_id} identified {medium} "
            f"medium-severity indicator(s) across {events:,} normalised "
            f"events. No high-severity compromise was detected, but the "
            f"activity below is abnormal enough to warrant analyst review."
        )
    else:
        headline = (
            f"Examination of case {case_id} processed {events:,} normalised "
            f"events. No high or medium-severity indicators were identified "
            f"in the collected evidence."
        )

    key_observations = _observations(findings, "high")
    if not key_observations:
        # A medium-only case still contributes recommended actions, so it
        # needs observations explaining them - otherwise the report tells
        # an analyst what to do without saying why. This fallback never
        # fires when high-severity findings exist, so a high-severity
        # report stays focused on what matters.
        key_observations = _observations(findings, "medium")

    recommended_actions: list[str] = []
    seen: set[str] = set()
    for f in findings:
        if f["severity"] not in _ACTIONABLE:
            continue
        step = (f.get("check_next") or "").strip()
        if not step:
            continue
        # Apostrophes are stripped only to collapse quoting variations of
        # the same advice (e.g. "the 'admin' account" vs "the admin
        # account"). Case is preserved: Linux usernames are case-sensitive,
        # so 'admin' and 'Admin' are different accounts and must each keep
        # their own recommendation.
        key = step.replace("'", "")
        if key in seen:
            continue
        seen.add(key)
        recommended_actions.append(step)
        if len(recommended_actions) == _MAX_ACTIONS:
            break

    return {
        "headline": headline,
        "key_observations": key_observations,
        "recommended_actions": recommended_actions,
    }
