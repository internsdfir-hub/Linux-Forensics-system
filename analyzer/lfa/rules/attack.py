"""Attack-behaviour correlation rules (spec 2.8.1).

Every rule here is deliberately simple and explainable, because an
investigator has to be able to defend the reasoning in front of someone
who disagrees. No machine learning: each finding names the rule, the
threshold, and the exact events it fired on.

Nothing in here concludes. It flags things for a human to judge.
"""
from __future__ import annotations

import re
import sqlite3
from collections import defaultdict
from datetime import timedelta

from .base import BaseRule, Finding, PlainSummary, events_within, parse_ts

# Rules never fire on our own collection session (P1b contamination record).
NOT_OURS = "COALESCE(tool_generated_flag, 0) = 0"


def _rows(conn, sql, params=()):
    conn.row_factory = sqlite3.Row
    return conn.execute(sql, params).fetchall()


class BruteForceRule(BaseRule):
    """N failed logins from one source IP inside a rolling window."""

    name = "brute_force"
    version = "1.0"
    parameters = {"min_failures": 5, "window_minutes": 5}

    def run(self, conn, ctx):
        min_failures = ctx.get("brute_force_min", self.parameters["min_failures"])
        window = timedelta(minutes=ctx.get("brute_force_window",
                                           self.parameters["window_minutes"]))

        rows = _rows(
            conn,
            f"SELECT * FROM events WHERE subcategory IN "
            f"('failed_login','invalid_user','auth_failure') "
            f"AND source_ip IS NOT NULL AND timestamp_utc IS NOT NULL "
            f"AND {NOT_OURS} ORDER BY source_ip, timestamp_utc",
        )
        by_ip: dict[str, list] = defaultdict(list)
        for row in rows:
            by_ip[row["source_ip"]].append(row)

        for ip, attempts in sorted(by_ip.items()):
            # slide a window across this IP's failures
            start = 0
            best: list | None = None
            for end in range(len(attempts)):
                end_ts = parse_ts(attempts[end]["timestamp_utc"])
                while start < end and end_ts - parse_ts(
                    attempts[start]["timestamp_utc"]
                ) > window:
                    start += 1
                burst = attempts[start:end + 1]
                if len(burst) >= min_failures and (best is None or len(burst) > len(best)):
                    best = burst
            if not best:
                continue

            # report the whole contiguous campaign, not just the peak window
            campaign = attempts
            users = sorted({a["actor_user"] for a in campaign if a["actor_user"]})
            first = campaign[0]["timestamp_utc"]
            last = campaign[-1]["timestamp_utc"]
            host = campaign[0]["host_id"]

            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="medium",
                title=f"Repeated failed logins from {ip}",
                plain=PlainSummary(
                    what_happened=(
                        f"There were {len(campaign)} failed login attempts from "
                        f"the address {ip} between {_short(first)} and "
                        f"{_short(last)}, against "
                        + (f"the account {users[0]}" if len(users) == 1
                           else f"{len(users)} different accounts")
                        + "."
                    ),
                    why_it_matters=(
                        "A rapid run of failed logins from a single address is "
                        "what password guessing looks like. On its own it means "
                        "someone tried; whether they succeeded is answered by "
                        "the events immediately after."
                    ),
                    confidence="High",
                    check_next=(
                        f"Confirm whether {ip} belongs to your organisation, and "
                        f"check whether any login from it succeeded afterwards."
                    ),
                ),
                technical_detail=(
                    f"rule={self.name} v{self.version}; threshold >= "
                    f"{min_failures} failures within "
                    f"{self.parameters['window_minutes']} minutes; peak window "
                    f"held {len(best)} attempts. source_ip={ip}; total "
                    f"attempts={len(campaign)}; usernames attempted="
                    f"{', '.join(users) if users else 'none recorded'}; "
                    f"window {first} .. {last}."
                ),
                event_ids=[r["event_id"] for r in campaign],
                first_ts_utc=first,
                last_ts_utc=last,
                host_id=host,
            )


class BruteForceSuccessRule(BaseRule):
    """A successful login from the same IP right after a burst of failures.
    This is the single most important correlation in the whole tool."""

    name = "brute_force_success"
    version = "1.0"
    parameters = {"min_failures": 5, "window_minutes": 5, "success_within_minutes": 10}

    def run(self, conn, ctx):
        min_failures = ctx.get("brute_force_min", self.parameters["min_failures"])
        window = self.parameters["window_minutes"]
        after = self.parameters["success_within_minutes"]

        successes = _rows(
            conn,
            f"SELECT * FROM events WHERE subcategory='successful_login' "
            f"AND source_ip IS NOT NULL AND timestamp_utc IS NOT NULL "
            f"AND {NOT_OURS} ORDER BY timestamp_utc",
        )
        for success in successes:
            ip = success["source_ip"]
            ts = parse_ts(success["timestamp_utc"])
            if ts is None:
                continue
            lo = (ts - timedelta(minutes=window + after)).isoformat()
            prior = _rows(
                conn,
                f"SELECT * FROM events WHERE subcategory IN "
                f"('failed_login','invalid_user','auth_failure') "
                f"AND source_ip = ? AND timestamp_utc >= ? AND timestamp_utc < ? "
                f"AND {NOT_OURS} ORDER BY timestamp_utc",
                (ip, lo, success["timestamp_utc"]),
            )
            if len(prior) < min_failures:
                continue

            user = success["actor_user"] or "an account"
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="high",
                title=f"Successful login from {ip} immediately after repeated failures",
                plain=PlainSummary(
                    what_happened=(
                        f"After {len(prior)} failed attempts, the address {ip} "
                        f"logged in successfully as {user} at "
                        f"{_short(success['timestamp_utc'])}."
                    ),
                    why_it_matters=(
                        "A successful login straight after many failures usually "
                        "means the password was guessed. From this point on, "
                        "anything this account did should be treated as "
                        "potentially the intruder's actions."
                    ),
                    confidence="High",
                    check_next=(
                        f"Confirm whether anyone legitimately uses {user} from "
                        f"{ip} at that time of day, and review everything that "
                        f"account did afterwards. If in doubt, reset its "
                        f"credentials and revoke its SSH keys."
                    ),
                ),
                technical_detail=(
                    f"rule={self.name} v{self.version}; {len(prior)} failures "
                    f"from {ip} within {window + after} minutes before a "
                    f"successful login at {success['timestamp_utc']}; "
                    f"account={user}; success event_id={success['event_id']}; "
                    f"source artifact={success['source_artifact_path']}."
                ),
                event_ids=[success["event_id"]] + [r["event_id"] for r in prior],
                first_ts_utc=prior[0]["timestamp_utc"],
                last_ts_utc=success["timestamp_utc"],
                host_id=success["host_id"],
            )


class NewAccountPrivilegeGrantRule(BaseRule):
    """An account created, then given administrator rights minutes later."""

    name = "new_account_privilege_grant"
    version = "1.0"
    parameters = {"window_minutes": 60}

    def run(self, conn, ctx):
        window = ctx.get("account_grant_window", self.parameters["window_minutes"])
        creations = _rows(
            conn,
            f"SELECT * FROM events WHERE subcategory='account_created' "
            f"AND timestamp_utc IS NOT NULL AND {NOT_OURS} ORDER BY timestamp_utc",
        )
        for created in creations:
            user = created["actor_user"]
            if not user:
                continue
            grants = [
                r for r in events_within(
                    conn, created["timestamp_utc"], window,
                    subcategory__in=("group_membership_added",
                                     "group_added",
                                     "privileged_group_member",
                                     "passwordless_sudo",
                                     "sudo_privilege"),
                )
                if r["actor_user"] == user
                and (parse_ts(r["timestamp_utc"]) or parse_ts(created["timestamp_utc"]))
                >= parse_ts(created["timestamp_utc"])
            ]
            if not grants:
                continue
            first_grant = grants[0]
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="high",
                title=f"Account {user} was created and given administrator rights",
                plain=PlainSummary(
                    what_happened=(
                        f"The account {user} was created at "
                        f"{_short(created['timestamp_utc'])} and was given "
                        f"administrator rights at "
                        f"{_short(first_grant['timestamp_utc'])}."
                    ),
                    why_it_matters=(
                        "Creating an account and immediately promoting it to "
                        "administrator is how an intruder keeps access after "
                        "the way they originally got in is closed. Legitimate "
                        "account creation is usually separated from privilege "
                        "changes by a ticket and some time."
                    ),
                    confidence="High",
                    check_next=(
                        f"Ask whether {user} was requested by anyone, and check "
                        f"who was logged in at the time it was created. If "
                        f"nobody claims it, disable the account rather than "
                        f"deleting it, so the evidence survives."
                    ),
                ),
                technical_detail=(
                    f"rule={self.name} v{self.version}; window="
                    f"{window} minutes; creation event_id={created['event_id']} "
                    f"at {created['timestamp_utc']}; grant event_id="
                    f"{first_grant['event_id']} at {first_grant['timestamp_utc']} "
                    f"(subcategory={first_grant['subcategory']})."
                ),
                event_ids=[created["event_id"]] + [g["event_id"] for g in grants],
                first_ts_utc=created["timestamp_utc"],
                last_ts_utc=grants[-1]["timestamp_utc"],
                host_id=created["host_id"],
            )


class PersistenceAfterLoginRule(BaseRule):
    """A scheduled job, systemd timer or SSH key created near a suspicious
    login. Of all categories this is the one investigators most often
    under-check, and it answers whether the problem is actually over."""

    name = "persistence_after_login"
    version = "1.0"
    parameters = {"window_minutes": 120}

    PERSISTENCE_SUBS = (
        "cron_job", "suspicious_cron_job", "cron_job_added",
        "systemd_unit", "systemd_timer", "suspicious_systemd_unit",
        "authorized_key", "authorized_key_added",
        "suspicious_startup_line", "ld_preload_set",
    )

    def run(self, conn, ctx):
        window = ctx.get("persistence_window", self.parameters["window_minutes"])
        anchors = _rows(
            conn,
            f"SELECT * FROM events WHERE subcategory='successful_login' "
            f"AND timestamp_utc IS NOT NULL AND {NOT_OURS} "
            f"AND (severity IN ('medium','high') OR source_ip IS NOT NULL) "
            f"ORDER BY timestamp_utc",
        )
        # only anchor on logins the attack rules already consider interesting
        suspicious_ips = {
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT source_ip FROM events WHERE subcategory IN "
                "('failed_login','invalid_user') AND source_ip IS NOT NULL "
                "GROUP BY source_ip HAVING COUNT(*) >= 5"
            )
        }
        seen: set[str] = set()
        for login in anchors:
            if login["source_ip"] not in suspicious_ips:
                continue
            nearby = [
                r for r in events_within(conn, login["timestamp_utc"], window,
                                         subcategory__in=self.PERSISTENCE_SUBS)
                if parse_ts(r["timestamp_utc"]) >= parse_ts(login["timestamp_utc"])
            ]
            # Also check persistence state findings with recent file mtimes
            placeholders = ",".join("?" for _ in self.PERSISTENCE_SUBS)
            state_items = _rows(
                conn,
                f"SELECT * FROM events WHERE subcategory IN ({placeholders}) AND timestamp_utc IS NULL",
                self.PERSISTENCE_SUBS,
            )
            login_dt = parse_ts(login["timestamp_utc"])
            for item in state_items:
                m = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?)", (item["description"] or "") + " " + (item["notes"] or ""))
                if m and login_dt:
                    m_dt = parse_ts(m.group(1))
                    if m_dt and abs((m_dt - login_dt).total_seconds()) <= window * 60:
                        nearby.append(item)

            if not nearby:
                continue
            key = f"{login['event_id']}"
            if key in seen:
                continue
            seen.add(key)
            kinds = sorted({r["subcategory"] for r in nearby})
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="high",
                title="A way back in was created shortly after a suspicious login",
                plain=PlainSummary(
                    what_happened=(
                        f"Within {window} minutes of the login from "
                        f"{login['source_ip']} at "
                        f"{_short(login['timestamp_utc'])}, "
                        f"{len(nearby)} persistence item(s) appeared: "
                        f"{', '.join(k.replace('_', ' ') for k in kinds)}."
                    ),
                    why_it_matters=(
                        "Anyone who breaks in wants to stay in. A scheduled job "
                        "or an added SSH key means closing the original hole is "
                        "not enough - the access survives a password reset and a "
                        "reboot. This is what decides whether the incident is "
                        "actually over."
                    ),
                    confidence="Medium",
                    check_next=(
                        "Review each item listed and confirm with the system "
                        "owner whether it is expected. Remove only after "
                        "recording it, because it is evidence."
                    ),
                ),
                technical_detail=(
                    f"rule={self.name} v{self.version}; window=+{window} minutes "
                    f"after login event_id={login['event_id']} "
                    f"({login['timestamp_utc']}, source_ip={login['source_ip']}); "
                    f"correlated persistence events: "
                    + "; ".join(
                        f"{r['subcategory']} @ {r['timestamp_utc']} "
                        f"[{r['source_artifact_path']}]" for r in nearby[:10]
                    )
                ),
                event_ids=[login["event_id"]] + [r["event_id"] for r in nearby],
                first_ts_utc=login["timestamp_utc"],
                last_ts_utc=nearby[-1]["timestamp_utc"],
                host_id=login["host_id"],
            )


class OffHoursPrivilegedRule(BaseRule):
    """Administrator activity outside working hours."""

    name = "off_hours_privileged"
    version = "1.0"
    parameters = {"business_hours": (8, 18)}

    def run(self, conn, ctx):
        start_h, end_h = ctx.get("business_hours", self.parameters["business_hours"])
        rows = _rows(
            conn,
            f"SELECT * FROM events WHERE category='privilege_escalation' "
            f"AND event_kind='event' AND timestamp_local IS NOT NULL "
            f"AND {NOT_OURS} ORDER BY timestamp_utc",
        )
        offenders: dict[str, list] = defaultdict(list)
        for row in rows:
            local = parse_ts(row["timestamp_local"])
            if local is None:
                continue
            if start_h <= local.hour < end_h:
                continue
            clean_u = (row["actor_user"] or "unknown").strip("'\"")
            offenders[clean_u].append(row)

        for user, hits in sorted(offenders.items()):
            first, last = hits[0]["timestamp_local"], hits[-1]["timestamp_local"]
            yield Finding(
                rule_name=self.name,
                rule_version=self.version,
                severity="medium" if len(hits) > 1 else "low",
                title=f"Administrator activity outside working hours by {user}",
                plain=PlainSummary(
                    what_happened=(
                        f"{user} used administrator privileges {len(hits)} "
                        f"time(s) outside the working day (before "
                        f"{start_h:02d}:00 or after {end_h:02d}:00 local time), "
                        f"between {_short(first)} and {_short(last)}."
                    ),
                    why_it_matters=(
                        "Administrator commands run outside the hours the "
                        "person normally works are worth a question. It is not "
                        "proof of anything on its own - on-call work looks the "
                        "same - but it narrows where to look."
                    ),
                    confidence="Medium",
                    check_next=(
                        f"Ask {user} whether they were working at those times, "
                        f"and compare against the on-call rota."
                    ),
                ),
                technical_detail=(
                    f"rule={self.name} v{self.version}; business hours "
                    f"{start_h:02d}:00-{end_h:02d}:00 local; {len(hits)} "
                    f"privilege_escalation events outside them; examples: "
                    + "; ".join(
                        f"{r['timestamp_local']} {r['subcategory']}: "
                        f"{r['description'][:80]}" for r in hits[:5]
                    )
                ),
                event_ids=[r["event_id"] for r in hits],
                first_ts_utc=hits[0]["timestamp_utc"],
                last_ts_utc=hits[-1]["timestamp_utc"],
                host_id=hits[0]["host_id"],
            )


def _short(ts: str | None) -> str:
    """Human-readable timestamp for the plain-language layer."""
    if not ts:
        return "an unknown time"
    parsed = parse_ts(ts)
    if parsed is None:
        return ts
    return parsed.strftime("%Y-%m-%d %H:%M")
