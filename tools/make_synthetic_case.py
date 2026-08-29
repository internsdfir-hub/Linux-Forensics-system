"""Synthetic case generator (spec 2.10 'unblocking trick').

Emits a few thousand plausible NormalizedEvents - background noise across
all categories plus one scripted attack - into a case DB, and writes the
attack's ground truth JSON next to it. Fully deterministic under a seed so
it doubles as a determinism fixture.

Usage: python tools/make_synthetic_case.py --out case.db --seed 42
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from lfa import db
from lfa.schema import make_event

CASE_ID = "SYNTH-001"
HOST_ID = "synth-host-0001"
TZ_NAME = "Asia/Karachi"
AUTH_LOG = "var/log/auth.log"
AUTH_SHA = "b" * 64

LEGIT_USERS = ["alice", "bob", "deploy", "www-data"]
LEGIT_IPS = ["10.0.0.5", "10.0.0.9", "192.168.1.20"]
ATTACKER_IP = "203.0.113.9"
ATTACKER_USER = "svc-backup"

BASE = datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc)


def _ts(dt: datetime) -> tuple[str, str]:
    local = dt.astimezone(ZoneInfo(TZ_NAME))
    return dt.isoformat(), local.isoformat()


class _Emitter:
    def __init__(self):
        self.events = []
        self._offset = 0

    def emit(self, dt, category, subcategory, description, *, severity="info",
             user=None, uid=None, process=None, ip=None, raw=None,
             artifact=AUTH_LOG, sha=AUTH_SHA, kind="event"):
        utc, local = _ts(dt) if dt is not None else (None, None)
        self._offset += 80
        self.events.append(
            make_event(
                case_id=CASE_ID,
                host_id=HOST_ID,
                event_kind=kind,
                timestamp_utc=utc,
                timestamp_local=local,
                timestamp_tz=TZ_NAME,
                tz_source="etc_localtime",
                timestamp_confidence="exact" if dt is not None else "unknown",
                category=category,
                subcategory=subcategory,
                actor_user=user,
                actor_uid=uid,
                actor_process=process,
                source_ip=ip,
                source_host=None,
                description=description,
                severity=severity,
                source_artifact_path=artifact,
                source_artifact_sha256=sha,
                raw_line=raw or description,
                raw_line_offset=self._offset,
                parser_name="synthetic",
                parser_version="1.0",
                tool_generated_flag=False,
                notes=None,
            )
        )


def _background(em: _Emitter, rng: random.Random) -> None:
    """14 days of ordinary server life."""
    for day in range(14):
        day_base = BASE + timedelta(days=day)
        for _ in range(rng.randint(60, 90)):
            dt = day_base + timedelta(
                hours=rng.uniform(7.5, 20.0), seconds=rng.randint(0, 59)
            )
            user = rng.choice(LEGIT_USERS[:2])
            ip = rng.choice(LEGIT_IPS)
            em.emit(dt, "login_activity", "successful_login",
                    f"Accepted publickey for {user} from {ip}",
                    user=user, ip=ip, process="sshd",
                    raw=f"Accepted publickey for {user} from {ip} port 51234 ssh2")
            if rng.random() < 0.4:
                em.emit(dt + timedelta(minutes=rng.randint(1, 30)),
                        "privilege_escalation", "sudo_command",
                        f"{user} ran sudo command",
                        user=user, process="sudo", severity="info",
                        raw=f"sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; "
                            f"USER=root ; COMMAND=/usr/bin/systemctl status nginx")
        # sporadic noise across the other categories
        for _ in range(rng.randint(60, 100)):
            dt = day_base + timedelta(hours=rng.uniform(0, 24))
            choice = rng.random()
            if choice < 0.25:
                pkg = rng.choice(["libssl3", "vim", "curl", "nginx", "htop"])
                em.emit(dt, "software_changes", "package_upgrade",
                        f"upgrade {pkg}", process="dpkg",
                        artifact="var/log/dpkg.log", sha="c" * 64)
            elif choice < 0.45:
                em.emit(dt, "persistence", "cron_run",
                        "CRON session for root", user="root", process="cron",
                        artifact="var/log/syslog", sha="d" * 64)
            elif choice < 0.6:
                em.emit(dt, "hardware_usb", "usb_connect",
                        "USB device 0781:5567 SanDisk Cruzer Blade connected",
                        artifact="var/log/kern.log", sha="e" * 64)
            elif choice < 0.75:
                em.emit(dt, "network_config", "firewall_block",
                        f"UFW BLOCK from {rng.choice(LEGIT_IPS)}",
                        artifact="var/log/ufw.log", sha="f" * 64)
            elif choice < 0.9:
                user = rng.choice(LEGIT_USERS[:2])
                em.emit(dt, "user_activity", "shell_command",
                        f"{user}: ls -la /var/www", user=user,
                        artifact=f"home/{user}/.bash_history", sha="9" * 64)
            else:
                em.emit(dt, "login_activity", "failed_login",
                        f"Failed password for {rng.choice(LEGIT_USERS)} "
                        f"from {rng.choice(LEGIT_IPS)}",
                        user=rng.choice(LEGIT_USERS),
                        ip=rng.choice(LEGIT_IPS), process="sshd",
                        severity="low")
    # a handful of stable state findings
    em.emit(None, "user_accounts", "account_state",
            "Account root has UID 0", user="root", uid=0,
            artifact="etc/passwd", sha="1" * 64, kind="state_finding")
    em.emit(None, "network_config", "listening_port",
            "sshd listening on 0.0.0.0:22", process="sshd",
            artifact="volatile/ss.txt", sha="2" * 64, kind="state_finding")


def _attack(em: _Emitter) -> list[dict]:
    """The scripted incident: brute force at 02:14, success 02:19, account
    creation, privilege grant, key drop, cron persistence, history wipe."""
    gt: list[dict] = []
    attack_day = BASE + timedelta(days=9)  # 2024-03-10
    burst_start = attack_day + timedelta(hours=2, minutes=14)

    for i in range(47):
        dt = burst_start + timedelta(seconds=i * 6)
        em.emit(dt, "login_activity", "failed_login",
                f"Failed password for admin from {ATTACKER_IP}",
                user="admin", ip=ATTACKER_IP, process="sshd", severity="low",
                raw=f"Failed password for admin from {ATTACKER_IP} port "
                    f"{40000 + i} ssh2")
    gt.append({
        "kind": "brute_force_burst", "source_ip": ATTACKER_IP,
        "user": "admin", "count": 47,
        "start_utc": burst_start.isoformat(),
    })

    success = burst_start + timedelta(minutes=5)
    em.emit(success, "login_activity", "successful_login",
            f"Accepted password for admin from {ATTACKER_IP}",
            user="admin", ip=ATTACKER_IP, process="sshd", severity="medium")
    gt.append({"kind": "break_in_success", "source_ip": ATTACKER_IP,
               "user": "admin", "ts_utc": success.isoformat()})

    created = success + timedelta(minutes=4)
    em.emit(created, "user_accounts", "account_created",
            f"new user: name={ATTACKER_USER}, UID=1004",
            user=ATTACKER_USER, process="useradd", severity="medium",
            raw=f"useradd[9001]: new user: name={ATTACKER_USER}, UID=1004, "
                f"GID=1004, home=/home/{ATTACKER_USER}, shell=/bin/bash")
    gt.append({"kind": "account_created", "user": ATTACKER_USER,
               "ts_utc": created.isoformat()})

    granted = created + timedelta(minutes=2)
    em.emit(granted, "privilege_escalation", "group_added",
            f"add '{ATTACKER_USER}' to group 'sudo'",
            user=ATTACKER_USER, process="usermod", severity="high",
            raw=f"usermod[9010]: add '{ATTACKER_USER}' to group 'sudo'")
    gt.append({"kind": "privilege_granted", "user": ATTACKER_USER,
               "ts_utc": granted.isoformat()})

    key = granted + timedelta(minutes=3)
    em.emit(key, "persistence", "authorized_key_added",
            f"authorized_keys modified for {ATTACKER_USER}",
            user=ATTACKER_USER, severity="high",
            artifact=f"home/{ATTACKER_USER}/.ssh/authorized_keys", sha="3" * 64)
    gt.append({"kind": "authorized_key_added", "user": ATTACKER_USER,
               "ts_utc": key.isoformat()})

    cron = key + timedelta(minutes=2)
    em.emit(cron, "persistence", "cron_job_added",
            f"crontab entry created for {ATTACKER_USER}: @reboot /tmp/.sync",
            user=ATTACKER_USER, severity="high",
            artifact=f"var/spool/cron/crontabs/{ATTACKER_USER}", sha="4" * 64)
    gt.append({"kind": "cron_job_added", "user": ATTACKER_USER,
               "ts_utc": cron.isoformat()})

    wipe = cron + timedelta(minutes=6)
    em.emit(wipe, "user_activity", "history_missing",
            f".bash_history for {ATTACKER_USER} is empty despite recorded "
            "sessions", user=ATTACKER_USER, severity="medium",
            artifact=f"home/{ATTACKER_USER}/.bash_history", sha="5" * 64,
            kind="state_finding")
    gt.append({"kind": "history_wiped", "user": ATTACKER_USER,
               "ts_utc": wipe.isoformat()})
    return gt


def build_case(out_path: str | Path, seed: int = 42) -> list[dict]:
    out_path = Path(out_path)
    if out_path.exists():
        out_path.unlink()
    rng = random.Random(seed)
    em = _Emitter()
    _background(em, rng)
    ground_truth = _attack(em)

    conn = db.open_case(out_path)
    stats = db.insert_events(conn, em.events)
    if stats.invalid:
        raise RuntimeError(f"synthetic generator produced {stats.invalid} invalid events")
    db.set_meta(conn, "case_id", CASE_ID)
    db.set_meta(conn, "synthetic", "true")
    conn.close()

    gt_path = out_path.with_suffix("").parent / (out_path.stem + ".ground_truth.json")
    gt_path.write_text(
        json.dumps(ground_truth, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return ground_truth


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    gt = build_case(args.out, seed=args.seed)
    print(f"wrote {args.out} with {len(gt)} ground-truth attack steps")


if __name__ == "__main__":
    main()
