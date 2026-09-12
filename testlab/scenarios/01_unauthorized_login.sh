#!/bin/sh
# 01_unauthorized_login.sh — MITRE T1078 Valid Accounts / T1021.004 SSH
#
# REAL-LIFE STORY
#   An attacker who already holds stolen-but-valid credentials logs in over
#   SSH from an unfamiliar external IP, outside working hours, and immediately
#   uses sudo. No brute force, no malware — just a login that should not be
#   happening. This is the single most common real breach and the hardest to
#   spot, because every individual action is "legitimate".
#
# WHAT IS GENUINE vs SIMULATED
#   - GENUINE: a real sudo session is created (pam_unix writes auth.log/journal).
#   - SIMULATED: the *source IP* and the *off-hours timestamp*. You cannot make
#     a local login appear to come from a routable external IP without a second
#     host, and you should not roll the system clock back. So the off-hours SSH
#     "Accepted password" line is injected via logger with the attacker IP, and
#     one off-hours sudo line is appended to auth.log. In a true engagement the
#     login and the sudo would be real and carry these values naturally.
#
# DETECTION LAYER
#   off_hours_privileged (finding) + login_activity timeline (evidence).
#
# REPRODUCIBLE: YES, fully. Deterministic; safe to re-run.

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DIR/lib.sh"
require_root "01_unauthorized_login"
confirm_lab

TARGET_USER="${LFA_TARGET_USER:-$(getent passwd 1000 | cut -d: -f1)}"
[ -n "$TARGET_USER" ] || TARGET_USER=root
OFF_HOURS_TS="$(date -u +'%b %e') 03:14:07"   # syslog format, 03:14 = off-hours

echo "[*] Simulating off-hours SSH login for '$TARGET_USER' from $ATTACKER_IP..."
logger -t sshd -p auth.info "Accepted password for $TARGET_USER from $ATTACKER_IP port 51022 ssh2"
logger -t sshd -p auth.info "pam_unix(sshd:session): session opened for user $TARGET_USER by (uid=0)"

echo "[*] Injecting an off-hours privileged (sudo) action..."
AUTHLOG=/var/log/auth.log
[ -f /var/log/secure ] && AUTHLOG=/var/log/secure
if [ -w "$AUTHLOG" ] || [ ! -e "$AUTHLOG" ]; then
    printf '%s %s sudo:   %s : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow\n' \
        "$OFF_HOURS_TS" "$(hostname)" "$TARGET_USER" >> "$AUTHLOG" 2>/dev/null \
        && echo "    appended off-hours sudo line to $AUTHLOG" \
        || echo "    (could not write $AUTHLOG; journald-only host — see note)"
else
    logger -t sudo -p authpriv.notice "$TARGET_USER : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    echo "    (journald-only host: injected via logger at CURRENT time, not off-hours)"
fi

write_ground_truth "$DIR/01_unauthorized_login.ground_truth.json" \
  "unauthorized_login" \
  '[
    {"threat_id":"T1078_offhours_login","name":"Off-hours login from foreign IP",
     "expected_rule":"off_hours_privileged","detection_layer":"finding",
     "details":"sudo/privileged action at 03:14 local time by '"$TARGET_USER"'",
     "verify":"grep -E \"sudo:.*'"$TARGET_USER"'\" /var/log/auth.log"},
    {"threat_id":"T1021_ssh_accepted","name":"Accepted SSH password from '"$ATTACKER_IP"'",
     "expected_rule":null,"detection_layer":"evidence",
     "details":"login_activity event for '"$TARGET_USER"' from '"$ATTACKER_IP"'",
     "verify":"SELECT * FROM events WHERE subcategory=\"successful_login\" AND source_ip=\"'"$ATTACKER_IP"'\""}
  ]'
echo "[+] Scenario 01 complete."
