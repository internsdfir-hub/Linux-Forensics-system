#!/bin/sh
# 02_brute_force_ssh.sh — MITRE T1110 Brute Force (+ T1110 success)
#
# REAL-LIFE STORY
#   An external host hammers SSH with a password list. Most attempts fail;
#   eventually one succeeds. The forensic signature is a burst of failed
#   logins from one IP followed by an "Accepted password" from the same IP.
#
# WHAT IS GENUINE vs SIMULATED
#   Two modes:
#     * DEFAULT (simulated source): injects the failure burst + success via
#       logger with the attacker IP. Clean, deterministic, needs no network.
#     * GENUINE_SSH=1: performs REAL failed SSH logins against localhost so
#       sshd/PAM write real auth.log/journal records through the real code
#       path. Source IP is then 127.0.0.1 (you cannot spoof it locally), so
#       the burst is genuine but attributed to loopback. Needs sshd running.
#
#   The analyzer's brute_force rule needs >= 5 failures within 5 minutes from
#   one source; this fires 6 to sit clearly past the threshold.
#
# DETECTION LAYER
#   brute_force (finding) + brute_force_success (finding).
#
# REPRODUCIBLE: YES, fully.

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DIR/lib.sh"
require_root "02_brute_force_ssh"
confirm_lab

VICTIM="${LFA_TARGET_USER:-$(getent passwd 1000 | cut -d: -f1)}"
[ -n "$VICTIM" ] || VICTIM=root

if [ "${GENUINE_SSH:-0}" = "1" ]; then
    echo "[*] GENUINE mode: 6 real failed SSH logins against localhost..."
    command -v ssh >/dev/null 2>&1 || { echo "[!] ssh client missing"; exit 1; }
    i=1
    while [ "$i" -le 6 ]; do
        ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
            -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
            "bruteforce_probe_$i@127.0.0.1" true 2>/dev/null || true
        i=$((i+1))
    done
    echo "    (real Failed password lines written by sshd; source = 127.0.0.1)"
else
    echo "[*] SIMULATED mode: injecting a 6-failure burst from $ATTACKER_IP..."
    for u in root admin test support oracle "$VICTIM"; do
        logger -t sshd -p auth.info "Failed password for $u from $ATTACKER_IP port 49152 ssh2"
        sleep 0.2
    done
    logger -t sshd -p auth.info "Failed password for invalid user postgres from $ATTACKER_IP port 49152 ssh2"
    echo "[*] Injecting the successful login that follows the burst..."
    logger -t sshd -p auth.info "Accepted password for $VICTIM from $ATTACKER_IP port 49158 ssh2"
    logger -t sshd -p auth.info "pam_unix(sshd:session): session opened for user $VICTIM by (uid=0)"
fi

write_ground_truth "$DIR/02_brute_force_ssh.ground_truth.json" \
  "brute_force_ssh" \
  '[
    {"threat_id":"T1110_brute_force","name":"SSH failed-login burst",
     "expected_rule":"brute_force","detection_layer":"finding",
     "details":">=5 failures within 5 minutes from one source",
     "verify":"lastb | head; grep -c \"Failed password\" /var/log/auth.log"},
    {"threat_id":"T1110_success","name":"Successful login after burst",
     "expected_rule":"brute_force_success","detection_layer":"finding",
     "details":"Accepted password immediately after the failure burst",
     "verify":"grep \"Accepted password\" /var/log/auth.log"}
  ]'
echo "[+] Scenario 02 complete."
