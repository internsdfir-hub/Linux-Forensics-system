#!/bin/sh
# 02_brute_force_ssh_remote.sh — MITRE T1110 Brute Force, performed FOR REAL
# from the attacker box against LFA_TARGET's sshd.
#
# WHAT IT DOES
#   Sends N failed SSH password attempts against the target, then (by default)
#   one successful login with the valid 'stolen' credentials. Every attempt is
#   a real connection the target's sshd handles: the failures become genuine
#   'Failed password' lines in the target's auth.log and the success a genuine
#   'Accepted password', all carrying YOUR real source IP and the real time.
#
# GENUINE vs SIMULATED
#   100% GENUINE. Nothing is injected. The only thing you cannot control from
#   here is the target's clock (so the timestamps are whatever 'now' is on the
#   target) — which is exactly the real-world constraint.
#
# WHAT THE ANALYZER SHOULD FIND (after you collect + analyse the TARGET)
#   brute_force            (>=5 failures in 5 min from your IP) and
#   brute_force_success    (the accepted login within 15 min of the burst,
#                           correlated by source IP — username need not match).
#
# CONFIG (env)
#   LFA_TARGET      target host/IP                       (REQUIRED)
#   LFA_SSH_PORT    ssh port                             (default 22)
#   LFA_BF_USER     account to guess against             (default: LFA_VALID_USER)
#   LFA_BF_COUNT    number of failed attempts            (default 6; rule needs >=5)
#   LFA_VALID_USER/LFA_VALID_PASS  the valid credentials (default msfadmin/msfadmin)
#   LFA_WITH_SUCCESS=0  skip the successful login (failures only)
#
# EXAMPLE
#   LFA_TARGET=192.168.56.101 sh 02_brute_force_ssh_remote.sh

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DIR/lib_remote.sh"
need_target "02_brute_force_ssh_remote.sh"
confirm_authorized
require_sshpass

BF_USER="${LFA_BF_USER:-$LFA_VALID_USER}"
N="${LFA_BF_COUNT:-6}"
SRC=$(attacker_ip); [ -n "$SRC" ] || SRC="your source IP"

echo "[*] Brute force: $N failed logins as '$BF_USER' against $LFA_TARGET:$LFA_SSH_PORT"
echo "    (source $SRC — each is a real 'Failed password' on the target)"
i=1
while [ "$i" -le "$N" ]; do
    ssh_attempt "$BF_USER" "wrong_password_$i" true >/dev/null 2>&1 || true
    printf '    attempt %s/%s\r' "$i" "$N"
    i=$((i + 1))
done
echo
echo "    burst sent."

SUCCESS_THREAT=""
if [ "${LFA_WITH_SUCCESS:-1}" = "1" ]; then
    echo "[*] The success that follows the burst: valid login as '$LFA_VALID_USER'..."
    if ssh_attempt "$LFA_VALID_USER" "$LFA_VALID_PASS" 'id; uname -a' 2>/dev/null; then
        echo "    accepted (real 'Accepted password' for $LFA_VALID_USER from $SRC)."
        SUCCESS_THREAT=",
    {\"threat_id\":\"T1110_success\",\"name\":\"Successful login after the burst\",
     \"expected_rule\":\"brute_force_success\",\"detection_layer\":\"finding\",
     \"details\":\"accepted password for $LFA_VALID_USER from the attacker IP within 15 min of >=5 failures\",
     \"verify\":\"grep 'Accepted password' /var/log/auth.log\"}"
    else
        echo "    [!] valid login failed — set LFA_VALID_USER / LFA_VALID_PASS to real"
        echo "        target credentials (or LFA_WITH_SUCCESS=0 for failures only)."
    fi
fi

write_ground_truth_remote "$DIR/02_brute_force_ssh_remote.ground_truth.json" \
  "brute_force_ssh_remote" \
  "[
    {\"threat_id\":\"T1110_brute_force\",\"name\":\"SSH failed-login burst\",
     \"expected_rule\":\"brute_force\",\"detection_layer\":\"finding\",
     \"details\":\"$N real failed SSH logins as $BF_USER from the attacker IP within seconds\",
     \"verify\":\"grep -c 'Failed password' /var/log/auth.log; lastb | head\"}$SUCCESS_THREAT
  ]"
echo "[+] Scenario 02 (remote) complete. Collect the TARGET next."
