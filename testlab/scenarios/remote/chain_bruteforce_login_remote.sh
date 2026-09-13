#!/bin/sh
# chain_bruteforce_login_remote.sh — the TWO-stage chain, performed FOR REAL
# from the attacker box: brute-force SSH -> unauthorized login, against
# LFA_TARGET, as one intrusion tied together by your single source IP.
#
# ORDER (forensic timeline, not the "1. login / 2. brute force" listing — the
# brute force is HOW access is gained, so it comes first):
#   1. 02  break in   real failed-login burst + a real successful login
#   2. 01  foothold    real login + a real off-hours privileged (sudo) action
#
# Everything is genuine: the target's own sshd/PAM/sudo produce the evidence,
# with your real IP and the real time. Nothing is injected on either machine.
#
# WHAT THE ANALYZER SHOULD FIND (after you collect + analyse the TARGET)
#   brute_force, brute_force_success   (stage 1)
#   off_hours_privileged               (stage 2, if run outside 08–18 target-local)
#   first_seen                          (your IP appears only in the recent log)
#   ...all attributable to the ONE source IP — search it in the report timeline.
#
# CONFIG: see lib_remote.sh. Minimum:  LFA_TARGET=<ip>  and valid creds
#   (LFA_VALID_USER/LFA_VALID_PASS, default msfadmin/msfadmin for Metasploitable).
#
# EXAMPLE
#   LFA_TARGET=192.168.56.101 sh chain_bruteforce_login_remote.sh

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DIR/lib_remote.sh"
need_target "chain_bruteforce_login_remote.sh"
confirm_authorized
require_sshpass

# Confirm once; children inherit this and do not re-prompt.
export LFA_LAB_CONFIRM=yes
SRC=$(attacker_ip); [ -n "$SRC" ] || SRC="your source IP"
CASE="${LFA_CASE:-CASE-INTRUSION}"

run_stage() {
    _n=$1; _label=$2; _script=$3
    echo
    echo "==== chain step $_n: $_label ($_script) ===="
    sh "$DIR/$_script"
}

run_stage 1 "break in (real brute-force burst + success)" 02_brute_force_ssh_remote.sh
run_stage 2 "foothold (real off-hours privileged action)" 01_unauthorized_login_remote.sh

cat <<EOF

===============================================================================
 CHAIN COMPLETE — both stages hit $LFA_TARGET from one source IP ($SRC).
 The evidence is now on the TARGET's disk (auth.log, wtmp, ...). Go collect it;
 do NOT log in and poke around first, or your own session contaminates it.
===============================================================================

 On the TARGET (or over a separate, documented admin session), collect:

   sudo sh collector/collect.sh -o /tmp/out -c $CASE -p "YourName" -z

 Then on the EXAMINER machine:

   python -m lfa analyse $CASE*.tar.gz --case-dir cases/$CASE --examiner "YourName"
   python -m lfa verify  cases/$CASE

   # merge the two stages' ground truth, then score:
   python - <<'PY'
   import json, glob
   threats=[]
   for f in sorted(glob.glob("testlab/scenarios/remote/0[12]_*_remote.ground_truth.json")):
       threats += json.load(open(f)).get("injected_threats", [])
   json.dump({"scenario_name":"bruteforce_then_login_remote","injected_threats":threats},
             open("testlab/scenarios/remote/chain_remote.ground_truth.json","w"), indent=2)
   print(f"merged {len(threats)} threats")
   PY
   python tools/score_detection.py --case-dir cases/$CASE \\
          --ground-truth testlab/scenarios/remote/chain_remote.ground_truth.json

 Story to read in the report timeline: search the attacker IP ($SRC) and you
 should see the failure burst -> the accepted login -> the off-hours sudo.
 (off_hours_privileged only fires if stage 2's sudo landed outside the target's
 08–18 local hours — see that stage's output.)
===============================================================================
EOF
echo "[+] chain_bruteforce_login_remote.sh complete (collection intentionally left to you)."
