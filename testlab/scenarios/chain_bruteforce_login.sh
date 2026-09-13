#!/bin/sh
# chain_bruteforce_login.sh — a TWO-stage chain: brute-force SSH -> unauthorized
# login, as one external-attacker story tied together by a single source IP.
#
# WHY CHAIN THESE TWO
#   On their own, scenario 02 proves the brute-force rules and scenario 01
#   proves off_hours_privileged. Chained on ONE snapshot they become a single
#   coherent intrusion: the SAME attacker IP (203.0.113.9) hammers SSH, breaks
#   in, and then acts with privilege out of hours. An analyst reading the report
#   should be able to search that one IP and get the whole story in order —
#   failure burst, the accepted login that ends it, then the off-hours sudo.
#
# ORDER (deliberately NOT the "1. login / 2. brute force" listing order — the
# forensic timeline runs the other way, because the brute force is HOW the
# unauthorized access is gained, so it must come first):
#   1. 02  break in   brute-force failure burst + a success from the attacker IP
#   2. 01  foothold    off-hours privileged (sudo) action from that same IP
#
# WHAT FIRES
#   brute_force + brute_force_success (from stage 1), off_hours_privileged (from
#   stage 2), and first_seen for 203.0.113.9 (it appears only in the recent part
#   of the log). There is no dedicated rule that CORRELATES the two stages — the
#   link is the shared IP and the shared timeline, which is exactly what the
#   report's timeline and the "Remote addresses" panel are for.
#
# METASPLOITABLE: works as-is — both stages use only logger + date, no timeout
#   or curl, so no cross-version shims are needed here.
#
# REPRODUCIBLE: YES, fully. Deterministic; safe to re-run. Snapshot first.

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DIR/lib.sh"
require_root "chain_bruteforce_login"
confirm_lab

# Confirm once here; the child scenarios inherit this and do not prompt again.
export LFA_LAB_CONFIRM=yes

# Keep stage 1 in its default SIMULATED mode so the burst carries the attacker
# IP. GENUINE_SSH=1 would attribute the failures to 127.0.0.1 and break the
# single-IP story this chain is built to show, so it is explicitly cleared.
unset GENUINE_SSH 2>/dev/null || true

# Clock sanity: syslog carries no year, so the analyzer infers it from the log
# file mtime. A stale VM clock (Metasploitable ships thinking it is 2010) lands
# every injected event in the wrong year. Warn, do not silently roll the clock.
YEAR=$(date -u +%Y)
if [ "$YEAR" -lt 2020 ]; then
    echo "==============================================================="
    echo " [!] System clock reads year $YEAR. Syslog has no year, so the"
    echo "     analyzer will date every event to $YEAR. Set the real time"
    echo "     FIRST (sudo date -u -s \"2026-09-13 09:00:00\" or your real"
    echo "     current UTC time), then re-run this driver."
    echo "==============================================================="
    [ "${LFA_IGNORE_CLOCK:-0}" = "1" ] || { echo "Aborted (set LFA_IGNORE_CLOCK=1 to override)."; exit 3; }
fi

CASE="${LFA_CASE:-CASE-INTRUSION}"

run_stage() {
    _n=$1; _label=$2; _script=$3
    echo
    echo "==== chain step $_n: $_label ($_script) ===="
    sh "$DIR/$_script"
}

# --- the two-stage chain, in timeline order ----------------------------------
run_stage 1 "break in (brute-force burst + success)" 02_brute_force_ssh.sh
run_stage 2 "foothold (off-hours privileged action)" 01_unauthorized_login.sh

cat <<EOF

===============================================================================
 CHAIN COMPLETE — both stages run on this one snapshot, same attacker IP
 ($ATTACKER_IP). DO NOT run manual analysis yet; collect first so your own
 commands do not contaminate the auth.log / wtmp the collector reads.
===============================================================================

 Next, on the TARGET (collect the bundle):

   sudo sh ../../collector/collect.sh -o /tmp/out -c $CASE -p "YourName" -z

 Then move /tmp/out/$CASE*.tar.gz to the EXAMINER machine and run:

   python -m lfa analyse $CASE*.tar.gz --case-dir cases/$CASE --examiner "YourName"
   python -m lfa verify  cases/$CASE

   # merge the two stages' ground truth, then score:
   python - <<'PY'
   import json, glob
   threats=[]
   for f in sorted(glob.glob("testlab/scenarios/0[12]_*.ground_truth.json")):
       threats += json.load(open(f)).get("injected_threats", [])
   json.dump({"scenario_name":"bruteforce_then_login","injected_threats":threats},
             open("testlab/scenarios/chain_bruteforce_login.ground_truth.json","w"), indent=2)
   print(f"merged {len(threats)} threats")
   PY
   python tools/score_detection.py --case-dir cases/$CASE \\
          --ground-truth testlab/scenarios/chain_bruteforce_login.ground_truth.json

 Expected findings:
   brute_force            >=5 failures in 5 min from $ATTACKER_IP
   brute_force_success    accepted login from $ATTACKER_IP right after the burst
   off_hours_privileged   the 03:14 sudo action from that same IP
   first_seen             $ATTACKER_IP appears only in the recent part of the log

 The story to read in the report timeline: search $ATTACKER_IP and you should
 see the failure burst -> the accepted login -> the off-hours sudo, in order.
===============================================================================
EOF
echo "[+] chain_bruteforce_login.sh complete (collection intentionally left to you)."
