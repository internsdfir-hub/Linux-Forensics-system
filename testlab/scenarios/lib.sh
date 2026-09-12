# testlab/scenarios/lib.sh — shared helpers for the six scenario scripts.
# Sourced, not executed. POSIX sh.
#
# Every scenario script is standalone in intent but shares these three
# concerns: refuse to run anywhere but a disposable lab, refuse to run
# without root where the actions need it, and record ground truth in the
# schema tools/score_detection.py already understands.

ATTACKER_IP="203.0.113.9"     # RFC 5737 TEST-NET-3: never routable, never a real host
ATTACKER_IP_2="198.51.100.7"  # RFC 5737 TEST-NET-2

now_iso() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[!] $1 needs root (real system mutations). Re-run with sudo." >&2
        exit 1
    fi
}

# Loud, unmissable confirmation that this is a throwaway machine. Set
# LFA_LAB_CONFIRM=yes to run non-interactively (CI / scripted lab).
confirm_lab() {
    echo "==============================================================="
    echo " THIS SCRIPT MUTATES THE SYSTEM (users, logs, cron, keys, ...)."
    echo " Run it ONLY on a VM you have snapshotted and can roll back."
    echo "==============================================================="
    if [ "${LFA_LAB_CONFIRM:-}" = "yes" ]; then
        echo "[i] LFA_LAB_CONFIRM=yes -> proceeding without prompt."
        return 0
    fi
    printf "Type 'lab' to confirm this is a disposable lab machine: "
    read -r answer
    [ "$answer" = "lab" ] || { echo "Aborted."; exit 2; }
}

# write_ground_truth <outfile> <scenario_name> <json-array-of-threats>
write_ground_truth() {
    out=$1; name=$2; threats=$3
    mkdir -p "$(dirname -- "$out")"
    cat > "$out" <<EOF
{
  "scenario_name": "$name",
  "executed_at": "$(now_iso)",
  "host": "$(hostname)",
  "attacker_ip": "$ATTACKER_IP",
  "injected_threats": $threats
}
EOF
    echo "[+] Ground truth: $out"
}
