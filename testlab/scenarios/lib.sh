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

# ---------------------------------------------------------------------------
# Portability shims — so the scenarios run on a MODERN box AND on Metasploitable
# 2 (Ubuntu 8.04 "Hardy", coreutils 6.10). Hardy predates `timeout` (added in
# coreutils 7.0) and often ships wget but not curl. The rest of the toolchain
# the scenarios rely on — logger routing auth.* to /var/log/auth.log via
# sysklogd, useradd -o -u 0, passwd -d, crontab, nc.traditional -e, bash
# /dev/tcp, base64 — is present on Hardy, so these three shims are all the
# cross-version handling the scripts need. Everything degrades, nothing aborts.
# ---------------------------------------------------------------------------

# have CMD -> true if CMD is on PATH.
have() { command -v "$1" >/dev/null 2>&1; }

# lab_timeout SECONDS CMD [ARGS...] -> run CMD, killing it after SECONDS.
# Uses coreutils `timeout` when present; otherwise a POSIX background+kill
# fallback for Hardy, which has no `timeout`. Returns CMD's exit status.
lab_timeout() {
    _t=$1; shift
    if have timeout; then
        timeout "$_t" "$@"
        return $?
    fi
    "$@" &
    _cmd_pid=$!
    ( sleep "$_t"; kill -TERM "$_cmd_pid" 2>/dev/null ) &
    _killer_pid=$!
    wait "$_cmd_pid" 2>/dev/null
    _rc=$?
    kill -TERM "$_killer_pid" 2>/dev/null
    wait "$_killer_pid" 2>/dev/null
    return "$_rc"
}

# http_get URL -> fetch URL to /dev/null with a hard 3s cap. Prefers curl,
# falls back to wget (Hardy's default), returns 127 if neither exists. The
# fetch is EXPECTED to fail here (the C2 target is a non-routable TEST-NET IP);
# the point is that the attempt runs and is captured, not that it connects.
http_get() {
    _url=$1
    if have curl; then
        lab_timeout 3 curl -s -o /dev/null "$_url"
    elif have wget; then
        lab_timeout 3 wget -q -O /dev/null "$_url"
    else
        echo "    (no curl or wget; skipping HTTP beacon)" >&2
        return 127
    fi
}

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
