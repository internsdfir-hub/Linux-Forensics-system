# testlab/scenarios/remote/lib_remote.sh — shared helpers for the ATTACKER-SIDE
# scenario scripts. Sourced, not executed. POSIX sh.
#
# These scripts run on YOUR attacker box (e.g. Kali) and act over the network
# against LFA_TARGET. Unlike the local-injection scenarios one directory up,
# they mutate NOTHING on the attacker machine and inject NOTHING into any log:
# the evidence is produced by the target's OWN sshd / PAM as it handles the real
# connections, with your real source IP and the real wall-clock time. That is as
# close to a genuine attack as a lab gets. You then collect + analyse the TARGET.
#
# AUTHORISATION. Running these against a host you are not authorised to test is
# an attack, not a simulation. Point them ONLY at your own snapshotted lab VM or
# an explicitly in-scope engagement target.

have() { command -v "$1" >/dev/null 2>&1; }
now_iso() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# --- configuration (env-overridable; defaults target Metasploitable 2) --------
: "${LFA_TARGET:=}"                 # target host/IP — REQUIRED, no safe default
: "${LFA_SSH_PORT:=22}"
: "${LFA_VALID_USER:=msfadmin}"     # the 'stolen' valid credentials
: "${LFA_VALID_PASS:=msfadmin}"     # (Metasploitable 2 default login)

need_target() {
    if [ -z "$LFA_TARGET" ]; then
        echo "[!] LFA_TARGET is required. Example:" >&2
        echo "      LFA_TARGET=192.168.56.101 sh $1" >&2
        exit 1
    fi
}

require_sshpass() {
    have sshpass || {
        echo "[!] sshpass is required for scripted password auth." >&2
        echo "    Install it:  sudo apt-get install -y sshpass   (Kali: already present)" >&2
        exit 1
    }
}

# Confirm you are authorised to attack this specific target.
confirm_authorized() {
    echo "==============================================================="
    echo " REAL SSH ATTACK against: $LFA_TARGET:$LFA_SSH_PORT"
    echo " Run ONLY against a host you are AUTHORISED to test (your own"
    echo " snapshotted lab VM, or an in-scope engagement target)."
    echo "==============================================================="
    if [ "${LFA_LAB_CONFIRM:-}" = "yes" ]; then
        echo "[i] LFA_LAB_CONFIRM=yes -> proceeding without prompt."
        return 0
    fi
    printf "Re-type the target (%s) to confirm you are authorised: " "$LFA_TARGET"
    read -r ans
    [ "$ans" = "$LFA_TARGET" ] || { echo "Aborted."; exit 2; }
}

# The source IP the target will see us from — for the write-up / ground truth.
attacker_ip() {
    if have ip; then
        ip -o route get "$LFA_TARGET" 2>/dev/null \
            | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1
    fi
}

# ssh options that let a MODERN client speak to Metasploitable's ancient sshd
# (old KEX / host-key / cipher algorithms), force password auth so keys/agents
# do not short-circuit the attempt, and cap it to ONE password prompt per
# connection so a wrong password is one clean 'Failed password', not three.
# The leading '+' appends to the client defaults, so this is harmless against a
# modern target too.
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
-o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 \
-o PreferredAuthentications=password -o PubkeyAuthentication=no \
-o KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1 \
-o HostKeyAlgorithms=+ssh-rsa,ssh-dss \
-o Ciphers=+aes128-cbc,3des-cbc"

# ssh_attempt USER PASS [REMOTE_CMD...] -> one login attempt over the network.
# ALWAYS pass a remote command on a login you expect to SUCCEED, or the shell
# opens interactively and hangs. Failed logins never reach a shell. Returns
# sshpass/ssh exit status (5 = auth failure, 0 = success).
ssh_attempt() {
    _u=$1; _p=$2; shift 2
    # shellcheck disable=SC2086  # SSH_OPTS is intentionally word-split
    sshpass -p "$_p" ssh $SSH_OPTS -p "$LFA_SSH_PORT" "$_u@$LFA_TARGET" "$@" 2>/dev/null
}

# write_ground_truth_remote <outfile> <scenario_name> <json-array-of-threats>
# Same schema tools/score_detection.py reads, plus the target + attacker source
# IP so the write-up records who hit what from where.
write_ground_truth_remote() {
    out=$1; name=$2; threats=$3
    src=$(attacker_ip); [ -n "$src" ] || src="unknown"
    mkdir -p "$(dirname -- "$out")"
    cat > "$out" <<EOF
{
  "scenario_name": "$name",
  "executed_at": "$(now_iso)",
  "mode": "remote_attacker",
  "attacker_source_ip": "$src",
  "target": "$LFA_TARGET",
  "target_ssh_port": "$LFA_SSH_PORT",
  "injected_threats": $threats
}
EOF
    echo "[+] Ground truth: $out  (attacker source IP recorded as $src)"
}
