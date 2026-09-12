#!/bin/sh
# 03_insider_activity.sh — MITRE T1078 Valid Accounts / T1070 Indicator Removal
#
# REAL-LIFE STORY
#   No external attacker. A trusted employee with a real account works at 2am,
#   runs privileged commands they don't normally run, collects data, then wipes
#   their shell history to cover the session. The account is legitimate; the
#   *pattern* is not. Insider cases are won on the timeline, not on a signature.
#
# WHAT IS GENUINE vs SIMULATED
#   - GENUINE: real ~/.bash_history truncation after real login sessions; a real
#     staging directory of "collected" files under /tmp.
#   - SIMULATED: the off-hours timestamp on the sudo line and the session-opened
#     records (so wiped_history's ">=3 sessions" precondition is met without
#     waiting for three real logins).
#
# DETECTION LAYER
#   off_hours_privileged (finding) + wiped_history (finding)
#   + user_activity timeline (evidence).
#
# REPRODUCIBLE: YES, fully.

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DIR/lib.sh"
require_root "03_insider_activity"
confirm_lab

INSIDER="${LFA_INSIDER_USER:-insider}"
if ! id "$INSIDER" >/dev/null 2>&1; then
    echo "[*] Creating a normal (non-privileged) employee account '$INSIDER'..."
    useradd -m -s /bin/bash "$INSIDER"
fi
HOME_DIR=$(getent passwd "$INSIDER" | cut -d: -f6)

echo "[*] Recording >=3 login sessions for '$INSIDER' (wiped_history precondition)..."
for _ in 1 2 3 4; do
    logger -t sshd -p auth.info "pam_unix(sshd:session): session opened for user $INSIDER by (uid=0)"
done

echo "[*] Off-hours privileged action by the insider..."
OFF_HOURS_TS="$(date -u +'%b %e') 02:41:55"
AUTHLOG=/var/log/auth.log; [ -f /var/log/secure ] && AUTHLOG=/var/log/secure
printf '%s %s sudo:   %s : TTY=pts/3 ; PWD=%s ; USER=root ; COMMAND=/usr/bin/tar czf /tmp/hr_salaries.tgz /srv/hr\n' \
    "$OFF_HOURS_TS" "$(hostname)" "$INSIDER" "$HOME_DIR" >> "$AUTHLOG" 2>/dev/null || \
    logger -t sudo "$INSIDER : off-hours tar of /srv/hr"

echo "[*] Staging 'collected' data (genuine files, benign content)..."
mkdir -p /tmp/exfil_staging
for f in salaries.csv contracts.pdf customers.db; do
    echo "LAB MARKER — synthetic insider staging $(now_iso)" > "/tmp/exfil_staging/$f"
done

echo "[*] Wiping the insider's shell history (genuine truncation)..."
: > "$HOME_DIR/.bash_history"
chown "$INSIDER:$INSIDER" "$HOME_DIR/.bash_history" 2>/dev/null || true
chmod 600 "$HOME_DIR/.bash_history"

write_ground_truth "$DIR/03_insider_activity.ground_truth.json" \
  "insider_activity" \
  '[
    {"threat_id":"T1078_offhours_priv","name":"Insider off-hours privileged action",
     "expected_rule":"off_hours_privileged","detection_layer":"finding",
     "details":"'"$INSIDER"' ran tar via sudo at 02:41 local time",
     "verify":"grep -E \"sudo:.*'"$INSIDER"'\" /var/log/auth.log"},
    {"threat_id":"T1070_wiped_history","name":"Shell history wiped after sessions",
     "expected_rule":"wiped_history","detection_layer":"finding",
     "details":"zero-byte .bash_history for '"$INSIDER"' after >=3 sessions",
     "verify":"ls -la '"$HOME_DIR"'/.bash_history"}
  ]'
echo "[+] Scenario 03 complete. Staging dir: /tmp/exfil_staging (delete on rollback)."
