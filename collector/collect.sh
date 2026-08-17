#!/bin/sh
# collect.sh - Linux forensic evidence collector (POSIX sh, dependency-free).
# Stub: real implementation lands in Phase 1. The artifact table below is
# generated from config/artifacts.yaml by tools/gen_artifact_table.py.

ARTIFACT_TABLE='
# ===BEGIN ARTIFACT TABLE===
os_release|environment|1|0|0|/etc/os-release
os_release|environment|1|0|0|/etc/redhat-release
os_release|environment|1|0|0|/etc/debian_version
localtime|environment|1|0|0|/etc/localtime
localtime|environment|1|0|0|/etc/timezone
machine_id|environment|0|0|0|/etc/machine-id
passwd|user_accounts|1|0|0|/etc/passwd
passwd|user_accounts|1|0|0|/etc/passwd-
passwd|user_accounts|1|0|0|/etc/group
passwd|user_accounts|1|0|0|/etc/group-
shadow|user_accounts|0|0|0|/etc/shadow
shadow|user_accounts|0|0|0|/etc/shadow-
shadow|user_accounts|0|0|0|/etc/gshadow
shadow|user_accounts|0|0|0|/etc/gshadow-
auth_log|login_activity|0|1|0|/var/log/auth.log
auth_log|login_activity|0|1|0|/var/log/secure
wtmp|login_activity|0|1|0|/var/log/wtmp
btmp|login_activity|0|1|0|/var/log/btmp
lastlog|login_activity|0|0|0|/var/log/lastlog
faillog|login_activity|0|0|0|/var/log/faillog
faillog|login_activity|0|0|0|/var/run/faillock/*
sudoers|privilege_escalation|1|0|0|/etc/sudoers
sudoers|privilege_escalation|1|0|0|/etc/sudoers.d/*
pam|privilege_escalation|0|0|0|/etc/pam.d/*
cron|persistence|1|0|0|/etc/crontab
cron|persistence|1|0|0|/etc/cron.d/*
cron|persistence|1|0|0|/var/spool/cron/crontabs/*
cron|persistence|1|0|0|/var/spool/cron/*
cron|persistence|1|0|0|/etc/cron.hourly/*
cron|persistence|1|0|0|/etc/cron.daily/*
cron|persistence|1|0|0|/etc/cron.weekly/*
cron|persistence|1|0|0|/etc/cron.monthly/*
cron_log|persistence|0|1|0|/var/log/cron
systemd_units|persistence|0|0|1|/etc/systemd/system
systemd_user_units|persistence|0|0|1|/home/*/.config/systemd/user
systemd_user_units|persistence|0|0|1|/root/.config/systemd/user
authorized_keys|persistence|0|0|0|/home/*/.ssh/authorized_keys
authorized_keys|persistence|0|0|0|/home/*/.ssh/authorized_keys2
authorized_keys|persistence|0|0|0|/root/.ssh/authorized_keys
authorized_keys|persistence|0|0|0|/root/.ssh/authorized_keys2
sshd_config|persistence|0|0|0|/etc/ssh/sshd_config
sshd_config|persistence|0|0|0|/etc/ssh/sshd_config.d/*
shell_startup|persistence|0|0|0|/etc/profile
shell_startup|persistence|0|0|0|/etc/profile.d/*
shell_startup|persistence|0|0|0|/etc/rc.local
shell_startup|persistence|0|0|0|/etc/ld.so.preload
shell_startup|persistence|0|0|0|/home/*/.bashrc
shell_startup|persistence|0|0|0|/home/*/.profile
shell_startup|persistence|0|0|0|/home/*/.bash_profile
shell_startup|persistence|0|0|0|/root/.bashrc
shell_startup|persistence|0|0|0|/root/.profile
dpkg_log|software_changes|0|1|0|/var/log/dpkg.log
apt_history|software_changes|0|1|0|/var/log/apt/history.log
apt_history|software_changes|0|1|0|/var/log/apt/term.log
dnf_log|software_changes|0|1|0|/var/log/dnf.log
dnf_log|software_changes|0|1|0|/var/log/dnf.rpm.log
dnf_log|software_changes|0|1|0|/var/log/yum.log
kern_syslog|hardware_usb|0|1|0|/var/log/kern.log
kern_syslog|hardware_usb|0|1|0|/var/log/syslog
kern_syslog|hardware_usb|0|1|0|/var/log/messages
sys_usb|hardware_usb|0|0|1|/sys/bus/usb/devices
hosts|network_config|1|0|0|/etc/hosts
hosts|network_config|1|0|0|/etc/resolv.conf
net_ifaces|network_config|0|0|0|/etc/network/interfaces
net_ifaces|network_config|0|0|0|/etc/netplan/*.yaml
ufw_log|network_config|0|1|0|/var/log/ufw.log
shell_history|user_activity|0|0|0|/home/*/.bash_history
shell_history|user_activity|0|0|0|/home/*/.zsh_history
shell_history|user_activity|0|0|0|/root/.bash_history
shell_history|user_activity|0|0|0|/root/.zsh_history
known_hosts|user_activity|0|0|0|/home/*/.ssh/known_hosts
known_hosts|user_activity|0|0|0|/root/.ssh/known_hosts
browser_firefox|user_activity|0|0|0|/home/*/.mozilla/firefox/*/places.sqlite
browser_chrome|user_activity|0|0|0|/home/*/.config/google-chrome/*/History
browser_chrome|user_activity|0|0|0|/home/*/.config/chromium/*/History
audit_log|audit|0|1|0|/var/log/audit/audit.log
# ===END ARTIFACT TABLE===
'

echo "collector stub - not yet implemented" >&2
exit 1
