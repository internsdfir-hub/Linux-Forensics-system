#!/bin/sh
# collect.sh - Linux forensic evidence collector.
#
# POSIX sh + coreutils only. No bashisms, no Python, no rsync. Runs on the
# worst machine we might meet: tested under dash and busybox-style shells.
#
# Design rules (spec section 2.4):
#   - reads, never writes, inside $ROOT
#   - copy first, hash the COPY; stat before and after; growth is an
#     observation (source_was_active), not an error
#   - every failure is per-artifact: log the reason and carry on; NEVER abort
#   - one file: the artifact table below is generated from
#     config/artifacts.yaml by tools/gen_artifact_table.py (do not hand-edit)
#
# Usage:
#   collect.sh [-r ROOT] [-o OUTDIR] [-c CASE_ID] [-p OPERATOR] [-V] [-z] [-R]
#              [-s STREAM_URL] [-T TOKEN] [-M] [-S]
#     -r ROOT        target tree (default /). Mounted images: mount ro,noatime.
#     -o OUTDIR      output directory on the EXAMINER side (never inside ROOT)
#     -c CASE_ID     case identifier recorded in the manifest
#     -p OPERATOR    operator name recorded in the manifest
#     -V             include volatile snapshot (live mode only; runs FIRST)
#     -z             also gzip the bundle (both layers hashed)
#     -R             redact secrets (shadow/gshadow contents not collected)
#     -s STREAM_URL  stream bundle directly to central LFA server ingestion API
#     -T TOKEN       authentication token for streaming server
#     -M             in-memory / RAM mode: stages in /dev/shm (zero disk writes)
#     -S             stdout stream mode: outputs raw tarball to stdout for pipes

VERSION="1.0.0"

set -u

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

# ---------------------------------------------------------------- helpers --

now_utc() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

log() {
    # collector.log gets every warning/degradation with a timestamp
    printf '%s %s\n' "$(now_utc)" "$*" >> "$LOGFILE"
}

json_escape() {
    # escape backslash, double quote, tab; strip CR; join multi-line values
    # with literal \n so the manifest stays valid JSON no matter what a
    # command printed. Good enough for paths and identifiers; anything
    # stranger is already an incident.
    printf '%s' "$1" | tr -d '\r' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
        -e 's/	/\\t/g' | awk 'NR>1{printf "\\n"} {printf "%s", $0}'
}

sha256() {
    # print just the hex digest of $1, or "HASH_FAILED"
    if [ "$HASHER" = "sha256sum" ]; then
        sha256sum "$1" 2>/dev/null | awk '{print $1}'
    elif [ "$HASHER" = "shasum" ]; then
        shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
    elif [ "$HASHER" = "openssl" ]; then
        openssl dgst -sha256 -r "$1" 2>/dev/null | awk '{print $1}'
    else
        printf 'HASH_FAILED'
    fi
}

# stat_file <path>  -> sets S_SIZE S_MODE S_OWNER S_ATIME S_MTIME S_CTIME
stat_file() {
    S_SIZE=""; S_MODE=""; S_OWNER=""; S_ATIME=""; S_MTIME=""; S_CTIME=""
    if [ "$STATMODE" = "gnu" ]; then
        set -- $(stat -c '%s %a %u:%g %X %Y %Z' "$1" 2>/dev/null) || return 1
        [ $# -eq 6 ] || return 1
        S_SIZE=$1; S_MODE=$2; S_OWNER=$3; S_ATIME=$4; S_MTIME=$5; S_CTIME=$6
    elif [ "$STATMODE" = "bsd" ]; then
        set -- $(stat -f '%z %Lp %u:%g %a %m %c' "$1" 2>/dev/null) || return 1
        [ $# -eq 6 ] || return 1
        S_SIZE=$1; S_MODE=$2; S_OWNER=$3; S_ATIME=$4; S_MTIME=$5; S_CTIME=$6
    else
        # ls fallback: size only; documented degradation
        S_SIZE=$(ls -ln "$1" 2>/dev/null | awk '{print $5}')
        [ -n "$S_SIZE" ] || return 1
        S_MODE="unknown"; S_OWNER="unknown"
        S_ATIME=""; S_MTIME=""; S_CTIME=""
    fi
    return 0
}

csv_path() {
    # CSV-quote a path field ("" doubling)
    printf '"%s"' "$(printf '%s' "$1" | sed 's/"/""/g')"
}

record_missing() { # id path reason
    printf '{"id":"%s","path":"%s","reason":"%s"}\n' \
        "$(json_escape "$1")" "$(json_escape "$2")" "$(json_escape "$3")" \
        >> "$MISSING_JSONL"
}

record_degradation() { # description
    printf '{"detail":"%s"}\n' "$(json_escape "$1")" >> "$DEGRADE_JSONL"
    log "DEGRADATION: $1"
}

# ------------------------------------------------------------ arg parsing --

ROOT="/"
OUTDIR=""
CASE_ID="UNSET"
OPERATOR="unknown"
VOLATILE=0
GZIP=0
REDACT=0
STREAM_URL=""
STREAM_TOKEN=""
IN_RAM=0
STDOUT_MODE=0
CLEANUP_OUTDIR=0

while getopts "r:o:c:p:VzRs:T:MS" opt; do
    case "$opt" in
        r) ROOT="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        c) CASE_ID="$OPTARG" ;;
        p) OPERATOR="$OPTARG" ;;
        V) VOLATILE=1 ;;
        z) GZIP=1 ;;
        R) REDACT=1 ;;
        s) STREAM_URL="$OPTARG" ;;
        T) STREAM_TOKEN="$OPTARG" ;;
        M) IN_RAM=1 ;;
        S) STDOUT_MODE=1 ;;
        *) printf 'usage: see header of %s\n' "$0" >&2; exit 2 ;;
    esac
done

# normalize ROOT: no trailing slash (unless it IS /)
case "$ROOT" in
    */) [ "$ROOT" != "/" ] && ROOT="${ROOT%/}" ;;
esac
[ "$ROOT" = "/" ] && ROOTPFX="" || ROOTPFX="$ROOT"

START_UTC=$(now_utc)
START_EPOCH=$(date -u +%s 2>/dev/null || printf '0')

# In-memory / RAM staging setup (zero physical disk footprint)
if [ "$IN_RAM" = 1 ] || [ -n "$STREAM_URL" ] || [ "$STDOUT_MODE" = 1 ]; then
    if [ -z "$OUTDIR" ]; then
        if [ -d "/dev/shm" ] && [ -w "/dev/shm" ]; then
            RAM_BASE="/dev/shm"
        elif [ -d "/run/user/$(id -u 2>/dev/null || printf '0')" ] && [ -w "/run/user/$(id -u 2>/dev/null || printf '0')" ]; then
            RAM_BASE="/run/user/$(id -u 2>/dev/null || printf '0')"
        elif [ -d "/run/lock" ] && [ -w "/run/lock" ]; then
            RAM_BASE="/run/lock"
        else
            RAM_BASE="/tmp"
        fi
        OUTDIR="$RAM_BASE/lfa-col-$$"
        CLEANUP_OUTDIR=1
    fi
fi

if [ -z "$OUTDIR" ]; then
    OUTDIR="./lfa-collection-$(date -u +%Y%m%d%H%M%S)"
fi

cleanup_on_exit() {
    if [ "$CLEANUP_OUTDIR" = 1 ] && [ -n "$OUTDIR" ] && [ -d "$OUTDIR" ]; then
        rm -rf "$OUTDIR" 2>/dev/null || :
    fi
}
trap cleanup_on_exit EXIT INT TERM HUP

mkdir -p "$OUTDIR/collected/files" "$OUTDIR/collected/volatile" \
         "$OUTDIR/collected/journal" || {
    printf 'FATAL: cannot create output directory %s\n' "$OUTDIR" >&2
    exit 2
}

LOGFILE="$OUTDIR/collector.log"
HASHCSV="$OUTDIR/hash_manifest.csv"
MISSING_JSONL="$OUTDIR/.missing.jsonl"
DEGRADE_JSONL="$OUTDIR/.degradations.jsonl"
: > "$LOGFILE"
: > "$MISSING_JSONL"
: > "$DEGRADE_JSONL"
printf 'original_path,sha256,size,mode,owner,atime,mtime,ctime,source_was_active,status\n' > "$HASHCSV"

log "collector v$VERSION starting; ROOT=$ROOT CASE=$CASE_ID"

# ------------------------------------------------------- capability probes --

if command -v sha256sum >/dev/null 2>&1; then HASHER="sha256sum"
elif command -v shasum >/dev/null 2>&1; then HASHER="shasum"
elif command -v openssl >/dev/null 2>&1; then HASHER="openssl"
else
    HASHER="none"
    record_degradation "no sha256 tool found (sha256sum/shasum/openssl); hashes unavailable"
fi

if stat -c '%s' "$OUTDIR" >/dev/null 2>&1; then STATMODE="gnu"
elif stat -f '%z' "$OUTDIR" >/dev/null 2>&1; then STATMODE="bsd"
else
    STATMODE="ls"
    record_degradation "no usable stat(1); falling back to ls -ln (size only)"
fi

if cp -p "$HASHCSV" "$OUTDIR/.cptest" 2>/dev/null; then
    CPMODE="cp-p"; rm -f "$OUTDIR/.cptest"
else
    CPMODE="cat"
    record_degradation "cp -p unavailable; degrading to cat < src > dst (no metadata preservation)"
fi

# ------------------------------------------------------------ P2 volatile --
# Volatile state changes second by second: if requested (and live), grab it
# before anything else.

VOLATILE_RAN=0
run_volatile() {
    name=$1; shift
    outfile="$OUTDIR/collected/volatile/$name.txt"
    if command -v "$1" >/dev/null 2>&1; then
        {
            printf '# captured_utc: %s\n# command: %s\n' "$(now_utc)" "$*"
            "$@" 2>&1
        } > "$outfile"
        vhash=$(sha256 "$outfile")
        vsize=$(stat_file "$outfile" && printf '%s' "$S_SIZE" || printf '')
        printf '%s,%s,%s,,,,,,0,collected_volatile\n' \
            "$(csv_path "volatile/$name.txt")" "$vhash" "$vsize" >> "$HASHCSV"
    else
        record_missing "volatile_$name" "$1" "command not present"
    fi
}

if [ "$VOLATILE" = 1 ]; then
    if [ "$ROOT" = "/" ]; then
        log "P2 volatile snapshot (runs first)"
        VOLATILE_RAN=1
        run_volatile ps ps aux
        if command -v ss >/dev/null 2>&1; then
            run_volatile ss ss -tulpn
        else
            run_volatile netstat netstat -tulpn
        fi
        run_volatile ip_addr ip addr
        run_volatile mount mount
        run_volatile lsblk lsblk -f
        run_volatile blkid blkid
        run_volatile uptime uptime
        run_volatile who who
        run_volatile w w
        run_volatile last last
        run_volatile systemctl_timers systemctl list-timers --all --no-pager
        if command -v docker >/dev/null 2>&1; then
            run_volatile docker_ps docker ps -a
        fi
    else
        log "P2 skipped: volatile requested but ROOT is not / (offline image)"
        record_degradation "volatile snapshot skipped: not a live root"
    fi
fi

# --------------------------------------------------------- P1 fingerprint --

log "P1 fingerprint"

osrel="$ROOTPFX/etc/os-release"
DISTRO_ID="unknown"; VERSION_ID="unknown"; PRETTY=""
if [ -r "$osrel" ]; then
    # never source evidence files - parse them
    DISTRO_ID=$(sed -n 's/^ID=//p' "$osrel" | head -1 | tr -d '"')
    VERSION_ID=$(sed -n 's/^VERSION_ID=//p' "$osrel" | head -1 | tr -d '"')
    PRETTY=$(sed -n 's/^PRETTY_NAME=//p' "$osrel" | head -1 | tr -d '"')
elif [ -r "$ROOTPFX/etc/redhat-release" ]; then
    DISTRO_ID="rhel-family"
    PRETTY=$(head -1 "$ROOTPFX/etc/redhat-release")
elif [ -r "$ROOTPFX/etc/debian_version" ]; then
    DISTRO_ID="debian"
    VERSION_ID=$(head -1 "$ROOTPFX/etc/debian_version")
else
    record_degradation "no os-release/redhat-release/debian_version under ROOT; distro unknown"
fi

if [ "$ROOT" = "/" ]; then
    KERNEL=$(uname -r 2>/dev/null || printf 'unknown')
    HOSTNAME_V=$(hostname 2>/dev/null || uname -n 2>/dev/null || printf 'unknown')
else
    KERNEL="offline-image"
    HOSTNAME_V=$( [ -r "$ROOTPFX/etc/hostname" ] && head -1 "$ROOTPFX/etc/hostname" || printf 'unknown' )
fi

MACHINE_ID=$( [ -r "$ROOTPFX/etc/machine-id" ] && head -1 "$ROOTPFX/etc/machine-id" || printf '' )

INIT_SYSTEM="other"
[ -d "$ROOTPFX/run/systemd/system" ] && INIT_SYSTEM="systemd"
[ "$ROOT" != "/" ] && [ -d "$ROOTPFX/etc/systemd/system" ] && INIT_SYSTEM="systemd"

TIMEZONE=""
TZ_HOW="none"
if [ -h "$ROOTPFX/etc/localtime" ]; then
    tzlink=$(readlink "$ROOTPFX/etc/localtime" 2>/dev/null || printf '')
    case "$tzlink" in
        *zoneinfo/*) TIMEZONE="${tzlink##*zoneinfo/}"; TZ_HOW="etc_localtime" ;;
    esac
fi
if [ -z "$TIMEZONE" ] && [ -r "$ROOTPFX/etc/timezone" ]; then
    TIMEZONE=$(head -1 "$ROOTPFX/etc/timezone" | tr -d '\r')
    TZ_HOW="etc_timezone"
fi
[ -z "$TIMEZONE" ] && record_degradation "timezone undeterminable; analyzer will assume UTC and flag it"

EUID_V=$(id -u 2>/dev/null || printf 'unknown')
IS_ROOT="false"
PRIV_WARNINGS=""
if [ "$EUID_V" = "0" ]; then
    IS_ROOT="true"
else
    PRIV_WARNINGS="not running as root: /etc/shadow, /var/log/btmp, other users home directories will likely be unreadable"
    log "WARNING: $PRIV_WARNINGS"
fi

# ------------------------------------------------ P1b contamination record --

OP_USER=$(id -un 2>/dev/null || printf 'unknown')
# tty(1) prints "not a tty" on stdout AND exits nonzero - capture then check
OP_TTY=$(tty 2>/dev/null)
if [ $? -ne 0 ] || [ -z "$OP_TTY" ]; then OP_TTY="none"; fi
OP_PID=$$
OP_SRC_IP=""
if [ -n "${SSH_CONNECTION:-}" ]; then
    OP_SRC_IP=$(printf '%s' "$SSH_CONNECTION" | awk '{print $1}')
fi
log "P1b contamination: user=$OP_USER tty=$OP_TTY pid=$OP_PID src=$OP_SRC_IP"

# ------------------------------------------------- P3 static file collect --

log "P3 static collection"
COLLECTED_COUNT=0

collect_file() { # aid category f
    aid=$1; acat=$2; f=$3
    rel="${f#"$ROOTPFX"}"

    if [ ! -r "$f" ]; then
        printf '%s,,,,,,,,0,unreadable\n' "$(csv_path "$rel")" >> "$HASHCSV"
        record_missing "$aid" "$rel" "exists but unreadable (permissions; euid=$EUID_V)"
        return
    fi

    if [ "$REDACT" = 1 ]; then
        case "$aid" in
            shadow)
                stat_file "$f" >/dev/null 2>&1
                printf '%s,,%s,%s,%s,%s,%s,%s,0,redacted\n' \
                    "$(csv_path "$rel")" "$S_SIZE" "$S_MODE" "$S_OWNER" \
                    "$S_ATIME" "$S_MTIME" "$S_CTIME" >> "$HASHCSV"
                log "redacted (metadata only): $rel"
                return
                ;;
        esac
    fi

    # 1. stat BEFORE touching the content
    if ! stat_file "$f"; then
        printf '%s,,,,,,,,0,stat_failed\n' "$(csv_path "$rel")" >> "$HASHCSV"
        record_missing "$aid" "$rel" "stat failed"
        return
    fi
    size1=$S_SIZE; mode1=$S_MODE; owner1=$S_OWNER
    atime1=$S_ATIME; mtime1=$S_MTIME; ctime1=$S_CTIME

    # 2. copy (never write into ROOT); preserve what we can
    dest="$OUTDIR/collected/files$rel"
    destdir=$(dirname "$dest")
    mkdir -p "$destdir" 2>/dev/null
    copied=0
    if [ "$aid" = "lastlog" ]; then
        # sparse UID-indexed file: a naive copy inflates it (trap #6)
        if cp --sparse=always "$f" "$dest" 2>/dev/null; then copied=1; fi
    fi
    if [ "$copied" = 0 ]; then
        if [ "$CPMODE" = "cp-p" ] && cp -p "$f" "$dest" 2>/dev/null; then
            copied=1
        elif cat < "$f" > "$dest" 2>/dev/null; then
            copied=1
            record_degradation "cat-copy used for $rel (cp -p failed)"
        fi
    fi
    if [ "$copied" = 0 ]; then
        printf '%s,,%s,%s,%s,%s,%s,%s,0,copy_failed\n' \
            "$(csv_path "$rel")" "$size1" "$mode1" "$owner1" \
            "$atime1" "$mtime1" "$ctime1" >> "$HASHCSV"
        record_missing "$aid" "$rel" "copy failed"
        return
    fi

    # 3. hash the COPY - the authoritative evidence hash
    fhash=$(sha256 "$dest")

    # 4. stat the source again; growth during collection is normal on live logs
    active=0
    if stat_file "$f"; then
        [ "$S_SIZE" != "$size1" ] && active=1
        [ -n "$mtime1" ] && [ "$S_MTIME" != "$mtime1" ] && active=1
    fi

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,collected\n' \
        "$(csv_path "$rel")" "$fhash" "$size1" "$mode1" "$owner1" \
        "$atime1" "$mtime1" "$ctime1" "$active" >> "$HASHCSV"
    COLLECTED_COUNT=$((COLLECTED_COUNT + 1))
}

TABLE_FILE="$OUTDIR/.artifact_table"
printf '%s\n' "$ARTIFACT_TABLE" | grep -v '^#' | grep -v '^[[:space:]]*$' > "$TABLE_FILE"

while IFS='|' read -r aid acat req rot deep pat; do
    [ -n "$aid" ] || continue
    if [ "$deep" = "1" ]; then
        dirpath="$ROOTPFX$pat"
        if [ -d "$dirpath" ]; then
            FINDLIST="$OUTDIR/.findlist"
            find "$dirpath" -type f 2>/dev/null > "$FINDLIST"
            if [ -s "$FINDLIST" ]; then
                while IFS= read -r f; do
                    collect_file "$aid" "$acat" "$f"
                done < "$FINDLIST"
            else
                record_missing "$aid" "$pat" "directory present but empty"
            fi
            rm -f "$FINDLIST"
        else
            reason="directory not present"
            [ "$req" = "1" ] && reason="REQUIRED directory not present"
            record_missing "$aid" "$pat" "$reason"
        fi
        continue
    fi

    pattern="$ROOTPFX$pat"
    [ "$rot" = "1" ] && pattern="$pattern*"
    matched=0
    old_ifs=$IFS
    IFS='
'
    for f in $pattern; do
        IFS=$old_ifs
        if [ -e "$f" ] && [ ! -d "$f" ]; then
            matched=1
            collect_file "$aid" "$acat" "$f"
        fi
        old_ifs=$IFS
        IFS='
'
    done
    IFS=$old_ifs
    if [ "$matched" = 0 ]; then
        reason="not present"
        [ "$req" = "1" ] && reason="REQUIRED artifact not present"
        case "$pat" in
            /var/log/auth.log) reason="$reason (normal on journald-only systems, e.g. Debian 12)" ;;
        esac
        record_missing "$aid" "$pat" "$reason"
    fi
done < "$TABLE_FILE"
rm -f "$TABLE_FILE"
log "P3 done: $COLLECTED_COUNT files collected"

# --------------------------------------------------- P4 journald export --

log "P4 journald export"
JOURNAL_BOOTS=0
JOURNAL_PERSISTENT="false"
[ -d "$ROOTPFX/var/log/journal" ] && JOURNAL_PERSISTENT="true"

JCTL=""
if command -v journalctl >/dev/null 2>&1; then
    if [ "$ROOT" = "/" ]; then
        JCTL="journalctl"
    elif [ -d "$ROOTPFX/var/log/journal" ]; then
        JCTL="journalctl -D $ROOTPFX/var/log/journal"
    fi
fi

if [ -n "$JCTL" ]; then
    BOOTLIST="$OUTDIR/.boots"
    if $JCTL --list-boots --no-pager 2>/dev/null | awk '{print $1}' \
        | grep -E '^-?[0-9]+$' > "$BOOTLIST"; then :; fi
    if [ -s "$BOOTLIST" ]; then
        while IFS= read -r bootid; do
            jout="$OUTDIR/collected/journal/boot-$bootid.json"
            if $JCTL -b "$bootid" -o json --no-pager > "$jout" 2>/dev/null; then
                jhash=$(sha256 "$jout")
                printf '%s,%s,,,,,,,0,journald_export\n' \
                    "$(csv_path "journal/boot-$bootid.json")" "$jhash" >> "$HASHCSV"
                JOURNAL_BOOTS=$((JOURNAL_BOOTS + 1))
            else
                rm -f "$jout"
                record_missing "journald" "boot $bootid" "journalctl export failed"
            fi
        done < "$BOOTLIST"
    else
        # no boot list; try a single flat export
        jout="$OUTDIR/collected/journal/boot-current.json"
        if $JCTL -o json --no-pager > "$jout" 2>/dev/null && [ -s "$jout" ]; then
            jhash=$(sha256 "$jout")
            printf '%s,%s,,,,,,,0,journald_export\n' \
                "$(csv_path "journal/boot-current.json")" "$jhash" >> "$HASHCSV"
            JOURNAL_BOOTS=1
        else
            rm -f "$jout"
            record_missing "journald" "journal" "journalctl produced no output"
        fi
    fi
    rm -f "$BOOTLIST"
else
    record_missing "journald" "journalctl" "journalctl not available for this root; continuing without journal"
    log "journalctl unavailable - continuing (never abort)"
fi
if [ "$JOURNAL_PERSISTENT" = "false" ]; then
    log "CAVEAT: journal is not persistent (no /var/log/journal); wiped on reboot"
fi

# ------------------------------------------------------ P5 package & seal --

log "P5 package and seal"
END_UTC=$(now_utc)

# assemble manifest.json (missing/degradations were accumulated as JSONL)
MISSING_JSON=$(awk 'NR>1{printf ","} {printf "%s", $0}' "$MISSING_JSONL")
DEGRADE_JSON=$(awk 'NR>1{printf ","} {printf "%s", $0}' "$DEGRADE_JSONL")

{
    printf '{\n'
    printf '  "collector_version": "%s",\n' "$VERSION"
    printf '  "case_id": "%s",\n' "$(json_escape "$CASE_ID")"
    printf '  "operator": "%s",\n' "$(json_escape "$OPERATOR")"
    printf '  "collection_start_utc": "%s",\n' "$START_UTC"
    printf '  "collection_end_utc": "%s",\n' "$END_UTC"
    printf '  "root": "%s",\n' "$(json_escape "$ROOT")"
    printf '  "redact_mode": %s,\n' "$( [ "$REDACT" = 1 ] && printf 'true' || printf 'false' )"
    printf '  "host": {\n'
    printf '    "distro_id": "%s",\n' "$(json_escape "$DISTRO_ID")"
    printf '    "version_id": "%s",\n' "$(json_escape "$VERSION_ID")"
    printf '    "pretty_name": "%s",\n' "$(json_escape "$PRETTY")"
    printf '    "kernel": "%s",\n' "$(json_escape "$KERNEL")"
    printf '    "hostname": "%s",\n' "$(json_escape "$HOSTNAME_V")"
    printf '    "machine_id": "%s",\n' "$(json_escape "$MACHINE_ID")"
    printf '    "timezone": "%s",\n' "$(json_escape "$TIMEZONE")"
    printf '    "timezone_source": "%s",\n' "$TZ_HOW"
    printf '    "init_system": "%s"\n' "$INIT_SYSTEM"
    printf '  },\n'
    printf '  "privilege": {"euid": "%s", "is_root": %s, "warnings": "%s"},\n' \
        "$EUID_V" "$IS_ROOT" "$(json_escape "$PRIV_WARNINGS")"
    printf '  "contamination": {"operator_user": "%s", "source_ip": "%s", "tty": "%s", "pid": "%s", "start_utc": "%s", "end_utc": "%s"},\n' \
        "$(json_escape "$OP_USER")" "$(json_escape "$OP_SRC_IP")" \
        "$(json_escape "$OP_TTY")" "$OP_PID" "$START_UTC" "$END_UTC"
    printf '  "journald": {"available": %s, "persistent": %s, "exported_boots": %s},\n' \
        "$( [ -n "$JCTL" ] && printf 'true' || printf 'false' )" \
        "$JOURNAL_PERSISTENT" "$JOURNAL_BOOTS"
    printf '  "volatile_captured": %s,\n' \
        "$( [ "$VOLATILE_RAN" = 1 ] && printf 'true' || printf 'false' )"
    printf '  "collected_files": %s,\n' "$COLLECTED_COUNT"
    printf '  "hasher": "%s",\n' "$HASHER"
    printf '  "stat_mode": "%s",\n' "$STATMODE"
    printf '  "missing": [%s],\n' "$MISSING_JSON"
    printf '  "degradations": [%s]\n' "$DEGRADE_JSON"
    printf '}\n'
} > "$OUTDIR/manifest.json"
rm -f "$MISSING_JSONL" "$DEGRADE_JSONL"

# seal: tar the evidence + manifests; hash the tar (and optional gzip)
TARBALL="$OUTDIR/bundle.tar"
if tar --numeric-owner -cf "$TARBALL" -C "$OUTDIR" \
        collected manifest.json hash_manifest.csv collector.log 2>/dev/null; then :
elif tar -cf "$TARBALL" -C "$OUTDIR" \
        collected manifest.json hash_manifest.csv collector.log 2>>"$LOGFILE"; then
    record_degradation "tar --numeric-owner unsupported; plain tar used"
else
    printf 'FATAL: tar failed; evidence remains unpacked in %s\n' "$OUTDIR" >&2
    log "FATAL: tar failed"
    exit 2
fi

TARHASH=$(sha256 "$TARBALL")
printf '%s  bundle.tar\n' "$TARHASH" > "$TARBALL.sha256"

if [ "$GZIP" = 1 ]; then
    if command -v gzip >/dev/null 2>&1; then
        gzip -kf "$TARBALL" 2>/dev/null || gzip -c "$TARBALL" > "$TARBALL.gz"
        GZHASH=$(sha256 "$TARBALL.gz")
        printf '%s  bundle.tar.gz\n' "$GZHASH" > "$TARBALL.gz.sha256"
    else
        record_degradation "gzip requested but unavailable"
    fi
fi

log "done: bundle=$TARBALL sha256=$TARHASH files=$COLLECTED_COUNT"

# 1. Stdout streaming mode (raw tarball emitted to stdout for pipes)
if [ "$STDOUT_MODE" = 1 ]; then
    if [ "$GZIP" = 1 ] && [ -f "$TARBALL.gz" ]; then
        cat "$TARBALL.gz"
    else
        cat "$TARBALL"
    fi
    exit 0
fi

# 2. HTTP/TLS streaming mode (direct upload to central server)
if [ -n "$STREAM_URL" ]; then
    # Auto-append the ingest API endpoint if the user only provided the base URL
    case "$STREAM_URL" in
        */api/v1/ingest) ;;
        */) STREAM_URL="${STREAM_URL}api/v1/ingest" ;;
        *)  STREAM_URL="${STREAM_URL}/api/v1/ingest" ;;
    esac

    PAYLOAD="$TARBALL"
    PAYLOAD_HASH="$TARHASH"
    if [ "$GZIP" = 1 ] && [ -f "$TARBALL.gz" ]; then
        PAYLOAD="$TARBALL.gz"
        PAYLOAD_HASH="$GZHASH"
    fi

    printf '[*] Streaming evidence bundle directly to %s...\n' "$STREAM_URL"

    AUTH_HDR=""
    [ -n "$STREAM_TOKEN" ] && AUTH_HDR="Authorization: Bearer $STREAM_TOKEN"

    UPLOAD_OK=0
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$AUTH_HDR" ]; then
            curl -s -S -f -X POST -H "$AUTH_HDR" \
                 -H "X-Case-ID: $CASE_ID" \
                 -H "X-Examiner: $OPERATOR" \
                 -H "X-Bundle-SHA256: $PAYLOAD_HASH" \
                 --data-binary "@$PAYLOAD" "$STREAM_URL" >/dev/null 2>&1 && UPLOAD_OK=1
        else
            curl -s -S -f -X POST \
                 -H "X-Case-ID: $CASE_ID" \
                 -H "X-Examiner: $OPERATOR" \
                 -H "X-Bundle-SHA256: $PAYLOAD_HASH" \
                 --data-binary "@$PAYLOAD" "$STREAM_URL" >/dev/null 2>&1 && UPLOAD_OK=1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "$AUTH_HDR" ]; then
            wget -q -O - --post-file="$PAYLOAD" \
                 --header="$AUTH_HDR" \
                 --header="X-Case-ID: $CASE_ID" \
                 --header="X-Examiner: $OPERATOR" \
                 --header="X-Bundle-SHA256: $PAYLOAD_HASH" \
                 "$STREAM_URL" >/dev/null 2>&1 && UPLOAD_OK=1
        else
            wget -q -O - --post-file="$PAYLOAD" \
                 --header="X-Case-ID: $CASE_ID" \
                 --header="X-Examiner: $OPERATOR" \
                 --header="X-Bundle-SHA256: $PAYLOAD_HASH" \
                 "$STREAM_URL" >/dev/null 2>&1 && UPLOAD_OK=1
        fi
    fi

    if [ "$UPLOAD_OK" = 1 ]; then
        printf '[+] Streaming transmission successful -> %s\n' "$STREAM_URL"
        printf '  files collected: %s\n' "$COLLECTED_COUNT"
        printf '  bundle sha256:   %s\n' "$PAYLOAD_HASH"
        exit 0
    else
        printf 'FATAL: Streaming upload to %s failed (check network, server status, or auth token)\n' "$STREAM_URL" >&2
        exit 1
    fi
fi

# 3. Standard local bundle creation output
printf 'collection complete: %s\n' "$TARBALL"
printf '  files collected: %s\n' "$COLLECTED_COUNT"
printf '  bundle sha256:   %s\n' "$TARHASH"
exit 0
