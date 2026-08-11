Live Linux Forensics Framework — Design & Artifact Catalogue
=========================================================

This document captures a full design for a live Linux forensics system: the architecture, collector design, transport, normalization, storage, analysis, reporting, and an exhaustive per-category list of artifacts to extract across different Linux distributions.

Summary
-------
- Goal: run a lightweight collector on endpoints that extracts forensic artifacts, sends them securely to a central server, where artifacts are parsed, normalized (ECS-like), stored, analyzed, and presented in a dashboard and forensic reports.
- Design principles: modularity, least privilege, signed/tamper-evident artifacts, extensible plugin modules per artifact category, and per-category UI toggles.

High-level Architecture
-----------------------
- Collector (endpoint agent)
  - Runs as a daemon (systemd service) or ad-hoc mode.
  - Modular plugin architecture: each category is a separate plugin/collector module.
  - Minimal footprint; written in Go/Rust for portability (Python for plugins allowed).
- Transport
  - Mutual-TLS over HTTPS (or MQTT/TLS) with chunked, compressed uploads.
  - Offline queueing, retry/backoff, and upload resumability.
- Ingestion & Parsing
  - HTTPS endpoint -> message queue (Kafka/RabbitMQ) -> parser workers.
  - Workers validate, decompress, parse into normalized schema (recommend Elastic Common Schema (ECS)).
- Storage
  - Searchable events store: ElasticSearch or OpenSearch.
  - Relational metadata: PostgreSQL.
  - Object store for raw artifacts: S3/MinIO.
- Analysis & Correlation
  - Rule engine (Sigma/Sigma-like), YARA for file signatures.
  - Anomaly detection models for baselining.
  - Timeline builder linking events by host, user, IP, and file hash.
- UI & Reporting
  - Web dashboard (React), per-host timelines, per-category views, alert list.
  - Exportable forensic reports (PDF/CSV).

Security & Integrity
--------------------
- Signed bundles: agent signs uploads; server verifies.
- SHA256 hashes recorded for all raw artifacts.
- RBAC and audit trails for server access.
- Optional PII redaction rules before upload.

Collector Design & Runtime Modes
--------------------------------
- Language: Go or Rust single-binary recommended for production; Python for quick prototyping.
- Modes
  - Agent (continuous): runs periodic or event-driven collections.
  - Ad-hoc (pull): triggered by analyst.
  - Remote-exec (SSH) mode for ephemeral collection.
- Plugin API: plugins return JSON events and optional raw files; each event contains metadata: `@timestamp`, `host.id`, `plugin.name`, `file.pointer` (to raw object), `hashes`.
- Resource controls: CPU limits, disk write limits, file-size limits, allowlist/denylist.

Normalization & Data Model
--------------------------
- Use an ECS-like model: `@timestamp`, `host.*`, `user.*`, `process.*`, `file.*`, `network.*`, `event.*`, `tags`.
- Store raw artifacts in object store and add pointer metadata to event entries (object path, size, hash).

Per-Category Extraction Catalogue (exhaustive)
---------------------------------------------
For each category, the collector should provide a "brief" extraction (safe, minimal info) and a "full" extraction (requires elevated privileges or more time). Each category is a plugin and a UI toggle.

1) User Information
- Files & commands
  - `/etc/passwd`, `/etc/shadow` (requires root), `/etc/group`, `/etc/gshadow`
  - `getent passwd`, `getent group`
  - `/var/lib/AccountsService/users/*` (Ubuntu/Debian)
  - `chage -l <user>` output (password aging)
  - `sudoers`: `/etc/sudoers`, `/etc/sudoers.d/*`
  - NSS / LDAP config: `/etc/nsswitch.conf`, `/etc/ldap/` related files
- Artifacts
  - Local users list (uid,gid,home,shell), password aging, locked accounts, sudoers entries, group memberships, LDAP/NIS pointers

2) Login & Authentication Activities
- Sources
  - `journalctl` (system and unit logs)
  - `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL/CentOS)
  - `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog`
  - `last`, `lastb`, `who`, `w`
  - `sshd` logs and `/etc/ssh/sshd_config`
  - `~/.ssh/authorized_keys` and `~/.ssh` folder contents
  - `auditd` USER_AUTH and USER_LOGIN events if `auditd` enabled
- Artifacts
  - Successful and failed logins (timestamps, source IPs, username), login durations, session IDs, tty, remote hostnames, authentication method (password/key), `authorized_keys` fingerprints, PAM messages, `sshd_config` authentication settings

3) Failed Login Aggregates
- Extract counts, IPs, users, geolocation (via GeoIP), time windows, correlated repeated failures across hosts

4) USB Device & Removable Media
- Sources
  - Kernel ring buffer (`dmesg`), `journalctl -k`
  - `/run/udev/data/*`, `/sys/bus/usb/devices/*/uevent`
  - `lsusb -v`, `udevadm info --query=all --name=/dev/sdX`, `blkid`, `lsblk -o`
  - `/dev/disk/by-id/`, `/var/log/udisks2`, automount logs
- Artifacts
  - Device addition/removal times, Vendor ID, Product ID, serial number, device model, USB class, assigned device node (`/dev/sdX`), filesystem UUID/label, mountpoints, mount options, user who mounted, mount duration

5) Storage & Filesystem (disks/partitions/LVM/RAID)
- Sources
  - `lsblk`, `blkid`, `fdisk -l`, `/etc/fstab`, `mount`, `/proc/mounts`
  - LVM metadata: `/etc/lvm/archive`, `lvdisplay`, `pvdisplay`, `vgdisplay`
  - mdadm config: `/etc/mdadm.conf`
  - SMART: `smartctl --all /dev/sdX`
- Artifacts
  - Partition layout, filesystem types, UUIDs, labels, LVM & RAID details, encrypted volumes (LUKS header metadata), S.M.A.R.T. summary

6) File & Persistence Artifacts (autoruns)
- Sources
  - Cron: `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/crontabs/*`, `crontab -l`
  - systemd units: `/etc/systemd/system/*.service`, `/etc/systemd/system/*.timer`, `systemctl list-timers`
  - user autostart: `~/.config/autostart`, `/etc/xdg/autostart`, `/etc/rc.local`, `/etc/init.d/*`
  - desktop environment autostart files, `/etc/profile.d/` scripts
- Artifacts
  - Scheduled tasks, startup entries, new services, unusual SUID/SGID files, modified init scripts, recently created/modified files with executable bit, suspicious binaries in uncommon paths

7) Browser & User Application Artifacts
- Chrome/Chromium/Edge/Brave
  - `~/.config/google-chrome/Default/History` (SQLite), `Cookies`, `Bookmarks`, `Preferences`, `Local Storage` directories, `Downloads` folder and History
- Firefox
  - `~/.mozilla/firefox/*/places.sqlite`, `cookies.sqlite`, `sessionstore-backups`, `formhistory.sqlite`, `extensions.sqlite`
- Other Apps
  - Electron app storages in `~/.config/*`, Thunderbird mail stores, Slack/Discord local caches, VSCode extensions and settings
- Artifacts
  - Visited URLs, timestamps, downloaded filenames, cached files, autofill/form history, saved passwords (if accessible), extension list, session restore data

8) Network & Internet Activities
- Sources
  - `/proc/net/tcp`, `/proc/net/udp`, `ss -tunap`, `netstat -tunap`
  - `iptables`/`nft` rules, `conntrack -L` state, NetworkManager logs, `dhclient` leases
  - DNS caches: `systemd-resolved` cache, `dnsmasq` or local caching service logs
  - Proxy logs (squid), local DNS server logs
- Artifacts
  - Active/listening services, established connections (IP/port), historic connections (where logged), DNS queries, DHCP leases, ARP cache, NAT/forwarding rules

9) Processes & Live System State
- Sources
  - `ps -ef`, `/proc/<pid>/cmdline`, `/proc/<pid>/environ`, `lsof`, `ss` for sockets, `/proc/<pid>/maps` for loaded libs
  - `systemctl list-units --type=service --all`
- Artifacts
  - Running processes, parents and ancestry, command lines, environment variables (if allowed), open files and sockets, listening ports, loaded kernel modules
  - Optional: `gcore` dumps for suspicious PIDs (requires careful handling and storage)

10) Audit & System Logs
- Sources
  - `journalctl --all`, `/var/log/syslog`, `/var/log/messages`, `/var/log/kern.log`
  - `auditd` logs: `/var/log/audit/audit.log` and `ausearch` output
- Artifacts
  - Service crashes, kernel oops, module load/unload, audit records for execve, file writes if audited, SELinux/AppArmor denials

11) Package & Software Changes
- Sources
  - Debian/Ubuntu: `/var/log/apt/history.log`, `/var/log/dpkg.log`, `dpkg -l`
  - RHEL/CentOS: `/var/log/yum.log`, `rpm -qa`
  - Arch: `/var/log/pacman.log`
  - SUSE: zypper logs
- Artifacts
  - Installed/removed packages, upgrade times, package signatures, package sources (repos), suspicious new packages or package managers

12) System Information & Configuration
- Sources
  - `/etc/os-release`, `uname -a`, `hostnamectl`, `/etc/hosts`, `/etc/resolv.conf`, `sysctl -a`, `dmesg` summary, `lshw` or `dmidecode` (if available)
- Artifacts
  - OS version, kernel, uptime, hardware inventory, BIOS/UEFI information, timezone

13) Firewall & Network Filtering Configs
- Sources
  - `iptables-save`, `nft list ruleset`, `ufw status verbose`, `firewalld` configs
- Artifacts
  - Active rules, NAT and forwarding rules, blocked/dropped packet counters, recent firewall changes

14) Authentication & Privilege Escalation Artifacts
- Sources
  - `auth.log`/`secure`, `auditd` USER_CMD, `sudo -l` outputs (if run as user), `pkexec` logs
- Artifacts
  - Commands run under sudo, environment preserved/not, UID/GID changes, su attempts, suspicious privilege escalations

15) Shell & User Histories
- Sources
  - `~/.bash_history`, `~/.zsh_history`, `~/.history`, `~/.mysql_history`, `~/.python_history`, shell timestamping (`HISTTIMEFORMAT`) where available
  - `~/.lesshst`, `~/.local/share/recently-used.xbel` and desktop recent files, terminal multiplexer logs (tmux, screen)
- Artifacts
  - Commands executed, download commands (curl/wget), base64 strings, obfuscated commands, script invocations, timestamps (if available)

16) Forensic Metadata & Hashes
- Actions
  - Compute SHA256 (and optionally MD5 or SHA1) for binaries, config files, suspicious files, and raw artifacts stored.
  - Record file metadata: size, permissions, ownership, mtime/ctime/atime.

17) Containers & Virtualization
- Sources
  - Docker: `/var/lib/docker/containers/*/json.log`, `docker ps -a`, `docker inspect` outputs
  - Podman, containerd, Kubernetes kubelet logs, `/var/log/containers/` (k8s)
  - VM hypervisor logs (libvirt `/var/log/libvirt/`, qemu logs)
- Artifacts
  - Container images, running containers, mounts, exposed ports, container process lists, container network namespaces, suspicious images pulled

18) Memory & Advanced Artifacts (optional)
- Sources
  - `gcore` per-PID dumps, LiME for full RAM image, `volatility` plugins for Linux where available
- Caveats
  - Memory capture is large and intrusive; requires legal/operational approval. Handle chain-of-custody and secure transport for images.

Extraction Rules for Multiple Linux Flavors
-----------------------------------------
- Always try `journalctl` first (systemd systems) and then fallback to legacy `/var/log/*` files.
- Detect distro via `/etc/os-release` and collect package-manager-specific logs (apt/yum/pacman/zypper/apk).
- Check for init system (systemd vs sysv) and parse appropriate directories and service files.
- Detect presence of `auditd`, `apparmor`, `selinux`, `docker`/`podman` and collect their logs/configs.

Transport, Privacy & Legal
-------------------------
- Transport: mTLS + TLS 1.2/1.3, strong ciphers, client cert-based authentication. Fallback: token-based with HMAC.
- Encryption at rest: server-side encryption on object store; database encryption for sensitive fields.
- PII & legal: implement redaction policies; collect `shadow` only when authorized; require explicit opt-in for memory images and `/etc/shadow`.

Processing & Correlation
------------------------
- Timestamp normalization to UTC; record host local time and server receive time to help clock skew.
- Correlate events by `host.id`, `user.name`, `file.hash`, `ip.address`.
- Enrich events: GeoIP for IPs, vendor DB for MACs and USB vendor IDs, VirusTotal/file reputation lookup (optional).
- Rule engine for alerts; timeline builder for per-host and cross-host correlation.

Dashboard & Reporting
---------------------
- Per-category UI panels with "brief" and "full" extraction toggles.
- Timeline view with filters (time range, users, processes, IPs, hashes).
- Alerting: critical alerts, medium alerts, informational. Integrations: email, Slack, webhook.
- Forensic report template: executive summary, per-host timeline, artifacts list with pointers to raw objects and hashes, alert list, recommended actions.

Storage & Retention
-------------------
- Retention policies: parsed events (days/weeks), raw artifacts (shorter or longer depending on policy). Use ILM (index lifecycle management) in ES/OpenSearch.
- Archive cold storage for long-term retention of raw images.

Implementation Recommendations & Tools
-------------------------------------
- Collector: Go single-binary with plugin system (plugins as subprocesses or dynamically loaded modules). Provide a Python plugin SDK for quick parsers.
- Ingestion: HTTPS endpoint + Kafka for scalability. Parser workers in Python for rich parsing (SQLite browser history, logs).
- Parsing helpers: use sqlite3 for browser DBs, python `pyelftools` for ELF metadata, `libmagic`/`file` for type detection.
- Storage: OpenSearch + MinIO + PostgreSQL.
- Dashboard: OpenSearch Dashboards / Kibana or custom React UI using the search API.
- Leverage existing components where appropriate: Elastic Beats or Filebeat modules as inspiration; osquery for endpoint query capabilities.

Minimal Viable Product (MVP)
----------------------------
- Collector with 3 initial modules: auth logs, USB events, browser history (Chrome/Firefox).
- Secure HTTPS transport to a simple ingestion server that stores events in OpenSearch and raw artifacts in MinIO.
- Basic React dashboard with per-host timeline and per-category cards.

Operational & Legal Notes
------------------------
- Access control and approvals are required for any sensitive collections (memory, `/etc/shadow`).
- Chain-of-custody metadata must be recorded for all raw artifacts (collector identity, timestamp, hash, transfer logs).

Next Steps / Offer
------------------
If you want, I can scaffold a runnable MVP prototype in this workspace:
- `collector/` (Go) with plugin scaffolding and 3 example plugins
- `ingest/` (simple Python/Flask) receiver that writes to OpenSearch/MinIO
- `dashboard/` placeholder React app with minimal timeline

Tell me which pieces to scaffold first (collector prototype, ingestion server, or dashboard), and I will generate the files and a README with run instructions.

— End of document
