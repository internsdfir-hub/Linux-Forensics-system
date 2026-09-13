# Real-target attack scenarios — reproducibility tickbox

Six scripts under `testlab/scenarios/`, one per attack, plus `lib.sh` (shared
helpers). They exist to demonstrate the analyzer on a **real Linux target**,
not a fixture — you run them on a disposable VM, collect a bundle, analyse it
offline, and compare the findings against the ground truth each script records.

> **Safety.** Every script mutates the system (users, logs, cron, keys). Run
> them **only on a snapshotted VM you can roll back**. Each refuses to run
> until you type `lab` (or set `LFA_LAB_CONFIRM=yes`), and each needs root.

---

## The tickbox — is each scenario reproducible on a real system?

| # | Scenario | Reproducible? | How / what it takes |
|---|----------|:---:|---------------------|
| 1 | Unauthorized login | ✅ **Fully** | `sudo sh 01_unauthorized_login.sh`. Login/off-hours values are injected; a real second host makes them natural. Deterministic, re-runnable. |
| 2 | Brute-force SSH | ✅ **Fully** | `sudo sh 02_brute_force_ssh.sh` (simulated burst). `GENUINE_SSH=1` performs *real* failed logins against localhost (source = 127.0.0.1). |
| 3 | Insider activity | ✅ **Fully** | `sudo sh 03_insider_activity.sh`. Real account + real history wipe; off-hours timestamp is injected so you needn't work at 2am. |
| 4 | USB data theft | ⚠️ **Partially** | **Manual + automatic.** Needs a VM with USB passthrough (VirtualBox/VMware) or bare metal — **not WSL**. Insertion is physical; the evidence it leaves is fully reproducible. |
| 5 | Privilege escalation | ✅ **Fully** | `sudo sh 05_privilege_escalation.sh`. 100% genuine `/etc/passwd`,`/etc/shadow`,`/etc/group` mutations. High blast radius — snapshot first. |
| 6 | Suspicious process execution | ✅ **Fully** | `sudo sh 06_suspicious_process_execution.sh`. Real command execution. `auditd` (`apt-get install auditd`, **absent on WSL**) gives kernel-level proof; without it the `suspicious_process` rule still scores from shell history — run the payload commands interactively so they land in `~/.bash_history`. |

Legend: ✅ fully scriptable & deterministic · ⚠️ needs a physical/manual step or specific hardware.

---

## Genuine vs simulated — and how real life differs

The honest distinction your demo should make: what the script *actually does*
to the machine vs. what it *fakes* because you can't safely reproduce it in a
one-host lab.

| # | GENUINE on the lab box | SIMULATED (and why) | How a real attacker/insider does it |
|---|------------------------|---------------------|-------------------------------------|
| 1 | A real privileged session / auth records | External source IP + off-hours time (can't spoof a routable IP locally; don't roll the clock) | Logs in over SSH with stolen valid creds from their own infra, at their timezone's convenience |
| 2 | With `GENUINE_SSH=1`: real sshd/PAM failure records | Attacker source IP for a clean single-source burst | Runs hydra/medusa/patator against the public SSH port from a VPS |
| 3 | Real employee account, real `.bash_history` truncation, real staged files | Off-hours timestamp + ≥3 prior sessions | A trusted user works late, collects data, clears history — every action individually "allowed" |
| 4 | **Everything USB-side is genuine** — real kernel messages, real device, real mount | Nothing (the constraint is physical, not faked) | Walks up, inserts a stick, copies files, leaves. The kernel logs vendor/product/serial regardless |
| 5 | **All genuine** — this *is* the real technique | Nothing | Post-foothold, creates a hidden UID-0 account / nopass account / adds a user to sudo for durable root |
| 6 | Real command execution (C2 target is non-routable so it fails safely) | Nothing — the commands really run | Runs curl beacons, reverse shells, base64 payloads. auditd is the only reliable record on a live box |

---

## Detection layer — what proves each one, and where

Two output layers matter (see the parser/rule split in the analyzer):

- **Finding** = a rule fired → row in the `findings` table → scored by
  `tools/score_detection.py`.
- **Evidence** = timeline row(s) in the `events` table, no dedicated rule.
  Validate with SQL against `case.db`; these are marked `[EVIDENCE]` (unscored)
  by the scorer.

| # | Detection layer | Rule(s) that should fire | Evidence to check if no rule |
|---|-----------------|--------------------------|------------------------------|
| 1 | Finding + evidence | `off_hours_privileged` | `successful_login` from the attacker IP |
| 2 | Finding | `brute_force`, `brute_force_success` | `failed_login` count per source |
| 3 | Finding + evidence | `off_hours_privileged`, `wiped_history` | staged files, session records |
| 4 | **Evidence only** | *(none today)* | `usb_connect` / `usb_disconnect`, `storage_device` |
| 5 | Finding (×4) | `uid0_account`, `passwordless_account`, `privileged_group_member`, `new_account_privilege_grant` | `/etc/passwd`, `/etc/group` diffs |
| 6 | Finding + evidence | `suspicious_process` | `process_execution` (auditd), `running_process` (ps), `shell_command` / `suspicious_command` (history) timeline entries |

Scenario 4 is evidence-only **by design** — the same way the existing `usb`,
`netstat`, and `browser` parsers work. That is a defensible scope boundary to
state out loud, not a defect.

Scenario 6 is now a **scored finding**: the `suspicious_process` rule flags
reverse-shell / C2-beacon / encoded-payload command shapes, and raises the
finding to **high confidence** when the command ran within an hour of a login
from an IP that also brute-forced the host (post-compromise execution).

It reads three artifacts, so it does not depend on any one of them: auditd
`execve` records, the `ps aux` snapshot, and shell history. History is what
makes the scenario score on a host with no auditd and no surviving process
— the Metasploitable default — but it is also the weakest source, so a
history-only finding is capped at **Medium** confidence and says why: history
records what was *typed*, not what the kernel ran, and the account owner can
edit or wipe it. A command recorded by two of the three artifacts is merged
into **one** finding that names both sources.

---

## The golden workflow (run this end to end)

```sh
# 0. SNAPSHOT the VM. Everything below is inside the snapshot.

# 1. (scenario 6 only) turn on execution auditing BEFORE the activity
sudo apt-get install -y auditd        # not on WSL

# 2. run the scenarios you want to demonstrate
cd testlab/scenarios
sudo sh 01_unauthorized_login.sh
sudo sh 02_brute_force_ssh.sh
sudo sh 03_insider_activity.sh
sudo sh 05_privilege_escalation.sh
sudo sh 06_suspicious_process_execution.sh
sudo sh 04_usb_data_theft.sh          # last: has a manual insertion step

# 3. COLLECT the bundle (collector first, before any manual live analysis)
sudo sh collector/collect.sh -o /tmp/out -c CASE-REAL -p "YourName" -z

# 4. move the bundle off-box, then analyse + verify integrity offline
python -m lfa analyse /tmp/out/CASE-REAL*.tar.gz --case-dir cases/CASE-REAL --examiner "YourName"
python -m lfa verify cases/CASE-REAL

# 5. score the rule-backed scenarios against their ground truth
for gt in testlab/scenarios/*.ground_truth.json; do
  echo "== $gt =="
  python tools/score_detection.py --case-dir cases/CASE-REAL --ground-truth "$gt"
done

# 6. validate the EVIDENCE-only scenarios (4, 6) with SQL — examples:
sqlite3 cases/CASE-REAL/case.db \
  "SELECT timestamp_utc,description FROM events WHERE subcategory IN ('usb_connect','usb_disconnect');"
sqlite3 cases/CASE-REAL/case.db \
  "SELECT timestamp_utc,severity,description FROM events WHERE subcategory='process_execution';"

# 7. ROLL BACK the snapshot.
```

**Do the manual live-analysis pass blind** — before you open the report — so
your independent findings aren't anchored by the tool's. Then diff three ways:
ground truth vs. tool output vs. your manual pass. Each `.ground_truth.json`
carries a `verify` command per threat for exactly that manual check.

---

## What changed to support these

- **New parser `execution.py`** — `auditd_parser` (real `execve` capture with
  epoch timestamps and reconstructed argv) and `ps_parser` (`ps aux` snapshot).
  Both were *collected already* but nothing read them; this closes scenario #6.
- **New rule `suspicious_process`** (`rules/execution.py`) — promotes the
  execution evidence to a scored finding: flags reverse-shell / C2-beacon /
  encoded-payload command shapes, high confidence when correlated with a
  brute-forced login. Scenario #6 is now scored, not evidence-only.
  v1.1 also consumes shell history (`shell_command`, `suspicious_command`),
  which removes the auditd / live-process dependency, and merges the same
  command seen in several artifacts into one corroborated finding.
- **New parsers `sshdconfig.py` + `startup.py`** — turn `/etc/ssh/sshd_config`,
  `/etc/ld.so.preload`, and shell startup files into events, reviving
  `sshd_config_risk` and `ld_preload_rootkit`, which previously **could not
  fire** (no parser fed them).
- **`sshd_config_risk` fix** — the finding text now names the actual risky
  directive instead of always saying "root login enabled".
- **`score_detection.py`** — evidence-only ground-truth items (`expected_rule:
  null`) are reported `[EVIDENCE]` and excluded from the detection rate, instead
  of being counted as misses.
