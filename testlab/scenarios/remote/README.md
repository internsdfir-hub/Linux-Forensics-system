# Attacker-side scenarios — run from the attacker box, hit the target for real

These are the network-attack twins of the local-injection scenarios one
directory up. The difference is where they run and how the evidence is made:

| | Local scenarios (`../`) | Remote scenarios (here) |
|---|---|---|
| Runs on | the **target** (victim) | the **attacker** box (e.g. Kali) |
| Evidence | injected via `logger` / file edits | produced by the **target's own** sshd / PAM / sudo |
| Source IP | simulated (`203.0.113.9`) | **your real attacker IP** |
| Timestamp | can be back-dated | the real wall clock (target-side) |
| Needs | root on the target | network reach + valid creds; **no** changes on the attacker box |

Nothing here mutates the attacker machine and nothing is injected into any log —
the target records the attack through its real code paths. That is as genuine as
a lab gets, and the source IP / timing are no longer faked.

> **Authorisation.** These perform a real SSH attack. Point them ONLY at a host
> you are authorised to test — your own snapshotted lab VM, or an in-scope
> engagement target. Each script makes you re-type the target IP to confirm
> (skip with `LFA_LAB_CONFIRM=yes`).

## Prerequisites (attacker box)

- `ssh` client and **`sshpass`** (`sudo apt-get install -y sshpass`; Kali has it).
- Network reachability to the target's SSH port.
- Valid ("stolen") credentials for the success/login stages. Defaults are
  Metasploitable 2's `msfadmin` / `msfadmin`.

The bundled SSH options already re-enable the old KEX / host-key / cipher
algorithms Metasploitable 2's ancient sshd needs, so a modern client connects.

## The scripts

| Script | Attack | Fires (on the target's analysed bundle) |
|--------|--------|------------------------------------------|
| `02_brute_force_ssh_remote.sh` | T1110 brute force + success | `brute_force`, `brute_force_success` |
| `01_unauthorized_login_remote.sh` | T1078 valid-account login + sudo | `off_hours_privileged`\*, `successful_login` (evidence) |
| `chain_bruteforce_login_remote.sh` | both, in kill-chain order | the above + `first_seen`, all tied to one IP |

\* `off_hours_privileged` is a finding **only if** the sudo lands outside the
target's 08:00–18:00 local hours. Run off-hours, or set the target clock first
(`sudo date -u -s "..."`). In hours it is still on the timeline as evidence.

## Config (environment variables)

| Var | Meaning | Default |
|-----|---------|---------|
| `LFA_TARGET` | target host/IP | **required** |
| `LFA_SSH_PORT` | ssh port | `22` |
| `LFA_VALID_USER` / `LFA_VALID_PASS` | valid credentials | `msfadmin` / `msfadmin` |
| `LFA_BF_USER` | account to guess against (scenario 02) | `LFA_VALID_USER` |
| `LFA_BF_COUNT` | number of failed attempts | `6` (rule needs ≥5) |
| `LFA_WITH_SUCCESS` | 0 = failures only (scenario 02) | `1` |
| `LFA_PRIV_CMD` | command to run via sudo (scenario 01) | `cat /etc/shadow` |
| `LFA_LAB_CONFIRM=yes` | skip the authorisation prompt | (prompts) |

## Workflow

```sh
# 1. attacker box — run the chain against the target
cd testlab/scenarios/remote
LFA_TARGET=192.168.56.101 sh chain_bruteforce_login_remote.sh

# 2. TARGET — collect the bundle (BEFORE any manual live analysis)
sudo sh collector/collect.sh -o /tmp/out -c CASE-INTRUSION -p "YourName" -z

# 3. examiner — analyse, verify, score (the chain script prints this block too)
python -m lfa analyse CASE-INTRUSION*.tar.gz --case-dir cases/CASE-INTRUSION --examiner "YourName"
python -m lfa verify  cases/CASE-INTRUSION
```

Collect the target **before** you log in to look around — your own session
would write fresh `auth.log` / `wtmp` entries and contaminate the evidence.
