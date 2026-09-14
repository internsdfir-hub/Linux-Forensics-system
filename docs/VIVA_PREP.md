# LFA — Viva Preparation Guide

**Project:** Linux Forensic Analyzer (`lfa`) — a two-stage, offline, deterministic forensic log collection and correlation system for Linux.

**Live numbers (verified, not estimated):**

| Metric | Value |
|---|---|
| Automated tests | **477 passing** (`python -m pytest`, ~5m48s) |
| Parsers | **29** auto-discovered plugins |
| Correlation rules | **19** auto-discovered plugins |
| Collector | **772 lines** of POSIX `sh`, zero runtime dependencies |
| Total source | ~24,000 lines (Python + sh + YAML + templates) |
| Evidence categories | **9** frozen enum values |
| Runtime deps (analyzer) | Python 3.11+, `PyYAML`, `Jinja2` — that's all |

---

## 1. The one-minute answer

> "LFA is a Linux forensic tool split into two halves that never run on the same machine. A 772-line POSIX shell collector runs on the compromised host — no Python, no installs — and copies evidence out, hashing every copy as it goes. A Python analyzer runs on the examiner's workstation, re-verifies every hash, parses ~30 artifact formats into one frozen event schema, stores them in SQLite, runs 19 explainable correlation rules over the timeline, and produces a fully self-contained offline HTML report plus byte-deterministic JSON/CSV exports. The guarantee is that the same evidence always produces the same output, byte for byte, and that every finding names the exact rule and the exact evidence lines that triggered it — no machine learning, no black boxes."

---

## 2. The problem, and why it needed solving

When a Linux server is suspected of compromise, an investigator faces four hard problems:

1. **Evidence is scattered and inconsistent.** Login data lives in `/var/log/auth.log` on Debian, `/var/log/secure` on RHEL, and possibly only in the systemd journal on Debian 12. Login records are in binary `utmp` structs on old systems and in a *SQLite database* (`wtmp.db`) on Kali 2024+/Ubuntu 24.04. Every distro is different.
2. **Touching the system destroys the evidence.** Logging in over SSH writes to `wtmp` and `auth.log`. Reading a file updates its `atime`. Your own shell writes `.bash_history`. The act of investigating contaminates what you're investigating.
3. **Timestamps lie.** Classic syslog lines carry **no year and no timezone** — `Mar 14 02:19:07`. A tool that normalises those to UTC without first collecting the host's timezone is silently wrong by hours, and produces a plausible-looking timeline that is simply false.
4. **Findings must be defensible.** An investigator may have to justify a conclusion to a manager, a lawyer, or an opposing expert. "The model gave it a 0.87 anomaly score" is not defensible. "Rule `brute_force_success` v1.0 fired because 47 authentication failures from 203.0.113.9 preceded a successful login for `kali` by 41 seconds, here are the 48 event IDs" is.

Existing tools solve parts of this. Elastic/Splunk require heavy infrastructure and an agent on the target. Autopsy/FTK are disk-image-oriented, not log-oriented. Linux triage scripts (UAC, CatScale) collect well but hand you a tarball with no correlation or reporting. LFA sits in that gap: **triage-grade collection with SIEM-grade correlation and court-grade determinism, in a package you can carry on a USB stick.**

---

## 3. Architecture — the two-sided split

The central architectural decision, from which almost everything else follows:

```
              TARGET / LIVE LINUX HOST  (possibly compromised)
  ┌────────────────────────────────────────────────────────────────┐
  │  collector/collect.sh                                          │
  │    • POSIX sh only — runs on dash, busybox, Ubuntu 8.04         │
  │    • Reads, never writes, inside $ROOT                          │
  │    • Copy first → hash the COPY → stat before & after           │
  │    • Emits: bundle.tar(.gz) + manifest.json + hash_manifest.csv │
  └──────────────┬─────────────────────────────────┬───────────────┘
                 │                                 │
       (A) USB / manual transfer          (B) HTTPS stream  /  (C) SSH pull
                 │                                 │
                 ▼                                 ▼
  ┌────────────────────────────────────────────────────────────────┐
  │           EXAMINER WORKSTATION / SOC SERVER  (trusted)          │
  │                                                                │
  │  ingest.py      extract → RE-HASH every file vs manifest       │
  │                 → mismatches quarantined, not deleted            │
  │  timeeng.py     timezone resolution + syslog year inference     │
  │  pipeline.py    walk artifacts → offer to 29 parsers            │
  │  parsers/*      each format → NormalizedEvent                   │
  │  db.py          SQLite case.db (deduped, indexed)               │
  │  rules/*        19 correlation rules → Findings                 │
  │  report/*       self-contained offline HTML + SVG charts        │
  │  canonical.py   byte-deterministic JSON + per-category CSV      │
  │  server.py      ingest API + SOC dashboard  (stdlib http.server)│
  │  explorer.py    Autopsy-style single-page investigation UI      │
  └────────────────────────────────────────────────────────────────┘
```

**Why split it this way?** Three reasons, and you should give all three:

- **Dependency reality.** You cannot assume a compromised production box has Python 3.11, or pip access, or internet. POSIX `sh` + coreutils is the only thing genuinely guaranteed. Putting the analysis in shell would be unmaintainable; putting the collection in Python would make it unrunnable. So: minimum-capability collector, full-power analyzer.
- **Trust boundary.** The target host is *potentially hostile*. A rootkit could have replaced `ls`, `ps`, even `sha256sum`. The less logic we run there, and the sooner we get evidence off it and onto trusted hardware, the better. All *analysis* happens where the attacker has no reach.
- **Forensic soundness.** The collector's job is acquisition with a chain of custody. The analyzer's job is interpretation. Mixing them means you can't re-analyse old evidence when your rules improve — and you *will* improve your rules. Here, `python -m lfa report` re-renders a case from `case.db` with updated logic, months later, without ever touching the target again.

---

## 4. End-to-end flow — follow one line of evidence

This is the question most likely to be asked as "walk me through what happens." Trace a single brute-force line.

**Stage 1 — Collection (on target).** `collect.sh` runs its phases in a deliberate order derived from RFC 3227's *Order of Volatility*:

- **P2 Volatile first** (`-V`): `ps aux`, `ss -tunap`, `ip addr`, `mount`, `who`, `last`, `systemctl list-timers`. These change second by second, so they're grabbed before anything slower.
- **P1 Fingerprint**: parse (never *source*) `/etc/os-release` for distro, read the `/etc/localtime` symlink target for the timezone, read `/etc/machine-id` for a stable host identifier.
- **P1b Contamination record**: who is running this, from what IP (`SSH_CONNECTION`), on what tty, at what PID, between what UTC times. *This is the evidence of our own interference.*
- **P3 Static collection**: walks the embedded artifact table (~90 path patterns). For each file: `stat` → copy → `sha256` the copy → `stat` again. A row goes into `hash_manifest.csv` regardless of outcome: `collected`, `unreadable`, `copy_failed`, `stat_failed`, `redacted`.
- **P4 Journald export**: `journalctl -b <n> -o json` per boot.
- **P5 Seal**: `tar` it, hash the tar, optionally gzip and hash that too.

Our line — `Mar 14 02:19:07 host sshd[1234]: Failed password for kali from 203.0.113.9 port 44122` — is now inside `collected/files/var/log/auth.log`, and `auth.log`'s SHA-256 is recorded in `hash_manifest.csv`.

**Stage 2 — Ingest (`ingest.py`).** The bundle is extracted to `cases/<case>/raw/<host_id>/`. Then every file listed in the manifest is **re-hashed and compared**. A mismatch means the file changed between collection and ingestion — so it's **moved to `_integrity_failed/` and never parsed**, because anything derived from it would be unattributable. Analysis continues on the rest. The verified hashes are written to `_verified_hashes.json` so `lfa verify` can prove later that nothing changed *after* ingest either. Files are `chmod 444`'d best-effort, and everything in the package reads evidence through `open_raw()`, which only ever opens `'rb'`.

**Stage 3 — Time resolution (`timeeng.py`).** Our line has no year and no timezone. The engine:
1. Takes the timezone from the collected `/etc/localtime` target, recording `tz_source="etc_localtime"`. If there was none, it falls back to UTC and records `tz_source="assumed_utc"` — so the report can *say so*.
2. Finds the year: first from any ISO-8601 anchor line in the same file; otherwise from the file's `mtime` as an upper bound, stepping the year backwards if the resulting date would be in the future (handles the **December→January rollover** inside one rotated file) or invalid (Feb 29 in a non-leap year).
3. Marks the result `timestamp_confidence="year_inferred"` — **never presented as certain.**

**Stage 4 — Parse (`pipeline.py` + `parsers/`).** The pipeline offers `var/log/auth.log` to all 29 parsers. `authlog_parser` claims it via its `applies_to` glob. It streams lines lazily with byte offsets, loads the YAML grammar for the Debian family, and matches. The rule `sshd_failed_password` in `config/grammars/common.yaml` matches, yielding named groups `user=kali`, `ip=203.0.113.9`, `port=44122`, with `category: login_activity`, `subcategory: failed_login`, `severity: low`.

**Stage 5 — Normalise (`schema.py`).** A `NormalizedEvent` is built. `event_hash = sha256(host_id ⋮ source_path ⋮ byte_offset ⋮ raw_line ⋮ subcategory)`. `event_id = uuid5(NAMESPACE_LFA, event_hash)` — deterministic, never random. Provenance fields (`source_artifact_path`, `source_artifact_sha256`, `parser_name`, `parser_version`, `raw_line`, `raw_line_offset`) are filled in automatically so every event can be traced back to a byte range in a hashed file.

**Stage 6 — Store (`db.py`).** Inserted in 5,000-row batches via `INSERT OR IGNORE` on the `UNIQUE` `event_hash` — so re-ingesting overlapping rotated logs deduplicates for free. Invalid events are counted and skipped; **a bad parser fails its own event, never the run.**

**Stage 7 — Correlate (`rules/`).** `BruteForceRule` groups failures by source IP and slides a 5-minute window looking for ≥5. `BruteForceSuccessRule` then looks for a `successful_login` from the same IP within 15 minutes after such a burst — and that pairing is the single most valuable correlation in the tool, because it turns "someone tried" into "someone got in."

**Stage 8 — Report (`report/`).** Jinja2 templates render a fully self-contained HTML file: CSS and JS inlined, charts generated as pure-Python SVG, zero external requests. Plus `exports/events.json` and per-category CSVs, byte-deterministic.

---

## 5. Tech stack — and the justification for each choice

You will be asked "why X and not Y." Have the answer, not just the name.

| Layer | Choice | Why this, not the obvious alternative |
|---|---|---|
| Collector language | **POSIX `sh`** | Go/Rust single binary is the production-grade answer, but needs cross-compilation per arch and you must trust a binary you can't read. Shell is auditable by the investigator on-site, runs on busybox and Ubuntu 8.04 alike, and is one copyable file. Explicitly **no bashisms** — tested under `dash`. |
| Analyzer language | **Python 3.11+** | Rich stdlib for exactly this job: `sqlite3`, `tarfile`, `hashlib`, `zoneinfo`, `struct` for binary utmp, `http.server`. 3.11 specifically for `zoneinfo` maturity and `X \| None` syntax. |
| Storage | **SQLite, one file per case** | A case is a self-contained artefact you archive, email, or hand to another examiner. Postgres/Elasticsearch would mean infrastructure, a service to secure, and a case you can't just *copy*. SQLite gives real SQL and indexes with zero ops. WAL mode for concurrent read during server operation. |
| Schema validation | **Hand-written `validate()` on a `@dataclass`** | `pydantic`/`jsonschema` are heavier dependencies with native wheels or big install trees, for a schema that is *frozen by design*. ~60 lines of explicit checks, and the error messages are ours. |
| Charts | **Pure-Python SVG generation** | matplotlib is a ~50MB dependency with a native wheel, is non-deterministic across versions (anti-aliasing, font metrics), and emits raster images. Hand-built SVG is deterministic byte-for-byte, scales for print, inlines into the HTML, and uses CSS `var()` so charts re-theme with the page. |
| Templating | **Jinja2, `autoescape=True`** | The only non-stdlib dependency besides PyYAML. Autoescape is non-negotiable: the report renders attacker-controlled strings (usernames, log lines, filenames) — an XSS in a forensic report is an attacker writing into the investigator's browser. |
| Grammars | **YAML regex files** (`config/grammars/`) | New distro or log-format drift = a new YAML file, **zero Python changes**. This is described in the source as "the single biggest maintainability decision." |
| Web server | **stdlib `http.server` + `ssl`** | Flask/FastAPI would be more comfortable, but the forensic constraint is *air-gap deployability*: `pip install` may be impossible on a SOC workstation. Threading via `socketserver.ThreadingMixIn`. |
| Frontend | **Vanilla CSS + vanilla JS, inlined** | A CDN request from a forensic report is an information leak about an active investigation, and fails in an air-gapped lab. A strict "no external fetches" rule. |
| Tests | **pytest, 477 of them** | Fixtures + synthetic bundle builder (`tests/bundle_builder.py`) so the whole pipeline is testable without a Linux host. |

---

## 6. The keystone: the NormalizedEvent schema

If the examiner asks for *the* central design idea, this is it. Every one of 29 parsers, reading 29 different formats, emits the same 27-field record. Rules, the report, the explorer and the exports all consume only this. Adding a parser costs nothing downstream.

```python
@dataclass
class NormalizedEvent:
    # identity & determinism
    event_id, case_id, host_id, event_hash, event_kind
    # time, with honesty built in
    timestamp_utc, timestamp_local, timestamp_tz, tz_source, timestamp_confidence
    # classification
    category, subcategory, severity
    # the actors
    actor_user, actor_uid, actor_process, source_ip, source_host
    # human-readable
    description
    # provenance — how to get back to the original bytes
    source_artifact_path, source_artifact_sha256, raw_line, raw_line_offset
    parser_name, parser_version
    # contamination & annotation
    tool_generated_flag, notes
```

Four features worth calling out explicitly:

- **`tz_source` and `timestamp_confidence` are first-class fields.** Most tools store a timestamp and pretend it's certain. Here, "this time was inferred from the file mtime, in a timezone we had to assume" travels with the event all the way to the report.
- **`event_kind`** distinguishes `"event"` (something happened at a time) from `"state_finding"` (something *is true* — a UID-0 account exists; there's no timestamp for a state, and the validator enforces that a timestamp-less `event` must declare `confidence="unknown"`).
- **Provenance is mandatory, not optional.** `source_artifact_sha256` + `raw_line_offset` means any event can be traced to a byte range in a file whose hash is in the chain of custody.
- **`tool_generated_flag`** — the contamination flag, see §8.

---

## 7. Feature inventory

**Acquisition**
- 90+ artifact path patterns across 9 categories, driven by `config/artifacts.yaml`
- Distro-aware: Debian/Ubuntu/Kali, RHEL/CentOS/Fedora, Arch, Alpine, busybox
- Offline-image mode (`-r /mnt/image`) as well as live collection
- **In-memory mode (`-M`)**: stages in `/dev/shm` — zero disk writes on the target
- **Volatile mode (`-V`)**: process list, sockets, mounts, timers — captured first
- **Redaction mode (`-R`)**: `/etc/shadow` metadata only, no hashes, for regulated environments
- **Three transports**: local tarball, direct HTTPS stream (`-s`), stdout pipe over SSH (`-S`)
- Graceful degradation everywhere: no `sha256sum` → try `shasum` → try `openssl`; no `stat` → `ls -ln` (size only); no `cp -p` → `cat` redirect. **Every degradation is recorded in the manifest**, never silently swallowed.

**Analysis**
- 29 parsers: auth.log/secure, journald JSON, binary utmp/wtmp/btmp **and SQLite wtmp.db**, lastlog, passwd/shadow/group, sudoers, cron + cron logs, systemd units, authorized_keys, known_hosts, shell history, apt/dpkg/dnf, USB from kern.log, web access logs, FTP logs, browser history (Firefox `places.sqlite`, Chrome `History`), netstat/ss, ps, network interfaces, storage, DNS config, ld.so.preload, startup scripts, auditd
- 19 correlation rules in four families (see §9)
- Timezone + year inference engine with rollover handling
- Byte-deterministic JSON and per-category CSV exports for SIEM/data-science handoff

**Presentation**
- Self-contained offline HTML report: executive summary, findings with dual-layer explanation, four deterministic SVG charts, timeline, evidence inventory, methodology appendix, real print stylesheet
- Interactive **Explorer** (Autopsy/FTK-inspired): event timeline with faceted search, evidence file tree with line-numbered viewer and live SHA-256, findings tab with one-click pivot into pre-filtered events
- Central server: streaming ingest API with in-flight hash validation, Bearer-token auth on every endpoint, optional TLS, auto-analysis on receipt, multi-case SOC dashboard

**Operations**
- `lfa analyse | verify | export | report | serve | remote | synth`
- Detection scoring against ground truth (`tools/score_detection.py`)
- 7 reproducible attack scenarios + a chained kill-chain driver in `testlab/`

---

## 8. The forensic-correctness ideas that make this more than a log parser

These are the answers that separate a good viva from an average one. Each is a real design decision with a documented reason.

### 8.1 Copy first, hash the copy — never the source

The naive design hashes the file, copies it, and hashes the copy to confirm. On a live system `auth.log` **grows during collection**, so source hash ≠ copy hash, and the tool declares an integrity failure on precisely the files you care most about. LFA copies first and hashes the copy — that copy *is* the evidence. It `stat`s before and after, and if the size or mtime changed, it records `source_was_active=1` as an **observation**, not an error.

### 8.2 The contamination record — the tool must not report itself

Collecting evidence *is* an intrusion. Your SSH login writes to `wtmp` and `auth.log`. Without handling this, the tool reports the investigator as a suspicious 3am login from an unknown IP. So P1b records the operator's username, `SUDO_USER`, source IP, tty, PID, and the exact collection window. Events matching that fingerprint get `tool_generated_flag=1`, and every correlation rule carries the SQL clause `COALESCE(tool_generated_flag, 0) = 0`.

**Crucially, flagged events still appear in the timeline** — they're excluded from *rules*, not from the record. Hiding them would itself be evidence tampering.

Be ready for the follow-up: the local-collection case has no source IP to match on, so it matches on the operator username within the collection window. Under `sudo` that username is `root`, which means an attacker's `sudo`-to-root session *during* a live collection could be excluded from rules. **This residual risk is documented in the source as accepted, not hidden** — and the event is still in the timeline. Knowing your tool's limits and saying so is the forensic mindset.

### 8.3 Absence of evidence is evidence

Six of the 19 rules reason about what is *missing or inconsistent* rather than what's present. This is the family examiners find most interesting:

- `wiped_history` — an account with 50 recorded sessions and an empty `.bash_history` didn't get shy
- `zero_length_login_log` — `wtmp`/`btmp` present but implausibly small
- `rotation_gap` — `auth.log.1` and `auth.log.3` exist but `.2` doesn't
- `timeline_gap` — 6 hours of silence in a log that averages 40+ events/hour
- `backwards_timestamps` — time runs backwards inside one file: the clock was changed, or lines were spliced
- `journald_sequence_gap` — journald's own sequence numbers skip: entries were purged

Every one of these has an innocent explanation (log rotation, disk-full, a clean reinstall, NTP correction), and **every one says so in its own plain-language layer.** They flag; they never conclude.

### 8.4 Dual-layer explainability — the four questions

Every finding is *structurally required* to answer four questions in plain English, enforced in `PlainSummary.__post_init__`:

1. **What happened?** — no jargon
2. **Why does it matter?** — the significance, including the innocent explanation
3. **How confident are we?** — the words `High`/`Medium`/`Low`, validated. *A number we can't justify is not allowed.*
4. **What should be checked next?** — the actionable step

Alongside sits `technical_detail`: rule name, version, exact thresholds, event IDs, source artifact paths. Two audiences, one finding. **A rule that cannot explain itself in plain English raises `ValueError` at construction and does not ship.**

### 8.5 Determinism as a hard contract

Analysing the same bundle twice must produce **byte-identical** exports. This means: `uuid5` not `uuid4`; every SQL query explicitly `ORDER BY`'d with tie-breakers down to `event_hash`; JSON with `sort_keys=True` and pinned separators; CSV with pinned line terminators; no `datetime.now()` anywhere in the report or chart path.

Why does it matter? **Reproducibility is the difference between an analysis and an opinion.** If an opposing expert re-runs your tool on the same evidence and gets a different file, your conclusions are impeachable. There's a cross-process determinism test guarding this.

### 8.6 Error isolation at every boundary

One malformed log line, one corrupt binary file, one parser bug must never lose the other 50,000 events. So: each parser runs inside its own `try/except`, failures write a full traceback to `parser_errors.log` and the run continues; invalid events are counted and skipped individually; the collector never aborts on a per-artifact failure. And the run's success/fail/skip counts are surfaced in the report's methodology section — **because an analyst needs to know what was NOT processed, not only what was.**

### 8.7 Never `source` an evidence file

`/etc/os-release` is shell-syntax and it is tempting to `source` it. It is also attacker-writable on a compromised host. The collector `sed`s the values out. Sourcing evidence is arbitrary code execution as root, chosen by your suspect.

---

## 9. The rule catalogue (19 rules, 4 families)

| Family | Rules | What they reason about |
|---|---|---|
| **Attack** (`attack.py`) | `brute_force`, `brute_force_success`, `new_account_privilege_grant`, `persistence_after_login`, `off_hours_privileged` | Behaviour over time — the temporal correlations |
| **State** (`state.py`) | `uid0_account`, `passwordless_account`, `privileged_group_member`, `sshd_config_risk`, `ld_preload_rootkit` | Dangerous *configuration* — true now, no timestamp |
| **Integrity** (`integrity.py`) | `wiped_history`, `zero_length_login_log`, `rotation_gap`, `timeline_gap`, `backwards_timestamps`, `journald_sequence_gap`, `suspicious_cron` | What's missing or inconsistent (§8.3) |
| **Behavioural** | `first_seen`, `suspicious_process` | Novelty and command shape |

Two worth knowing in detail:

**`first_seen`** — "for every IP and username, when did it first appear?" Two lines of SQL, and often more useful than any threshold: an address never seen in weeks of logs, appearing the moment things went wrong, is a better lead than any score. The refinement that makes it usable: **only report things first appearing in the *late* half of the dataset**, because everything is "first seen" at the start of a window and saying so is noise.

**`suspicious_process`** (v1.1) — three layers. (1) *Shape*: regex for reverse shells, `curl … | sh`, `/dev/tcp/`, `nc -e`, base64-piped-to-shell, beacons to bare IPs. (2) *Corroboration*: the same command seen in auditd, the `ps` snapshot and shell history is **one** finding citing three sources, not three findings. (3) *Correlation*: if it ran within 60 minutes of a login from a brute-forcing IP, it's raised to high confidence — that's post-compromise execution, the payload of the break-in. Shell history is read because it's the only execution record surviving on a host without auditd, but it's also the weakest — the account owner can edit it — and a history-only finding **says exactly that** and tells the analyst to corroborate.

---

## 10. Challenges — what actually went wrong, with evidence

This is the section examiners probe hardest. Split your answer into inherent domain challenges and the specific bugs you hit, because the second proves the first.

### 10.1 Inherent challenges any developer would face

| # | Challenge | Resolution |
|---|---|---|
| 1 | Hashing the source before copying fails on live systems | Copy first, hash the copy; `source_was_active` as observation (§8.1) |
| 2 | "Read-only" is not literally achievable — `relatime` updates atime on read, your login writes `wtmp` | `stat` before reading preserves original atime in the manifest; contamination record; `ro,noatime` for offline images |
| 3 | GNU extensions break the POSIX promise — `stat -c`, `cp --preserve=`, `rsync` don't exist on busybox | Capability probes at startup, `cp -p` only, documented degradation paths |
| 4 | No timezone collected = every timestamp silently wrong | Timezone chain collected first; `tz_source` travels with every event |
| 5 | The 32/64-bit utmp offset problem is *mostly a myth* — glibc pins `ut_tv` to two `int32`, so `struct utmp` is 384 bytes on both | Ship one 384-byte layout, validate with `filesize % 384 == 0` plus a plausible-date sanity check. **Effort saved was spent on real problems.** This is a great answer: knowing what *not* to build is engineering judgement. |
| 6 | `lastlog` is a **sparse** UID-indexed file — a naive copy inflates it to gigabytes | `cp --sparse=always` with a fallback path |
| 7 | Non-UTF-8 bytes in logs — real logs contain binary garbage | `surrogateescape` decoding throughout, plus `clean_surrogates()` before any DB/JSON/HTML boundary |
| 8 | Gigabyte log files | Lazy line streaming everywhere, never `.readlines()` (decision D10) |
| 9 | Syslog's missing year, especially across a Dec→Jan rotation | ISO anchor → mtime upper bound → step year backwards; dedicated unit test |
| 10 | Windows dev, Linux target | WSL Kali + Ubuntu-24.04 for real validation; `_rmtree()` with read-only-attribute stripping; timezone fallbacks that never crash on an unknown zone name |

### 10.2 Bugs actually hit and fixed — the honest list

Every one of these is a real commit in the history. Being able to name them is far more convincing than claiming it went smoothly.

- **`wtmp` became SQLite.** Debian 12+/Kali 2024+/Ubuntu 24.04 replaced C-struct `wtmp` with a SQLite DB (`wtmp.db`). The parser read 384-byte structs out of a SQLite file, produced surrogate garbage (`\udcb9`), and crashed the DB transaction. Fix: sniff the `SQLite format 3\x00` header and branch to a SQL query. *Lesson: the format you learned from documentation may have changed under you.*
- **Surrogates crashed SQLite.** `UnicodeEncodeError: surrogates not allowed` at the DB driver. Fix: `clean_surrogates()` at every serialization boundary.
- **A crashed parser was recorded as a success** (commit `57e81d9`). When several parsers claim one artifact and one raises, the honest status is `fail`. Silently reporting success in the methodology section would have been an *integrity* bug, not a cosmetic one.
- **`lfa verify` crashed on every run** (`3404878`) — and had no test coverage. Fixed and covered. *Lesson: the command nobody demos is the command nobody tests.*
- **The event hash collapsed legitimate events.** The dedupe key was `(host, path, offset, raw_line)`. But one line can legitimately yield two distinct events — a `/etc/group` line is both `group_membership` and `privileged_group_member`. `INSERT OR IGNORE` silently dropped the second, so `privileged_group_member` **never survived**. Fix: include `subcategory` in the hash material. *A silent data-loss bug that no test failure pointed at — found only by looking at real output.*
- **Quoted usernames broke every join.** systemd-logind writes `session opened for user 'kali'`. `'kali'` ≠ `kali` from `/etc/passwd`, so correlations silently didn't fire. Fixed centrally in the grammar engine with `_unquote()` on identifier groups — one fix for every consumer.
- **Server security round.** Endpoints were unauthenticated and CORS was wildcard (`ea4226d`); `compare_digest` crashed on non-ASCII tokens (`a31410e`); evidence-derived strings were rendered into HTML unescaped — an **XSS via attacker-controlled log content** (`7466ff4`, plus a follow-up round fixing three defects *in the fix*); `_list_cases` leaked SQLite connections and **wrote to the evidence directory** (`ffdba87`). *That last one is the best story you have: a read-only guarantee violated by a listing function.*
- **The report emitted Markdown into an autoescaped template** — so reports displayed literal `**CASE-205**`. Fixed by returning structured data, not markup (`446d0d2`).
- **Chart labels overflowed the canvas.** Username labels are unbounded (32 chars on Linux) but the gutter was sized for numeric axis labels. Fixed by sizing the gutter to the longest label, capped.
- **Service accounts triggered false positives.** `lightdm`, `nobody`, `daemon` have no shell history *by design* and were firing `wiped_history`. Fixed with a service-account allowlist. *Tuning false positives is most of what makes a detection tool usable.*
- **Re-analysis duplicated findings.** Fix: `DELETE FROM findings WHERE case_id = ?` before insert — idempotent re-analysis.

**The meta-lesson, and the best thing you can say:** the green test suite could not see several of these. They were found only by rendering a **real Kali bundle** and looking at the output. Fixtures test what you thought of; real evidence tests what you didn't.

---

## 11. Testing and validation strategy

Four layers, and you should name all four:

1. **Unit tests** per parser, per rule, per engine — 477 total, currently all passing.
2. **Structural invariant tests** that enforce design decisions in CI rather than in code review:
   - `test_artifact_table_sync.py` — the table embedded in `collect.sh` must match `config/artifacts.yaml` (drift is impossible)
   - `test_design_tokens.py` — no raw colour literals in CSS, everything via tokens (there's a commit closing a *test evasion* where named CSS colours slipped past the first version of this check)
   - `test_canonical.py` — cross-process determinism
   - `test_collector.py` — the shell script itself, run under `dash`
3. **Integration tests** — `tests/bundle_builder.py` constructs synthetic bundles so the full ingest→parse→correlate→report pipeline runs without a Linux host.
4. **End-to-end validation on real targets** — `testlab/scenarios/` has 7 attack scripts (unauthorized login, SSH brute force, insider activity, USB data theft, privilege escalation, suspicious process execution, persistence) plus `chain.sh`, which runs them **in kill-chain order on one snapshot in one clock window** so the cross-stage correlations genuinely form. Each records ground truth; `tools/score_detection.py` produces a detection scorecard with false negatives and positives.

The scenario README is unusually honest about what is **genuine** versus **simulated** — e.g. the attacker's source IP is injected because you cannot safely spoof a routable IP in a one-host lab, and off-hours timestamps are injected rather than rolling the system clock. Being explicit about the boundary between simulated and real is itself a forensic virtue, and it's the kind of thing that earns marks.

**Demo tip:** `chain.sh` deliberately **stops before collection**, because running your own commands after the attack would contaminate the very artifacts the collector is about to read. That detail alone shows you understood the domain.

---

## 12. Known limitations — say these before you're asked

Volunteering limits reads as mastery, not weakness.

- **No memory forensics.** No LiME/Volatility integration. Full RAM capture is large, intrusive, and needs separate legal approval; it was scoped out deliberately.
- **No file-content malware analysis.** No YARA, no hashing against threat-intel feeds, no file-carving.
- **Correlation is single-host.** Cross-host lateral-movement mapping is designed for but not built.
- **Rules are threshold-based, not adaptive.** Deliberate — see §8.4 — but it means a slow brute force (4 attempts every 10 minutes) stays under `brute_force`'s threshold. Mitigated partly by `first_seen`, which is threshold-free.
- **Shell history is weak evidence** and the tool says so, but it remains the primary execution record on hosts without auditd.
- **The local-collection contamination predicate is broader than ideal** (§8.2), documented as accepted risk.
- **The collector needs root** for `/etc/shadow`, `/var/log/btmp` and other users' home directories. Without it, collection continues and every unreadable file is recorded as `unreadable` — degraded, not failed.
- **Transport auth is bearer-token, not mutual TLS.** The design document specifies mTLS as the production target; the implementation ships token + optional server-side TLS.

---

## 13. If asked "what would you do next?"

1. **Sigma rule support** — convert community Sigma detection rules into LFA rules, inheriting a large public detection library without abandoning explainability.
2. **Multi-host correlation** — join by user, IP, and file hash across hosts to map lateral movement; the schema already carries `host_id` on every event for exactly this.
3. **Mutual TLS + signed bundles** — the collector signs, the server verifies; closes the gap in §12.
4. **Baseline differencing** — collect a known-good image, diff the state findings, so "this cron job exists" becomes "this cron job is *new*."
5. **eBPF-based live collection** for the continuous-agent mode described in the original framework document.

---

## 14. Rapid-fire question bank

**Q: Why not use Elastic/Splunk?**
Infrastructure, an agent on the target, and a licence. LFA produces a case file you can hand to another examiner on a USB stick, and it runs air-gapped. The canonical JSON export exists precisely so you *can* feed a SIEM afterwards if you want one.

**Q: Why no machine learning?**
Because a finding has to be defensible. "Rule `brute_force_success` v1.0, threshold ≥5 failures in 5 minutes, here are the 48 event IDs" survives cross-examination. "Anomaly score 0.87" does not. There's also no labelled training data for one organisation's normal. Determinism and ML are also in direct tension — the same evidence must give the same answer.

**Q: How do you guarantee evidence integrity?**
Three checkpoints. The collector hashes every copied file into `hash_manifest.csv`, and hashes the sealed tarball. Ingest re-hashes everything against that manifest and **quarantines** mismatches rather than deleting or ignoring them. `lfa verify` re-hashes again against `_verified_hashes.json` to prove nothing changed after ingest. Plus: `raw/` is opened read-only in code via a single `open_raw()` function, and `chmod 444` is applied best-effort.

**Q: What if the attacker tampered with the logs before you arrived?**
That's what the integrity rule family is for (§8.3) — gaps, backwards timestamps, missing rotation numbers, journald sequence jumps, wiped histories. LFA can't recover deleted content, but it can **detect the shape of deletion** and say so.

**Q: How does it handle a distro you've never tested?**
Three fallback layers. The collector probes capabilities at runtime and degrades with a recorded reason. Artifact paths include RHEL, Debian, Arch and SUSE variants; absent ones are recorded as expected-but-missing. The grammar engine loads `common.yaml` plus a family file — an unknown distro still gets the common patterns, and adding support is a new YAML file, not a code change.

**Q: What's the single hardest bug you fixed?**
The event-hash collision (§10.2): a dedupe key that silently dropped legitimately distinct events, so `privileged_group_member` findings never appeared. No test failed. No error was logged. It was only visible by comparing expected findings against a real Kali bundle's output — which is why "render real evidence before you call it done" became a rule.

**Q: What does `tool_generated_flag` do and why does it exist?**
It marks events produced by our own collection session. Without it, the tool reports the investigator as a suspicious login. Rules exclude flagged events; the timeline still shows them, because hiding evidence would be worse than the false positive.

**Q: Why SQLite and not just JSON files?**
Correlation rules are joins over time windows, users and IPs. Doing that over JSON means loading everything into memory and hand-writing the index. SQLite gives real indexes on exactly the spec's join keys (`timestamp_utc`, `category`, `actor_user`, `source_ip`, `host_id`) and still keeps a case as one copyable file.

**Q: What's the biggest weakness?**
Detection coverage is bounded by the rules written — it finds what it was taught to find. That's the accepted trade for explainability, and `first_seen` is the deliberate counterweight because it's a *novelty* detector with no threshold to slip under.

---

## 15. Live demo script

If you get to run something, this sequence tells the whole story in four commands:

```bash
# 1. Prove it works with zero setup — deterministic synthetic case
python -m lfa synth --out cases/DEMO/case.db --seed 42
python -m lfa report cases/DEMO --out cases/DEMO/report.html

# 2. The real thing: collect from a live Linux host (WSL Kali)
wsl -d kali-linux -u kali bash -c "cd /mnt/d/C/Git/Linux-Forensics-system && \
  echo kali | sudo -S sh collector/collect.sh -r / -o /tmp/out -c VIVA-01 -p Fahad -V -z"

# 3. Analyse offline — ingest, verify, parse, correlate, report
python -m lfa analyse /tmp/out/bundle.tar.gz --case-dir cases/VIVA-01 --examiner "Fahad"

# 4. Prove integrity, then show the scorecard
python -m lfa verify cases/VIVA-01
python tools/score_detection.py --case-dir cases/VIVA-01 --ground-truth testlab/ground_truth.json
```

Then open `cases/VIVA-01/report.html` — **disconnect the network first** and show that it still renders perfectly. That single gesture demonstrates the self-contained-offline guarantee better than any explanation.

For the server: `python -m lfa serve --port 8443 --token demo123`, then stream from the target with `collect.sh -M -s http://<ip>:8443 -T demo123 -c LIVE-01` — the case appears on the dashboard, already analysed. Open the **Explorer** and pivot from a finding straight into its filtered events.

**Have ready:** `python -m pytest` (477 passing), and the `chain.sh` scenario output if you ran it.

---

## 16. Thirty-second recap to memorise

> Two-stage design. A dependency-free POSIX shell collector on the target, a Python analyzer on trusted hardware. Copy first and hash the copy, because live logs grow. Record your own contamination so the tool doesn't report the investigator. Normalise 29 artifact formats into one frozen 27-field event schema with mandatory provenance and honest timestamp confidence. Store in SQLite, correlate with 19 explainable rules — including six that reason about what's *missing*, because absence of evidence is evidence. Every finding answers four plain-English questions and carries its technical proof. Output a fully self-contained offline report and byte-deterministic exports, so the same evidence always yields the same answer. 477 tests, validated against real attack scenarios on real Linux hosts.
