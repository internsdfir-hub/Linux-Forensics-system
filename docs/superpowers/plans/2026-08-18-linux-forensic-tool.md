# Linux Forensic Log Processing Tool — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline execution chosen by user — autonomous overnight build) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a two-stage offline Linux forensic tool: a dependency-free POSIX `sh` collector that seals evidence into a hashed bundle, and a Python analyzer that verifies, parses ~20 artifact formats into one normalized event schema in SQLite, runs explainable correlation rules, and renders a self-contained two-layer HTML report.

**Architecture:** Collector (5 passes: fingerprint → contamination record → volatile opt-in → stat/copy/hash → journald JSON export → seal) produces `bundle.tar.gz` + manifest. Analyzer pipeline: ingest/verify → parser plugins → NormalizedEvent → SQLite case DB → correlation rule plugins → Jinja2 HTML + CSV/JSON exports. Everything downstream of parsing operates only on NormalizedEvent — the frozen week-1 contract.

**Tech Stack:** POSIX sh + coreutils (collector, tested under `dash` and WSL). Python 3.11+ stdlib (`struct`, `sqlite3`, `re`, `zoneinfo`), PyYAML, Jinja2 as only third-party analyzer deps (+`tzdata` on Windows examiners). pytest. Hand-rolled deterministic SVG for charts (no matplotlib — see Decision D3).

**Spec:** `docs/spec/forensic_tool_plan_v3.txt` (text extraction of `forensic_tool_plan_v3 (1).pdf`, 13 pages). The spec's §-references below point into that document.

## Global Constraints

- Collector: POSIX `sh` only — no bashisms, no Python, no `rsync`, no `stat -c` reliance without fallback; must pass `dash` parse & run. Verified each phase.
- Collector never writes inside `$ROOT`; per-artifact failure logging, **never abort**.
- Copy first, hash the copy; `stat` before and after; `source_was_active` observation, not error.
- Rotated compressed logs copied still-compressed; hash attests to bytes as found.
- Analyzer: Python **3.11+**; third-party deps limited to `PyYAML`, `Jinja2` (+ `tzdata` on Windows).
- All text artifacts opened `encoding='utf-8', errors='surrogateescape'`; `had_decode_errors` flag per artifact.
- Every event validated against the frozen schema before insert; a bad parser fails its own events, not the pipeline.
- Every parser and rule runs inside its own try/except boundary; failures go to `parser_errors.log` with full traceback; run produces success/fail/skip counts surfaced in the report methodology section.
- Deterministic canonical export: same bundle → byte-identical JSON/CSV export (hash-verified). No random UUIDs, no wall-clock leakage into canonical outputs, stable sort orders everywhere.
- Report: single self-contained HTML — all CSS/JS/SVG inlined, zero network access, severity never conveyed by colour alone.
- Rules: no ML. Every rule emits `technical_detail` + `plain_summary` with the four fields (what happened / why it matters / confidence / check next) — enforced by the rule interface.
- Raw evidence under `cases/<case_id>/raw/` opened `'rb'` only, never written after ingest; final re-verification pass.
- `raw_line` truncated at 2 KB. Stream line-by-line (never `readlines()`); batched inserts (~5000/txn).

---

## Gap analysis — deviations from the spec, with reasons (Decisions D1–D10)

- **D1 — `artifacts.yaml` cannot be parsed by POSIX sh.** Spec §2.4.2/P3 says the collector "iterates artifacts.yaml"; POSIX sh has no YAML parser. **Decision:** `config/artifacts.yaml` stays the single source of truth (analyzer + docs consume it directly); `tools/gen_artifact_table.py` compiles it into a pipe-delimited table embedded between markers inside `collector/collect.sh`, and test `test_artifact_table_sync.py` fails if they drift. Alternatives rejected: awk mini-parser (fragile), separate table file shipped alongside the script (drift risk when the script is copied to a target alone — a collector must be one file).
- **D2 — Random `event_id` UUID contradicts the determinism guarantee (§2.5).** A `uuid4` per row makes the canonical export differ across runs. **Decision:** `event_id = uuid5(NAMESPACE_LFA, event_hash)`. Same event → same id forever.
- **D3 — matplotlib dropped.** Heavy native-wheel dep; SVG output embeds version-dependent ids breaking byte-determinism; spec's own principles (offline, portable, deterministic) argue against it. **Decision:** stdlib-generated SVG event-density histogram. Con: plainer chart. Pro: zero deps, deterministic bytes, still prints.
- **D4 — JSON Schema library dropped.** The schema is single and frozen; a full jsonschema dep buys little. **Decision:** `analyzer/lfa/schema.py` implements the frozen field/type/enum validation with exhaustive unit tests. Con: not a standards-compliant validator. Pro: fewer deps, faster, error messages tailored to parser authors.
- **D5 — Person A/B split reorganized.** Solo (AI) build ⇒ split by dependency order, not evidence domain: contracts → collector → ingest → engines → parsers → rules → report → E2E. The spec's gates survive as phase exit criteria.
- **D6 — Docker attack lab → WSL attack scenario.** No Docker on this machine; WSL2 Ubuntu 24.04 + Kali available. **Decision:** `testlab/scenario.sh` runs inside WSL producing ground truth; the Dockerfile is still written (STRETCH) for the user's real-Linux validation. Detection scoring identical either way.
- **D7 — Multi-host story clarified.** Schema has `host_id` but spec never defines the CLI story. **Decision:** one bundle = one host; `lfa` may ingest N bundles into one case DB; correlation and report group by host where relevant. First-seen analysis runs across the whole case (that is its point).
- **D8 — Windows examiner timezone data.** `zoneinfo` needs the `tzdata` pip package on Windows. Added as platform-conditional dep; `tz_source=assumed_utc` fallback if a zone can't load — never crash.
- **D9 — Tool naming.** Spec leaves the tool unnamed; CLI verbs `collect`/`analyse`. **Decision:** package name `lfa` (Linux Forensic Analyzer); commands `collect.sh` (collector) and `python -m lfa analyse|verify|export|report` on the examiner side.
- **D10 — journald export volume.** Per-boot JSON can reach GBs. Parser streams line-by-line; collector caps nothing (evidence is evidence) but records per-file sizes; analyzer batch-inserts.

## File structure (locked)

```
collector/collect.sh                 # the single-file POSIX collector (embedded artifact table)
config/artifacts.yaml                # artifact catalogue: id, category, paths, distros, required, glob_rotated, notes
config/grammars/common.yaml          # distro-independent syslog patterns
config/grammars/debian.yaml          # debian/ubuntu-specific patterns
config/grammars/rhel.yaml            # rhel-family patterns
config/usb_vendors.csv               # bundled offline USB vendor-ID DB (subset of usb.ids)
analyzer/pyproject.toml
analyzer/lfa/__init__.py             # version
analyzer/lfa/__main__.py             # CLI: analyse, verify, export, report, synth
analyzer/lfa/schema.py               # NormalizedEvent dataclass + validate() + event_hash + uuid5 id
analyzer/lfa/db.py                   # DDL, batched inserts w/ dedupe, indexes, query helpers
analyzer/lfa/canonical.py            # deterministic JSON/CSV export + export hash
analyzer/lfa/ingest.py               # bundle extract, re-hash vs manifest, quarantine, case_metadata.json, final re-verify
analyzer/lfa/timeeng.py              # timezone resolution chain + syslog year inference + confidence marking
analyzer/lfa/parsers/base.py         # BaseParser, registry autodiscovery, error isolation, run stats
analyzer/lfa/parsers/grammar.py      # YAML-grammar-driven text parser engine
analyzer/lfa/parsers/<name>.py       # one module per parser (see Phase 4 list)
analyzer/lfa/rules/base.py           # BaseRule, PlainSummary(4 fields) enforced, window helper
analyzer/lfa/rules/<name>.py         # one module per rule group (see Phase 5 list)
analyzer/lfa/report/data.py          # queries feeding each report section
analyzer/lfa/report/narrative.py     # executive summary + narrative timeline prose
analyzer/lfa/report/chart.py         # stdlib SVG density chart
analyzer/lfa/report/render.py        # Jinja2 render, inlining, CSV/JSON exports
analyzer/lfa/report/templates/report.html.j2
analyzer/lfa/report/templates/style.css
analyzer/lfa/report/templates/tables.js
tools/gen_artifact_table.py          # YAML → embedded sh table (D1)
tools/make_synthetic_case.py         # emits plausible events incl. scripted attack (spec §2.10 unblocking trick)
tools/score_detection.py             # detections vs ground truth: rate, named FN/FP
testlab/scenario.sh                  # WSL/VM attack scenario producing ground truth JSON
testlab/ground_truth.json            # what scenario.sh injected
tests/fixtures/...                   # golden fixtures per parser (incl. binary wtmp/btmp/lastlog, journald json, sqlite)
tests/test_*.py                      # one test module per source module
docs/README.md                       # usage, scope honesty, limitations
```

## Phase gates (from spec §2.12, renumbered)

- **G0** (end Phase 0): synthetic case → validated events → SQLite → deterministic export. Schema frozen.
- **G1** (end Phase 2): synthetic case renders a real HTML report skeleton; real WSL-collected bundle ingests and verifies.
- **G2** (end Phase 4): real collected data → real report with real parsed events.
- **G3** (end Phase 7): attack scenario detection rate measured and stated with named misses; definition-of-done checklist all green.
- Cut rule: if G2 slips, drop Extended parsers; narrow-but-working beats wide-but-broken.

---

## Phase 0 — Foundation & frozen contracts

### Task 0.1: Repo scaffold + pytest infra
**Files:** Create `analyzer/pyproject.toml`, `analyzer/lfa/__init__.py`, `tests/conftest.py`, `.gitignore`.
- [ ] pyproject with `[project] name="lfa" requires-python=">=3.11" dependencies=["PyYAML>=6","Jinja2>=3"]` + `[tool.pytest.ini_options] testpaths=["tests"]`
- [ ] `pip install -e analyzer` succeeds; `pytest` collects 0 tests, exits 0 (with `--collect-only`)
- [ ] Commit.

### Task 0.2: NormalizedEvent schema + validator (THE frozen contract, spec §2.5)
**Files:** Create `analyzer/lfa/schema.py`, `tests/test_schema.py`.
**Produces:** `NormalizedEvent` dataclass with exactly the spec §2.5 fields; `compute_event_hash(host_id, source_path, offset, raw_line) -> str`; `event_id_for(event_hash) -> str` (uuid5); `validate(event) -> list[str]` (empty = valid). Enums: `event_kind ∈ {event,state_finding}`, `tz_source ∈ {etc_localtime,etc_timezone,log_offset,assumed_utc}`, `timestamp_confidence ∈ {exact,year_inferred,unknown}`, `severity ∈ {info,low,medium,high}`, `category` ∈ the 8 + `environment`.
- [ ] Failing tests: field presence, enum rejection, null-timestamp allowed for state_finding, raw_line >2KB truncated by `make_event()` helper, event_hash stability, uuid5 determinism.
- [ ] Implement; tests pass; commit. **Schema is now frozen — changes require explicit justification logged in this plan.**

### Task 0.3: SQLite layer
**Files:** Create `analyzer/lfa/db.py`, `tests/test_db.py`.
**Produces:** `open_case(path) -> Connection` (DDL: `events` table mirroring schema; `artifacts` table for per-file ingest metadata; `findings` table for rule output; `case_meta` key/value). `insert_events(conn, events) -> InsertStats` — batched (5000/txn), `INSERT OR IGNORE` on unique `event_hash`. Indexes exactly: `timestamp_utc, category, actor_user, source_ip, host_id`.
- [ ] Failing tests: DDL idempotent; dedupe on re-insert of same events (spec trap #11); stats counts; index list matches spec.
- [ ] Implement; pass; commit.

### Task 0.4: Canonical deterministic export
**Files:** Create `analyzer/lfa/canonical.py`, `tests/test_canonical.py`.
**Produces:** `export_json(conn, out_path) -> sha256hex`, `export_csv_per_category(conn, out_dir) -> dict[str,sha256]`. Sort: `(timestamp_utc IS NULL, timestamp_utc, category, event_hash)`; JSON `sort_keys=True, separators=(',',':'), ensure_ascii=False`, `\n` endings; CSV `lineterminator='\n'`.
- [ ] Failing test: two exports of the same DB → identical bytes; export after re-ingest of same bundle → identical hash.
- [ ] Implement; pass; commit.

### Task 0.5: artifacts.yaml + embedded-table compiler (D1)
**Files:** Create `config/artifacts.yaml` (full catalogue from spec §2.3/2.4.3 — every CORE row + Extended rows marked `tier:`), `tools/gen_artifact_table.py`, `tests/test_artifact_table_sync.py`.
**Produces:** table lines `id|category|required|glob_rotated|path` between `# ===BEGIN ARTIFACT TABLE===` / `# ===END===` markers in `collector/collect.sh`.
- [ ] Failing sync test (script doesn't exist yet → test asserts compiler output == embedded block; create minimal collect.sh stub with markers)
- [ ] Implement compiler; run it; pass; commit.

### Task 0.6: Synthetic case generator (spec §2.10 unblocking trick)
**Files:** Create `tools/make_synthetic_case.py`, `tests/test_synthetic.py`.
**Produces:** `python tools/make_synthetic_case.py --out case.db --seed 42` → few thousand valid events across all 8 categories + a scripted attack (brute force → success → useradd → sudo grant → authorized_keys → cron → wiped history) + `ground_truth` list emitted as JSON next to the DB. Seeded RNG → deterministic.
- [ ] Failing tests: N events, all validate, attack events present, deterministic across runs with same seed.
- [ ] Implement; pass; commit. **Gate G0 check: export hash of synthetic case stable across two runs.**

## Phase 1 — Collector (POSIX sh)

### Task 1.1: Skeleton + P1 fingerprint + privilege warning + manifest header
**Files:** Create `collector/collect.sh` (real), `tests/test_collector.py` (drives it under `sh` and `dash` against fixture root trees in `tests/fixtures/fakeroot/`).
Flags: `-r ROOT` (default `/`), `-o OUTDIR`, `-c CASE_ID`, `-p OPERATOR`, `-V` (include volatile), `-z` (gzip), `-R` (redact secrets: skip shadow/gshadow content, record metadata only).
P1: os-release → fallback redhat-release → debian_version → uname; init detect via `/run/systemd/system`; timezone via `readlink /etc/localtime` fallback `/etc/timezone`; root check with explicit warning list; `manifest.json` header written with careful sh JSON escaping.
- [ ] Failing pytest: run under `dash` against a Debian-like fakeroot → manifest.json has distro id, tz, non-root warning recorded.
- [ ] Implement; pass (both `sh` and `dash`); commit.

### Task 1.2: P1b contamination record — operator user, `SSH_CONNECTION` source IP, tty, PID, start/end times into manifest.
### Task 1.3: P3 static collection loop — iterate embedded table; glob rotated; stat-before (portable: `ls -ln` + `stat` if present, degrade logged); `cp -p` (degrade to `cat < src > dst` logged); `--sparse=always` for lastlog when GNU cp; sha256 the copy (sha256sum→shasum fallback); stat-after → `source_was_active`; append `hash_manifest.csv`; required-but-missing recorded with reason.
### Task 1.4: P4 journald export — `--list-boots`, per-boot `-o json`, `journald_persistent` flag, hash each; absent journalctl logged, continue.
### Task 1.5: P2 volatile snapshot (only with `-V` on live root `/`) — runs FIRST in main(): ps aux, ss -tulpn (netstat fallback), ip addr, mount, lsblk -f, blkid, uptime, who, w, last, systemctl list-timers, docker ps -a if present; each to own file+hash+timestamp under `collected/volatile/`.
### Task 1.6: P5 package & seal — `tar --numeric-owner`, hash tar, optional gzip + hash both layers, finalize manifest (full hash list, end time, expected-but-missing list with reasons).
- [ ] Each of 1.2–1.6: failing pytest against fakeroot (incl. a fakeroot *missing* things to prove never-abort), implement, pass under sh+dash, commit.

### Task 1.7: Real-Linux validation (WSL)
- [ ] Run collector inside WSL Ubuntu 24.04 (`wsl -d Ubuntu-24.04`) as root and non-root; bundle produced both times; manifest lists unreadables under non-root; journald exported. Record results. Commit fixes.

## Phase 2 — Ingest & verification

### Task 2.1: `lfa.ingest` — extract bundle → `cases/<id>/raw/`, re-hash vs `hash_manifest.csv`, mismatches → `raw/_integrity_failed/` + logged, continue; write `case_metadata.json` (collector manifest ⊕ examiner name, ingest time, analyzer version).
### Task 2.2: read-only enforcement — module-level `open_raw(path)` returning `'rb'` handles only; final re-verification pass API `verify_raw(case_dir)`; chmod 444 best-effort.
### Task 2.3: multi-bundle ingest into one case; `host_id` from machine-id (fallback hostname).
- [ ] TDD each against bundles produced by Task 1 fixtures (incl. deliberately corrupted file → quarantined, analysis continues — definition-of-done item). Commit per task. **Gate G1: synthetic case renders HTML skeleton (stub template) + real WSL bundle ingests clean.**

## Phase 3 — Engines

### Task 3.1: Parser framework — `BaseParser` exactly per spec §2.6.1 (`name, version, artifact_category, applies_to`, `can_parse(path, distro_profile)`, `parse(path, context) -> Iterator[NormalizedEvent]`), registry autodiscovery of `lfa/parsers/*.py`, per-plugin try/except → `parser_errors.log` + continue, per-artifact success/fail/skip stats persisted to `case_meta`.
### Task 3.2: Timestamp engine (spec §2.6.2 — hardest component) — `TimeContext(tz_name, tz_source)` built from collected localtime/timezone; `resolve_syslog_ts(month,day,hms, file_mtime, rotation_hint, iso_anchor) -> (utc, local, confidence)`; year inference: mtime upper bound, rotation ordering, ISO cross-check; **Dec→Jan rollover dedicated test**; everything inferred marked `year_inferred`.
### Task 3.3: Grammar engine — YAML pattern files with named groups (`ts,user,ip,port,pid...`) → events; grammar id becomes `subcategory`; per-line no-match is fine (count `unmatched`), decode errors surrogate-escaped.
### Task 3.4: env parser — os-release, localtime target, timezone, machine-id, timedatectl output → `environment` state findings + provides `DistroProfile` + `TimeContext` to all other parsers.
- [ ] TDD each; commit each.

## Phase 4 — Parsers (each task = fixture(s) + golden test + parser; uniform recipe)

Recipe per parser: (1) write/obtain golden fixture (real sanitized sample — generate from WSL where possible); (2) failing test asserting exact expected events (count, key fields, severity, subcategory, confidence); (3) implement; (4) corruption fixture (truncated/garbage) asserting per-artifact failure isolation; (5) commit.

**Identity:** `passwd_parser` (passwd/shadow/group/gshadow + `-` backups diff; shadow last-changed is **days**-since-epoch — dedicated test, spec trap #10; state findings: uid0≠root, passwordless, shell-no-password), `authlog_parser` (grammar-driven: failed/accepted password, publickey, invalid user, session open/close, sshd + login), `journald_parser` (JSON lines; `_COMM` sshd/login/systemd-logind + sudo; `__REALTIME_TIMESTAMP` µs epoch — exact confidence), `sudo_parser` (sudo: lines both auth.log & journal; command, cwd, target user), `sudoers_parser` (sudoers + sudoers.d; NOPASSWD, %group, !authenticate → state findings), `utmp_parser` (384-byte records, `filesize % 384 == 0` sanity + plausible-timestamp check else unsupported-layout; wtmp login/logout/boot, btmp failures), `lastlog_parser` (seek `uid*292` for passwd UIDs only, skip zero — spec trap #6), `shellhist_parser` (bash/zsh incl. `HISTTIMEFORMAT` epoch comments and zsh extended `: <epoch>:<dur>;cmd`; untimestamped → `timestamp_confidence=unknown`, ordering preserved by offset; **empty/missing history for active user = handled in rules**), `knownhosts_parser`.

**Activity:** `cron_parser` (crontab/cron.d/spool + `@reboot`; file mtimes as state), `cronlog_parser` (CRON syslog lines), `systemd_unit_parser` (unit/timer files under /etc + user units: ExecStart, WantedBy; mtimes), `authkeys_parser` (keys + options like `command=`; **file mtime recorded** for rule use), `sshdconfig_parser` (PermitRootLogin/PasswordAuthentication/etc → state findings), `startup_parser` (bashrc/profile.d/rc.local/ld.so.preload — non-empty preload = high state finding), `dpkg_parser` (`YYYY-MM-DD HH:MM:SS action pkg:arch ver`), `apt_parser` (stanza blocks; Commandline + Requested-By — the user attribution dpkg lacks), `dnf_parser`, `usb_parser` (multi-line stateful stitch by bus-port id, disconnect matching → duration — spec trap #9), `udev_parser` (`/sys/bus/usb/devices/*/uevent` + `udevadm info --export-db` snapshot), `netconfig_parser` (hosts, resolv.conf, interfaces, netplan YAML), `firewall_parser` (ufw.log + iptables kern.log lines), `volatile_parser` (ss/netstat listening ports, ps snapshot → state findings tagged volatile).

**Extended (only after G2):** `browser_parser` (Firefox places.sqlite; Chrome History — copy to temp before open, **WebKit 1601-epoch µs conversion with dedicated test**, spec trap #8), `faillog_parser`, `fstimeline_parser` (find -printf body file), `pam_parser`.

- [ ] Execute recipe per parser in the order above; commit per parser. **Gate G2 after identity+activity Core parsers: real WSL bundle → analyse → report shows real events.**

## Phase 5 — Correlation rules

### Task 5.1: Framework — `BaseRule(name, version)`, `run(conn, case_ctx) -> Iterator[Finding]`; `Finding` requires `technical_detail` AND `PlainSummary(what_happened, why_it_matters, confidence, check_next)` — constructor raises if any empty (spec: enforced by interface, not review). Shared helper `events_within(conn, anchor_event, minutes, **filters)`.
### Task 5.2: Attack rules — brute force (≥N=5 fails/IP in rolling 5-min window, usernames listed), success-after-burst from same IP → high, off-hours privileged activity (configurable hours, default 08–18 local), new-account→privilege-grant within window, persistence-created-near-suspicious-login (cron/systemd/authkeys mtime or event in window), authorized_keys mtime inside incident window, unknown USB vendor vs `config/usb_vendors.csv` (offline; unknown = flagged for review, never auto-malicious).
### Task 5.3: First-seen — for every source_ip and actor_user: first appearance timestamp; SQL, surfaced as info findings and used by narrative.
### Task 5.4: Evidence-integrity rules — wtmp/btmp/lastlog present-but-empty/implausibly small; `.bash_history` missing/empty/symlink→/dev/null for users **with recorded sessions**; rotation sequence gap (auth.log.1, auth.log.3, no .2); timeline gap (N hours zero events where file averages ≥X/hour); backwards timestamps within one file; journald non-persistent → report-level caveat.
### Task 5.5: State-finding rules — UID-0 non-root, passwordless, sudo/wheel/adm/docker membership (docker ≈ root note), sshd PermitRootLogin/PasswordAuthentication yes, ld.so.preload non-empty, passwd vs passwd- diff.
- [ ] TDD each against synthetic case (which contains the scripted attack) + targeted fixtures; commit each.

## Phase 6 — Report & CLI

### Task 6.1: `report/data.py` — queries per section (counts, findings by severity, per-category tables, methodology stats, hash table collection-vs-ingest, limitations inputs).
### Task 6.2: Template — sections exactly per spec §2.8.2 (1 authorisation/scope/privacy … 9 glossary); two layers side-by-side per finding; inline CSS + vanilla-JS sortable/filterable tables; print stylesheet; severity shown by icon+text+colour.
### Task 6.3: `chart.py` — stdlib SVG event-density histogram over case span, anomalies (findings) highlighted; deterministic output bytes.
### Task 6.4: `narrative.py` — executive summary + ordered-prose narrative from flagged findings (template-based sentence generation from PlainSummary fields — no LLM, deterministic).
### Task 6.5: Exports — per-category CSV/JSON via `canonical.py`.
### Task 6.6: CLI — `python -m lfa analyse <bundle...> --case-dir X --examiner NAME [--business-hours 8-18] [--redacted]` runs ingest→parse→correlate→report; also `verify`, `export`, `report`, `synth` subcommands; exit codes 0 ok / 1 completed-with-integrity-failures / 2 fatal.
- [ ] TDD each (template smoke test: renders synthetic case, output contains all 9 section ids, zero `http(s)://` references — offline check; chart bytes stable). Commit each. 

## Phase 7 — End-to-end, scoring, hardening

### Task 7.1: `testlab/scenario.sh` in WSL Ubuntu 24.04: 6 failed SSH-style auth events → success → `useradd eviluser` → usermod -aG sudo → drop authorized_keys → install cron job → wipe a `.bash_history`; emits `ground_truth.json` (machine-readable list of injected events with timestamps).
### Task 7.2: Real run: collect in WSL (root) → copy bundle out → `lfa analyse` → HTML report. Verify report opens offline (no network refs), all sections present.
### Task 7.3: `tools/score_detection.py` — compares findings vs ground_truth: "detected X of Y; false negatives named with reason; false positives listed." Output lands in docs and the report methodology.
### Task 7.4: Corruption suite — per-artifact truncate/zero/garbage across all fixtures; assert analysis completes and quarantine/error counts correct. Deliberately corrupt one file in a real bundle → quarantined + completes (definition-of-done).
### Task 7.5: Definition-of-done sweep (spec §2.13 checklist), determinism re-verify, README + limitations doc (auditd, containers, musl, timestamp ambiguity, privacy scope), final `dash` pass over collector, memory files updated.
- [ ] Each with evidence recorded; commit. **Gate G3.**

## Phase 8 — Perfection loop
- [ ] Run code-review skill over the branch; fix findings; re-run full pytest + E2E; repeat until clean. Update memory with everything learned.

## Self-review notes
- Spec coverage: every §2.3 CORE row has a named parser task in Phase 4; §2.7 traps #1–15 are each embedded in a specific task above (1↔T1.3, 2↔T1.2/T1.3, 3↔T1.3, 4↔T3.2, 5↔utmp, 6↔lastlog, 7↔journald-core, 8↔browser, 9↔usb, 10↔passwd, 11↔T0.3, 12↔T3.3/global, 13↔`-R` flag+report section, 14↔global streaming, 15↔docs).
- Audit logs: collected (artifacts.yaml row), never parsed — stated in limitations (spec §2.3 last row).
- Types consistent: `NormalizedEvent` named identically everywhere; parsers yield it; rules read DB rows; report reads DB only.
