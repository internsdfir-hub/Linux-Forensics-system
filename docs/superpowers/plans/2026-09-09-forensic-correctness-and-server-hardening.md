# Forensic Correctness & Server Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the four defects that make LFA state untrue things about evidence, and close the four security holes in the investigation server.

**Architecture:** Seven independent tasks against an existing, working codebase. Cluster 1 (Tasks 1–4) corrects the forensic claims: the `verify` CLI, quoted usernames breaking cross-source correlation, crashed parsers reported as successes, and contamination tagging that never fires locally. Cluster 2 (Tasks 5–7) hardens `server.py`: authentication on every endpoint, CORS removal, HTML escaping of evidence-derived values, and a read-only, leak-free case lister. Each task is independently testable and independently revertible.

**Tech Stack:** Python 3.11+ (stdlib + PyYAML + Jinja2), pytest 8, POSIX `sh` (collector), SQLite.

**Spec:** `docs/superpowers/specs/2026-09-09-forensic-correctness-and-server-hardening-design.md`

## Global Constraints

- **Python floor is 3.11.** Do not use syntax newer than 3.11.
- **No new runtime dependencies.** The analyzer's dependencies are exactly `PyYAML>=6`, `Jinja2>=3`, and `tzdata` on Windows. Everything else must be stdlib.
- **The collector is POSIX `sh`.** No bashisms in `collector/collect.sh`. It is tested under both `sh` and `dash`.
- **Import style in tests is `from lfa...`**, not `from analyzer.lfa...`. The package is installed editable; both resolve, but `from lfa...` is used by 25 of the test modules and is the house style.
- **`NormalizedEvent` is a frozen contract.** Do not add, remove, or rename fields in `analyzer/lfa/schema.py`.
- **Determinism must hold.** Identical evidence must still produce byte-identical canonical exports. Never introduce `uuid4()`, wall-clock values, or set/dict iteration order into anything that reaches an event or an export.
- **Rules must never abort the run.** Parser and rule error isolation boundaries stay intact.
- **Run the full suite with `python -m pytest`** from the repo root. It takes roughly 4 minutes; that is normal, not a hang.
- **Do not touch** `testlab/data_exfil_simulator.py` or `testlab/data_exfil_receiver.py`. They are out of scope.

---

### Task 0: Create the working branch

**Files:**
- No source changes.

**Interfaces:**
- Consumes: nothing.
- Produces: a branch named `fix/forensic-correctness-and-server-hardening` that all later tasks commit onto.

- [ ] **Step 1: Confirm the working tree state**

Run: `git status --short`

Expected: a number of modified and untracked files (new parsers, report changes, `uploads/`). This is pre-existing work in progress and is **not** yours to commit. You will only ever `git add` the specific paths named in each task's commit step.

- [ ] **Step 2: Create and switch to the branch**

```bash
git checkout -b fix/forensic-correctness-and-server-hardening
```

- [ ] **Step 3: Verify the baseline suite passes before you change anything**

Run: `python -m pytest`
Expected: `284 passed` (roughly 4 minutes). If this does not pass, stop and report — you need a green baseline to attribute later failures.

---

### Task 1: Fix the `lfa verify` command

**Files:**
- Modify: `analyzer/lfa/__main__.py:44-54`
- Modify: `analyzer/lfa/ingest.py:199-217`
- Test: `tests/test_cli.py` (create)

**Interfaces:**
- Consumes: `ingest.verify_raw(case_dir) -> VerifyReport`, where `VerifyReport` is a dataclass with fields `reverified: int` and `mismatches: list[str]` (defined at `analyzer/lfa/ingest.py:54-58`).
- Produces: `lfa.__main__.main(argv: list[str] | None) -> int`, callable in-process by tests. `main(["verify", str(case_dir)])` returns `0` when clean and `1` when any mismatch is found.

**Background:** `cmd_verify` currently does `mismatches = ingest.verify_raw(case_dir)` and then `if mismatches:`. `verify_raw` returns a `VerifyReport` dataclass, which is **always truthy**, so every run enters the failure branch and then raises `TypeError` on `len()`. Separately, `verify_raw` calls `(case_dir / "raw").iterdir()` unguarded, which raises `FileNotFoundError` when a case has no `raw/` directory.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_cli.py`:

```python
"""CLI entrypoint tests (analyzer/lfa/__main__.py).

The CLI had no test coverage at all, which is how `lfa verify` shipped
completely broken while 284 other tests passed.
"""
import json
from pathlib import Path

import pytest

from lfa.__main__ import main

from bundle_builder import build_bundle


def _analysed_case(tmp_path: Path) -> Path:
    """Ingest a tiny bundle so there is a real case directory to verify."""
    bundle = build_bundle(
        tmp_path / "src",
        {
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n",
            "/etc/os-release": b'ID=debian\nVERSION_ID="12"\n',
        },
    )
    case_dir = tmp_path / "case"
    rc = main([
        "analyse", str(bundle),
        "--case-dir", str(case_dir),
        "--examiner", "Test Examiner",
    ])
    assert rc == 0
    return case_dir


def test_verify_returns_zero_on_clean_case(tmp_path, capsys):
    case_dir = _analysed_case(tmp_path)

    rc = main(["verify", str(case_dir)])

    assert rc == 0
    assert "verified" in capsys.readouterr().out.lower()


def test_verify_returns_one_when_evidence_modified(tmp_path, capsys):
    case_dir = _analysed_case(tmp_path)

    # Tamper with a file after ingest; verify_raw must notice.
    target = next((case_dir / "raw").rglob("passwd"))
    target.chmod(0o644)
    target.write_bytes(b"root:x:0:0:root:/root:/bin/bash\nevil:x:0:0::/root:/bin/sh\n")

    rc = main(["verify", str(case_dir)])

    assert rc == 1
    assert "INTEGRITY FAILURE" in capsys.readouterr().err


def test_verify_handles_case_with_no_raw_directory(tmp_path, capsys):
    empty_case = tmp_path / "empty"
    empty_case.mkdir()

    rc = main(["verify", str(empty_case)])

    assert rc == 0
    assert "no raw evidence" in capsys.readouterr().out.lower()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_cli.py -v`
Expected: FAIL. `test_verify_returns_zero_on_clean_case` and `test_verify_returns_one_when_evidence_modified` fail with `TypeError: object of type 'VerifyReport' has no len()`; `test_verify_handles_case_with_no_raw_directory` fails with `FileNotFoundError`.

- [ ] **Step 3: Guard `verify_raw` against a missing `raw/` directory**

In `analyzer/lfa/ingest.py`, replace the body of `verify_raw` (currently lines 199-217) with:

```python
def verify_raw(case_dir: str | Path) -> VerifyReport:
    """Final re-verification: prove nothing under raw/ changed since ingest."""
    case_dir = Path(case_dir)
    report = VerifyReport()
    raw_root = case_dir / "raw"
    if not raw_root.is_dir():
        return report
    for host_dir in sorted(raw_root.iterdir()):
        record = host_dir / "_verified_hashes.json"
        if not record.exists():
            continue
        expected = json.loads(record.read_text(encoding="utf-8"))
        for rel, digest in expected.items():
            stored = host_dir / rel
            if not stored.exists():
                report.mismatches.append(f"{host_dir.name}:{rel}: missing")
                continue
            if _sha256_file(stored) != digest:
                report.mismatches.append(f"{host_dir.name}:{rel}: modified after ingest")
            else:
                report.reverified += 1
    return report
```

- [ ] **Step 4: Fix `cmd_verify` to read the dataclass correctly**

In `analyzer/lfa/__main__.py`, replace `cmd_verify` (currently lines 44-54) with:

```python
def cmd_verify(args) -> int:
    case_dir = Path(args.case_dir)
    print(f"[*] Verifying evidence integrity in '{case_dir}'")
    report = ingest.verify_raw(case_dir)

    if report.mismatches:
        print(
            f"[!] INTEGRITY FAILURE: {len(report.mismatches)} artifact(s) "
            f"failed hash verification!",
            file=sys.stderr,
        )
        for m in report.mismatches:
            print(f"    - {m}", file=sys.stderr)
        return 1

    if report.reverified == 0:
        print("[*] No raw evidence recorded for this case; nothing to verify.")
        return 0

    print(
        f"[+] All {report.reverified} raw evidence artifact(s) verified clean "
        f"against collection manifests."
    )
    return 0
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_cli.py -v`
Expected: 3 passed.

- [ ] **Step 6: Confirm the real command no longer crashes**

Run: `python -m lfa verify cases/103`
Expected: either a clean-verification line or a list of mismatches. **No traceback.**

- [ ] **Step 7: Run the full suite**

Run: `python -m pytest`
Expected: `287 passed`.

- [ ] **Step 8: Commit**

```bash
git add analyzer/lfa/__main__.py analyzer/lfa/ingest.py tests/test_cli.py
git commit -m "fix(cli): lfa verify crashed on every run; add CLI test coverage

cmd_verify treated the VerifyReport dataclass as a list. The dataclass is
always truthy, so every invocation entered the failure branch and then
raised TypeError on len(). verify_raw also crashed on cases with no raw/
directory. The CLI had no tests at all, which is why this shipped."
```

---

### Task 2: Normalise quoted usernames in the grammar engine

**Files:**
- Modify: `analyzer/lfa/parsers/grammar.py:51-61`
- Test: `tests/test_grammar.py` (append)
- Test: `tests/test_journald_parser.py` (append)

**Interfaces:**
- Consumes: `GrammarEngine.match_line(line: str) -> list[tuple[str, dict, dict]]`, returning `(rule_name, rule, groups)` triples.
- Produces: the same signature, but values of the `user`, `target_user`, and `group` keys in `groups` now have a matched surrounding pair of `'` or `"` stripped. All other group values are returned untouched.

**Background:** `config/grammars/common.yaml:190` matches systemd-logind's `New session 'c1' of user 'kali' with class 'user'` using `(?P<user>\S+)`, which captures `'kali'` including the quote characters. Verified in `cases/kali_case/case.db`: `journald_parser` stores `'kali'` (31 events) and `'root'` (4 events) while `passwd_parser` and `cron_parser` store `kali` and `root`. Any rule joining on `actor_user` silently misses the journald rows.

Fixing this in the engine rather than the regex covers `authlog_parser`, `journald_parser`, and `cronlog_parser` at once, and protects every grammar rule written in future.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_grammar.py`:

```python
def test_logind_username_is_unquoted(tmp_path):
    """systemd-logind wraps names in single quotes; actor_user must not."""
    from lfa.parsers.authlog import GRAMMAR_DIR
    from lfa.parsers.grammar import GrammarEngine

    engine = GrammarEngine.load(GRAMMAR_DIR, "debian")
    line = (
        "systemd-logind[712]: New session 'c1' of user 'kali' "
        "with class 'user' and type 'tty'."
    )

    matches = engine.match_line(line)
    users = [g.get("user") for _, _, g in matches if "user" in g]

    assert users, "expected the logind rule to match"
    assert all(u == "kali" for u in users), users


def test_unquoted_usernames_are_left_alone(tmp_path):
    from lfa.parsers.authlog import GRAMMAR_DIR
    from lfa.parsers.grammar import GrammarEngine

    engine = GrammarEngine.load(GRAMMAR_DIR, "debian")
    line = "sshd[123]: Failed password for admin from 203.0.113.9 port 22"

    matches = engine.match_line(line)
    users = [g.get("user") for _, _, g in matches if "user" in g]

    assert users == ["admin"]


def test_apostrophe_inside_a_name_is_preserved():
    """Only a matched surrounding pair is stripped, never an inner quote."""
    from lfa.parsers.grammar import GrammarEngine

    engine = GrammarEngine({
        "probe": {
            "pattern": r"user (?P<user>\S+)",
            "category": "login_activity",
            "subcategory": "successful_login",
            "severity": "info",
        }
    })

    assert engine.match_line("user o'brien")[0][2]["user"] == "o'brien"
    assert engine.match_line("user 'o'brien'")[0][2]["user"] == "o'brien"


def test_non_identifier_groups_are_not_normalised():
    """Only user-ish groups are touched; `session` keeps its quotes."""
    from lfa.parsers.grammar import GrammarEngine

    engine = GrammarEngine({
        "probe": {
            "pattern": r"session (?P<session>\S+) of user (?P<user>\S+)",
            "category": "login_activity",
            "subcategory": "session_opened",
            "severity": "info",
        }
    })

    groups = engine.match_line("session 'c1' of user 'kali'")[0][2]

    assert groups["user"] == "kali"
    assert groups["session"] == "'c1'"
```

Append to `tests/test_journald_parser.py`:

```python
def test_logind_session_actor_user_has_no_quotes(tmp_path):
    """End-to-end: a logind journal entry must yield a bare username."""
    import json as _json

    from lfa.parsers.base import ParseContext
    from lfa.parsers.journald import JournaldParser
    from lfa.timeeng import TimeContext

    entry = {
        "__REALTIME_TIMESTAMP": "1710382747000000",
        "_COMM": "systemd-logind",
        "_PID": "712",
        "USER_ID": "kali",
        "MESSAGE": "New session 'c1' of user 'kali' with class 'user' and type 'tty'.",
    }
    journal = tmp_path / "boot-0.json"
    journal.write_text(_json.dumps(entry) + "\n", encoding="utf-8")

    context = ParseContext(
        case_id="CASE-Q",
        host_id="host-q",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("UTC", "etc_localtime"),
        distro_profile={"distro_id": "debian"},
        artifact_rel="journal/boot-0.json",
        artifact_sha256="b" * 64,
    )

    events = list(JournaldParser().parse(journal, context))
    users = {e.actor_user for e in events if e.actor_user}

    assert users == {"kali"}, users
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_grammar.py tests/test_journald_parser.py -v`
Expected: FAIL. The logind assertions report `"'kali'"` where `"kali"` was expected.

- [ ] **Step 3: Implement normalisation in the grammar engine**

In `analyzer/lfa/parsers/grammar.py`, add this module-level constant and helper immediately after the `_FAMILY` dict (after line 23):

```python
# Groups that name a principal. Some log formats quote these — systemd-logind
# writes "New session 'c1' of user 'kali'" — and a quoted value will not join
# against the same username recorded by /etc/passwd or cron. Normalising here
# rather than in each pattern fixes every grammar consumer at once.
_IDENTIFIER_GROUPS = ("user", "target_user", "group")


def _unquote(value: str) -> str:
    """Strip one matched surrounding pair of single or double quotes.

    An apostrophe inside a name is preserved: only a genuine matching pair
    that wraps the whole value is removed.
    """
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value
```

Then replace `match_line` (currently lines 51-61) with:

```python
    def match_line(self, line: str) -> list[tuple[str, dict, dict]]:
        """Return every (rule_name, rule, groupdict) whose pattern matches.
        A single line may legitimately yield multiple events - parsers yield
        freely rather than forcing one line into one bucket."""
        out = []
        for name, regex in self._compiled.items():
            m = regex.search(line)
            if m:
                groups = {k: v for k, v in m.groupdict().items() if v is not None}
                for key in _IDENTIFIER_GROUPS:
                    if key in groups:
                        groups[key] = _unquote(groups[key])
                out.append((name, self.rules[name], groups))
        return out
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_grammar.py tests/test_journald_parser.py -v`
Expected: all pass.

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest`
Expected: `292 passed`. Pay attention to `tests/test_authlog_parser.py` and `tests/test_cronlog_parser.py` — they consume the same engine and must be unaffected.

- [ ] **Step 6: Commit**

```bash
git add analyzer/lfa/parsers/grammar.py tests/test_grammar.py tests/test_journald_parser.py
git commit -m "fix(grammar): strip quotes from captured usernames

systemd-logind writes \"of user 'kali'\", and the \\S+ capture kept the
quotes. actor_user was stored as 'kali' from journald but kali from
passwd/cron, so every correlation rule joining on actor_user silently
missed journald rows - the primary log source on modern distros.

Normalised in the engine so authlog, journald and cronlog are all fixed,
and future grammar rules inherit it. Existing case DBs keep the old
values; re-running analyse regenerates them."
```

---

### Task 3: Record crashed parsers as failures, not successes

**Files:**
- Modify: `analyzer/lfa/parsers/base.py:145-202`
- Modify: `analyzer/lfa/pipeline.py:118-136`
- Test: `tests/test_pipeline.py` (append)

**Interfaces:**
- Consumes: `ParserRun(parsers, errors_log)` with existing attributes `stats`, `skipped: list[str]`, `artifact_results: list[dict]`.
- Produces: `ParserRun` gains `failures: list[str]`, appended with the artifact's relative path each time a parser raises. `parse_artifact` keeps its existing signature and return type (`list[NormalizedEvent]`).

**Background:** `pipeline.py:133` computes status as
`"skip" if was_skipped else ("success" if events or not was_skipped else "fail")`.
When `was_skipped` is `False`, `not was_skipped` is `True`, so the ternary always yields `"success"` — `"fail"` is unreachable. An artifact whose parser raised is logged to `parser_errors.log` and then written to the `artifacts` table as a success with 0 events, which is exactly backwards from the module's stated purpose.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_pipeline.py`:

```python
def test_crashed_parser_is_recorded_as_fail(tmp_path, monkeypatch):
    """A parser that raises must not be recorded as a successful parse."""
    from lfa import db, pipeline
    from lfa.parsers.base import BaseParser

    from bundle_builder import build_bundle

    class ExplodingParser(BaseParser):
        name = "exploding_parser"
        version = "1.0"
        artifact_category = "user_accounts"
        applies_to = ["etc/passwd"]

        def parse(self, path, context):
            raise RuntimeError("boom")
            yield  # pragma: no cover - makes this a generator

    monkeypatch.setattr(
        pipeline, "discover_parsers", lambda: [ExplodingParser()]
    )

    bundle = build_bundle(
        tmp_path / "src",
        {"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"},
    )
    case_dir = tmp_path / "case"

    from lfa import ingest
    ingest.ingest_bundle(bundle, case_dir, "Examiner")

    conn = db.open_case(case_dir / "case.db")
    pipeline.parse_case(conn, case_dir, "CASE-FAIL")

    row = conn.execute(
        "SELECT parse_status, parse_events FROM artifacts "
        "WHERE original_path = '/etc/passwd'"
    ).fetchone()
    conn.close()

    assert row is not None, "artifact row was not recorded at all"
    assert row[0] == "fail", f"expected parse_status='fail', got {row[0]!r}"
    assert row[1] == 0


def test_successful_parser_is_still_recorded_as_success(tmp_path, monkeypatch):
    from lfa import db, ingest, pipeline
    from lfa.parsers.base import BaseParser

    from bundle_builder import build_bundle

    class WorkingParser(BaseParser):
        name = "working_parser"
        version = "1.0"
        artifact_category = "user_accounts"
        applies_to = ["etc/passwd"]

        def parse(self, path, context):
            yield context.build_event(
                event_kind="event",
                timestamp_utc="2024-03-14T02:19:07+00:00",
                timestamp_local="2024-03-14T02:19:07+00:00",
                timestamp_confidence="exact",
                category="user_accounts",
                subcategory="account",
                actor_user="root",
                description="root account present",
                severity="info",
                raw_line="root:x:0:0:root:/root:/bin/bash",
                raw_line_offset=0,
            )

    monkeypatch.setattr(pipeline, "discover_parsers", lambda: [WorkingParser()])

    bundle = build_bundle(
        tmp_path / "src",
        {"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"},
    )
    case_dir = tmp_path / "case"
    ingest.ingest_bundle(bundle, case_dir, "Examiner")

    conn = db.open_case(case_dir / "case.db")
    pipeline.parse_case(conn, case_dir, "CASE-OK")

    row = conn.execute(
        "SELECT parse_status, parse_events FROM artifacts "
        "WHERE original_path = '/etc/passwd'"
    ).fetchone()
    conn.close()

    assert row[0] == "success"
    assert row[1] == 1
```

- [ ] **Step 2: Run the tests to verify the first one fails**

Run: `python -m pytest tests/test_pipeline.py -k crashed_parser -v`
Expected: FAIL with `expected parse_status='fail', got 'success'`.

- [ ] **Step 3: Track failures in `ParserRun`**

In `analyzer/lfa/parsers/base.py`, in `ParserRun.__init__` (currently lines 148-155), add the `failures` list alongside `skipped`:

```python
    def __init__(self, parsers: list[BaseParser], errors_log: Path):
        self.parsers = parsers
        self.errors_log = Path(errors_log)
        self.stats: dict[str, dict[str, int]] = {
            p.name: {"success": 0, "fail": 0, "events": 0} for p in parsers
        }
        self.skipped: list[str] = []
        self.failures: list[str] = []
        self.artifact_results: list[dict] = []
```

Then in `parse_artifact`, inside the `except Exception as exc:` block (currently line 186), record the failure. The block becomes:

```python
            except Exception as exc:  # isolation boundary: never fail the run
                self._log_error(parser, rel_path, exc)
                self.stats[parser.name]["fail"] += 1
                self.failures.append(rel_path)
                self.artifact_results.append(
                    {"artifact": rel_path, "parser": parser.name,
                     "status": "fail", "events": 0, "error": repr(exc)}
                )
                continue
```

- [ ] **Step 4: Use the failure signal in the pipeline**

In `analyzer/lfa/pipeline.py`, replace the block currently at lines 118-136 with:

```python
            before_skips = len(run.skipped)
            before_fails = len(run.failures)
            events = run.parse_artifact(path, artifact_rel, context)
            was_skipped = len(run.skipped) > before_skips
            was_failed = len(run.failures) > before_fails

            if events:
                insert = db.insert_events(conn, events)
                stats.events_inserted += insert.inserted
                stats.events_deduped += insert.deduped
                stats.events_invalid += insert.invalid

            # A parser that raised must never be recorded as a success: the
            # methodology section of the report exists to tell an analyst what
            # was NOT processed. When several parsers claim one artifact and
            # any of them failed, "fail" is the honest answer.
            if was_skipped:
                artifact_status = "skip"
            elif was_failed:
                artifact_status = "fail"
            else:
                artifact_status = "success"

            _record_artifact(
                conn,
                host_id=host_id,
                row=row,
                artifact_rel=artifact_rel,
                status=artifact_status,
                events=len(events),
                had_decode_errors=context.had_decode_errors,
            )
```

- [ ] **Step 5: Expose the failure list on the stats object**

Still in `analyzer/lfa/pipeline.py`, add a `failed` field to `PipelineStats` (currently lines 27-34):

```python
@dataclass
class PipelineStats:
    artifacts_seen: int = 0
    events_inserted: int = 0
    events_deduped: int = 0
    events_invalid: int = 0
    skipped: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    parser_stats: dict = field(default_factory=dict)
```

And populate it next to the existing `stats.skipped` assignment (currently line 138), so the block reads:

```python
    stats.skipped = list(run.skipped)
    stats.failed = list(run.failures)
    stats.parser_stats = run.stats
    db.set_meta(conn, "parser_stats", json.dumps(run.stats, sort_keys=True))
    db.set_meta(conn, "parser_artifacts",
                json.dumps(run.artifact_results, sort_keys=True))
    db.set_meta(conn, "parser_skipped", json.dumps(sorted(run.skipped)))
    db.set_meta(conn, "parser_failed", json.dumps(sorted(run.failures)))
    conn.commit()
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/test_pipeline.py -v`
Expected: all pass, including the two new tests.

- [ ] **Step 7: Run the full suite**

Run: `python -m pytest`
Expected: `294 passed`.

- [ ] **Step 8: Commit**

```bash
git add analyzer/lfa/parsers/base.py analyzer/lfa/pipeline.py tests/test_pipeline.py
git commit -m "fix(pipeline): crashed parsers were recorded as successes

The status ternary could never yield 'fail' - its else branch tested
'not was_skipped', which is always True where it is reached. Artifacts
whose parser raised were written to the artifacts table as successes with
0 events, so the report's methodology section understated what was not
processed. ParserRun now tracks failures the same way it tracks skips."
```

---

### Task 4: Tag the operator's own session during local collection

**Files:**
- Modify: `collector/collect.sh:413-424` and `:644-648`
- Modify: `analyzer/lfa/parsers/base.py:43-66`
- Modify: `analyzer/lfa/parsers/journald.py:141`
- Modify: `analyzer/lfa/parsers/authlog.py:86`
- Test: `tests/test_parser_framework.py` (append)
- Test: `tests/test_collector.py` (append)

**Interfaces:**
- Consumes: `ParseContext.contamination: dict`, populated from `manifest.json`'s `contamination` object by `pipeline.parse_case`.
- Produces: `ParseContext.is_tool_generated(source_ip: str | None, ts_utc_iso: str | None, actor_user: str | None = None) -> bool`. Existing two-argument call sites keep working. The collector's `contamination` object gains an `operator_login_user` key.

**Background:** `tool_generated_flag` is `0` for all 13,848 events in `cases/kali_case/case.db`. `is_tool_generated` only matches on `source_ip`, and the collector only sets `OP_SRC_IP` when `SSH_CONNECTION` is present — so a local console or WSL operator is never tagged, and the tool can report its own operator as suspicious activity. Separately, `id -un` under `sudo` returns `root` rather than the human being audited.

The new local path is deliberately narrow: it requires the event to have **no** source IP, the username to match, **and** the timestamp to fall inside the collection window. That window is normally seconds to minutes.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_parser_framework.py`:

```python
CONTAMINATION = {
    "operator_user": "root",
    "operator_login_user": "kali",
    "source_ip": "",
    "tty": "pts/0",
    "pid": "4242",
    "start_utc": "2024-03-14T02:00:00Z",
    "end_utc": "2024-03-14T02:05:00Z",
}


def _ctx_with_contamination():
    from lfa.parsers.base import ParseContext
    from lfa.timeeng import TimeContext

    return ParseContext(
        case_id="CASE-C",
        host_id="host-c",
        raw_host_dir=Path("."),
        time_ctx=TimeContext("UTC", "etc_localtime"),
        distro_profile={},
        contamination=CONTAMINATION,
    )


def test_local_operator_session_is_tagged():
    """No source IP, operator's login name, inside the window -> ours."""
    ctx = _ctx_with_contamination()

    assert ctx.is_tool_generated(None, "2024-03-14T02:01:00+00:00", "kali") is True


def test_local_operator_matches_sudo_elevated_name_too():
    ctx = _ctx_with_contamination()

    assert ctx.is_tool_generated(None, "2024-03-14T02:01:00+00:00", "root") is True


def test_local_session_outside_the_window_is_not_tagged():
    ctx = _ctx_with_contamination()

    assert ctx.is_tool_generated(None, "2024-03-14T09:00:00+00:00", "kali") is False


def test_different_user_in_the_window_is_not_tagged():
    ctx = _ctx_with_contamination()

    assert ctx.is_tool_generated(None, "2024-03-14T02:01:00+00:00", "backdooruser") is False


def test_remote_event_in_the_window_is_not_tagged_by_the_local_path():
    """An event with a source IP must go through the IP rule, not the local one."""
    ctx = _ctx_with_contamination()

    assert ctx.is_tool_generated("203.0.113.9", "2024-03-14T02:01:00+00:00", "kali") is False


def test_two_argument_calls_still_work():
    """Existing parsers call this with two arguments; that must not break."""
    ctx = _ctx_with_contamination()

    assert ctx.is_tool_generated(None, "2024-03-14T02:01:00+00:00") is False
```

Note: `tests/test_parser_framework.py` already imports `Path`; if it does not, add `from pathlib import Path` at the top.

Append to `tests/test_collector.py`:

```python
@pytest.mark.parametrize("shell", SHELLS)
def test_manifest_records_sudo_login_user(tmp_path, shell):
    """Under sudo, id -un reports root; the human's name must survive."""
    root = make_fakeroot(tmp_path)
    out = tmp_path / "out"

    env = dict(os.environ)
    env["SUDO_USER"] = "analyst"

    subprocess.run(
        [shell, str(COLLECT_SH), "-r", str(root), "-o", str(out), "-c", "CASE-SUDO"],
        check=False,
        capture_output=True,
        env=env,
    )

    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    contamination = manifest["contamination"]

    assert contamination["operator_login_user"] == "analyst"
    assert "operator_user" in contamination
```

Add `import os` to the imports at the top of `tests/test_collector.py` if it is not already there.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_parser_framework.py tests/test_collector.py -v`
Expected: FAIL. The `is_tool_generated` tests fail with `TypeError` (three arguments given, two accepted); the collector test fails with `KeyError: 'operator_login_user'`.

- [ ] **Step 3: Record the real operator in the collector**

In `collector/collect.sh`, replace the P1b block (currently lines 413-424) with:

```sh
# ------------------------------------------------ P1b contamination record --

OP_USER=$(id -un 2>/dev/null || printf 'unknown')
# Under sudo, id -un reports root. The human being audited is SUDO_USER, and
# that is the name their session events will actually carry.
OP_LOGIN_USER="${SUDO_USER:-$OP_USER}"
# tty(1) prints "not a tty" on stdout AND exits nonzero - capture then check
OP_TTY=$(tty 2>/dev/null)
if [ $? -ne 0 ] || [ -z "$OP_TTY" ]; then OP_TTY="none"; fi
OP_PID=$$
OP_SRC_IP=""
if [ -n "${SSH_CONNECTION:-}" ]; then
    OP_SRC_IP=$(printf '%s' "$SSH_CONNECTION" | awk '{print $1}')
fi
log "P1b contamination: user=$OP_USER login_user=$OP_LOGIN_USER tty=$OP_TTY pid=$OP_PID src=$OP_SRC_IP"
```

Then in the manifest assembly (currently lines 644-648), replace the contamination line with:

```sh
    printf '  "contamination": {"operator_user": "%s", "operator_login_user": "%s", "source_ip": "%s", "tty": "%s", "pid": "%s", "start_utc": "%s", "end_utc": "%s"},\n' \
        "$(json_escape "$OP_USER")" "$(json_escape "$OP_LOGIN_USER")" \
        "$(json_escape "$OP_SRC_IP")" \
        "$(json_escape "$OP_TTY")" "$OP_PID" "$START_UTC" "$END_UTC"
```

- [ ] **Step 4: Add the local-operator path to `is_tool_generated`**

In `analyzer/lfa/parsers/base.py`, replace `is_tool_generated` (currently lines 43-66) with:

```python
    def is_tool_generated(self, source_ip: str | None,
                          ts_utc_iso: str | None,
                          actor_user: str | None = None) -> bool:
        """Auto-tag our own collection session (P1b contamination record):
        events from the operator's source IP inside the collection window
        must never show up as findings (spec: 'without this the tool reports
        its own operator as a suspicious 3am login').

        Two paths. Remote collection is identified by source IP. Local
        collection has no source IP at all, so it is identified by the
        operator's username INSIDE the collection window - normally seconds
        to minutes, which keeps the false-positive risk bounded."""
        if not self.contamination:
            return False

        start = self.contamination.get("start_utc")
        end = self.contamination.get("end_utc")
        op_ip = self.contamination.get("source_ip")

        if source_ip:
            if not op_ip or source_ip != op_ip:
                return False
            if not (start and end and ts_utc_iso):
                # same IP but no window to check: still safer to tag
                return True
            return self._within_collection_window(ts_utc_iso, start, end, default=True)

        # local collection: no source IP to match on
        if not actor_user:
            return False
        operators = {
            self.contamination.get("operator_user"),
            self.contamination.get("operator_login_user"),
        }
        operators.discard(None)
        operators.discard("")
        if actor_user not in operators:
            return False
        if not (start and end and ts_utc_iso):
            # a local username with no window is far too broad to tag
            return False
        return self._within_collection_window(ts_utc_iso, start, end, default=False)

    @staticmethod
    def _within_collection_window(ts_utc_iso: str, start: str, end: str,
                                  *, default: bool) -> bool:
        """True when ts falls inside [start-5min, end+5min]. `default` is
        returned when a timestamp cannot be parsed at all."""
        norm = lambda s: s.replace("Z", "+00:00")
        try:
            ts = datetime.fromisoformat(norm(ts_utc_iso))
            lo = datetime.fromisoformat(norm(start)) - timedelta(minutes=5)
            hi = datetime.fromisoformat(norm(end)) + timedelta(minutes=5)
        except ValueError:
            return default
        return lo <= ts <= hi
```

`datetime` and `timedelta` are already imported at the top of this module (line 16); no import change is needed.

- [ ] **Step 5: Pass the username at the parser call sites**

In `analyzer/lfa/parsers/journald.py`, change line 141 from:

```python
                    tool_generated_flag=context.is_tool_generated(source_ip, ts_utc),
```

to:

```python
                    tool_generated_flag=context.is_tool_generated(
                        source_ip, ts_utc, groups.get("user")
                    ),
```

In `analyzer/lfa/parsers/authlog.py`, change line 86 from:

```python
                    tool_generated_flag=context.is_tool_generated(source_ip, utc),
```

to:

```python
                    tool_generated_flag=context.is_tool_generated(
                        source_ip, utc, groups.get("user")
                    ),
```

Leave the three `utmp.py` call sites on the two-argument form. utmp records carry a host field rather than a username-plus-window pairing, and widening them is not needed for the definition of done.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/test_parser_framework.py tests/test_collector.py tests/test_authlog_parser.py -v`
Expected: all pass. `tests/test_authlog_parser.py:119` (the existing IP-based contamination test) must still pass — if it fails, the remote path was changed and must be restored.

- [ ] **Step 7: Run the full suite**

Run: `python -m pytest`
Expected: `302 passed` (300 if `dash` is not installed - the collector test is parametrised over the shells that exist).

- [ ] **Step 8: Commit**

```bash
git add collector/collect.sh analyzer/lfa/parsers/base.py analyzer/lfa/parsers/journald.py analyzer/lfa/parsers/authlog.py tests/test_parser_framework.py tests/test_collector.py
git commit -m "fix(contamination): tag the operator's own session on local collection

is_tool_generated only matched on source_ip, and the collector only records
one under SSH. Every event in a locally collected case was therefore
untagged - tool_generated_flag was 0 for all 13,848 events in kali_case -
so the tool could report its own operator as suspicious activity.

Adds a narrow local path: no source IP, operator's username, and inside
the collection window. The collector now also records SUDO_USER, since
id -un under sudo reports root rather than the human."
```

---

### Task 5: Require authentication on every endpoint

**Files:**
- Modify: `analyzer/lfa/server.py:55-68` (`_check_auth`), `:70-92` (senders and `do_OPTIONS`), `:95-103` (`do_GET` entry)
- Test: `tests/test_server_auth.py` (create)

**Interfaces:**
- Consumes: `LFAServerHandler`, and `server.auth_token` set by `run_server`.
- Produces: `_check_auth()` additionally accepts an `lfa_token` cookie. A new `GET /login?token=...` sets that cookie and returns 302 to `/`. Every other path returns 401 when a token is configured and no valid credential is presented. No response carries `Access-Control-Allow-Origin`.

**Background:** `_check_auth()` is defined at line 55 and called from exactly one place — line 459, inside `do_POST`. Every GET, including `/api/v1/cases/<id>/artifact-content` which returns raw evidence file bodies, is unauthenticated. Combined with `Access-Control-Allow-Origin: *`, any site the examiner has open can read a whole case.

Browsers cannot attach `Authorization` headers to ordinary navigation, so a cookie path is required for the dashboard to remain usable.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_server_auth.py`:

```python
"""Authentication and CORS tests for the investigation server.

_check_auth was defined but called from exactly one place - do_POST - so
every GET endpoint served evidence to anyone who could reach the port.
"""
import http.server
import socketserver
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from lfa.server import LFAServerHandler

TOKEN = "test-secret-token"


def _find_free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path):
    """A running server with a token configured and one empty case."""
    cases_dir = tmp_path / "cases"
    (cases_dir / "CASE-1").mkdir(parents=True)

    class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    port = _find_free_port()
    httpd = ThreadedServer(("127.0.0.1", port), LFAServerHandler)
    httpd.cases_dir = cases_dir
    httpd.auth_token = TOKEN
    httpd.auto_analyse = False
    httpd.business_hours = "08-18"
    httpd.examiner = "Test"

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


PROTECTED_PATHS = [
    "/",
    "/dashboard",
    "/api/v1/cases",
    "/api/v1/cases/CASE-1/events",
    "/api/v1/cases/CASE-1/artifacts",
    "/api/v1/cases/CASE-1/artifact-content?path=/etc/passwd",
    "/api/v1/cases/CASE-1/findings",
    "/cases/CASE-1/explorer",
]


@pytest.mark.parametrize("path", PROTECTED_PATHS)
def test_endpoint_rejects_unauthenticated_request(server, path):
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{server}{path}", timeout=10)
    assert exc.value.code == 401, path


@pytest.mark.parametrize("path", PROTECTED_PATHS)
def test_endpoint_accepts_bearer_token(server, path):
    req = urllib.request.Request(
        f"{server}{path}", headers={"Authorization": f"Bearer {TOKEN}"}
    )
    # 404 is fine (empty case); 401 is not.
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        assert resp.status != 401
    except urllib.error.HTTPError as exc:
        assert exc.code != 401, path


def test_login_sets_a_cookie_and_redirects(server):
    req = urllib.request.Request(f"{server}/login?token={TOKEN}")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        resp = opener.open(req, timeout=10)
        status, headers = resp.status, resp.headers
    except urllib.error.HTTPError as exc:
        status, headers = exc.code, exc.headers

    assert status == 302
    cookie = headers.get("Set-Cookie", "")
    assert "lfa_token=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie


def test_cookie_authenticates_subsequent_requests(server):
    req = urllib.request.Request(
        f"{server}/api/v1/cases", headers={"Cookie": f"lfa_token={TOKEN}"}
    )
    resp = urllib.request.urlopen(req, timeout=10)
    assert resp.status == 200


def test_login_with_a_wrong_token_is_rejected(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{server}/login?token=wrong", timeout=10)
    assert exc.value.code == 401


def test_health_requires_auth_too(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{server}/api/v1/health", timeout=10)
    assert exc.value.code == 401


def test_no_cors_header_is_emitted(server):
    req = urllib.request.Request(
        f"{server}/api/v1/cases", headers={"Authorization": f"Bearer {TOKEN}"}
    )
    resp = urllib.request.urlopen(req, timeout=10)
    assert resp.headers.get("Access-Control-Allow-Origin") is None


def test_server_without_a_token_stays_open(tmp_path):
    """Default behaviour is unchanged: no token configured means no auth."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    port = _find_free_port()
    httpd = ThreadedServer(("127.0.0.1", port), LFAServerHandler)
    httpd.cases_dir = cases_dir
    httpd.auth_token = None
    httpd.auto_analyse = False
    httpd.business_hours = "08-18"
    httpd.examiner = "Test"

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/cases", timeout=10)
        assert resp.status == 200
    finally:
        httpd.shutdown()
        httpd.server_close()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_server_auth.py -v`
Expected: FAIL. The unauthenticated tests get 200 instead of 401; the `/login` tests get 404; the CORS test finds `*`.

- [ ] **Step 3: Teach `_check_auth` about the cookie**

In `analyzer/lfa/server.py`, replace `_check_auth` (currently lines 55-68) with:

```python
    def _check_auth(self) -> bool:
        """Verify token authentication if configured on server.

        Accepts a Bearer header, an X-LFA-Token header, or an lfa_token
        cookie. The cookie exists because a browser cannot attach headers to
        ordinary navigation, and the dashboard has to stay usable.
        """
        if not self.auth_token:
            return True

        candidates = []

        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            candidates.append(auth_header[7:].strip())

        token_header = self.headers.get("X-LFA-Token", "")
        if token_header:
            candidates.append(token_header.strip())

        cookie_header = self.headers.get("Cookie", "")
        if cookie_header:
            for part in cookie_header.split(";"):
                name, _, value = part.strip().partition("=")
                if name == "lfa_token":
                    candidates.append(value.strip())

        return any(
            secrets.compare_digest(c, self.auth_token) for c in candidates if c
        )
```

- [ ] **Step 4: Remove the CORS headers and the OPTIONS handler**

Still in `analyzer/lfa/server.py`, remove the `Access-Control-Allow-Origin` line from `_send_json` (currently line 75), so the method reads:

```python
    def _send_json(self, status_code: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
```

Then delete the entire `do_OPTIONS` method (currently lines 87-93). Nothing legitimately needs cross-origin access to evidence.

- [ ] **Step 5: Add the login endpoint and the global gate**

Still in `analyzer/lfa/server.py`, replace the opening of `do_GET` (currently lines 95-103) with:

```python
    def _send_redirect(self, location: str, cookie: str | None = None) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        """Serve Dashboard, Interactive Explorer, Reports, and JSON APIs."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip("/")
        if path == "":
            path = "/"
        params = urllib.parse.parse_qs(parsed_url.query)

        # 0. Cookie login, so a browser can reach a token-protected server.
        #    This is the only path that may be reached without credentials.
        if path == "/login":
            supplied = (params.get("token") or [""])[0]
            if not self.auth_token:
                self._send_redirect("/")
                return
            if supplied and secrets.compare_digest(supplied, self.auth_token):
                self._send_redirect(
                    "/",
                    f"lfa_token={supplied}; HttpOnly; SameSite=Strict; Path=/",
                )
                return
            self._send_json(401, {"error": "Unauthorized: invalid token"})
            return

        # Everything else requires credentials whenever a token is configured.
        if not self._check_auth():
            self._send_json(
                401,
                {"error": "Unauthorized: Invalid or missing authentication token"},
            )
            return
```

Leave the rest of `do_GET` (the numbered route table starting at "1. Health / Status API") exactly as it is.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/test_server_auth.py -v`
Expected: all pass.

- [ ] **Step 7: Run the existing server tests, which do not use a token**

Run: `python -m pytest tests/test_server_stream.py -v`
Expected: all pass unchanged. If a test there asserts on a CORS header, update that assertion to expect its absence — removing CORS is intentional.

- [ ] **Step 8: Run the full suite**

Run: `python -m pytest`
Expected: `324 passed`.

- [ ] **Step 9: Commit**

```bash
git add analyzer/lfa/server.py tests/test_server_auth.py
git commit -m "fix(server): authenticate every endpoint, drop wildcard CORS

_check_auth was called from exactly one site - do_POST - so with --token
set, every GET still served case data unauthenticated, including
/artifact-content, which returns raw evidence file bodies. Wildcard CORS
meant any site the examiner had open could read a whole case.

Auth now gates all of do_GET. _check_auth also accepts an lfa_token
cookie, set by GET /login?token=..., because browsers cannot attach
headers to navigation. With no token configured the server stays open,
so existing local workflows are unchanged."
```

---

### Task 6: Escape evidence-derived values in server-rendered HTML

**Files:**
- Modify: `analyzer/lfa/server.py` (imports, `_render_dashboard_html`, `do_POST` examiner handling)
- Modify: `analyzer/lfa/explorer.py:16-30`
- Test: `tests/test_server_xss.py` (create)

**Interfaces:**
- Consumes: `_list_cases() -> list[dict]`, whose entries carry `case_id`, `hosts`, `examiner`, `ingest_time`.
- Produces: no signature changes. Every evidence-derived value interpolated into HTML passes through `html.escape(value, quote=True)`. `X-Examiner` is sanitised at ingest to printable characters, capped at 128.

**Background:** `server.py` never imports `html`, and `_render_dashboard_html` interpolates `c["case_id"]`, `hosts_str`, `c["examiner"]` and `ingest_str` straight into an f-string. `examiner` comes from the unsanitised `X-Examiner` header; `hosts` comes from `host_id`, which is `machine_id` or `hostname` **read off the machine being investigated**. A forensic tool must never treat evidence as markup. `explorer.py` interpolates the same values into its page header.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_server_xss.py`:

```python
"""Evidence must never be rendered as markup.

examiner comes from the X-Examiner ingest header; host_id comes from
machine_id/hostname read off the machine under investigation. Both reach
server-rendered HTML.
"""
import json
from pathlib import Path

from lfa.explorer import render_explorer_html
from lfa.server import LFAServerHandler

PAYLOAD = "<script>alert('xss')</script>"


def _case_info(**overrides):
    info = {
        "case_id": "CASE-1",
        "path": "cases/CASE-1",
        "has_db": True,
        "has_report": True,
        "report_url": "/cases/CASE-1/report.html",
        "hosts": ["host-1"],
        "examiner": "Jane Doe",
        "events_count": 10,
        "findings_count": 2,
        "high_findings": 1,
        "ingest_time": "2026-09-09T10:00:00+00:00",
    }
    info.update(overrides)
    return info


def _render_dashboard(cases):
    # _render_dashboard_html reads self.auth_token (a property backed by
    # self.server), so the fake handler needs a server object.
    handler = LFAServerHandler.__new__(LFAServerHandler)
    handler.server = type("S", (), {"auth_token": None, "server_address": ("", 8443)})()
    return LFAServerHandler._render_dashboard_html(handler, cases)


def test_dashboard_escapes_a_malicious_examiner():
    html_out = _render_dashboard([_case_info(examiner=PAYLOAD)])

    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out


def test_dashboard_escapes_a_malicious_host_id():
    html_out = _render_dashboard([_case_info(hosts=[PAYLOAD])])

    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out


def test_dashboard_escapes_a_malicious_case_id():
    html_out = _render_dashboard([_case_info(case_id=PAYLOAD)])

    assert "<script>alert" not in html_out


def test_explorer_escapes_a_malicious_examiner():
    html_out = render_explorer_html("CASE-1", _case_info(examiner=PAYLOAD))

    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out


def test_explorer_escapes_a_malicious_host_id():
    html_out = render_explorer_html("CASE-1", _case_info(hosts=[PAYLOAD]))

    assert "<script>alert" not in html_out


def test_explorer_escapes_a_malicious_case_id():
    html_out = render_explorer_html(PAYLOAD, _case_info())

    assert "<script>alert" not in html_out


def test_examiner_header_is_sanitised():
    from lfa.server import sanitise_examiner

    assert "\n" not in sanitise_examiner("Jane\nDoe")
    assert "\r" not in sanitise_examiner("Jane\rDoe")
    assert len(sanitise_examiner("A" * 500)) <= 128
    assert sanitise_examiner("") == "Remote Investigator"
    assert sanitise_examiner(None) == "Remote Investigator"
    assert sanitise_examiner("Jane Doe") == "Jane Doe"


def test_dashboard_does_not_print_the_auth_token(tmp_path):
    """The copy-paste command box rendered the live token in plaintext."""
    handler = LFAServerHandler.__new__(LFAServerHandler)
    handler.server = type(
        "S", (), {"auth_token": "super-secret-token", "server_address": ("", 8443)}
    )()

    html_out = LFAServerHandler._render_dashboard_html(handler, [])

    assert "super-secret-token" not in html_out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_server_xss.py -v`
Expected: FAIL. The dashboard and explorer tests find the raw `<script>`; the sanitiser test fails with `ImportError`.

- [ ] **Step 3: Add the import and the examiner sanitiser**

In `analyzer/lfa/server.py`, add `import html` to the imports (alphabetically, immediately after `import hashlib` on line 13).

Then add this module-level function immediately before the `class LFAServerHandler` declaration (before line 30):

```python
def sanitise_examiner(value: str | None) -> str:
    """Clean the X-Examiner header before it is stored or rendered.

    This value comes off the wire from whatever streamed the bundle, and it
    ends up in case_metadata.json and in server-rendered HTML. Strip control
    characters, collapse whitespace, and cap the length.
    """
    if not value:
        return "Remote Investigator"
    cleaned = "".join(ch for ch in str(value) if ch.isprintable())
    cleaned = " ".join(cleaned.split()).strip()
    if not cleaned:
        return "Remote Investigator"
    return cleaned[:128]
```

- [ ] **Step 4: Sanitise the examiner header at ingest**

Still in `analyzer/lfa/server.py`, in `do_POST`, change the examiner line (currently line 479) from:

```python
        examiner = self.headers.get("X-Examiner") or self.examiner
```

to:

```python
        examiner = sanitise_examiner(self.headers.get("X-Examiner")) \
            if self.headers.get("X-Examiner") else self.examiner
```

- [ ] **Step 5: Escape every interpolated value in the dashboard**

Still in `analyzer/lfa/server.py`, inside `_render_dashboard_html`, replace the whole `for c in cases:` body — currently lines 640-664, from `for c in cases:` down to and including the `"""` that closes the `rows_html` f-string — with this complete block:

```python
            for c in cases:
                case_id_safe = html.escape(str(c["case_id"]), quote=True)
                hosts_str = html.escape(
                    ", ".join(str(h) for h in c["hosts"]) if c["hosts"] else "—",
                    quote=True,
                )
                examiner_safe = html.escape(str(c["examiner"]), quote=True)
                report_url_safe = html.escape(str(c["report_url"] or ""), quote=True)

                badge_high = f'<span class="badge badge-high">{c["high_findings"]} High</span>' if c["high_findings"] > 0 else ""
                badge_total = f'<span class="badge badge-neutral">{c["findings_count"]} Total</span>'

                explore_btn = f'<a href="/cases/{case_id_safe}/explorer" class="btn btn-primary">🔬 Explore</a>' if c["has_db"] else '<span class="btn btn-disabled">No DB</span>'
                report_btn = f'<a href="{report_url_safe}" target="_blank" class="btn btn-secondary">🔍 Report</a>' if c["has_report"] else '<span class="btn btn-disabled">Pending</span>'

                ingest_str = html.escape(
                    c["ingest_time"][:19].replace("T", " ") if c["ingest_time"] else "—",
                    quote=True,
                )

                rows_html += f"""
                <tr>
                  <td><strong class="case-title">{case_id_safe}</strong></td>
                  <td><span class="mono-tag">{hosts_str}</span></td>
                  <td>{examiner_safe}</td>
                  <td class="num">{c["events_count"]:,}</td>
                  <td>{badge_high} {badge_total}</td>
                  <td class="subtext">{ingest_str}</td>
                  <td>
                    <div style="display:flex; gap:0.4rem;">
                      {explore_btn}
                      {report_btn}
                    </div>
                  </td>
                </tr>
                """
```

The only changes are the escaped value bindings; the emitted markup is identical.

- [ ] **Step 5b: Stop printing the live auth token into the page**

Still in `_render_dashboard_html`, line 667 currently renders the server's own token into a copy-paste command box shown on the dashboard:

```python
        token_arg = f'--token "{self.auth_token}"' if self.auth_token else ''
```

Replace it with a placeholder, so the secret is never written into a page that can be cached, screenshotted, or shoulder-surfed:

```python
        # Never render the live token into the page. The examiner already knows
        # it - they started the server with it.
        token_arg = '-T "<YOUR-INGEST-TOKEN>"' if self.auth_token else ''
```

- [ ] **Step 6: Escape the explorer page header**

In `analyzer/lfa/explorer.py`, add `import html` at the top of the module (after the `from __future__` line and any existing imports), then replace the opening of `render_explorer_html` (currently lines 16-23) with:

```python
def render_explorer_html(case_id: str, case_info: dict[str, Any]) -> str:
    """Render the single-page interactive investigation explorer."""
    # case_id, examiner and host ids are all evidence-derived or wire-derived.
    # They are interpolated into this page's markup, so they are escaped here.
    case_id = html.escape(str(case_id), quote=True)
    examiner = html.escape(
        str(case_info.get("examiner", "Forensic Investigator")), quote=True
    )
    hosts_str = html.escape(
        ", ".join(str(h) for h in case_info.get("hosts", []))
        if case_info.get("hosts")
        else "—",
        quote=True,
    )
    events_count = case_info.get("events_count", 0)
    findings_count = case_info.get("findings_count", 0)
    high_findings = case_info.get("high_findings", 0)
    report_url = html.escape(
        str(case_info.get("report_url", f"/cases/{case_id}/report.html")), quote=True
    )
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `python -m pytest tests/test_server_xss.py -v`
Expected: all pass.

- [ ] **Step 8: Run the full suite**

Run: `python -m pytest`
Expected: `332 passed`.

- [ ] **Step 9: Commit**

```bash
git add analyzer/lfa/server.py analyzer/lfa/explorer.py tests/test_server_xss.py
git commit -m "fix(server): escape evidence-derived values in rendered HTML

server.py never imported html, and the dashboard interpolated case_id,
host_id and examiner straight into f-strings. examiner arrives on the
unsanitised X-Examiner header; host_id is machine_id/hostname read off
the machine under investigation. A forensic tool must never render
evidence as markup. The explorer header had the same hole.

The offline Jinja report was already safe (autoescape=True)."
```

---

### Task 7: Make the case lister read-only and leak-free

**Files:**
- Modify: `analyzer/lfa/server.py:596-618` (the `if db_path.exists():` block inside `_list_cases`)
- Test: `tests/test_server_caselist.py` (create)

**Interfaces:**
- Consumes: `db.get_case_meta(conn: sqlite3.Connection, key: str) -> str | None` — a **two**-parameter function.
- Produces: `_list_cases()` unchanged in signature and in the shape of its returned dicts, but it now opens each case database read-only and closes it on every path, including error paths.

**Background:** line 611 calls `db.get_case_meta(conn, "examiner", "Unknown")` with three arguments against a two-parameter function. The `TypeError` is swallowed by the surrounding bare `except Exception: pass`, which also skips `conn.close()` — leaking a SQLite connection on every dashboard load, and always leaving `examiner` as `"Unknown"`. The block also uses `db.open_case()`, which opens read-write and executes DDL against evidence databases, while every other handler correctly uses `?mode=ro`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_server_caselist.py`:

```python
"""_list_cases must read evidence databases read-only and never leak handles."""
import gc
import json
import sqlite3
from pathlib import Path

from lfa import db
from lfa.server import LFAServerHandler


def _make_case(cases_dir: Path, case_id: str, examiner: str) -> Path:
    case_dir = cases_dir / case_id
    case_dir.mkdir(parents=True)
    conn = db.open_case(case_dir / "case.db")
    db.set_case_meta(conn, "case_id", case_id)
    db.set_case_meta(conn, "examiner", examiner)
    conn.commit()
    conn.close()
    (case_dir / "report.html").write_text("<html></html>", encoding="utf-8")
    return case_dir


def _list(cases_dir: Path):
    handler = LFAServerHandler.__new__(LFAServerHandler)
    handler.server = type("S", (), {"cases_dir": cases_dir})()
    return LFAServerHandler._list_cases(handler)


def test_examiner_is_read_from_the_database(tmp_path):
    """This silently returned 'Unknown' because of a TypeError swallowed
    by a bare except."""
    cases_dir = tmp_path / "cases"
    _make_case(cases_dir, "CASE-1", "Jane Doe")

    cases = _list(cases_dir)

    assert len(cases) == 1
    assert cases[0]["examiner"] == "Jane Doe"


def test_listing_does_not_modify_the_evidence_database(tmp_path):
    """open_case() runs DDL against the case DB; a read must not touch it."""
    cases_dir = tmp_path / "cases"
    case_dir = _make_case(cases_dir, "CASE-1", "Jane Doe")
    db_file = case_dir / "case.db"

    before_mtime = db_file.stat().st_mtime_ns
    before_bytes = db_file.read_bytes()

    _list(cases_dir)
    gc.collect()

    assert db_file.stat().st_mtime_ns == before_mtime, "listing wrote to evidence"
    assert db_file.read_bytes() == before_bytes, "listing altered evidence bytes"


def test_listing_reports_counts(tmp_path):
    cases_dir = tmp_path / "cases"
    _make_case(cases_dir, "CASE-1", "Jane Doe")

    cases = _list(cases_dir)

    assert cases[0]["events_count"] == 0
    assert cases[0]["findings_count"] == 0
    assert cases[0]["high_findings"] == 0
    assert cases[0]["has_report"] is True
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_server_caselist.py -v`
Expected: FAIL. `test_examiner_is_read_from_the_database` gets `"Unknown"`; `test_listing_does_not_create_wal_files` finds a `case.db-wal`.

- [ ] **Step 3: Rewrite the database block in `_list_cases`**

In `analyzer/lfa/server.py`, replace the `if db_path.exists():` block inside `_list_cases` (currently lines 596-618) with:

```python
            if db_path.exists():
                conn = None
                try:
                    # Read-only: listing cases must never write to evidence.
                    conn = sqlite3.connect(
                        f"file:{db_path.as_posix()}?mode=ro", uri=True
                    )
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM events")
                    case_info["events_count"] = cur.fetchone()[0]

                    cur.execute("SELECT COUNT(*) FROM findings")
                    case_info["findings_count"] = cur.fetchone()[0]

                    cur.execute("SELECT COUNT(*) FROM findings WHERE severity = 'high'")
                    case_info["high_findings"] = cur.fetchone()[0]

                    if case_info["examiner"] == "Unknown":
                        row = cur.execute(
                            "SELECT value FROM case_meta WHERE key = 'examiner'"
                        ).fetchone()
                        if row and row[0]:
                            case_info["examiner"] = row[0]
                except Exception:
                    pass
                finally:
                    if conn is not None:
                        conn.close()
```

Querying `case_meta` directly avoids depending on `db.get_case_meta`, which needs a read-write connection contract it does not actually require here.

- [ ] **Step 4: Confirm `sqlite3` is imported in `server.py`**

Run: `grep -n "^import sqlite3" analyzer/lfa/server.py`
Expected: a match. If there is none, add `import sqlite3` to the imports alphabetically (after `import socketserver`).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_server_caselist.py -v`
Expected: 3 passed.

- [ ] **Step 6: Run the full suite**

Run: `python -m pytest`
Expected: `335 passed`.

- [ ] **Step 7: Commit**

```bash
git add analyzer/lfa/server.py tests/test_server_caselist.py
git commit -m "fix(server): _list_cases leaked connections and wrote to evidence

get_case_meta was called with three arguments against a two-parameter
function. The TypeError was swallowed by a bare except that also skipped
conn.close(), so every dashboard load leaked a SQLite handle and the
examiner always displayed as Unknown. The block also used open_case(),
which opens read-write and runs DDL against evidence databases; it now
uses ?mode=ro with a finally-close like every other handler."
```

---

### Task 8: Re-analyse a real case and confirm the fixes hold end to end

**Files:**
- No source changes. Verification only.

**Interfaces:**
- Consumes: everything built in Tasks 1–7.
- Produces: evidence that the definition of done in the spec is met against real data.

- [ ] **Step 1: Re-analyse the Kali case from its original bundle**

Run:

```bash
python -m lfa analyse cases/wsl_kali/*.tar.gz --case-dir cases/verify_kali --examiner "Fahad"
```

Expected: completes and prints an events count and a findings count.

If `cases/wsl_kali/*.tar.gz` does not exist, use any bundle under `cases/` that does, and note which one you used in the final report.

- [ ] **Step 2: Confirm no quoted usernames survive**

Run:

```bash
python -c "import sqlite3; c=sqlite3.connect('cases/verify_kali/case.db'); rows=[r[0] for r in c.execute(\"SELECT DISTINCT actor_user FROM events WHERE actor_user LIKE '''%' OR actor_user LIKE '%'''\")]; print('QUOTED:', rows); assert not rows, rows; print('OK: no quoted usernames')"
```

Expected: `OK: no quoted usernames`.

- [ ] **Step 3: Confirm `first_seen` no longer double-reports the same user**

Run:

```bash
python -c "import sqlite3; c=sqlite3.connect('cases/verify_kali/case.db'); [print(r[0]) for r in c.execute(\"SELECT title FROM findings WHERE rule_name='first_seen' ORDER BY title\")]"
```

Expected: each username appears once. There must be no pair like `First appearance of username root` alongside `First appearance of username 'root'`.

- [ ] **Step 4: Confirm the verify command works on the new case**

Run: `python -m lfa verify cases/verify_kali`
Expected: a clean-verification line with a nonzero count, exit code 0, no traceback.

- [ ] **Step 5: Confirm artifact statuses are honest**

Run:

```bash
python -c "import sqlite3; c=sqlite3.connect('cases/verify_kali/case.db'); print(dict(c.execute('SELECT parse_status, COUNT(*) FROM artifacts GROUP BY parse_status').fetchall()))"
```

Expected: a dict of `skip`/`success`, plus `fail` if and only if `cases/verify_kali/parser_errors.log` is non-empty. Cross-check: if that log has entries, there must be `fail` rows; if it is empty or absent, there must be none.

- [ ] **Step 6: Confirm the server refuses anonymous access**

Start the server in one terminal:

```bash
python -m lfa serve --port 8443 --cases-dir cases --token "verify-token" --no-auto-analyse
```

In another terminal:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8443/api/v1/cases
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer verify-token" http://127.0.0.1:8443/api/v1/cases
curl -s -D - -o /dev/null "http://127.0.0.1:8443/login?token=verify-token"
```

Expected: `401`, then `200`, then a `302` carrying `Set-Cookie: lfa_token=...; HttpOnly; SameSite=Strict; Path=/`. Stop the server when done.

- [ ] **Step 7: Run the full suite one final time**

Run: `python -m pytest`
Expected: `335 passed`, 0 failures.

- [ ] **Step 8: Remove the scratch verification case and commit nothing**

```bash
rm -rf cases/verify_kali
```

`cases/` is gitignored, so there is nothing to commit from this task. Report the observed numbers from Steps 2–7 in your summary.

---

## Notes for the implementer

- **Test counts in the "Expected" lines are cumulative** and assume every prior task landed. If you run tasks out of order, the absolute number will differ; what matters is that nothing that previously passed now fails.
- **`cases/` is gitignored.** Never `git add` anything under it.
- **The working tree already had uncommitted changes before you started** — new parsers, report changes, `uploads/`. Those are not yours. Only stage the exact paths listed in each commit step.
- **The suite takes about 4 minutes.** That is the collector tests shelling out to `sh` and `dash`. It is not hung.
- **If a collector test fails on Windows**, check that `dash` is actually on `PATH`; `tests/test_collector.py` skips shells it cannot find, so a missing shell reduces coverage rather than failing.
