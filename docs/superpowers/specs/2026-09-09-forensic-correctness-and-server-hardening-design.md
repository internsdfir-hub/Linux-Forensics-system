# Forensic Correctness & Server Hardening — Design

**Date:** 2026-09-09
**Status:** Approved for implementation
**Scope:** Cluster 1 (correctness of forensic claims) + Cluster 2 (server hardening).
Cluster 3 (the `data_exfil_simulator.py` / `data_exfil_receiver.py` second evidence path)
is explicitly **out of scope** and left untouched.

---

## 1. Problem statement

An audit of the LFA codebase (2026-09-08) found that the tool's architecture is
sound but that several defects cause it to **state things that are not true** —
the worst failure mode for a forensic tool — and that the investigation server
exposes evidence without authentication.

All findings below were verified against the running code and against
`cases/kali_case/case.db` (13,848 events), not inferred from reading.

### Cluster 1 — the tool reports untrue things

| ID | Defect | Evidence |
| :- | :----- | :------- |
| C1.1 | `python -m lfa verify` crashes on every invocation. `cmd_verify` treats the `VerifyReport` dataclass returned by `verify_raw()` as a list; the dataclass is always truthy, so control always enters the "INTEGRITY FAILURE" branch and then raises `TypeError: object of type 'VerifyReport' has no len()`. | `analyzer/lfa/__main__.py:47-52`; reproduced against `cases/103` |
| C1.2 | Cross-source correlation is silently broken. The systemd-logind grammar rule captures `(?P<user>\S+)` from `New session 'c1' of user 'kali'`, storing `actor_user` as `'kali'` **with literal quote characters**, while every other parser stores `kali`. Rules that join on `actor_user` therefore never match journald rows — and journald is the primary log source on modern distros. | `config/grammars/common.yaml:190`; `journald_parser` rows in `kali_case` show `"'kali'"` (n=31) and `"'root'"` (n=4) alongside unquoted `kali`/`root` from other parsers |
| C1.3 | Artifacts whose parser raised are recorded as `parse_status="success"`. The status expression can never evaluate to `"fail"`, because the `else` branch tests `not was_skipped`, which is `True` whenever that branch is reached. This defeats the module's stated purpose of telling analysts what was **not** processed. | `analyzer/lfa/pipeline.py:133`; proven exhaustively over all four input combinations |
| C1.4 | Contamination tagging never fires for local collection. `is_tool_generated()` requires the event's `source_ip` to equal the operator's, but the collector only records `OP_SRC_IP` when `SSH_CONNECTION` is set. A local console or WSL operator is never tagged. `tool_generated_flag` is `0` for all 13,848 events in `kali_case`. Additionally `id -un` under `sudo` reports `root`, not the human who ran the collection. | `collector/collect.sh:415-424`; `analyzer/lfa/parsers/base.py:43-66` |

### Cluster 2 — the server exposes evidence

| ID | Defect | Evidence |
| :- | :----- | :------- |
| C2.1 | No authentication on any GET endpoint. `_check_auth()` is called from exactly one site — `do_POST`. With `--token` set, `/api/v1/cases`, `/events`, `/findings`, `/artifacts` and **`/artifact-content`** (raw evidence file bodies, including `/etc/shadow`) are all served to anyone who can reach the port. | `analyzer/lfa/server.py:55` (definition), `:459` (only call site) |
| C2.2 | `Access-Control-Allow-Origin: *` on every JSON response means any website the examiner has open in the same browser can read the entire case via JavaScript. | `analyzer/lfa/server.py:75, 90` |
| C2.3 | Stored XSS in the dashboard from evidence-controlled data. `_render_dashboard_html` builds HTML with f-strings and no escaping (`server.py` never imports `html`). Injection reaches it via the unsanitised `X-Examiner` ingest header, and via `host_id`, which is derived from `machine_id`/`hostname` **on the collected machine**. `explorer.py` has the same unescaped header interpolation. | `analyzer/lfa/server.py:641-654`, `:479`; `analyzer/lfa/explorer.py:16-30` |
| C2.4 | `db.get_case_meta(conn, "examiner", "Unknown")` passes three arguments to a two-parameter function. The resulting `TypeError` is swallowed by a bare `except Exception: pass`, which also skips `conn.close()` — leaking a SQLite connection on every dashboard load. | `analyzer/lfa/server.py:610-616` |
| C2.5 | `_list_cases` opens case databases read-write via `db.open_case()`, executing DDL against evidence databases on every dashboard hit, while every other handler correctly uses `?mode=ro`. | `analyzer/lfa/server.py:604` |
| C2.6 | The dashboard renders the server's live ingest token in plaintext, inside a copy-paste command box: `token_arg = f'--token "{self.auth_token}"'`. The secret ends up in a page that can be cached, screenshotted, or shoulder-surfed. (Found while fixing C2.3.) | `analyzer/lfa/server.py:667`, rendered at `:946` |

---

## 2. Design decisions

### D-A: Normalise quoted identifiers centrally, in the grammar engine

The quote bug is fixed in `GrammarEngine.match_line()` rather than in the
regex or in each parser. One change then covers `authlog_parser`,
`journald_parser`, `cronlog_parser` and every future grammar consumer.

Only identifier-bearing groups are normalised — `user`, `target_user`, `group` —
and only a **matched surrounding pair** of `'` or `"` is stripped. Usernames
that legitimately contain a quote are left alone, and no other group (such as
`session`) is touched.

Rejected: editing the `common.yaml` pattern to `[^\s']+`. That fixes one rule
and leaves the same trap for the next one written.

**Migration:** existing case databases keep the bad values. Re-running
`lfa analyse` regenerates them correctly. No migration script — evidence is
re-derivable from `raw/` by design, and rewriting stored events in place would
violate the determinism contract.

### D-B: Track parser failures the way skips are already tracked

`ParserRun` gains a `failures: list[str]` attribute, appended on the exception
path, exactly mirroring the existing `skipped` list. `parse_case` then computes
status with the same before/after idiom it already uses for skips. This follows
the established house pattern rather than introducing a new return type.

When one parser fails and another succeeds on the same artifact, the status is
`"fail"` — the conservative choice, because it prompts an analyst to look.

### D-C: Contamination tagging gains a local-operator path

`is_tool_generated()` keeps its existing IP-matching behaviour unchanged (the
test at `tests/test_authlog_parser.py:119` must keep passing) and gains a
second, deliberately narrow path:

> If the event carries **no** `source_ip`, and its `actor_user` matches the
> recorded operator, and its timestamp falls inside the collection window
> (±5 minutes), tag it.

The window is typically seconds to minutes, so the false-positive risk is low
and bounded. The collector additionally records `operator_login_user` from
`$SUDO_USER`, because `id -un` under `sudo` reports `root` rather than the human
being audited.

`is_tool_generated` gains an optional third parameter `actor_user=None`;
existing two-argument calls keep working unchanged.

### D-D: Authenticate everything, with a cookie so browsers still work

When `--token` is set, **every** request requires it. Browsers cannot send
`Authorization` headers on ordinary navigation, so `_check_auth()` additionally
accepts an `lfa_token` cookie, and a new `GET /login?token=...` endpoint sets that
cookie (`HttpOnly`, `SameSite=Strict`, `Path=/`) and redirects to `/`.

When no token is configured the server stays fully open, exactly as today — the
default behaviour is unchanged, so existing local workflows do not break.

Rejected: accepting `?token=` on every request. It leaks the token into server
logs, browser history and `Referer` headers.

### D-E: Remove CORS entirely

No legitimate consumer is cross-origin. The `Access-Control-Allow-*` headers and
the `do_OPTIONS` handler are removed rather than narrowed.

### D-F: Escape at the point of rendering

`html.escape(..., quote=True)` is applied to every evidence-derived value
interpolated into server-side HTML, in both `server.py` and `explorer.py`.
`X-Examiner` is additionally sanitised at ingest (control characters stripped,
length capped at 128) as defence in depth. The offline Jinja report already has
`autoescape=True` and needs no change.

The dashboard's copy-paste command box stops echoing the live token and renders
a `<YOUR-INGEST-TOKEN>` placeholder instead (C2.6). The examiner already knows
the token — they started the server with it — so displaying it buys nothing and
puts a secret into a cacheable page.

---

## 3. Out of scope

Deliberately excluded from this work, to be revisited separately:

- Cluster 3: `testlab/data_exfil_simulator.py` and `testlab/data_exfil_receiver.py`.
- `ftplog.py` treating local timestamps as UTC.
- `weblog.py` silently dropping error logs.
- The `brute_force` rule reporting all-time failures as one campaign.
- Markdown asterisks leaking into the rendered executive summary.
- Bundle-level signing / detached signatures.
- `score_detection.py` false-positive measurement.
- The missing `audit` category and audit parser.

---

## 4. Definition of done

1. `python -m lfa verify <case>` exits 0 on a clean case and 1 on a tampered
   one, printing a count — never a traceback.
2. No `actor_user` value in a freshly analysed case carries surrounding quotes.
3. An artifact whose parser raised is recorded with `parse_status="fail"`.
4. A locally collected bundle tags the operator's own session events.
5. With `--token` set, every endpoint returns 401 without credentials; with the
   cookie set by `/login`, the dashboard and explorer work in a browser.
6. No response carries an `Access-Control-Allow-Origin` header.
7. A case whose examiner or host_id contains `<script>` renders escaped.
8. The dashboard never contains the live ingest token.
9. `_list_cases` opens databases read-only and closes them on every path.
10. The full suite passes; new tests cover each of the above.
