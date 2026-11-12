# Building the Portable Offline Analyzer (Windows x64)

Produces a self-contained folder that runs the LFA analyzer on a **stock,
air-gapped Windows 10/11 machine** — no Python, no installer, no admin
rights, no network.

Scope: the **examiner side only** (`analyse`, `verify`, `report`, `serve`,
`export`). The collector (`collector/collect.sh`) still runs on the Linux
target host; it is not part of this bundle.

---

## Quick reference

```bash
# On a machine WITH internet, once:
python packaging/build_portable.py --zip

# On a machine WITHOUT internet (packaging/vendor/ already populated):
python packaging/build_portable.py --offline --zip
```

Output: `dist/LFA-Portable/` (~26 MB) and `dist/LFA-Portable.zip` (~12 MB).

---

## The three stages

The build script has three stages. `--stage all` (the default) runs them in
order; `--stage <name>` runs just one.

### 1. `vendor` — the only stage that needs the internet

Downloads into `packaging/vendor/`:

| Item | Size | Why |
|---|---|---|
| `python-3.13.7-embed-amd64.zip` | 10.9 MB | The embeddable CPython runtime, Authenticode-signed by the PSF |
| `pyyaml-6.0.3-cp313-cp313-win_amd64.whl` | 154 KB | Grammar/rule YAML loading |
| `jinja2-3.1.6-py3-none-any.whl` | 134 KB | HTML report rendering |
| `markupsafe-3.0.3-cp313-cp313-win_amd64.whl` | 15 KB | Jinja2 dependency |
| `tzdata-2026.4-py2.py3-none-any.whl` | 347 KB | `zoneinfo` has no system tz database on Windows |

Wheels are cross-downloaded for the **target** interpreter, not the one
running the build:

```
pip download --only-binary=:all: --platform win_amd64 \
             --python-version 313 --implementation cp ...
```

This matters because PyYAML and MarkupSafe ship compiled C extensions. A
wheel built for a different CPython ABI will import-error at runtime on the
examiner box. **If you change `PY_VERSION`, you must re-run `vendor`** so the
ABI tags match.

A `SHA256SUMS` file is written alongside the downloads.

Run this once, commit `packaging/vendor/`, and every later build works
offline.

### 2. `build` — assemble the bundle

```
dist/LFA-Portable/
  lfa.cmd                 CLI entry point
  lfa-dashboard.cmd       starts the web dashboard on https://127.0.0.1:8443
  verify-install.cmd      one-click install check
  README-OFFLINE.txt      instructions for the examiner
  SHA256SUMS              hash of every shipped file
  runtime/                embeddable CPython 3.13.7
  app/lfa/                the analyzer package
  app/site-packages/      PyYAML, Jinja2, MarkupSafe, tzdata
  config/                 grammars/*.yaml + artifacts.yaml   <-- see below
  cases/                  default case output directory
```

**Two details are load-bearing:**

**`runtime/python313._pth`.** The embeddable distribution replaces normal
`sys.path` discovery with this file. The build writes:

```
python313.zip
.
..\app
..\app\site-packages

# enable site so the vendored packages above are importable
import site
```

Paths resolve relative to `python.exe`'s directory. Without the `import site`
line the `site-packages` entry is ignored and every third-party import fails.
The upside of this mechanism is total isolation — verified:

```
sys.path = [runtime\python313.zip, runtime\, app\, app\site-packages\]
sys.prefix = ...\LFA-Portable\runtime
```

No system Python, no user site-packages, no `PYTHONPATH` leakage. It cannot
collide with anything already installed on the examiner's machine.

**`config/` must sit at the bundle root.** `analyzer/lfa/parsers/authlog.py`
resolves its grammar directory as:

```python
GRAMMAR_DIR = Path(__file__).resolve().parents[3] / "config" / "grammars"
```

In a dev checkout that is the repo root (`analyzer/lfa/parsers` → up 3). The
portable layout mirrors that depth on purpose (`app/lfa/parsers` → up 3 →
bundle root), so `config/` lands exactly where the analyzer already looks —
no code change needed.

> **This is the failure mode to know about.** If `config/grammars/` is
> missing, the grammar engine loads **zero patterns and raises nothing**.
> Analysis still exits 0, file-based parsers (passwd, group, crontab) still
> work, and a perfectly plausible report is produced. What silently
> disappears is every log-driven detection — cron beacons, sshd auth lines.
> The build now hard-fails if `config/grammars/common.yaml` is absent.

### 3. `smoke` — run the assembled bundle end-to-end

Builds a synthetic evidence bundle via `tests/bundle_builder.py`, then drives
`dist/LFA-Portable/lfa.cmd` — **the packaged runtime, not the developer's
interpreter** — through `analyse` → `verify` → `report`.

It asserts on *detections*, not exit codes:

- `suspicious_cron_command` and `cron_command` appear in `events.subcategory`
  (proves the grammar YAML actually loaded)
- at least one row in `findings` (proves correlation ran)
- `report.html` exists, is >2 KB, and contains the beacon IP

Exit codes alone are not enough: the config-less build above passed a naive
"did it produce a report" check while detecting nothing.

---

## Command mapping: dev checkout → portable bundle

Nothing about the CLI changes. `lfa.cmd` **is** `python -m lfa` with the
bundled interpreter wired in. Same subcommands, same flags, same output.

| Dev checkout | Portable bundle |
|---|---|
| `python -m lfa serve --port 8443 --token "s3cret"` | `lfa-server.cmd s3cret 8443` |
| `python -m lfa analyse bundle.tar.gz --case-dir cases/INCIDENT-42 --examiner "Bob"` | `lfa.cmd analyse bundle.tar.gz --case-dir cases\INCIDENT-42 --examiner "Bob"` |
| `python -m lfa verify cases/INCIDENT-42` | `lfa.cmd verify cases\INCIDENT-42` |
| `python -m lfa report cases/INCIDENT-42` | `lfa.cmd report cases\INCIDENT-42` |

`lfa.cmd serve ...` also works verbatim if you want full control over
`--host`, `--cert` and `--key`. The two `.cmd` wrappers only exist to supply
sensible defaults:

- `lfa-dashboard.cmd` → `serve --host 127.0.0.1` (loopback; local case review)
- `lfa-server.cmd <token> [port]` → `serve --host 0.0.0.0 --token <token>`
  (network ingestion; token mandatory)

**Nothing on the Linux side changes.** `collector/collect.sh` is unaffected.

## Transport: HTTP vs HTTPS

`serve` speaks **plain HTTP unless you pass both `--cert` and `--key`**
(`server.py:1087`). No certificate is generated for you, and no certificate
tooling ships in the bundle — a stock Windows box has no `openssl`.

The collector appends `/api/v1/ingest` to whatever `-s` URL you give it, so
`-s http://examiner:8443` becomes `http://examiner:8443/api/v1/ingest`, with
the token sent as `Authorization: Bearer <token>`.

Practical options, in order of preference:

1. **USB tarball** — no network at all. The natural fit for an air-gapped
   examiner box, and the reason this bundle exists.
2. **Plain HTTP on an isolated segment** — acceptable on a dedicated
   incident-response VLAN. The token authenticates; it does not encrypt.
3. **Supply your own cert** — `lfa.cmd serve --host 0.0.0.0 --token <tok>
   --cert cert.pem --key key.pem`, then use `-s https://...` on the collector.

### Security defaults

- **A non-loopback bind requires a token.** `serve` refuses to start on any
  interface other than `127.0.0.1`/`::1` unless `--token` is set, so a bare
  `lfa serve` can never expose cases unauthenticated on the network. The
  loopback dashboard (`lfa-dashboard.cmd`) needs no token; `lfa-server.cmd`
  always supplies one.
- **Streamed bundles are size-capped** at 8 GiB by default; a larger upload is
  rejected with HTTP 413 before it touches disk. Raise it for a genuinely
  large journald bundle with `lfa.cmd serve … --max-ingest-gb <N>`.
- **File serving is confined to the cases directory.** Report/artifact requests
  are resolved and containment-checked, so neither a `..` path nor an absolute
  path (`C:\…`, `/etc/…`) can read outside the case tree.

## Verifying a build

Determinism is the real acceptance test. The portable build (Python 3.13.7)
and a dev checkout (Python 3.14.5) must produce **byte-identical** canonical
exports from the same bundle:

```bash
# portable
dist/LFA-Portable/lfa.cmd analyse --case-dir /tmp/a --case-id X bundle.tar.gz
# dev
cd analyzer && python -m lfa analyse --case-dir /tmp/b --case-id X bundle.tar.gz

sha256sum /tmp/a/exports/events.json /tmp/b/exports/events.json  # must match
```

Confirmed against `cases/CASE-CHAINED_ATTACKS/bundle.tar.gz` (real
Metasploitable evidence): 180 events, 1 finding, JSON SHA-256
`f93cdd7f403f94e3…` from both.

---

## Shipping it

Transfer `dist/LFA-Portable.zip` (~12 MB) by USB or approved file transfer.
On the examiner workstation:

1. Extract anywhere — local disk, USB, network share. No install step.
2. Run `verify-install.cmd`. Expect `OK - portable LFA is functional.`
3. Check `SHA256SUMS` against the build host if tool integrity is in scope.

Nothing is written outside the bundle folder and the case directories the
examiner names.

---

## Why not a container?

Docker Desktop on Windows needs a ~650 MB installer, WSL2 or Hyper-V,
hardware virtualisation, an admin install and a reboot — usually not
permitted on a locked-down forensic workstation. The image itself would be
~50 MB gzipped, but you must ship the engine too, putting the real total near
700 MB versus 12 MB here.

Containers earn their cost when dependency isolation is hard. This analyzer
has three pure-Python-resolvable dependencies and no system libraries, so
there is nothing to isolate. Containerisation is still the right tool for
`testlab/` (spinning up Linux targets to generate evidence) — that is a
development concern, not a deployment one.

---

## Changing the pinned Python

Edit `PY_VERSION` and `PY_ABI_TAG` together at the top of
`packaging/build_portable.py`, then re-run the `vendor` stage. The two must
agree (`3.13.7` ↔ `313`) or the wheel ABI tags will not match the runtime.

The analyzer declares `requires-python = ">=3.11"` and is verified on 3.13
and 3.14.

## Known limitations

- **x64 only.** ARM64 Windows needs a second bundle built from the
  `arm64` embeddable distribution.
- **`lfa remote` is unavailable.** It shells out to `ssh` and needs
  `collector/collect.sh`, neither of which ships here. Collect on the Linux
  host and bring the `.tar.gz` bundle to the examiner workstation.
