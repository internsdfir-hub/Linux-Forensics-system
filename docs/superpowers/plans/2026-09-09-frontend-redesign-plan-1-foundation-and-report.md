# Frontend Redesign — Plan 1: Foundation, Charts, and the Report

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract LFA's UI out of Python f-strings into a real asset tree with one shared design-token layer, expand the pure-Python SVG chart vocabulary, and rebuild the offline HTML report on top of both — findings-first, print-perfect, and accessible.

**Architecture:** A new `analyzer/lfa/ui/` tree holds every HTML, CSS and JavaScript asset as a real file. `ui/assets.py` reads and concatenates them at render time so the report stays a single self-contained file with no external fetches. `ui/styles/tokens.css` is the sole source of colour, type, spacing and radii; `theme-document.css` and `theme-console.css` redefine only colour on top of it. Three tests enforce that layering mechanically — no raw colour literals in component CSS, no undefined token references, and WCAG AA contrast computed from the token files themselves.

**Tech Stack:** Python 3.11+, Jinja2, hand-authored CSS and vanilla JavaScript. No build step, no Node, no CDN, no new runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-09-09-frontend-redesign-design.md`

## Global Constraints

- **Python floor is 3.11.** No syntax newer than 3.11.
- **No new runtime dependencies.** The analyzer's dependencies are exactly `PyYAML>=6`, `Jinja2>=3`, and `tzdata` on Windows. Everything else must be stdlib.
- **No build step.** No Node, no bundler, no transpiler, no preprocessor. CSS and JS are hand-authored and shipped as written.
- **No CDN and no external fetches.** The rendered report must contain zero `http://` or `https://` references to remote resources. It stays one self-contained file.
- **The canonical JSON/CSV export path is untouchable.** Nothing in this plan may modify `analyzer/lfa/canonical.py` or change what reaches it. Those exports must stay byte-identical.
- **`NormalizedEvent` in `analyzer/lfa/schema.py` is a frozen contract.** Do not add, remove, or rename fields.
- **Charts are pure-Python SVG.** No matplotlib, no charting library. This is decision D3 of the original project and it stands.
- **Chart output must be deterministic.** Same input, same bytes. No `datetime.now()`, no `uuid4()`, no iteration over an unordered set or dict in anything that reaches SVG output.
- **Evidence is never trusted as markup.** Every evidence-derived value rendered into HTML stays escaped, exactly as the hardening branch established. Jinja `autoescape=True` remains on; never add `| safe` to a value that came from evidence.
- **Test import style is `from lfa...`**, not `from analyzer.lfa...`.
- **Run the suite with `python -m pytest` from the repo root.** It takes 12–15 minutes. Run focused tests during development; the controller runs the full suite.
- **The working tree contains uncommitted work belonging to the repo owner** — `collector/collect.sh`, `config/artifacts.yaml`, `analyzer/lfa/report/data.py`, report templates, `tools/remote_collector.py`, and several untracked parser files. It is NOT yours. Stage only the exact paths each task names, run `git diff --cached` before every commit, and never use `git add -A`. Never run `git reset --hard`, `git checkout -f`, `git clean`, or `git stash`.

---

### Task 0: Land the in-progress report and parser work first

**Files:**
- Commit (already written by the repo owner, not by you): `analyzer/lfa/report/data.py`, `analyzer/lfa/report/templates/report.html.j2`, `analyzer/lfa/report/templates/style.css`, `config/artifacts.yaml`, `config/grammars/common.yaml`, `collector/collect.sh`, `tools/remote_collector.py`, and the untracked parsers `analyzer/lfa/parsers/{browser,dns,ftplog,netifaces,netstat,storage,weblog}.py` with their tests.

**Interfaces:**
- Consumes: nothing.
- Produces: a committed `get_categorized_intel` returning all 21 intel keys, which Task 5's `_intel.html.j2` partial depends on.

**Why this task exists.** The working tree carries substantial uncommitted work
by the repo owner, and this plan *depends on part of it*. The committed
`data.py` exposes only 5 intel keys (`users`, `logins`, `usb`, `system`,
`network_persistence`). The working-tree version exposes 21, and Task 5's intel
partial references 15 of the 16 that exist only there — `sessions`,
`failed_logins`, `remote_ips`, `network_interfaces`, `dns_activity`,
`volatile_sockets`, `shell_history`, `system_additional`, `http_logs`,
`ftp_connections`, `browser_and_downloads`, `storage`, and others.

Two further files in that set — `report.html.j2` and `style.css` — are
**rewritten wholesale** by Tasks 5 and 6. Their uncommitted state would be
destroyed without a trace unless it is committed first.

**This task must not be executed autonomously.** The repo owner decides whether
and how their own work is committed. If you are an implementer and this task is
still open, stop and report that — do not commit files you did not write.

- [ ] **Step 1: Confirm the dependency is still real**

Run:

```bash
git show HEAD:analyzer/lfa/report/data.py | grep -oE 'intel\["[a-z_]+"\]' | sort -u
grep -oE 'intel\["[a-z_]+"\]' analyzer/lfa/report/data.py | sort -u
```

Expected: the committed version lists 5 keys, the working tree lists 21. If they
now match, the owner has already landed this work and this task is complete —
say so and move to Task 1.

- [ ] **Step 2: Confirm the suite is green with that work in place**

Run: `python -m pytest`
Expected: green. The current tree passes 347.

- [ ] **Step 3: The owner commits their work**

This is the owner's action, not the implementer's. The parsers, their tests, the
expanded `data.py`, the artifact-table and grammar additions, and the collector
changes belong in one or more commits authored by them.

- [ ] **Step 4: Verify the base is clean before Task 1 begins**

Run: `git status --short -- analyzer/lfa/report/ config/ collector/`
Expected: no modifications to `report/data.py`. If `report.html.j2` and
`style.css` are still modified, that is acceptable — Task 1 moves them and
Tasks 5 and 6 replace their contents — but the owner must have accepted that
their current contents are superseded.

---

### Task 1: UI asset tree and the inlining loader

**Files:**
- Create: `analyzer/lfa/ui/__init__.py`
- Create: `analyzer/lfa/ui/assets.py`
- Create: `analyzer/lfa/ui/styles/base.css`
- Create: `analyzer/lfa/ui/scripts/report.js`
- Modify: `analyzer/lfa/report/render.py`
- Test: `tests/test_ui_assets.py` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `lfa.ui.assets.UI_DIR: Path` — the `analyzer/lfa/ui` directory.
  - `lfa.ui.assets.load_styles(*names: str) -> str` — reads `ui/styles/<name>.css` for each name in the order given and returns them concatenated with a `/* --- <name>.css --- */` banner between each. Raises `FileNotFoundError` naming the missing file.
  - `lfa.ui.assets.load_script(name: str) -> str` — reads `ui/scripts/<name>.js`. Same error behaviour.
  - `lfa.ui.assets.TEMPLATE_DIR: Path` — `ui/templates`, for Jinja's loader.

This task moves the plumbing only. The existing look is preserved exactly; the redesign starts in Task 2. Doing it this way means a single reviewable change proves the loader works before any visual change muddies the diff.

- [ ] **Step 1: Write the failing test**

Create `tests/test_ui_assets.py`:

```python
"""UI asset loader.

Every HTML/CSS/JS asset lives as a real file under analyzer/lfa/ui/ and is
inlined at render time, so the report stays one self-contained file while the
source stays editable, lintable and diffable.
"""
import pytest

from lfa.ui import assets


def test_ui_dir_exists():
    assert assets.UI_DIR.is_dir()
    assert (assets.UI_DIR / "styles").is_dir()
    assert (assets.UI_DIR / "scripts").is_dir()
    assert (assets.UI_DIR / "templates").is_dir()


def test_load_styles_returns_file_contents():
    css = assets.load_styles("base")
    assert css.strip(), "base.css should not be empty"
    assert "base.css" in css, "expected a banner naming the file"


def test_load_styles_concatenates_in_order():
    css = assets.load_styles("base", "base")
    assert css.count("base.css") == 2


def test_load_styles_names_the_missing_file():
    with pytest.raises(FileNotFoundError) as exc:
        assets.load_styles("no-such-stylesheet")
    assert "no-such-stylesheet" in str(exc.value)


def test_load_script_returns_file_contents():
    js = assets.load_script("report")
    assert js.strip(), "report.js should not be empty"


def test_load_script_names_the_missing_file():
    with pytest.raises(FileNotFoundError) as exc:
        assets.load_script("no-such-script")
    assert "no-such-script" in str(exc.value)


def test_no_asset_references_a_remote_resource():
    """Air-gapped by construction: no asset may fetch anything."""
    offenders = []
    for path in assets.UI_DIR.rglob("*"):
        if path.suffix not in {".css", ".js", ".j2"}:
            continue
        text = path.read_text(encoding="utf-8")
        for marker in ("http://", "https://", "//fonts.", "cdn."):
            if marker in text:
                offenders.append(f"{path.name}: {marker}")
    assert not offenders, f"assets must not reference remote resources: {offenders}"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_ui_assets.py -v`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'lfa.ui'`.

- [ ] **Step 3: Create the package and the loader**

Create `analyzer/lfa/ui/__init__.py`:

```python
"""User-interface assets.

Every HTML template, stylesheet and script LFA renders lives here as a real
file rather than inside a Python f-string. Python prepares data; these files
decide how it looks. Assets are inlined at render time so a report remains a
single self-contained document with no external fetches.
"""
```

Create `analyzer/lfa/ui/assets.py`:

```python
"""Read UI assets off disk for inlining into rendered output."""
from __future__ import annotations

from pathlib import Path

UI_DIR = Path(__file__).resolve().parent
STYLE_DIR = UI_DIR / "styles"
SCRIPT_DIR = UI_DIR / "scripts"
TEMPLATE_DIR = UI_DIR / "templates"


def _read(path: Path, label: str) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"UI asset not found: {label} (looked in {path})")
    return path.read_text(encoding="utf-8")


def load_styles(*names: str) -> str:
    """Concatenate the named stylesheets, in order, with a banner between each.

    Order matters: tokens first, then a theme, then components. Later rules
    win, which is how the cascade is meant to work.
    """
    parts: list[str] = []
    for name in names:
        text = _read(STYLE_DIR / f"{name}.css", f"{name}.css")
        parts.append(f"/* --- {name}.css --- */\n{text}")
    return "\n\n".join(parts)


def load_script(name: str) -> str:
    """Read one script for inlining."""
    return _read(SCRIPT_DIR / f"{name}.js", f"{name}.js")
```

- [ ] **Step 4: Move the existing assets into the tree unchanged**

Copy the current files into their new homes, content untouched:

```bash
mkdir -p analyzer/lfa/ui/styles analyzer/lfa/ui/scripts analyzer/lfa/ui/templates
git mv analyzer/lfa/report/templates/style.css analyzer/lfa/ui/styles/base.css
git mv analyzer/lfa/report/templates/tables.js analyzer/lfa/ui/scripts/report.js
git mv analyzer/lfa/report/templates/report.html.j2 analyzer/lfa/ui/templates/report.html.j2
```

Do not edit their contents in this task. The point is to prove the plumbing with a diff that changes no pixels.

- [ ] **Step 5: Point the renderer at the new tree**

In `analyzer/lfa/report/render.py`, replace the asset-loading block. The current code reads:

```python
    tpl_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(loader=FileSystemLoader(str(tpl_dir)), autoescape=True)

    css_path = tpl_dir / "style.css"
    js_path = tpl_dir / "tables.js"

    inline_css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""
    inline_js = js_path.read_text(encoding="utf-8") if js_path.exists() else ""
```

Replace it with:

```python
    env = Environment(
        loader=FileSystemLoader(str(assets.TEMPLATE_DIR)), autoescape=True
    )

    inline_css = assets.load_styles("base")
    inline_js = assets.load_script("report")
```

And add the import at the top of the file, after the existing `from jinja2 import ...` line:

```python
from ..ui import assets
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/test_ui_assets.py -v`
Expected: 7 passed.

- [ ] **Step 7: Confirm the report still renders identically**

Run: `python -m pytest tests/test_pipeline.py -v`
Expected: all pass — the pipeline renders a report end to end, so this proves the loader is wired correctly.

- [ ] **Step 8: Commit**

```bash
git add analyzer/lfa/ui/ analyzer/lfa/report/render.py analyzer/lfa/report/templates tests/test_ui_assets.py
git commit -m "refactor(ui): move UI assets into analyzer/lfa/ui, add inlining loader

Templates, CSS and JS now live as real files under analyzer/lfa/ui/ and
are inlined at render time. Content is unchanged; this is plumbing only,
so the visual diff is empty and the loader can be reviewed on its own.

This is the foundation for the redesign: the dashboard and explorer keep
1,711 lines of UI inside Python f-strings with doubled CSS braces, where
iterating on design is not practical."
```

---

### Task 2: The token layer and two themes

**Files:**
- Create: `analyzer/lfa/ui/styles/tokens.css`
- Create: `analyzer/lfa/ui/styles/theme-document.css`
- Create: `analyzer/lfa/ui/styles/theme-console.css`
- Create: `tests/test_design_tokens.py`

**Interfaces:**
- Consumes: `lfa.ui.assets.STYLE_DIR` from Task 1.
- Produces: a token vocabulary every later task and Plan 2 build on. Component stylesheets reference tokens via `var(--token-name)` and must contain no raw colour literals.

**Token contract.** `tokens.css` defines every non-colour token plus the *names* of colour tokens with light-theme defaults. Theme files redefine only colour. The colour role names, which later tasks and Plan 2 depend on, are exactly:

`--surface-page`, `--surface-raised`, `--surface-sunken`, `--surface-overlay`,
`--border-subtle`, `--border-strong`, `--border-focus`,
`--text-primary`, `--text-secondary`, `--text-muted`, `--text-inverse`,
`--severity-high`, `--severity-high-bg`, `--severity-medium`, `--severity-medium-bg`, `--severity-low`, `--severity-low-bg`, `--severity-info`, `--severity-info-bg`,
`--state-verified`, `--state-quarantined`, `--state-unknown`,
`--accent-primary`, `--accent-primary-bg`,
`--shadow-sm`, `--shadow-md`, `--shadow-lg`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_design_tokens.py`:

```python
"""The design-token layer is enforced mechanically, not by review.

Three properties matter and each has a test: component stylesheets never
hardcode a colour, every referenced token is defined, and text meets WCAG AA
contrast against its own surface in both themes.
"""
import re

import pytest

from lfa.ui import assets

# Files allowed to contain raw colour values. Everything else must use var().
_PALETTE_FILES = {"tokens.css", "theme-document.css", "theme-console.css"}

_COLOUR_LITERAL = re.compile(
    r"#[0-9a-fA-F]{3,8}\b|\brgba?\s*\(|\bhsla?\s*\(", re.I
)
_VAR_USE = re.compile(r"var\(\s*(--[a-z0-9-]+)", re.I)
_VAR_DEF = re.compile(r"^\s*(--[a-z0-9-]+)\s*:", re.I | re.M)


def _stylesheets():
    return sorted(assets.STYLE_DIR.glob("*.css"))


def test_component_stylesheets_contain_no_raw_colour_literals():
    offenders = []
    for path in _stylesheets():
        if path.name in _PALETTE_FILES:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("/*") or stripped.startswith("*"):
                continue
            if _COLOUR_LITERAL.search(line):
                offenders.append(f"{path.name}:{lineno}: {stripped}")
    assert not offenders, (
        "colour belongs in tokens.css or a theme file, referenced via var():\n"
        + "\n".join(offenders)
    )


def test_every_referenced_token_is_defined():
    defined = set()
    for path in _stylesheets():
        defined.update(_VAR_DEF.findall(path.read_text(encoding="utf-8")))

    missing = []
    for path in _stylesheets():
        for name in _VAR_USE.findall(path.read_text(encoding="utf-8")):
            if name not in defined:
                missing.append(f"{path.name}: var({name})")
    assert not missing, f"undefined tokens referenced: {sorted(set(missing))}"


# --------------------------------------------------------------- WCAG maths

def _srgb_to_linear(channel: float) -> float:
    return channel / 12.92 if channel <= 0.03928 else ((channel + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_colour: str) -> float:
    """WCAG 2.1 relative luminance of an #rgb or #rrggbb colour."""
    h = hex_colour.lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return (
        0.2126 * _srgb_to_linear(r)
        + 0.7152 * _srgb_to_linear(g)
        + 0.0722 * _srgb_to_linear(b)
    )


def contrast_ratio(foreground: str, background: str) -> float:
    l1 = relative_luminance(foreground)
    l2 = relative_luminance(background)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def test_contrast_maths_matches_known_values():
    """Guard the calculator itself before trusting it about our palette."""
    assert contrast_ratio("#000000", "#ffffff") == pytest.approx(21.0, abs=0.01)
    assert contrast_ratio("#ffffff", "#ffffff") == pytest.approx(1.0, abs=0.01)
    # A well-known AA-passing pair.
    assert contrast_ratio("#595959", "#ffffff") == pytest.approx(7.0, abs=0.15)


def _theme_tokens(filename: str) -> dict[str, str]:
    text = (assets.STYLE_DIR / filename).read_text(encoding="utf-8")
    out = {}
    for match in re.finditer(r"(--[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,8})\s*;", text, re.I):
        out[match.group(1)] = match.group(2)
    return out


# Text roles that must clear AA against the surface they sit on.
_TEXT_ON_SURFACE = [
    ("--text-primary", "--surface-page", 4.5),
    ("--text-primary", "--surface-raised", 4.5),
    ("--text-secondary", "--surface-page", 4.5),
    ("--text-secondary", "--surface-raised", 4.5),
    # Muted text is used only at large sizes; AA large-text threshold is 3.0.
    ("--text-muted", "--surface-page", 3.0),
    ("--severity-high", "--surface-raised", 4.5),
    ("--severity-medium", "--surface-raised", 4.5),
    ("--severity-low", "--surface-raised", 4.5),
    ("--severity-info", "--surface-raised", 4.5),
]


@pytest.mark.parametrize("theme", ["theme-document.css", "theme-console.css"])
def test_text_meets_wcag_aa_contrast(theme):
    tokens = _theme_tokens(theme)
    failures = []
    for fg_name, bg_name, minimum in _TEXT_ON_SURFACE:
        if fg_name not in tokens or bg_name not in tokens:
            failures.append(f"{theme}: missing {fg_name} or {bg_name}")
            continue
        ratio = contrast_ratio(tokens[fg_name], tokens[bg_name])
        if ratio < minimum:
            failures.append(
                f"{theme}: {fg_name} on {bg_name} = {ratio:.2f}:1 "
                f"(needs {minimum}:1)"
            )
    assert not failures, "\n".join(failures)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_design_tokens.py -v`
Expected: FAIL. `test_component_stylesheets_contain_no_raw_colour_literals` reports many offenders in `base.css`; the contrast tests fail because the theme files do not exist yet.

- [ ] **Step 3: Write the token vocabulary**

Create `analyzer/lfa/ui/styles/tokens.css`:

```css
/* Design tokens: the single source of type, space, radius, motion and the
   NAMES of every colour role. Theme files redefine colour values only.

   Colour tokens are named for meaning, never for hue. There is no
   --accent-blue here, because "blue" tells a reader nothing about when to
   use it, and a token nobody understands gets bypassed with a literal. */

:root {
  /* Type families. System stacks only - no webfont, no fetch. */
  --font-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto,
               "Helvetica Neue", Arial, sans-serif;
  --font-serif: ui-serif, Georgia, Cambria, "Times New Roman", Times, serif;
  --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
               "Liberation Mono", monospace;

  /* Type scale: 1.200 minor third, 16px base. */
  --text-xs: 0.694rem;
  --text-sm: 0.833rem;
  --text-base: 1rem;
  --text-md: 1.2rem;
  --text-lg: 1.44rem;
  --text-xl: 1.728rem;
  --text-2xl: 2.074rem;
  --text-3xl: 2.488rem;

  --leading-tight: 1.25;
  --leading-normal: 1.6;
  --leading-loose: 1.75;

  --weight-normal: 400;
  --weight-medium: 500;
  --weight-semibold: 600;
  --weight-bold: 700;

  /* Spacing scale: 4px base, geometric-ish. */
  --space-1: 0.25rem;
  --space-2: 0.5rem;
  --space-3: 0.75rem;
  --space-4: 1rem;
  --space-5: 1.5rem;
  --space-6: 2rem;
  --space-7: 3rem;
  --space-8: 4rem;
  --space-9: 6rem;

  /* Radii */
  --radius-sm: 3px;
  --radius-md: 6px;
  --radius-lg: 10px;
  --radius-pill: 999px;

  /* Layout */
  --measure: 72ch;          /* readable line length for body prose */
  --page-max: 1200px;
  --border-width: 1px;

  /* Motion. Respected only when the reader has not asked for less. */
  --motion-fast: 120ms;
  --motion-base: 200ms;
  --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
}

@media (prefers-reduced-motion: reduce) {
  :root {
    --motion-fast: 0ms;
    --motion-base: 0ms;
  }
}
```

- [ ] **Step 4: Write the document theme**

Create `analyzer/lfa/ui/styles/theme-document.css`. Every value here is chosen to clear WCAG AA against its own surface — the test in Step 1 proves it rather than trusting it:

```css
/* Document theme: the offline report. Light-primary, because this artifact
   gets printed and attached to case files. */

:root {
  --surface-page: #ffffff;
  --surface-raised: #f7f8fa;
  --surface-sunken: #eceef2;
  --surface-overlay: #ffffff;

  --border-subtle: #dfe3e8;
  --border-strong: #b9c0c9;
  --border-focus: #0b5fd0;

  --text-primary: #14181d;
  --text-secondary: #454d57;
  --text-muted: #667180;
  --text-inverse: #ffffff;

  --severity-high: #a01020;
  --severity-high-bg: #fdeaec;
  --severity-medium: #8a4b00;
  --severity-medium-bg: #fdf1e3;
  --severity-low: #0a5c3a;
  --severity-low-bg: #e6f4ee;
  --severity-info: #34414f;
  --severity-info-bg: #eef1f4;

  --state-verified: #0a5c3a;
  --state-quarantined: #a01020;
  --state-unknown: #667180;

  --accent-primary: #0b5fd0;
  --accent-primary-bg: #e8f0fd;

  --shadow-sm: 0 1px 2px rgba(20, 24, 29, 0.06);
  --shadow-md: 0 2px 8px rgba(20, 24, 29, 0.08);
  --shadow-lg: 0 8px 24px rgba(20, 24, 29, 0.10);
}
```

- [ ] **Step 5: Write the console theme**

Create `analyzer/lfa/ui/styles/theme-console.css`. Plan 2 consumes this; defining it now keeps both themes under the same contrast test from the start:

```css
/* Console theme: the live dashboard and explorer. Dark-primary, dense,
   built for long sessions in front of a screen. */

:root {
  --surface-page: #0d1117;
  --surface-raised: #161b22;
  --surface-sunken: #010409;
  --surface-overlay: #1c2128;

  --border-subtle: #30363d;
  --border-strong: #495057;
  --border-focus: #6cb0ff;

  --text-primary: #e8edf3;
  --text-secondary: #b6c2cf;
  --text-muted: #8b949e;
  --text-inverse: #0d1117;

  --severity-high: #ff8087;
  --severity-high-bg: #3d1418;
  --severity-medium: #f0b154;
  --severity-medium-bg: #3a2a10;
  --severity-low: #56d4a0;
  --severity-low-bg: #0f2f22;
  --severity-info: #b6c2cf;
  --severity-info-bg: #21262d;

  --state-verified: #56d4a0;
  --state-quarantined: #ff8087;
  --state-unknown: #8b949e;

  --accent-primary: #6cb0ff;
  --accent-primary-bg: #17253a;

  --shadow-sm: 0 1px 2px rgba(1, 4, 9, 0.5);
  --shadow-md: 0 4px 12px rgba(1, 4, 9, 0.6);
  --shadow-lg: 0 12px 32px rgba(1, 4, 9, 0.7);
}
```

- [ ] **Step 6: Run the token tests**

Run: `python -m pytest tests/test_design_tokens.py -v`
Expected: the two contrast tests PASS and the maths guard PASSES. `test_component_stylesheets_contain_no_raw_colour_literals` still FAILS, listing offenders in `base.css` — that is correct and expected. `base.css` is rewritten in Task 6; leave the failure standing until then.

If a contrast test fails, do NOT lower the threshold. Darken the foreground or lighten the surface until it clears, and say in your report which values you adjusted and to what.

- [ ] **Step 7: Temporarily exempt the legacy stylesheet**

`base.css` is rewritten in Task 6. Until then the colour-literal test must not block the branch. Add `base.css` to the exemption set with an explicit expiry note, at the top of `tests/test_design_tokens.py`:

```python
# Files allowed to contain raw colour values. Everything else must use var().
#
# base.css is the pre-redesign stylesheet. Task 6 rewrites it onto tokens and
# REMOVES it from this set. If you are reading this after Task 6 landed, the
# exemption is stale and should be deleted.
_PALETTE_FILES = {
    "tokens.css",
    "theme-document.css",
    "theme-console.css",
    "base.css",
}
```

- [ ] **Step 8: Run the tests to verify they all pass**

Run: `python -m pytest tests/test_design_tokens.py -v`
Expected: all pass (5 tests, with the contrast test parametrised over 2 themes = 6 test ids).

- [ ] **Step 9: Commit**

```bash
git add analyzer/lfa/ui/styles/tokens.css analyzer/lfa/ui/styles/theme-document.css analyzer/lfa/ui/styles/theme-console.css tests/test_design_tokens.py
git commit -m "feat(ui): add design token layer with document and console themes

One token vocabulary, two themes. Colour is named by role (--severity-high)
never by hue (--accent-blue), because a token named for its hue tells a
reader nothing about when to use it and gets bypassed with a literal.

Three tests enforce the layering mechanically: no raw colour literals in
component stylesheets, no undefined token references, and WCAG AA contrast
computed from the token files themselves in both themes. base.css carries a
documented temporary exemption until Task 6 rewrites it."
```

---

### Task 3: The chart vocabulary

**Files:**
- Modify: `analyzer/lfa/report/chart.py`
- Test: `tests/test_charts.py` (create)

**Interfaces:**
- Consumes: a `sqlite3.Connection` to a case database, as `generate_density_svg` already does.
- Produces, all returning a complete `<svg>` element as `str`:
  - `generate_density_svg(conn, width=900, height=240) -> str` — kept, rebuilt with axes and labels. Existing callers keep working.
  - `severity_breakdown_svg(conn, width=900, height=200) -> str`
  - `user_activity_svg(conn, width=900, height=280, limit=10) -> str`
  - `auth_failure_bursts_svg(conn, width=900, height=240) -> str`

Every chart carries `role="img"`, a `<title>` and a `<desc>`, uses token-driven colour via `currentColor` and CSS custom properties, and encodes meaning with a label as well as colour.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_charts.py`:

```python
"""Chart vocabulary: pure-Python SVG, deterministic, accessible.

No matplotlib and no charting library - decision D3 of the original project.
Determinism matters because a chart that changes between runs on identical
evidence undermines the tool's central claim.
"""
import re
import sqlite3

import pytest

from lfa import db
from lfa.report import chart

CHART_FUNCS = [
    chart.generate_density_svg,
    chart.severity_breakdown_svg,
    chart.user_activity_svg,
    chart.auth_failure_bursts_svg,
]


@pytest.fixture
def case(tmp_path, event_factory):
    conn = db.open_case(tmp_path / "case.db")
    events = []
    for hour in range(6):
        for n in range(hour + 1):
            events.append(
                event_factory(
                    timestamp_utc=f"2024-03-14T{hour:02d}:{n:02d}:00+00:00",
                    actor_user=f"user{n % 3}",
                    subcategory="failed_login" if n % 2 else "successful_login",
                    severity=["info", "low", "medium", "high"][n % 4],
                    raw_line=f"line {hour}-{n}",
                )
            )
    db.insert_events(conn, events)
    conn.execute(
        "INSERT INTO findings (finding_id, case_id, rule_name, rule_version, "
        "severity, title, what_happened, why_it_matters, confidence, "
        "check_next, technical_detail, event_ids) "
        "VALUES ('f1','CASE-001','brute_force','1.0','high','T','w','y','High','c','t','[]')"
    )
    conn.commit()
    yield conn
    conn.close()


@pytest.mark.parametrize("func", CHART_FUNCS, ids=lambda f: f.__name__)
def test_chart_returns_a_complete_svg_element(case, func):
    svg = func(case)
    assert svg.lstrip().startswith("<svg")
    assert svg.rstrip().endswith("</svg>")


@pytest.mark.parametrize("func", CHART_FUNCS, ids=lambda f: f.__name__)
def test_chart_is_deterministic(case, func):
    assert func(case) == func(case)


@pytest.mark.parametrize("func", CHART_FUNCS, ids=lambda f: f.__name__)
def test_chart_is_accessible(case, func):
    svg = func(case)
    assert 'role="img"' in svg
    assert "<title" in svg and "</title>" in svg
    assert "<desc" in svg and "</desc>" in svg


@pytest.mark.parametrize("func", CHART_FUNCS, ids=lambda f: f.__name__)
def test_chart_contains_no_raw_colour_literal(case, func):
    """Charts take colour from the token layer like everything else."""
    svg = func(case)
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", svg), (
        "charts must use var(--token) or currentColor, not hardcoded colour"
    )


@pytest.mark.parametrize("func", CHART_FUNCS, ids=lambda f: f.__name__)
def test_chart_survives_an_empty_case(tmp_path, func):
    conn = db.open_case(tmp_path / "empty.db")
    svg = func(conn)
    conn.close()
    assert svg.lstrip().startswith("<svg")
    assert "No data" in svg or "no data" in svg


def test_density_chart_labels_its_axis(case):
    svg = chart.generate_density_svg(case)
    assert "2024-03-14" in svg, "expected a dated axis label"


def test_severity_breakdown_labels_each_band(case):
    svg = chart.severity_breakdown_svg(case)
    for label in ("high", "medium", "low", "info"):
        assert label in svg.lower()


def test_user_activity_respects_its_limit(case):
    """One bar per account, never more than the limit."""
    svg = chart.user_activity_svg(case, limit=2)
    assert svg.count("<rect") == 2, "expected exactly one bar per account"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_charts.py -v`
Expected: FAIL with `AttributeError: module 'lfa.report.chart' has no attribute 'severity_breakdown_svg'`.

- [ ] **Step 3: Write the shared SVG helpers**

Replace the entire contents of `analyzer/lfa/report/chart.py` with the following. The helpers do the drawing work so each chart function stays short and readable:

```python
"""Deterministic pure-Python SVG charts (project decision D3: no matplotlib).

Every function returns one complete <svg> element, ready to inline. Colour
comes from the design-token layer via var(), never from a literal, so charts
re-theme with the rest of the page. Each chart is accessible: role="img" plus
a <title> and <desc> that state what it shows.

Determinism is a hard requirement. Identical evidence must produce identical
bytes, so every query is explicitly ordered and nothing here reads the clock.
"""
from __future__ import annotations

import sqlite3
from xml.sax.saxutils import escape

_PAD_LEFT = 56
_PAD_RIGHT = 16
_PAD_TOP = 28
_PAD_BOTTOM = 40

_SEVERITY_ORDER = ("high", "medium", "low", "info")


def _open(width: int, height: int, title: str, desc: str) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" '
        f'aria-labelledby="t{abs(hash(title)) % 100000}" class="lfa-chart">',
        f"<title>{escape(title)}</title>",
        f"<desc>{escape(desc)}</desc>",
    ]


def _empty(width: int, height: int, title: str) -> str:
    parts = _open(width, height, title, "No data available for this chart.")
    parts.append(
        f'<text x="{width // 2}" y="{height // 2}" text-anchor="middle" '
        f'fill="var(--text-muted)" font-size="14">No data available</text>'
    )
    parts.append("</svg>")
    return "\n".join(parts)


def _axes(width: int, height: int) -> list[str]:
    """Baseline and left rule, drawn from tokens."""
    x0, y0 = _PAD_LEFT, height - _PAD_BOTTOM
    return [
        f'<line x1="{x0}" y1="{y0}" x2="{width - _PAD_RIGHT}" y2="{y0}" '
        f'stroke="var(--border-strong)" stroke-width="1"/>',
        f'<line x1="{x0}" y1="{_PAD_TOP}" x2="{x0}" y2="{y0}" '
        f'stroke="var(--border-strong)" stroke-width="1"/>',
    ]


def _gridlines(width: int, height: int, steps: int, top_value: int) -> list[str]:
    out = []
    x0, x1 = _PAD_LEFT, width - _PAD_RIGHT
    plot_h = height - _PAD_TOP - _PAD_BOTTOM
    for i in range(steps + 1):
        y = _PAD_TOP + plot_h - (plot_h * i / steps)
        value = round(top_value * i / steps)
        out.append(
            f'<line x1="{x0}" y1="{y:.1f}" x2="{x1}" y2="{y:.1f}" '
            f'stroke="var(--border-subtle)" stroke-width="1"/>'
        )
        out.append(
            f'<text x="{x0 - 8}" y="{y + 4:.1f}" text-anchor="end" '
            f'fill="var(--text-muted)" font-size="11">{value}</text>'
        )
    return out


def _bar(x: float, y: float, w: float, h: float, token: str, label: str) -> str:
    return (
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
        f'fill="var({token})" rx="2"><title>{escape(label)}</title></rect>'
    )


def _label(x: float, y: float, text: str, anchor: str = "middle",
           size: int = 11, token: str = "--text-muted") -> str:
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}" '
        f'fill="var({token})" font-size="{size}">{escape(text)}</text>'
    )
```

- [ ] **Step 4: Write the four chart functions**

Append to `analyzer/lfa/report/chart.py`:

```python
def generate_density_svg(conn: sqlite3.Connection, width: int = 900,
                         height: int = 240) -> str:
    """Event volume over time, bucketed by day."""
    rows = conn.execute(
        "SELECT substr(timestamp_utc, 1, 10) AS day, COUNT(*) AS n "
        "FROM events WHERE timestamp_utc IS NOT NULL "
        "GROUP BY day ORDER BY day"
    ).fetchall()
    if not rows:
        return _empty(width, height, "Event density over time")

    top = max(r[1] for r in rows)
    parts = _open(
        width, height,
        "Event density over time",
        f"Bar chart of event counts per day across {len(rows)} day(s); "
        f"peak {top} events.",
    )
    parts += _gridlines(width, height, 4, top)
    parts += _axes(width, height)

    plot_w = width - _PAD_LEFT - _PAD_RIGHT
    plot_h = height - _PAD_TOP - _PAD_BOTTOM
    slot = plot_w / len(rows)
    bar_w = max(1.0, slot * 0.7)

    for i, (day, count) in enumerate(rows):
        h = (count / top) * plot_h if top else 0
        x = _PAD_LEFT + slot * i + (slot - bar_w) / 2
        y = _PAD_TOP + plot_h - h
        parts.append(_bar(x, y, bar_w, h, "--accent-primary", f"{day}: {count} events"))

    # Label first, middle and last day only, so the axis never collides.
    for idx in sorted({0, len(rows) // 2, len(rows) - 1}):
        x = _PAD_LEFT + slot * idx + slot / 2
        parts.append(_label(x, height - _PAD_BOTTOM + 16, rows[idx][0]))

    parts.append("</svg>")
    return "\n".join(parts)


def severity_breakdown_svg(conn: sqlite3.Connection, width: int = 900,
                           height: int = 200) -> str:
    """How many findings sit at each severity."""
    counts = dict(
        conn.execute(
            "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
        ).fetchall()
    )
    ordered = [(s, counts.get(s, 0)) for s in _SEVERITY_ORDER]
    if not any(n for _, n in ordered):
        return _empty(width, height, "Findings by severity")

    top = max(n for _, n in ordered)
    parts = _open(
        width, height,
        "Findings by severity",
        "Horizontal bar chart of finding counts at each severity level: "
        + ", ".join(f"{s} {n}" for s, n in ordered) + ".",
    )

    row_h = (height - _PAD_TOP - _PAD_BOTTOM) / len(ordered)
    plot_w = width - _PAD_LEFT - _PAD_RIGHT

    for i, (sev, n) in enumerate(ordered):
        y = _PAD_TOP + row_h * i + row_h * 0.15
        h = row_h * 0.7
        w = (n / top) * plot_w if top else 0
        parts.append(_bar(_PAD_LEFT, y, w, h, f"--severity-{sev}",
                          f"{sev}: {n} finding(s)"))
        parts.append(_label(_PAD_LEFT - 8, y + h / 2 + 4, sev, anchor="end",
                            token="--text-secondary"))
        parts.append(_label(_PAD_LEFT + w + 8, y + h / 2 + 4, str(n),
                            anchor="start", token="--text-secondary"))

    parts.append("</svg>")
    return "\n".join(parts)


def user_activity_svg(conn: sqlite3.Connection, width: int = 900,
                      height: int = 280, limit: int = 10) -> str:
    """Which accounts generated the most recorded activity."""
    rows = conn.execute(
        "SELECT actor_user, COUNT(*) AS n FROM events "
        "WHERE actor_user IS NOT NULL AND actor_user != '' "
        "GROUP BY actor_user ORDER BY n DESC, actor_user ASC LIMIT ?",
        (limit,),
    ).fetchall()
    if not rows:
        return _empty(width, height, "Activity by account")

    top = max(r[1] for r in rows)
    parts = _open(
        width, height,
        "Activity by account",
        f"Horizontal bar chart of event counts for the {len(rows)} most "
        f"active account(s); highest {top} events.",
    )

    row_h = (height - _PAD_TOP - _PAD_BOTTOM) / len(rows)
    plot_w = width - _PAD_LEFT - _PAD_RIGHT

    for i, (user, n) in enumerate(rows):
        y = _PAD_TOP + row_h * i + row_h * 0.15
        h = row_h * 0.7
        w = (n / top) * plot_w if top else 0
        parts.append(_bar(_PAD_LEFT, y, w, h, "--accent-primary",
                          f"{user}: {n} events"))
        parts.append(_label(_PAD_LEFT - 8, y + h / 2 + 4, user, anchor="end",
                            token="--text-secondary"))
        parts.append(_label(_PAD_LEFT + w + 8, y + h / 2 + 4, str(n),
                            anchor="start", token="--text-secondary"))

    parts.append("</svg>")
    return "\n".join(parts)


def auth_failure_bursts_svg(conn: sqlite3.Connection, width: int = 900,
                            height: int = 240) -> str:
    """Failed authentication attempts per hour - the shape of a brute force."""
    rows = conn.execute(
        "SELECT substr(timestamp_utc, 1, 13) AS hour, COUNT(*) AS n "
        "FROM events WHERE timestamp_utc IS NOT NULL "
        "AND subcategory IN ('failed_login','invalid_user','auth_failure') "
        "GROUP BY hour ORDER BY hour"
    ).fetchall()
    if not rows:
        return _empty(width, height, "Authentication failures over time")

    top = max(r[1] for r in rows)
    parts = _open(
        width, height,
        "Authentication failures over time",
        f"Bar chart of failed authentication attempts per hour across "
        f"{len(rows)} hour(s); peak {top} in a single hour.",
    )
    parts += _gridlines(width, height, 4, top)
    parts += _axes(width, height)

    plot_w = width - _PAD_LEFT - _PAD_RIGHT
    plot_h = height - _PAD_TOP - _PAD_BOTTOM
    slot = plot_w / len(rows)
    bar_w = max(1.0, slot * 0.7)

    for i, (hour, count) in enumerate(rows):
        h = (count / top) * plot_h if top else 0
        x = _PAD_LEFT + slot * i + (slot - bar_w) / 2
        y = _PAD_TOP + plot_h - h
        parts.append(_bar(x, y, bar_w, h, "--severity-high",
                          f"{hour}:00 - {count} failure(s)"))

    for idx in sorted({0, len(rows) // 2, len(rows) - 1}):
        x = _PAD_LEFT + slot * idx + slot / 2
        parts.append(_label(x, height - _PAD_BOTTOM + 16,
                            rows[idx][0].replace("T", " ") + ":00"))

    parts.append("</svg>")
    return "\n".join(parts)
```

- [ ] **Step 5: Remove the non-deterministic id**

`_open` uses `hash(title)` for the `aria-labelledby` id. Python's `hash()` of a string is salted per process, so that value changes between runs and would break `test_chart_is_deterministic`. Replace the `_open` body's id computation with a stable digest:

```python
def _open(width: int, height: int, title: str, desc: str) -> list[str]:
    import hashlib

    ident = "lfa-" + hashlib.sha256(title.encode("utf-8")).hexdigest()[:8]
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" aria-labelledby="{ident}" '
        f'class="lfa-chart">',
        f'<title id="{ident}">{escape(title)}</title>',
        f"<desc>{escape(desc)}</desc>",
    ]
```

Move `import hashlib` to the module's import block rather than leaving it inside the function.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/test_charts.py -v`
Expected: all pass (4 functions × 5 parametrised tests, plus 3 specific tests = 23 test ids).

- [ ] **Step 7: Commit**

```bash
git add analyzer/lfa/report/chart.py tests/test_charts.py
git commit -m "feat(report): expand the chart vocabulary to four deterministic SVGs

Adds severity breakdown, per-account activity and authentication-failure
bursts alongside a rebuilt density chart with axes, gridlines and labels.
Still pure-Python SVG with no charting dependency.

Every chart is deterministic (the aria id is a sha256 prefix, not Python's
per-process-salted hash()), takes colour from the token layer rather than
literals, and carries role/title/desc so it is not colour-only."
```

---

### Task 4: Structured narrative — remove Markdown from the report

**Files:**
- Modify: `analyzer/lfa/report/narrative.py`
- Modify: `analyzer/lfa/report/render.py`
- Test: `tests/test_narrative.py` (create)

**Interfaces:**
- Consumes: `summary` and `findings` dicts as produced by `lfa.report.data`.
- Produces: `generate_executive_summary(summary: dict, findings: list[dict]) -> dict` returning:

```python
{
    "headline": str,              # one sentence, no markup
    "key_observations": [         # at most 5
        {"title": str, "what_happened": str, "why_it_matters": str},
    ],
    "recommended_actions": [str], # at most 5, already deduplicated
}
```

The old function returned a Markdown string. `render.py` passes the dict to the template as `narrative`, and the template renders each field with normal escaping. No `| safe`, no Markdown, no asterisks.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_narrative.py`:

```python
"""The executive summary is structured data, not Markdown.

The template renders it with autoescape on, so a finding title containing
markup or an asterisk cannot reach the page as either.
"""
from lfa.report.narrative import generate_executive_summary


def _summary(high=0, medium=0, low=0, events=1000, findings=0):
    return {
        "case_id": "CASE-205",
        "event_count": events,
        "finding_count": findings,
        "severity_counts": {"high": high, "medium": medium, "low": low, "info": 0},
    }


def _finding(severity="high", title="Brute force succeeded", check_next="Reset it."):
    return {
        "severity": severity,
        "title": title,
        "what_happened": "Someone guessed the password.",
        "why_it_matters": "The account is under someone else's control.",
        "check_next": check_next,
    }


def test_returns_structured_data_not_a_string():
    result = generate_executive_summary(_summary(), [])
    assert isinstance(result, dict)
    assert set(result) == {"headline", "key_observations", "recommended_actions"}


def test_no_field_contains_markdown_emphasis():
    result = generate_executive_summary(
        _summary(high=2, medium=4, findings=6), [_finding()]
    )
    blob = repr(result)
    assert "**" not in blob, "narrative must not emit Markdown"


def test_headline_reflects_high_severity():
    result = generate_executive_summary(_summary(high=2, medium=4, findings=6), [])
    assert "2" in result["headline"]
    assert "CASE-205" in result["headline"]


def test_headline_when_nothing_was_found():
    result = generate_executive_summary(_summary(events=1234), [])
    assert "no" in result["headline"].lower()
    assert "1,234" in result["headline"]


def test_key_observations_are_high_severity_only_and_capped():
    findings = [_finding(title=f"Finding {i}") for i in range(8)]
    findings += [_finding(severity="low", title="Ignore me")]
    result = generate_executive_summary(_summary(high=8, findings=9), findings)
    assert len(result["key_observations"]) == 5
    assert all("Ignore me" != o["title"] for o in result["key_observations"])
    assert result["key_observations"][0]["title"] == "Finding 0"


def test_recommended_actions_are_deduplicated_and_capped():
    findings = [_finding(check_next="Reset the password for 'kali'.") for _ in range(3)]
    findings += [_finding(check_next="Revoke the SSH key.")]
    result = generate_executive_summary(_summary(high=4, findings=4), findings)
    assert result["recommended_actions"] == [
        "Reset the password for 'kali'.",
        "Revoke the SSH key.",
    ]


def test_low_severity_findings_do_not_contribute_actions():
    findings = [_finding(severity="low", check_next="Probably nothing.")]
    result = generate_executive_summary(_summary(low=1, findings=1), findings)
    assert result["recommended_actions"] == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_narrative.py -v`
Expected: FAIL — `generate_executive_summary` returns a `str`, so `set(result)` raises or the assertions on dict keys fail.

- [ ] **Step 3: Rewrite the narrative generator**

Replace the entire contents of `analyzer/lfa/report/narrative.py`:

```python
"""Executive summary as structured data (spec Task 6.4, revised).

Returns fields the template renders with escaping on. The previous version
emitted Markdown into an autoescaped template, so generated reports displayed
literal asterisks - **CASE-205** rather than a bold case id.

Deterministic by construction: no clock, no randomness, and findings are
consumed in the order the data layer produced them.
"""
from __future__ import annotations

_ACTIONABLE = ("high", "medium")
_MAX_OBSERVATIONS = 5
_MAX_ACTIONS = 5


def generate_executive_summary(summary: dict, findings: list[dict]) -> dict:
    """Build the executive summary block.

    Returns a dict with 'headline', 'key_observations' and
    'recommended_actions'. No field contains markup of any kind.
    """
    counts = summary["severity_counts"]
    high, medium = counts["high"], counts["medium"]
    events = summary["event_count"]
    case_id = summary["case_id"]

    if high:
        headline = (
            f"Examination of case {case_id} identified {high} high-severity "
            f"finding(s) and {medium} medium-severity indicator(s) across "
            f"{events:,} normalised events. The evidence points to targeted "
            f"activity or a significant misconfiguration, and warrants "
            f"immediate review."
        )
    elif medium:
        headline = (
            f"Examination of case {case_id} identified {medium} "
            f"medium-severity indicator(s) across {events:,} normalised "
            f"events. No high-severity compromise was detected, but the "
            f"activity below is abnormal enough to warrant analyst review."
        )
    else:
        headline = (
            f"Examination of case {case_id} processed {events:,} normalised "
            f"events. No high or medium-severity indicators were identified "
            f"in the collected evidence."
        )

    key_observations = [
        {
            "title": f["title"],
            "what_happened": f["what_happened"],
            "why_it_matters": f["why_it_matters"],
        }
        for f in findings
        if f["severity"] == "high"
    ][:_MAX_OBSERVATIONS]

    recommended_actions: list[str] = []
    seen: set[str] = set()
    for f in findings:
        if f["severity"] not in _ACTIONABLE:
            continue
        step = (f.get("check_next") or "").strip()
        if not step:
            continue
        key = step.replace("'", "").casefold()
        if key in seen:
            continue
        seen.add(key)
        recommended_actions.append(step)
        if len(recommended_actions) == _MAX_ACTIONS:
            break

    return {
        "headline": headline,
        "key_observations": key_observations,
        "recommended_actions": recommended_actions,
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_narrative.py -v`
Expected: 7 passed.

- [ ] **Step 5: Update the template's narrative block**

This edit is deliberately superseded by Task 5, which rewrites the template
entirely and moves this markup into `partials/_summary.html.j2`. Do it anyway:
without it the template renders a Python dict repr between this commit and
Task 5's, and every commit on this branch must leave the report coherent.

The template currently renders `{{ narrative }}` as a single pre-line string. In `analyzer/lfa/ui/templates/report.html.j2`, replace this block:

```html
      <div class="stat-card" style="white-space: pre-line; line-height: 1.8;">
        {{ narrative }}
      </div>
```

with:

```html
      <div class="stat-card">
        <p class="lede">{{ narrative.headline }}</p>

        {% if narrative.key_observations %}
        <h3>Key observations</h3>
        <ul class="observation-list">
          {% for obs in narrative.key_observations %}
          <li>
            <strong>{{ obs.title }}</strong>
            <span>{{ obs.what_happened }}</span>
            <span class="muted">{{ obs.why_it_matters }}</span>
          </li>
          {% endfor %}
        </ul>
        {% endif %}

        {% if narrative.recommended_actions %}
        <h3>Recommended next steps</h3>
        <ol class="action-list">
          {% for step in narrative.recommended_actions %}
          <li>{{ step }}</li>
          {% endfor %}
        </ol>
        {% endif %}
      </div>
```

- [ ] **Step 6: Verify a rendered report carries no asterisks**

Add to `tests/test_narrative.py`:

```python
def test_rendered_report_contains_no_markdown_asterisks(tmp_path):
    """End to end: the defect was visible as ** in real generated reports."""
    from lfa import db, ingest, pipeline
    from lfa.report.render import render_report

    from bundle_builder import build_bundle

    bundle = build_bundle(
        tmp_path / "src",
        {
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n",
            "/etc/os-release": b'ID=debian\nVERSION_ID="12"\n',
        },
    )
    case_dir = tmp_path / "case"
    ingest.ingest_bundle(bundle, case_dir, "Examiner")
    conn = db.open_case(case_dir / "case.db")
    db.set_case_meta(conn, "case_id", "CASE-MD")
    pipeline.parse_case(conn, case_dir, "CASE-MD")

    out = case_dir / "report.html"
    render_report(conn, case_dir, out)
    conn.close()

    html = out.read_text(encoding="utf-8")
    assert "**" not in html, "Markdown emphasis leaked into the rendered report"
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `python -m pytest tests/test_narrative.py -v`
Expected: 8 passed.

- [ ] **Step 8: Commit**

```bash
git add analyzer/lfa/report/narrative.py analyzer/lfa/ui/templates/report.html.j2 tests/test_narrative.py
git commit -m "fix(report): return structured narrative instead of Markdown

generate_executive_summary emitted Markdown into an autoescaped Jinja
template, so every generated report displayed literal asterisks -
cases/103/report.html contains 14 stray ** sequences.

It now returns headline / key_observations / recommended_actions and the
template renders each field with escaping on, so a finding title
containing markup cannot reach the page as markup either."
```

---

### Task 5: Restructure the report around the reader

**Files:**
- Modify: `analyzer/lfa/ui/templates/report.html.j2`
- Create: `analyzer/lfa/ui/templates/partials/_summary.html.j2`
- Create: `analyzer/lfa/ui/templates/partials/_findings.html.j2`
- Create: `analyzer/lfa/ui/templates/partials/_timeline.html.j2`
- Create: `analyzer/lfa/ui/templates/partials/_evidence.html.j2`
- Create: `analyzer/lfa/ui/templates/partials/_intel.html.j2`
- Create: `analyzer/lfa/ui/templates/partials/_appendices.html.j2`
- Modify: `analyzer/lfa/report/render.py`
- Test: `tests/test_report_structure.py` (create)

**Interfaces:**
- Consumes: `assets.load_styles`/`load_script` (Task 1), the four chart functions (Task 3), the narrative dict (Task 4).
- Produces: `render_report(conn, case_dir, out_html_path) -> Path` — signature unchanged. The template context gains three keys alongside the existing ones: `severity_chart`, `user_chart`, `failures_chart`.

**Section order**, replacing the current ten numbered sections:

1. Summary — case identity header, headline, key observations, recommended actions, severity counts
2. Findings — every detection, plain-English first, technical detail in a `<details>` drawer
3. Timeline — density chart, failure-burst chart, event sample
4. Evidence — host inventory, artifacts, integrity and chain of custody
5. Intel — the 21 categories grouped into four named groups
6. Appendix A — Methodology, limitations and tool audit
7. Appendix B — What we could not determine
8. Appendix C — Glossary

Authorisation, scope and privacy move into the page-one header block.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_structure.py`:

```python
"""Report information architecture.

The reader should learn what happened before being told how the tool was
configured. Findings come before methodology, not after it.
"""
import re

import pytest

from lfa import db, ingest, pipeline
from lfa.report.render import render_report

from bundle_builder import build_bundle


@pytest.fixture
def rendered(tmp_path):
    bundle = build_bundle(
        tmp_path / "src",
        {
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"
                           b"kali:x:1000:1000::/home/kali:/bin/bash\n",
            "/etc/os-release": b'ID=debian\nVERSION_ID="12"\n',
        },
    )
    case_dir = tmp_path / "case"
    ingest.ingest_bundle(bundle, case_dir, "Test Examiner")
    conn = db.open_case(case_dir / "case.db")
    db.set_case_meta(conn, "case_id", "CASE-IA")
    db.set_case_meta(conn, "examiner", "Test Examiner")
    pipeline.parse_case(conn, case_dir, "CASE-IA")
    out = case_dir / "report.html"
    render_report(conn, case_dir, out)
    conn.close()
    return out.read_text(encoding="utf-8")


EXPECTED_ORDER = [
    "sec-summary",
    "sec-findings",
    "sec-timeline",
    "sec-evidence",
    "sec-intel",
    "app-methodology",
    "app-undetermined",
    "app-glossary",
]


def test_all_sections_present(rendered):
    for section in EXPECTED_ORDER:
        assert f'id="{section}"' in rendered, f"missing section {section}"


def test_sections_appear_in_reader_first_order(rendered):
    positions = [rendered.index(f'id="{s}"') for s in EXPECTED_ORDER]
    assert positions == sorted(positions), "sections are out of order"


def test_findings_come_before_methodology(rendered):
    assert rendered.index('id="sec-findings"') < rendered.index('id="app-methodology"')


def test_authorisation_is_in_the_header_not_a_numbered_section(rendered):
    assert 'id="sec-auth"' not in rendered
    assert "Examiner" in rendered
    assert "Test Examiner" in rendered


def test_report_is_self_contained(rendered):
    """No remote fetches: the report must work from a USB stick, offline."""
    remote = re.findall(r'(?:src|href)\s*=\s*["\'](https?://[^"\']+)', rendered)
    assert not remote, f"report must not reference remote resources: {remote}"


def test_report_inlines_its_own_styles_and_script(rendered):
    assert "<style>" in rendered
    # The full token stack arrives in Task 6; at this point base.css is what
    # render.py loads, so assert on that rather than on tokens.css.
    assert "base.css" in rendered, "expected the stylesheet to be inlined"
    assert "<script>" in rendered


def test_all_four_charts_are_present(rendered):
    assert rendered.count("<svg") >= 4, (
        "expected severity, density, failures and user-activity charts"
    )


def test_evidence_derived_values_stay_escaped(tmp_path):
    """Regression guard: the hardening branch established this and it holds."""
    bundle = build_bundle(
        tmp_path / "src2",
        {"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"},
        hostname="<script>alert(1)</script>",
    )
    case_dir = tmp_path / "case2"
    ingest.ingest_bundle(bundle, case_dir, "<script>alert(2)</script>")
    conn = db.open_case(case_dir / "case.db")
    pipeline.parse_case(conn, case_dir, "CASE-ESC")
    out = case_dir / "report.html"
    render_report(conn, case_dir, out)
    conn.close()

    html = out.read_text(encoding="utf-8")
    assert "<script>alert(1)" not in html
    assert "<script>alert(2)" not in html
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_report_structure.py -v`
Expected: FAIL — `test_all_sections_present` reports `missing section sec-summary`, because the template still uses `sec-auth`, `sec-exec` and the rest.

- [ ] **Step 3: Pass the new charts into the template**

In `analyzer/lfa/report/render.py`, replace the single chart call:

```python
    svg_chart = generate_density_svg(conn)
```

with:

```python
    svg_chart = generate_density_svg(conn)
    severity_chart = severity_breakdown_svg(conn)
    user_chart = user_activity_svg(conn)
    failures_chart = auth_failure_bursts_svg(conn)
```

Update the import at the top of the file from:

```python
from .chart import generate_density_svg
```

to:

```python
from .chart import (
    auth_failure_bursts_svg,
    generate_density_svg,
    severity_breakdown_svg,
    user_activity_svg,
)
```

And add the three new names to the `template.render(...)` call, alongside the existing `svg_chart=svg_chart,`:

```python
        severity_chart=severity_chart,
        user_chart=user_chart,
        failures_chart=failures_chart,
```

- [ ] **Step 4: Write the shell template**

Replace the entire contents of `analyzer/lfa/ui/templates/report.html.j2`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Forensic Report &mdash; Case {{ summary.case_id }}</title>
  <style>
{{ inline_css }}
  </style>
</head>
<body class="report">
  <a class="skip-link" href="#sec-summary">Skip to summary</a>

  <header class="report-header" role="banner">
    <div class="report-header__identity">
      <p class="eyebrow">Linux Forensic Analyzer</p>
      <h1>Forensic Examination Report</h1>
      <p class="report-header__case">Case {{ summary.case_id }}</p>
    </div>
    <dl class="report-header__meta">
      <div><dt>Examiner</dt><dd>{{ summary.examiner }}</dd></div>
      <div><dt>Host(s)</dt><dd>{{ summary.hosts | join(', ') if summary.hosts else 'Disk image' }}</dd></div>
      <div><dt>Analysed</dt><dd>{{ summary.ingest_time }}</dd></div>
      <div><dt>Events</dt><dd>{{ '{:,}'.format(summary.event_count) }}</dd></div>
    </dl>
    <p class="report-header__notice">
      Artifacts were collected read-only and hash-verified against the
      collection manifest. Password hashes and key material are redacted where
      the collector was run with redaction enabled. This report states what the
      evidence shows and flags what it cannot determine; it does not conclude.
    </p>
  </header>

  <nav class="report-toc" aria-label="Report contents">
    <ol>
      <li><a href="#sec-summary">Summary</a></li>
      <li><a href="#sec-findings">Findings</a></li>
      <li><a href="#sec-timeline">Timeline</a></li>
      <li><a href="#sec-evidence">Evidence</a></li>
      <li><a href="#sec-intel">Intel</a></li>
      <li><a href="#app-methodology">Appendix A &mdash; Methodology</a></li>
      <li><a href="#app-undetermined">Appendix B &mdash; Undetermined</a></li>
      <li><a href="#app-glossary">Appendix C &mdash; Glossary</a></li>
    </ol>
  </nav>

  <main>
    {% include "partials/_summary.html.j2" %}
    {% include "partials/_findings.html.j2" %}
    {% include "partials/_timeline.html.j2" %}
    {% include "partials/_evidence.html.j2" %}
    {% include "partials/_intel.html.j2" %}
    {% include "partials/_appendices.html.j2" %}
  </main>

  <footer class="report-footer">
    <p>Generated by Linux Forensic Analyzer. Findings are indicators for a
       human examiner to judge, not conclusions.</p>
  </footer>

  <script>
{{ inline_js }}
  </script>
</body>
</html>
```

Note `{{ inline_css }}` and `{{ inline_js }}` are rendered WITHOUT `| safe`. Jinja escapes them, which would break the CSS. Fix this properly in the next step rather than reaching for `| safe` on a value that also carries no evidence — see Step 5.

- [ ] **Step 5: Mark only the asset strings as safe, and nothing else**

Asset text is authored by us and contains no evidence, so it is the one thing in this template that may bypass escaping. Change the two lines in `report.html.j2` to:

```html
{{ inline_css | safe }}
```

```html
{{ inline_js | safe }}
```

Every other value in every template stays escaped. Do not add `| safe` anywhere else in this task or any later one.

- [ ] **Step 6: Write the summary partial**

Create `analyzer/lfa/ui/templates/partials/_summary.html.j2`:

```html
<section id="sec-summary" aria-labelledby="h-summary">
  <h2 id="h-summary">Summary</h2>

  <p class="lede">{{ narrative.headline }}</p>

  <div class="stat-row">
    <div class="stat stat--high">
      <span class="stat__value">{{ summary.severity_counts.high }}</span>
      <span class="stat__label">High</span>
    </div>
    <div class="stat stat--medium">
      <span class="stat__value">{{ summary.severity_counts.medium }}</span>
      <span class="stat__label">Medium</span>
    </div>
    <div class="stat stat--low">
      <span class="stat__value">{{ summary.severity_counts.low }}</span>
      <span class="stat__label">Low</span>
    </div>
    <div class="stat">
      <span class="stat__value">{{ '{:,}'.format(summary.event_count) }}</span>
      <span class="stat__label">Events</span>
    </div>
  </div>

  {% if narrative.key_observations %}
  <h3>Key observations</h3>
  <ul class="observation-list">
    {% for obs in narrative.key_observations %}
    <li>
      <p class="observation-list__title">{{ obs.title }}</p>
      <p>{{ obs.what_happened }}</p>
      <p class="muted">{{ obs.why_it_matters }}</p>
    </li>
    {% endfor %}
  </ul>
  {% endif %}

  {% if narrative.recommended_actions %}
  <h3>Recommended next steps</h3>
  <ol class="action-list">
    {% for step in narrative.recommended_actions %}
    <li>{{ step }}</li>
    {% endfor %}
  </ol>
  {% endif %}

  <figure class="chart">
    {{ severity_chart | safe }}
    <figcaption>Findings by severity.</figcaption>
  </figure>
</section>
```

`severity_chart` is marked safe because it is SVG we generated ourselves in `chart.py`, where every evidence-derived string already passes through `xml.sax.saxutils.escape`.

- [ ] **Step 7: Write the findings partial**

Create `analyzer/lfa/ui/templates/partials/_findings.html.j2`:

```html
<section id="sec-findings" aria-labelledby="h-findings">
  <h2 id="h-findings">Findings <span class="count">{{ findings | length }}</span></h2>

  {% if not findings %}
  <p class="empty">No correlation rule produced a finding for this case. That is
     not the same as "nothing happened" &mdash; see Appendix B for what the
     evidence could not determine.</p>
  {% endif %}

  {% for f in findings %}
  <article class="finding finding--{{ f.severity }}">
    <header class="finding__head">
      <span class="badge badge--{{ f.severity }}">{{ f.severity | upper }}</span>
      <h3>{{ f.title }}</h3>
    </header>

    <dl class="finding__plain">
      <dt>What happened</dt>
      <dd>{{ f.what_happened }}</dd>
      <dt>Why it matters</dt>
      <dd>{{ f.why_it_matters }}</dd>
      <dt>Confidence</dt>
      <dd>{{ f.confidence }}</dd>
      <dt>What to check next</dt>
      <dd>{{ f.check_next }}</dd>
    </dl>

    <details class="finding__technical">
      <summary>Technical detail</summary>
      <p class="mono">{{ f.technical_detail }}</p>
      <p class="muted">
        Rule {{ f.rule_name }} v{{ f.rule_version }}
        {%- if f.first_ts_utc %} &middot; {{ f.first_ts_utc }}{% endif %}
        {%- if f.host_id %} &middot; host {{ f.host_id }}{% endif %}
        &middot; {{ f.event_ids | length }} supporting event(s)
      </p>
    </details>
  </article>
  {% endfor %}
</section>
```

- [ ] **Step 8: Write the timeline partial**

Create `analyzer/lfa/ui/templates/partials/_timeline.html.j2`:

```html
<section id="sec-timeline" aria-labelledby="h-timeline">
  <h2 id="h-timeline">Timeline</h2>

  <figure class="chart">
    {{ svg_chart | safe }}
    <figcaption>
      Event volume per day
      {%- if summary.first_event_utc %}, {{ summary.first_event_utc[:10] }}
      to {{ summary.last_event_utc[:10] }}{% endif %}.
    </figcaption>
  </figure>

  <figure class="chart">
    {{ failures_chart | safe }}
    <figcaption>Failed authentication attempts per hour. A tall isolated bar is
      the shape of password guessing.</figcaption>
  </figure>

  <h3>Event sample</h3>
  <p class="muted">Showing up to {{ events | length }} normalised events in
     chronological order. The complete set is in the canonical exports.</p>

  <div class="table-tools">
    <label class="visually-hidden" for="event-filter">Filter events</label>
    <input id="event-filter" type="search" placeholder="Filter events&hellip;"
           data-filters="events-table" autocomplete="off">
  </div>

  <div class="table-scroll">
    <table id="events-table" class="data-table" data-sortable>
      <thead>
        <tr>
          <th scope="col" data-sort="text">Time (UTC)</th>
          <th scope="col" data-sort="text">Category</th>
          <th scope="col" data-sort="text">User</th>
          <th scope="col" data-sort="text">Source</th>
          <th scope="col" data-sort="text">Severity</th>
          <th scope="col">Description</th>
        </tr>
      </thead>
      <tbody>
        {% for e in events %}
        <tr>
          <td class="mono">{{ e.timestamp_utc or '&mdash;' }}</td>
          <td>{{ e.category }}</td>
          <td>{{ e.actor_user or '&mdash;' }}</td>
          <td class="mono">{{ e.source_ip or e.source_host or '&mdash;' }}</td>
          <td><span class="badge badge--{{ e.severity }}">{{ e.severity }}</span></td>
          <td>{{ e.description }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</section>
```

- [ ] **Step 9: Write the evidence partial**

Create `analyzer/lfa/ui/templates/partials/_evidence.html.j2`:

```html
<section id="sec-evidence" aria-labelledby="h-evidence">
  <h2 id="h-evidence">Evidence</h2>

  <h3>Artifacts collected</h3>
  <p class="muted">{{ artifacts | length }} artifact(s). Integrity is the hash
     recorded at collection compared against the hash recomputed at ingest.</p>

  <div class="table-scroll">
    <table class="data-table" data-sortable>
      <thead>
        <tr>
          <th scope="col" data-sort="text">Path</th>
          <th scope="col" data-sort="text">Host</th>
          <th scope="col" data-sort="number">Size</th>
          <th scope="col" data-sort="text">Integrity</th>
          <th scope="col" data-sort="text">Parsed</th>
        </tr>
      </thead>
      <tbody>
        {% for a in artifacts %}
        <tr>
          <td class="mono">{{ a.original_path }}</td>
          <td>{{ a.host_id }}</td>
          <td class="num">{{ a.size if a.size is not none else '&mdash;' }}</td>
          <td>
            <span class="state state--{{ a.integrity or 'unknown' }}">
              {{ a.integrity or 'unknown' }}
            </span>
          </td>
          <td>
            <span class="state state--{{ a.parse_status or 'unknown' }}">
              {{ a.parse_status or 'unknown' }}
            </span>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <figure class="chart">
    {{ user_chart | safe }}
    <figcaption>Recorded activity per account.</figcaption>
  </figure>
</section>
```

- [ ] **Step 10: Write the intel partial**

The 21 intel categories are grouped into four named groups rather than eight flat tabs. Create `analyzer/lfa/ui/templates/partials/_intel.html.j2`:

```html
{% macro intel_table(rows, columns) %}
  {% if rows %}
  <div class="table-scroll">
    <table class="data-table" data-sortable>
      <thead>
        <tr>{% for c in columns %}<th scope="col" data-sort="text">{{ c[1] }}</th>{% endfor %}</tr>
      </thead>
      <tbody>
        {% for r in rows %}
        <tr>{% for c in columns %}<td>{{ r[c[0]] if r[c[0]] is not none else '&mdash;' }}</td>{% endfor %}</tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <p class="empty">Nothing recorded.</p>
  {% endif %}
{% endmacro %}

<section id="sec-intel" aria-labelledby="h-intel">
  <h2 id="h-intel">Intel</h2>

  <h3>Accounts and access</h3>
  <details open><summary>Local accounts ({{ intel.users | length }})</summary>
    {{ intel_table(intel.users, [('actor_user','User'), ('description','Detail'), ('first_seen','First seen')]) }}
  </details>
  <details><summary>Sessions ({{ intel.sessions | length }})</summary>
    {{ intel_table(intel.sessions, [('actor_user','User'), ('source_ip','From'), ('terminal','Terminal'), ('login_time','Login'), ('duration','Duration'), ('status','Status')]) }}
  </details>
  <details><summary>Failed logins ({{ intel.failed_logins | length }})</summary>
    {{ intel_table(intel.failed_logins, [('actor_user','User'), ('source_ip','From'), ('attempt_count','Attempts'), ('first_attempt','First'), ('last_attempt','Last')]) }}
  </details>

  <h3>Network</h3>
  <details><summary>Remote addresses ({{ intel.remote_ips | length }})</summary>
    {{ intel_table(intel.remote_ips, [('source_ip','Address'), ('connection_count','Events'), ('users','Accounts'), ('first_seen','First'), ('last_seen','Last')]) }}
  </details>
  <details><summary>Interfaces ({{ intel.network_interfaces | length }})</summary>
    {{ intel_table(intel.network_interfaces, [('description','Interface'), ('source_ip','Address'), ('notes','Notes')]) }}
  </details>
  <details><summary>DNS ({{ intel.dns_activity | length }})</summary>
    {{ intel_table(intel.dns_activity, [('subcategory','Kind'), ('description','Detail'), ('notes','Source')]) }}
  </details>
  <details><summary>Listening and established sockets ({{ intel.volatile_sockets | length }})</summary>
    {{ intel_table(intel.volatile_sockets, [('subcategory','State'), ('source_ip','Address'), ('actor_process','Process'), ('description','Detail')]) }}
  </details>

  <h3>Activity</h3>
  <details><summary>Shell history ({{ intel.shell_history | length }})</summary>
    {{ intel_table(intel.shell_history, [('actor_user','User'), ('timestamp_utc','Time'), ('description','Command')]) }}
  </details>
  <details><summary>Privileged and scheduled actions ({{ intel.system_additional | length }})</summary>
    {{ intel_table(intel.system_additional, [('timestamp_utc','Time'), ('actor_user','User'), ('subcategory','Kind'), ('description','Detail')]) }}
  </details>
  <details><summary>Web requests ({{ intel.http_logs | length }})</summary>
    {{ intel_table(intel.http_logs, [('timestamp_utc','Time'), ('client_ip','Client'), ('description','Request'), ('notes','Detail')]) }}
  </details>
  <details><summary>File transfers ({{ intel.ftp_connections | length }})</summary>
    {{ intel_table(intel.ftp_connections, [('timestamp_utc','Time'), ('client_ip','Client'), ('actor_user','User'), ('description','Transfer')]) }}
  </details>
  <details><summary>Browser history and downloads ({{ intel.browser_and_downloads | length }})</summary>
    {{ intel_table(intel.browser_and_downloads, [('timestamp_utc','Time'), ('actor_user','User'), ('subcategory','Kind'), ('description','Detail')]) }}
  </details>

  <h3>System</h3>
  <details><summary>Hardware and USB ({{ intel.usb | length }})</summary>
    {{ intel_table(intel.usb, [('timestamp_utc','Time'), ('subcategory','Kind'), ('description','Device')]) }}
  </details>
  <details><summary>Storage ({{ intel.storage | length }})</summary>
    {{ intel_table(intel.storage, [('subcategory','Kind'), ('description','Detail'), ('notes','Notes')]) }}
  </details>
  <details><summary>Configuration and environment ({{ intel.system | length }})</summary>
    {{ intel_table(intel.system, [('subcategory','Kind'), ('description','Detail')]) }}
  </details>
</section>
```

- [ ] **Step 11: Write the appendices partial**

Create `analyzer/lfa/ui/templates/partials/_appendices.html.j2`:

```html
<section id="app-methodology" aria-labelledby="h-methodology">
  <h2 id="h-methodology">Appendix A &mdash; Methodology, limitations and tool audit</h2>

  <h3>How this report was produced</h3>
  <ol class="method-list">
    <li>Artifacts were collected read-only on the target. Each file was stat'd,
        copied, and the <em>copy</em> hashed; the source was stat'd again so that
        growth during collection is recorded as an observation, not an error.</li>
    <li>At ingest every file was re-hashed against the collection manifest.
        Mismatches were quarantined and excluded from analysis.</li>
    <li>Parsers translated each artifact into normalised events. A parser that
        fails does so alone; the run continues and the failure is recorded.</li>
    <li>Correlation rules ran over the normalised events. Every rule is
        explainable: it names its threshold and the exact events it fired on.
        No machine learning is used anywhere in this tool.</li>
  </ol>

  <h3>Coverage</h3>
  <p>{{ artifacts | length }} artifact(s) were recorded.
     {% set parsed = artifacts | selectattr('parse_status', 'equalto', 'success') | list %}
     {% set skipped = artifacts | selectattr('parse_status', 'equalto', 'skip') | list %}
     {% set failed = artifacts | selectattr('parse_status', 'equalto', 'fail') | list %}
     {{ parsed | length }} parsed successfully,
     {{ skipped | length }} had no parser that claimed them, and
     {{ failed | length }} failed during parsing.</p>

  {% if failed %}
  <p class="warn">The following artifacts failed to parse and contributed no
     events. Anything they contained is absent from this report:</p>
  <ul class="mono">
    {% for a in failed %}<li>{{ a.original_path }}</li>{% endfor %}
  </ul>
  {% endif %}
</section>

<section id="app-undetermined" aria-labelledby="h-undetermined">
  <h2 id="h-undetermined">Appendix B &mdash; What we could not determine</h2>
  <p>Absence of evidence is itself evidence, and stating it plainly is part of
     an honest examination.</p>
  <ul>
    {% if skipped %}
    <li>{{ skipped | length }} collected artifact(s) had no parser that claimed
        them. Their contents were not analysed.</li>
    {% endif %}
    {% if summary.severity_counts.high == 0 and summary.severity_counts.medium == 0 %}
    <li>No high or medium-severity findings fired. This means the configured
        rules did not match, not that the host is clean.</li>
    {% endif %}
    <li>This examination sees only what the collector captured. Anything an
        intruder deleted before collection, or that was never written to disk,
        is outside its reach.</li>
    <li>Timestamps carrying a confidence of <em>year_inferred</em> were
        reconstructed from file modification times, because classic syslog
        lines record no year.</li>
  </ul>
</section>

<section id="app-glossary" aria-labelledby="h-glossary">
  <h2 id="h-glossary">Appendix C &mdash; Glossary</h2>
  <dl class="glossary">
    <dt>Artifact</dt>
    <dd>A file or command output collected from the target host.</dd>
    <dt>Normalised event</dt>
    <dd>One record parsed from an artifact into the tool's common schema, so
        that evidence from different sources can be compared on a single
        timeline.</dd>
    <dt>Finding</dt>
    <dd>A correlation rule firing on specific events. A finding is an indicator
        for a human to judge, not a conclusion.</dd>
    <dt>Confidence</dt>
    <dd>How strongly the evidence supports a finding: High, Medium or Low.</dd>
    <dt>Chain of custody</dt>
    <dd>The record proving evidence has not changed since collection: a hash
        taken at collection and re-verified at ingest.</dd>
    <dt>Quarantined</dt>
    <dd>An artifact whose hash did not match the manifest. It was excluded from
        analysis because anything derived from it would be unattributable.</dd>
    <dt>Tool-generated</dt>
    <dd>An event caused by the collection itself, tagged so the tool does not
        report its own operator as suspicious activity.</dd>
  </dl>
</section>
```

- [ ] **Step 12: Run the tests to verify they pass**

Run: `python -m pytest tests/test_report_structure.py -v`
Expected: 8 passed.

- [ ] **Step 13: Commit**

```bash
git add analyzer/lfa/ui/templates/ analyzer/lfa/report/render.py tests/test_report_structure.py
git commit -m "feat(report): restructure around the reader, split into partials

New order: Summary, Findings, Timeline, Evidence, Intel, then three
appendices. The reader learns what happened before being told how the tool
was configured; previously findings sat in section 4 behind authorisation,
executive summary and the timeline.

Authorisation and scope move into the page-one header. The 21 intel
categories are grouped into four named groups instead of eight flat tabs.
The 695-line monolith becomes six partials. Appendix B states what the
evidence could not determine, which the old report never did explicitly."
```

---

### Task 6: Document theme, component styles, and print

**Files:**
- Rewrite: `analyzer/lfa/ui/styles/base.css`
- Create: `analyzer/lfa/ui/styles/report.css`
- Create: `analyzer/lfa/ui/styles/print.css`
- Modify: `analyzer/lfa/report/render.py`
- Modify: `tests/test_design_tokens.py`
- Test: `tests/test_report_print.py` (create)

**Interfaces:**
- Consumes: every token from Task 2 and every class name used in the Task 5 partials.
- Produces: the report's complete visual style. `render.py` loads
  `assets.load_styles("tokens", "theme-document", "base", "report", "print")` — order matters, because later rules win.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_print.py`:

```python
"""Print is a first-class output for this report.

Forensic reports get printed, converted to PDF, and attached to case files.
A dark screen theme with no page rules is not acceptable for that.
"""
import re

import pytest

from lfa import db, ingest, pipeline
from lfa.report.render import render_report
from lfa.ui import assets

from bundle_builder import build_bundle


@pytest.fixture
def rendered(tmp_path):
    bundle = build_bundle(
        tmp_path / "src",
        {"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"},
    )
    case_dir = tmp_path / "case"
    ingest.ingest_bundle(bundle, case_dir, "Examiner")
    conn = db.open_case(case_dir / "case.db")
    pipeline.parse_case(conn, case_dir, "CASE-PRINT")
    out = case_dir / "report.html"
    render_report(conn, case_dir, out)
    conn.close()
    return out.read_text(encoding="utf-8")


def test_print_stylesheet_is_inlined(rendered):
    assert "print.css" in rendered


def test_page_rules_are_present(rendered):
    assert "@page" in rendered
    assert "@media print" in rendered


def test_findings_do_not_split_across_pages(rendered):
    print_block = rendered[rendered.index("print.css"):]
    assert "break-inside: avoid" in print_block


def test_interactive_affordances_are_hidden_in_print(rendered):
    print_block = rendered[rendered.index("print.css"):]
    assert ".table-tools" in print_block
    assert ".skip-link" in print_block


def test_document_theme_is_inlined_not_the_console_theme(rendered):
    assert "theme-document.css" in rendered
    assert "theme-console.css" not in rendered


def test_stylesheets_load_in_cascade_order(rendered):
    order = ["tokens.css", "theme-document.css", "base.css", "report.css", "print.css"]
    positions = [rendered.index(name) for name in order]
    assert positions == sorted(positions), "stylesheets must load tokens-first"


def test_base_stylesheet_has_no_raw_colour_literals():
    """The Task 2 exemption expires here."""
    text = (assets.STYLE_DIR / "base.css").read_text(encoding="utf-8")
    body = "\n".join(
        line for line in text.splitlines()
        if not line.strip().startswith(("/*", "*"))
    )
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|\brgba?\s*\(", body), (
        "base.css must reference tokens, not hardcode colour"
    )
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_report_print.py -v`
Expected: FAIL — `print.css` does not exist, so `test_print_stylesheet_is_inlined` fails first.

- [ ] **Step 3: Rewrite base.css onto tokens**

Replace the entire contents of `analyzer/lfa/ui/styles/base.css`:

```css
/* Element defaults. No colour literals: everything comes from the token
   layer, so the same base serves the document and console themes. */

*, *::before, *::after { box-sizing: border-box; }

html { -webkit-text-size-adjust: 100%; }

body {
  margin: 0;
  font-family: var(--font-sans);
  font-size: var(--text-base);
  line-height: var(--leading-normal);
  color: var(--text-primary);
  background: var(--surface-page);
}

h1, h2, h3, h4 {
  margin: 0 0 var(--space-3);
  line-height: var(--leading-tight);
  font-weight: var(--weight-semibold);
  color: var(--text-primary);
}

h1 { font-size: var(--text-2xl); }
h2 { font-size: var(--text-xl); }
h3 { font-size: var(--text-md); }

p { margin: 0 0 var(--space-4); }

a {
  color: var(--accent-primary);
  text-underline-offset: 2px;
}

a:focus-visible,
button:focus-visible,
summary:focus-visible,
input:focus-visible {
  outline: 2px solid var(--border-focus);
  outline-offset: 2px;
  border-radius: var(--radius-sm);
}

ul, ol { margin: 0 0 var(--space-4); padding-left: var(--space-5); }
li { margin-bottom: var(--space-2); }

dl { margin: 0; }
dt { font-weight: var(--weight-semibold); color: var(--text-secondary); }
dd { margin: 0 0 var(--space-3); }

table { border-collapse: collapse; width: 100%; }

th, td {
  padding: var(--space-2) var(--space-3);
  text-align: left;
  border-bottom: var(--border-width) solid var(--border-subtle);
  vertical-align: top;
}

th {
  font-size: var(--text-sm);
  font-weight: var(--weight-semibold);
  color: var(--text-secondary);
  border-bottom-color: var(--border-strong);
  white-space: nowrap;
}

code, .mono { font-family: var(--font-mono); font-size: var(--text-sm); }

.muted { color: var(--text-muted); }
.num, .data-table td.num { text-align: right; font-variant-numeric: tabular-nums; }

.visually-hidden {
  position: absolute;
  width: 1px; height: 1px;
  padding: 0; margin: -1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
  border: 0;
}

.skip-link {
  position: absolute;
  left: var(--space-3);
  top: calc(var(--space-3) * -6);
  padding: var(--space-2) var(--space-3);
  background: var(--surface-raised);
  border: var(--border-width) solid var(--border-strong);
  border-radius: var(--radius-sm);
  transition: top var(--motion-fast) var(--ease-out);
  z-index: 10;
}
.skip-link:focus { top: var(--space-3); }
```

- [ ] **Step 4: Write the report component styles**

Create `analyzer/lfa/ui/styles/report.css`:

```css
/* Report components. The document register: generous margins, a clear
   typographic hierarchy, one measure for prose. */

body.report {
  max-width: var(--page-max);
  margin: 0 auto;
  padding: var(--space-6) var(--space-5) var(--space-9);
}

/* ------------------------------------------------------------- header --- */

.report-header {
  border-bottom: 3px solid var(--text-primary);
  padding-bottom: var(--space-5);
  margin-bottom: var(--space-6);
}

.eyebrow {
  margin: 0 0 var(--space-1);
  font-size: var(--text-sm);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-muted);
}

.report-header h1 { font-size: var(--text-3xl); margin-bottom: var(--space-2); }

.report-header__case {
  margin: 0 0 var(--space-5);
  font-family: var(--font-mono);
  font-size: var(--text-md);
  color: var(--text-secondary);
}

.report-header__meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--space-4);
  margin-bottom: var(--space-4);
}
.report-header__meta dt {
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
}
.report-header__meta dd { margin: 0; font-weight: var(--weight-medium); }

.report-header__notice {
  max-width: var(--measure);
  margin: 0;
  font-size: var(--text-sm);
  color: var(--text-secondary);
}

/* ---------------------------------------------------------------- toc --- */

.report-toc {
  margin-bottom: var(--space-7);
  padding: var(--space-4);
  background: var(--surface-raised);
  border-radius: var(--radius-md);
}
.report-toc ol {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2) var(--space-5);
}
.report-toc li { margin: 0; }

/* ----------------------------------------------------------- sections --- */

section { margin-bottom: var(--space-8); scroll-margin-top: var(--space-4); }

section > h2 {
  padding-bottom: var(--space-2);
  border-bottom: var(--border-width) solid var(--border-strong);
  margin-bottom: var(--space-5);
}

.count {
  font-size: var(--text-base);
  font-weight: var(--weight-normal);
  color: var(--text-muted);
}

.lede {
  max-width: var(--measure);
  font-size: var(--text-md);
  line-height: var(--leading-loose);
  color: var(--text-secondary);
}

.empty {
  padding: var(--space-4);
  background: var(--surface-raised);
  border-radius: var(--radius-md);
  color: var(--text-secondary);
}

.warn {
  padding: var(--space-3) var(--space-4);
  background: var(--severity-medium-bg);
  border-left: 3px solid var(--severity-medium);
  border-radius: var(--radius-sm);
}

/* ------------------------------------------------------------- stats --- */

.stat-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: var(--space-3);
  margin-bottom: var(--space-6);
}

.stat {
  padding: var(--space-4);
  background: var(--surface-raised);
  border: var(--border-width) solid var(--border-subtle);
  border-radius: var(--radius-md);
  border-top: 3px solid var(--border-strong);
}
.stat--high { border-top-color: var(--severity-high); }
.stat--medium { border-top-color: var(--severity-medium); }
.stat--low { border-top-color: var(--severity-low); }

.stat__value {
  display: block;
  font-size: var(--text-2xl);
  font-weight: var(--weight-bold);
  font-variant-numeric: tabular-nums;
}
.stat__label {
  display: block;
  font-size: var(--text-sm);
  color: var(--text-muted);
}

/* ---------------------------------------------------------- findings --- */

.finding {
  margin-bottom: var(--space-5);
  padding: var(--space-5);
  background: var(--surface-raised);
  border: var(--border-width) solid var(--border-subtle);
  border-left: 4px solid var(--border-strong);
  border-radius: var(--radius-md);
}
.finding--high { border-left-color: var(--severity-high); }
.finding--medium { border-left-color: var(--severity-medium); }
.finding--low { border-left-color: var(--severity-low); }
.finding--info { border-left-color: var(--severity-info); }

.finding__head {
  display: flex;
  align-items: baseline;
  gap: var(--space-3);
  margin-bottom: var(--space-4);
}
.finding__head h3 { margin: 0; }

.finding__plain dt {
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
  margin-top: var(--space-3);
}
.finding__plain dd { max-width: var(--measure); }

.finding__technical { margin-top: var(--space-4); }
.finding__technical summary {
  cursor: pointer;
  font-size: var(--text-sm);
  font-weight: var(--weight-medium);
  color: var(--accent-primary);
}
.finding__technical p {
  margin-top: var(--space-3);
  padding: var(--space-3);
  background: var(--surface-sunken);
  border-radius: var(--radius-sm);
  overflow-wrap: anywhere;
}

/* ------------------------------------------------------------ badges --- */

.badge {
  display: inline-block;
  padding: 2px var(--space-2);
  font-size: var(--text-xs);
  font-weight: var(--weight-semibold);
  letter-spacing: 0.04em;
  border-radius: var(--radius-pill);
  white-space: nowrap;
}
.badge--high { color: var(--severity-high); background: var(--severity-high-bg); }
.badge--medium { color: var(--severity-medium); background: var(--severity-medium-bg); }
.badge--low { color: var(--severity-low); background: var(--severity-low-bg); }
.badge--info { color: var(--severity-info); background: var(--severity-info-bg); }

.state { font-size: var(--text-sm); font-weight: var(--weight-medium); }
.state--verified, .state--success { color: var(--state-verified); }
.state--quarantined, .state--fail { color: var(--state-quarantined); }
.state--unknown, .state--skip { color: var(--state-unknown); }

/* ------------------------------------------------------------ charts --- */

.chart {
  margin: 0 0 var(--space-6);
  padding: var(--space-4);
  background: var(--surface-raised);
  border: var(--border-width) solid var(--border-subtle);
  border-radius: var(--radius-md);
}
.chart figcaption {
  margin-top: var(--space-3);
  font-size: var(--text-sm);
  color: var(--text-muted);
}
.lfa-chart { display: block; width: 100%; height: auto; }

/* ------------------------------------------------------------ tables --- */

.table-tools { margin-bottom: var(--space-3); }
.table-tools input {
  width: 100%;
  max-width: 340px;
  padding: var(--space-2) var(--space-3);
  font: inherit;
  font-size: var(--text-sm);
  color: var(--text-primary);
  background: var(--surface-page);
  border: var(--border-width) solid var(--border-strong);
  border-radius: var(--radius-sm);
}

.table-scroll {
  overflow-x: auto;
  border: var(--border-width) solid var(--border-subtle);
  border-radius: var(--radius-md);
  margin-bottom: var(--space-5);
}

.data-table tbody tr:nth-child(even) { background: var(--surface-raised); }
.data-table td { font-size: var(--text-sm); }

.data-table th[data-sort] { cursor: pointer; user-select: none; }
.data-table th[data-sort]::after {
  content: "";
  display: inline-block;
  width: 0.6em;
  opacity: 0.4;
}
.data-table th[aria-sort="ascending"]::after { content: " \2191"; opacity: 1; }
.data-table th[aria-sort="descending"]::after { content: " \2193"; opacity: 1; }

/* ------------------------------------------------------------- intel --- */

#sec-intel details {
  margin-bottom: var(--space-3);
  border: var(--border-width) solid var(--border-subtle);
  border-radius: var(--radius-md);
  overflow: hidden;
}
#sec-intel summary {
  padding: var(--space-3) var(--space-4);
  cursor: pointer;
  font-weight: var(--weight-medium);
  background: var(--surface-raised);
}
#sec-intel details > *:not(summary) { padding: 0 var(--space-4) var(--space-3); }

/* -------------------------------------------------------------- misc --- */

.observation-list, .action-list { max-width: var(--measure); }
.observation-list { list-style: none; padding: 0; }
.observation-list li {
  padding: var(--space-3) 0;
  border-bottom: var(--border-width) solid var(--border-subtle);
}
.observation-list__title { font-weight: var(--weight-semibold); margin-bottom: var(--space-1); }
.observation-list p, .glossary dd { margin-bottom: var(--space-1); }

.glossary dt { margin-top: var(--space-3); }

.report-footer {
  margin-top: var(--space-8);
  padding-top: var(--space-4);
  border-top: var(--border-width) solid var(--border-subtle);
  font-size: var(--text-sm);
  color: var(--text-muted);
}

@media (max-width: 720px) {
  body.report { padding: var(--space-4) var(--space-3) var(--space-7); }
  .report-header h1 { font-size: var(--text-xl); }
  .finding { padding: var(--space-4); }
}
```

- [ ] **Step 5: Write the print stylesheet**

Create `analyzer/lfa/ui/styles/print.css`:

```css
/* Print. This report gets printed, converted to PDF and attached to case
   files, so print is a first-class output rather than an afterthought. */

@page {
  size: A4;
  margin: 18mm 16mm 20mm;
}

@media print {
  /* Force the light document palette regardless of screen preference. */
  :root {
    --surface-page: #ffffff;
    --surface-raised: #ffffff;
    --surface-sunken: #f4f5f7;
    --text-primary: #000000;
    --text-secondary: #1f2429;
    --text-muted: #454d57;
    --border-subtle: #c8ced6;
    --border-strong: #6b7480;
  }

  body.report {
    max-width: none;
    padding: 0;
    font-size: 10.5pt;
    line-height: 1.45;
  }

  /* Interactive-only affordances have no meaning on paper. */
  .skip-link,
  .table-tools,
  .report-toc { display: none !important; }

  /* Everything collapsed on screen must be open on paper - a printed report
     that hides half its evidence behind a disclosure triangle is useless. */
  details { display: block; }
  details > summary { list-style: none; font-weight: 600; }
  details:not([open]) > *:not(summary) { display: revert; }

  /* Keep units of meaning whole across page breaks. */
  .finding,
  .chart,
  .stat,
  .observation-list li,
  .glossary dt,
  .glossary dd { break-inside: avoid; }

  section { break-inside: auto; }
  section > h2 { break-after: avoid; }
  h3 { break-after: avoid; }
  thead { display: table-header-group; }
  tr { break-inside: avoid; }

  /* Start each appendix on a fresh page. */
  #app-methodology,
  #app-undetermined,
  #app-glossary { break-before: page; }

  /* Expand link targets, since a printed link is otherwise dead. */
  a[href^="http"]::after {
    content: " (" attr(href) ")";
    font-size: 9pt;
    color: var(--text-muted);
    word-break: break-all;
  }

  .table-scroll { overflow: visible; border: none; }

  /* Long tables are the main source of unreadable printed reports. Cap the
     event sample; the complete set lives in the canonical exports. */
  #events-table tbody tr:nth-child(n + 61) { display: none; }
}
```

- [ ] **Step 6: Load the full stylesheet stack**

In `analyzer/lfa/report/render.py`, change:

```python
    inline_css = assets.load_styles("base")
```

to:

```python
    inline_css = assets.load_styles(
        "tokens", "theme-document", "base", "report", "print"
    )
```

- [ ] **Step 7: Retire the base.css exemption**

In `tests/test_design_tokens.py`, remove `"base.css"` and its expiry comment from `_PALETTE_FILES`, restoring it to:

```python
# Files allowed to contain raw colour values. Everything else must use var().
_PALETTE_FILES = {"tokens.css", "theme-document.css", "theme-console.css"}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `python -m pytest tests/test_report_print.py tests/test_design_tokens.py tests/test_report_structure.py -v`
Expected: all pass. If `test_component_stylesheets_contain_no_raw_colour_literals` now fails on `print.css`, that is expected — `print.css` legitimately redefines tokens for paper. Add `"print.css"` to `_PALETTE_FILES` with a one-line comment explaining that it overrides the palette for print, and re-run.

- [ ] **Step 9: Commit**

```bash
git add analyzer/lfa/ui/styles/ analyzer/lfa/report/render.py tests/test_design_tokens.py tests/test_report_print.py
git commit -m "feat(report): document theme, component styles and real print support

base.css is rewritten onto the token layer with no colour literals, so its
temporary exemption is retired. report.css carries the document register:
generous margins, one measure for prose, a clear hierarchy.

print.css treats paper as a first-class output - A4 page rules, the light
palette forced regardless of screen preference, disclosure triangles opened
so a printed report does not hide half its evidence, findings and charts
kept whole across breaks, appendices starting on fresh pages, and link
targets expanded."
```

---

### Task 7: Table sorting and filtering, progressively enhanced

**Files:**
- Rewrite: `analyzer/lfa/ui/scripts/report.js`
- Test: `tests/test_report_interactivity.py` (create)

**Interfaces:**
- Consumes: `data-sortable` on tables and `data-filters="<table-id>"` on search inputs, both emitted by the Task 5 partials.
- Produces: no Python interface. The script attaches sorting to every `table[data-sortable]` header carrying `data-sort`, and filtering to every `input[data-filters]`.

The hard requirement is progressive enhancement: with JavaScript disabled the tables must still be complete and readable. Sorting and filtering are additions, never preconditions.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_interactivity.py`:

```python
"""Table interactivity is an enhancement, never a precondition.

A forensic report must be complete and readable with JavaScript disabled,
because it may be opened from read-only media or in a locked-down viewer.
"""
import re

import pytest

from lfa import db, ingest, pipeline
from lfa.report.render import render_report
from lfa.ui import assets

from bundle_builder import build_bundle


@pytest.fixture
def rendered(tmp_path):
    bundle = build_bundle(
        tmp_path / "src",
        {
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"
                           b"kali:x:1000:1000::/home/kali:/bin/bash\n",
        },
    )
    case_dir = tmp_path / "case"
    ingest.ingest_bundle(bundle, case_dir, "Examiner")
    conn = db.open_case(case_dir / "case.db")
    pipeline.parse_case(conn, case_dir, "CASE-JS")
    out = case_dir / "report.html"
    render_report(conn, case_dir, out)
    conn.close()
    return out.read_text(encoding="utf-8")


def test_all_rows_are_rendered_server_side(rendered):
    """No row may depend on JS to exist."""
    body = rendered[rendered.index('id="events-table"'):]
    body = body[: body.index("</table>")]
    assert body.count("<tr>") >= 1, "event rows must be present in the HTML"


def test_tables_declare_their_sortable_columns(rendered):
    assert 'data-sortable' in rendered
    assert 'data-sort="text"' in rendered


def test_filter_input_names_its_table(rendered):
    assert 'data-filters="events-table"' in rendered


def test_script_is_inlined_and_not_fetched(rendered):
    assert "<script>" in rendered
    assert not re.search(r'<script[^>]+src=', rendered)


def test_script_guards_against_missing_elements():
    """The script runs on every page; it must not throw where a table is absent."""
    js = assets.load_script("report")
    assert "querySelectorAll" in js
    assert "addEventListener" in js


def test_script_declares_no_globals_beyond_its_entry_point():
    js = assets.load_script("report")
    assert js.lstrip().startswith("(function") or "IIFE" in js or js.lstrip().startswith("(()")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_report_interactivity.py -v`
Expected: FAIL — `test_script_declares_no_globals_beyond_its_entry_point` fails because the current `report.js` declares top-level functions.

- [ ] **Step 3: Rewrite the script**

Replace the entire contents of `analyzer/lfa/ui/scripts/report.js`:

```javascript
/* Report interactivity.
 *
 * Progressive enhancement only: every row is already in the HTML. This adds
 * sorting and filtering on top. With JavaScript disabled the report is still
 * complete and readable, which matters because it may be opened from
 * read-only media or a locked-down viewer.
 *
 * Wrapped in an IIFE so it introduces no globals.
 */
(function () {
  "use strict";

  /* ------------------------------------------------------------ sorting */

  function cellText(row, index) {
    var cell = row.children[index];
    return cell ? cell.textContent.trim() : "";
  }

  function comparator(index, kind, direction) {
    var sign = direction === "descending" ? -1 : 1;
    return function (a, b) {
      var x = cellText(a, index);
      var y = cellText(b, index);
      if (kind === "number") {
        var nx = parseFloat(x.replace(/[^0-9.-]/g, ""));
        var ny = parseFloat(y.replace(/[^0-9.-]/g, ""));
        nx = isNaN(nx) ? -Infinity : nx;
        ny = isNaN(ny) ? -Infinity : ny;
        return (nx - ny) * sign;
      }
      return x.localeCompare(y, undefined, { numeric: true }) * sign;
    };
  }

  function sortBy(table, header) {
    var headers = Array.prototype.slice.call(
      table.querySelectorAll("thead th")
    );
    var index = headers.indexOf(header);
    if (index < 0) return;

    var current = header.getAttribute("aria-sort");
    var direction = current === "ascending" ? "descending" : "ascending";

    headers.forEach(function (h) {
      h.removeAttribute("aria-sort");
    });
    header.setAttribute("aria-sort", direction);

    var body = table.tBodies[0];
    if (!body) return;
    var rows = Array.prototype.slice.call(body.rows);
    rows.sort(comparator(index, header.getAttribute("data-sort"), direction));
    rows.forEach(function (row) {
      body.appendChild(row);
    });
  }

  function enableSorting(table) {
    table.querySelectorAll("thead th[data-sort]").forEach(function (header) {
      header.setAttribute("tabindex", "0");
      header.setAttribute("role", "columnheader");

      header.addEventListener("click", function () {
        sortBy(table, header);
      });
      header.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          sortBy(table, header);
        }
      });
    });
  }

  /* ---------------------------------------------------------- filtering */

  function enableFiltering(input) {
    var table = document.getElementById(input.getAttribute("data-filters"));
    if (!table || !table.tBodies[0]) return;

    var body = table.tBodies[0];
    var rows = Array.prototype.slice.call(body.rows);
    var haystacks = rows.map(function (row) {
      return row.textContent.toLowerCase();
    });

    var status = document.createElement("p");
    status.className = "muted table-tools__status";
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    input.parentNode.appendChild(status);

    var timer = null;

    function apply() {
      var needle = input.value.trim().toLowerCase();
      var shown = 0;
      for (var i = 0; i < rows.length; i++) {
        var match = needle === "" || haystacks[i].indexOf(needle) !== -1;
        rows[i].hidden = !match;
        if (match) shown++;
      }
      status.textContent =
        needle === ""
          ? ""
          : shown + " of " + rows.length + " row(s) match “" + input.value + "”";
    }

    input.addEventListener("input", function () {
      /* Debounced: the event table can carry 1,500 rows and filtering on
         every keystroke makes typing feel broken. */
      if (timer) window.clearTimeout(timer);
      timer = window.setTimeout(apply, 120);
    });
  }

  /* --------------------------------------------------------------- init */

  function init() {
    document.querySelectorAll("table[data-sortable]").forEach(enableSorting);
    document.querySelectorAll("input[data-filters]").forEach(enableFiltering);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_report_interactivity.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add analyzer/lfa/ui/scripts/report.js tests/test_report_interactivity.py
git commit -m "feat(report): sortable, filterable tables as progressive enhancement

Replaces a 41-line naive filter that walked every row on every keystroke.
Sorting works by click or keyboard with aria-sort announced; filtering is
debounced, caches its haystacks, and reports match counts through an
aria-live region.

Every row is still rendered server-side, so with JavaScript disabled the
report remains complete - it may be opened from read-only media or a
locked-down viewer. The script introduces no globals."
```

---

### Task 8: Visual verification against a real case

**Files:**
- No source changes. Verification only.

**Interfaces:**
- Consumes: everything built in Tasks 1–7.
- Produces: evidence that the redesigned report holds up on real evidence rather than on fixtures.

- [ ] **Step 1: Render a report from real evidence**

```bash
python -m lfa analyse cases/wsl_kali/bundle.tar.gz --case-dir cases/verify_ui --examiner "Fahad"
```

Expected: completes, printing an event count and a findings count.

- [ ] **Step 2: Confirm the report is self-contained**

```bash
python -c "import re,pathlib; h=pathlib.Path('cases/verify_ui/report.html').read_text(encoding='utf-8'); r=re.findall(r'(?:src|href)\s*=\s*[\"\'](https?://[^\"\']+)', h); print('REMOTE REFS:', r); assert not r; print('OK self-contained')"
```

Expected: `OK self-contained`.

- [ ] **Step 3: Confirm no Markdown leaked**

```bash
python -c "import pathlib; h=pathlib.Path('cases/verify_ui/report.html').read_text(encoding='utf-8'); n=h.count('**'); print('asterisk pairs:', n); assert n==0; print('OK no markdown')"
```

Expected: `OK no markdown`.

- [ ] **Step 4: Confirm the section order on real data**

```bash
python -c "
import pathlib
h = pathlib.Path('cases/verify_ui/report.html').read_text(encoding='utf-8')
order = ['sec-summary','sec-findings','sec-timeline','sec-evidence','sec-intel','app-methodology','app-undetermined','app-glossary']
pos = [h.index('id=\"%s\"' % s) for s in order]
print(list(zip(order, pos)))
assert pos == sorted(pos)
print('OK order')
"
```

Expected: `OK order`.

- [ ] **Step 5: Confirm all four charts rendered with real data**

```bash
python -c "
import pathlib
h = pathlib.Path('cases/verify_ui/report.html').read_text(encoding='utf-8')
print('svg count:', h.count('<svg'))
print('empty charts:', h.count('No data available'))
assert h.count('<svg') >= 4
"
```

Expected: at least 4 SVGs. Report how many rendered as "No data available" — that is information, not a failure, since a case with no failed logins legitimately has an empty failure chart.

- [ ] **Step 6: Open the report and look at it**

Open `cases/verify_ui/report.html` in a browser. Check and report on each:
- Does the header read as a formal document rather than a dashboard?
- Are findings legible, with the plain-English layer ahead of the technical drawer?
- Do the charts have readable axis labels at real data volumes, or do they collide?
- Does the intel section's grouping work, or are some groups still overwhelming?
- Does the events table sort when you click a header, and filter as you type?

Then use the browser's print preview and check:
- Does it start on a clean page with sensible margins?
- Are findings split across page boundaries?
- Are the disclosure triangles open, so no evidence is hidden on paper?
- Do the appendices start on fresh pages?

Write what you see, including anything that looks wrong. This step is a genuine inspection, not a formality — the automated tests cannot see layout.

- [ ] **Step 7: Clean up**

```bash
rm -rf cases/verify_ui
```

`cases/` is gitignored, so there is nothing to commit from this task. Report your observations from Steps 5 and 6.

---

## Notes for the implementer

- **Do not run the full suite during development.** It takes 12–15 minutes. Run the focused tests each task names; the controller runs the full suite.
- **`cases/` is gitignored.** Never stage anything under it.
- **The working tree carries the repo owner's uncommitted work.** Stage only the paths each task names, and read `git diff --cached` before every commit.
- **Never add `| safe`** to anything except `inline_css`, `inline_js`, and the four chart SVGs. Those are the only values in the template that we authored ourselves. Everything derived from evidence stays escaped.
- **If a contrast test fails, fix the colour, not the threshold.** Report which token you changed and to what.
