# Frontend Redesign — Design

**Date:** 2026-09-09
**Status:** Awaiting review
**Scope:** All three of LFA's user interfaces — the offline HTML report, the SOC dashboard, and the forensic explorer.

---

## 1. Problem statement

LFA has three user interfaces totalling roughly 2,900 lines. They look and feel
below the standard of the engine behind them. The cause is structural, not a
matter of taste.

### 1.1 Two-thirds of the UI is trapped in Python f-strings

| Surface | Location | Lines |
| :------ | :------- | ----: |
| Offline HTML report | `report.html.j2` + `style.css` + `tables.js` + `chart.py` | 1,204 |
| SOC dashboard | f-strings inside `analyzer/lfa/server.py` | 393 |
| Forensic explorer | f-strings inside `analyzer/lfa/explorer.py` | 1,318 |

1,711 of those lines are HTML, CSS and JavaScript written inside Python
f-strings, where every CSS brace must be doubled (`{{`, `}}`). In that medium
there is no syntax highlighting, no formatter, no linter, and no way to iterate
on a design visually. Good design is not merely absent — it is economically
impossible. This is the root cause and the first thing the redesign must fix.

### 1.2 Three unshared design systems

`style.css` defines 18 CSS custom properties. `server.py` defines its own
`:root` block inside a Python string. `explorer.py` defines a third. Across the
three surfaces there are **94 hardcoded colour literals**, only 18 of which sit
in any token block. The same product speaks three visual languages that are
guaranteed to drift apart with every edit.

### 1.3 Tokens are named by hue, not by role

`--accent-blue`, `--accent-green`, `--accent-red`. Because no token says
*what a colour means*, severity colours are re-hardcoded at each call site.
Changing how "high severity" looks means finding every literal.

### 1.4 No responsive design, and dark-only

There is exactly one `@media` rule in the entire codebase — a print block in
`style.css`. The dashboard and explorer have none. `prefers-color-scheme` is
never used. Everything is dark-only, which is a poor fit for a report that is
printed and attached to a case file.

### 1.5 Thin interactivity and a single chart

`tables.js` is 41 lines: a naive substring filter that walks every row on every
keystroke, plus tab switching. No sorting, no column filters, no pagination.
`chart.py` exposes exactly one function, `generate_density_svg`.

### 1.6 The report's information architecture buries the answer

Ten numbered sections run Authorisation → Executive Summary → Timeline →
Findings → Inventory → Intel → Events → Integrity → Methodology → Glossary.
The reader must reach section 4 before learning what happened. Section 6 packs
21 distinct intel categories behind 8 tabs.

### 1.7 A rendering defect

`narrative.py` emits Markdown (`**bold**`) into a Jinja template with
`autoescape=True`, so generated reports display literal asterisks —
`**CASE-205**`, `**2 critical/high-severity security finding(s)**`. Fourteen
stray `**` sequences appear in `cases/103/report.html`.

---

## 2. Decisions

### D1 — Extract every UI asset out of Python into real files

All HTML, CSS and JavaScript moves into `.j2`, `.css` and `.js` files under a
single `analyzer/lfa/ui/` tree. Python keeps only data preparation and a thin
render call. Assets are read and inlined at render time (report) or serve time
(dashboard, explorer), preserving the single-file and zero-CDN guarantees.

This is the foundational decision. Every other decision here depends on it,
and without it the redesign would decay back to its current state within a few
edits.

### D2 — One shared token layer, two themes

`ui/styles/tokens.css` defines the complete token vocabulary once: colour
roles, a type scale, a spacing scale, radii, shadows, and motion. Two theme
files layer on top and redefine only colour:

- `ui/styles/theme-document.css` — light-primary, for the report
- `ui/styles/theme-console.css` — dark-primary, for the dashboard and explorer

No component stylesheet may contain a raw colour literal. This is enforced by
a test, not by review.

### D3 — Two visual registers, one product

The report reads as a **formal deliverable**: generous margins, a real
typographic hierarchy, light-primary, print-perfect. The dashboard and explorer
read as a **security console**: dense, dark, monospace accents, keyboard-first.
They remain visibly one product because they share `tokens.css` — the same
spacing scale, the same type scale, the same severity semantics.

### D4 — Colour by role, never by hue

Tokens are named for meaning: `--severity-high`, `--severity-medium`,
`--severity-low`, `--severity-info`, `--state-verified`, `--state-quarantined`,
`--surface-raised`, `--text-muted`. No token is named for its hue.

### D5 — A small, deliberate chart vocabulary in pure Python SVG

`chart.py` grows from one function to a focused set, still with zero
dependencies (decision D3 of the original project — no matplotlib — stands):

- timeline density (existing, rebuilt with axes, labels and gridlines)
- severity breakdown
- per-user activity
- authentication-failure bursts over time

Every chart is deterministic for fixed input, encodes meaning by shape or label
as well as colour, and carries an accessible text alternative.

### D6 — Restructure the report around the reader

New order, findings-first:

1. **Summary** — case identity, what happened, severity counts, the narrative
2. **Findings** — every detection, plain-English layer first, technical drawer second
3. **Timeline** — density chart and the reconstructed sequence
4. **Evidence** — host inventory, artifacts, integrity and chain of custody
5. **Intel** — the 21 categories, grouped into a navigable structure rather than 8 flat tabs
6. **Appendix A — Methodology, limitations and tool audit**
7. **Appendix B — What we could not determine**
8. **Appendix C — Glossary**

Authorisation and scope move to a header block on page one rather than
occupying a numbered section ahead of the findings.

### D7 — Print is a first-class output

The report ships real print support: `@page` rules with margins and running
headers, `break-inside: avoid` on findings and table rows, the document theme
forced to its light palette regardless of `prefers-color-scheme`, external link
URLs expanded inline, and interactive-only affordances hidden.

### D8 — Real table interactivity, progressively enhanced

Vanilla JS, no framework. Sortable columns, faceted filters bound to the
existing category/severity/user facets, and pagination for large tables.
Tables must remain readable and complete with JavaScript disabled — filtering
and sorting are enhancements over a fully-rendered table, never a precondition
for seeing the data.

### D9 — Accessibility is a requirement, not a polish item

WCAG 2.1 AA contrast for all text against its own surface, verified by a test
that computes the ratios from the token files. Visible focus states on every
interactive element. Semantic HTML with real landmarks and table headers.
Meaning never conveyed by colour alone — severity carries a label or shape too.
Respect `prefers-reduced-motion`.

### D10 — Constraints that do not move

- **No build step.** No Node, no bundler, no transpiler. The project is Python
  plus POSIX sh and stays that way.
- **No runtime dependencies** beyond the existing `PyYAML` and `Jinja2`.
- **No CDN, no external fetches.** The report remains one self-contained file;
  the dashboard and explorer remain fully functional air-gapped.
- **The canonical JSON/CSV exports stay byte-identical.** Verified: no test
  asserts byte-stability of the HTML report itself, so the report may be
  restructured freely — but nothing in this work may touch the export path.

### D11 — Fix the Markdown defect as part of the report work

`narrative.py` stops emitting Markdown. It returns structured data and the
template renders it, so no asterisks can reach the page.

---

## 3. Proposed decomposition

This is too large for one plan. It splits into two, each of which produces
working, shippable software on its own.

**Plan 1 — Foundation, charts, and the report.**
Extract the UI tree, build the token layer and both themes, expand the chart
vocabulary, then rebuild the offline report on top of it: new IA, document
theme, print support, the Markdown fix. Ships a genuinely better report even if
Plan 2 never runs.

**Plan 2 — The console: dashboard and explorer.**
Move both surfaces out of their f-strings onto the shared token layer and the
console theme, and add real table interactivity. Depends on Plan 1's foundation
existing; changes no report behaviour.

The alternative — one plan of roughly fifteen tasks — was rejected because a
half-executed monolith would leave the product with two design systems instead
of three, which is worse than either endpoint.

---

## 4. Out of scope

- The correctness and security work on `fix/forensic-correctness-and-server-hardening`.
  That branch is complete and awaiting an integration decision; this redesign
  builds on top of it, not beside it.
- The pre-existing client-side XSS in `explorer.py`'s inline `onclick` handlers
  (`escapeHtml` used where `escapeJs` is required). **Plan 2 rewrites those
  handlers, so it must not reintroduce the pattern** — but fixing it is tracked
  separately and is not this work's deliverable.
- Any change to parsers, rules, the schema, the collector, or the export path.
- `testlab/data_exfil_simulator.py` and `testlab/data_exfil_receiver.py`.

---

## 5. Definition of done

1. No HTML, CSS or JavaScript remains inside a Python f-string in
   `analyzer/lfa/`.
2. `tokens.css` is the single source of colour, type, spacing and radii; a test
   fails if any component stylesheet contains a raw colour literal, and a test
   fails if any referenced token is undefined.
3. A test computes WCAG contrast ratios from the token files and fails below AA
   for text roles, in both themes.
4. The rendered report contains no external `http(s)` reference and no literal
   `**` sequence.
5. The report prints correctly: `@page` rules present, light palette forced,
   findings not split across pages.
6. Charts render deterministically for fixed input and carry text alternatives.
7. Explorer tables sort, filter and paginate; all rows remain present and
   readable with JavaScript disabled.
8. Dashboard and explorer render from real asset files, inlined at serve time,
   with no external fetches.
9. The full suite passes, and every surface still escapes evidence-derived
   values as the hardening branch established.
