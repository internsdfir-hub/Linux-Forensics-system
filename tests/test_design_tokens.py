"""The design-token layer is enforced mechanically, not by review.

Three properties matter and each has a test: component stylesheets never
hardcode a colour, every referenced token is defined, and text meets WCAG AA
contrast against its own surface in both themes.
"""
import re

import pytest

from lfa.ui import assets

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
