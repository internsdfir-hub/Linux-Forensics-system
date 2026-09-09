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
