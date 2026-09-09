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
