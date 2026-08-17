"""Compile config/artifacts.yaml into the pipe-delimited table embedded in
collector/collect.sh (decision D1: POSIX sh cannot parse YAML, and a
collector must remain a single copyable file).

Usage: python tools/gen_artifact_table.py          # rewrite the block in place
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
ARTIFACTS_YAML = REPO / "config" / "artifacts.yaml"
COLLECT_SH = REPO / "collector" / "collect.sh"

BEGIN_MARKER = "# ===BEGIN ARTIFACT TABLE==="
END_MARKER = "# ===END ARTIFACT TABLE==="


def generate_table(yaml_path: Path = ARTIFACTS_YAML) -> str:
    """One line per (artifact id, path): id|category|required|rotated|deep|path"""
    entries = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    lines = []
    for entry in entries:
        required = "1" if entry.get("required") else "0"
        rotated = "1" if entry.get("glob_rotated") else "0"
        deep = "1" if entry.get("deep") else "0"
        for path in entry["paths"]:
            lines.append(
                f"{entry['id']}|{entry['category']}|{required}|{rotated}|{deep}|{path}"
            )
    return "\n".join(lines) + "\n"


def extract_embedded_table(script_path: Path = COLLECT_SH) -> str:
    text = script_path.read_text(encoding="utf-8")
    try:
        start = text.index(BEGIN_MARKER) + len(BEGIN_MARKER)
        end = text.index(END_MARKER)
    except ValueError as exc:
        raise SystemExit(f"{script_path}: artifact table markers missing") from exc
    return text[start:end].lstrip("\n")


def embed_table(script_path: Path = COLLECT_SH, yaml_path: Path = ARTIFACTS_YAML) -> None:
    text = script_path.read_text(encoding="utf-8")
    start = text.index(BEGIN_MARKER) + len(BEGIN_MARKER)
    end = text.index(END_MARKER)
    new_text = text[:start] + "\n" + generate_table(yaml_path) + text[end:]
    script_path.write_text(new_text, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    embed_table()
    print(f"embedded {len(generate_table().splitlines())} artifact rows into {COLLECT_SH}")
    sys.exit(0)
