"""Decision D1: artifacts.yaml is the source of truth; the collector carries
an embedded compiled table. This test fails whenever they drift."""
from pathlib import Path

import yaml

from tools.gen_artifact_table import generate_table, extract_embedded_table

REPO = Path(__file__).resolve().parent.parent
ARTIFACTS_YAML = REPO / "config" / "artifacts.yaml"
COLLECT_SH = REPO / "collector" / "collect.sh"

VALID_CATEGORIES = {
    "user_accounts",
    "login_activity",
    "privilege_escalation",
    "persistence",
    "software_changes",
    "hardware_usb",
    "network_config",
    "user_activity",
    "environment",
    "audit",
}


def test_artifacts_yaml_is_well_formed():
    entries = yaml.safe_load(ARTIFACTS_YAML.read_text(encoding="utf-8"))
    assert isinstance(entries, list) and entries
    seen_ids = set()
    for entry in entries:
        assert entry["id"] not in seen_ids, f"duplicate id {entry['id']}"
        seen_ids.add(entry["id"])
        assert entry["category"] in VALID_CATEGORIES, entry["id"]
        assert entry["tier"] in {"core", "extended"}, entry["id"]
        assert isinstance(entry["required"], bool), entry["id"]
        assert entry["paths"], entry["id"]
        for path in entry["paths"]:
            assert path.startswith("/"), f"{entry['id']}: {path} not absolute"
            assert "|" not in path, f"{entry['id']}: pipe would break the sh table"


def test_generated_table_lines_have_six_fields():
    table = generate_table(ARTIFACTS_YAML)
    lines = table.strip().splitlines()
    assert lines
    for line in lines:
        parts = line.split("|")
        assert len(parts) == 6, line
        art_id, category, required, rotated, deep, path = parts
        assert required in {"1", "0"}
        assert rotated in {"1", "0"}
        assert deep in {"1", "0"}
        assert path.startswith("/")


def test_embedded_table_in_sync_with_yaml():
    expected = generate_table(ARTIFACTS_YAML)
    embedded = extract_embedded_table(COLLECT_SH)
    assert embedded == expected, (
        "collector/collect.sh artifact table is out of date - "
        "run: python tools/gen_artifact_table.py"
    )
