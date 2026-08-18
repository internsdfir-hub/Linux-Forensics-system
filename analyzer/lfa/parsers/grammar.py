"""Grammar engine (spec 2.6.3): regex patterns for text logs live in YAML
files under config/grammars/. New distro or format drift = new config file,
no Python changes. This is the single biggest maintainability decision."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

# distro id -> grammar family file
_FAMILY = {
    "debian": "debian",
    "ubuntu": "debian",
    "linuxmint": "debian",
    "kali": "debian",
    "rhel": "rhel",
    "centos": "rhel",
    "fedora": "rhel",
    "rocky": "rhel",
    "almalinux": "rhel",
    "rhel-family": "rhel",
}


class GrammarEngine:
    def __init__(self, rules: dict[str, dict]):
        self.rules = rules
        self._compiled = {
            name: re.compile(rule["pattern"]) for name, rule in rules.items()
        }

    @classmethod
    def load(cls, grammar_dir: str | Path, distro_id: str) -> "GrammarEngine":
        grammar_dir = Path(grammar_dir)
        rules: dict[str, dict] = {}
        files = ["common.yaml"]
        family = _FAMILY.get((distro_id or "").lower())
        if family:
            files.append(f"{family}.yaml")
        for fname in files:
            path = grammar_dir / fname
            if not path.exists():
                continue
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for name, rule in loaded.items():
                rule.setdefault("severity", "info")
                rules[name] = rule
        return cls(rules)

    def match_line(self, line: str) -> list[tuple[str, dict, dict]]:
        """Return every (rule_name, rule, groupdict) whose pattern matches.
        A single line may legitimately yield multiple events - parsers yield
        freely rather than forcing one line into one bucket."""
        out = []
        for name, regex in self._compiled.items():
            m = regex.search(line)
            if m:
                groups = {k: v for k, v in m.groupdict().items() if v is not None}
                out.append((name, self.rules[name], groups))
        return out
