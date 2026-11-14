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

# Groups that name a principal. Some log formats quote these — systemd-logind
# writes "New session 'c1' of user 'kali'" — and a quoted value will not join
# against the same username recorded by /etc/passwd or cron. Normalising here
# rather than in each pattern fixes every grammar consumer at once.
_IDENTIFIER_GROUPS = ("user", "target_user", "group")


def _unquote(value: str) -> str:
    """Strip one matched surrounding pair of single or double quotes.

    An apostrophe inside a name is preserved: only a genuine matching pair
    that wraps the whole value is removed.
    """
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


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
                for key in _IDENTIFIER_GROUPS:
                    if key in groups:
                        groups[key] = _unquote(groups[key])
                out.append((name, self.rules[name], groups))
        return out
