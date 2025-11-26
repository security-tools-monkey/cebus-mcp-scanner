from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

from .settings import ScanMode, SeverityLevel


@dataclass
class RuleConfig:
    enabled: bool = True
    severity_override: Dict[str, str] = field(default_factory=dict)


@dataclass
class ScannerConfig:
    rules: Dict[str, RuleConfig] = field(default_factory=dict)
    allow_lists: Dict[str, list[str]] = field(default_factory=dict)

    def get_severity_override(
        self, rule_id: str, mode: ScanMode
    ) -> Optional[SeverityLevel]:
        """Get severity override for a rule in a given mode."""
        rule_config = self.rules.get(rule_id)
        if not rule_config or not rule_config.severity_override:
            return None
        mode_str = mode.value
        severity_str = rule_config.severity_override.get(mode_str)
        if severity_str:
            try:
                return SeverityLevel(severity_str.lower())
            except ValueError:
                return None
        return None

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled."""
        rule_config = self.rules.get(rule_id)
        if rule_config is None:
            return True  # Default: enabled
        return rule_config.enabled


def load_config(path: str | Path) -> ScannerConfig:
    """Load scanner configuration from YAML or JSON file."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(config_path, "r", encoding="utf-8") as f:
        if config_path.suffix in (".yaml", ".yml"):
            if yaml is None:
                raise RuntimeError("PyYAML required for YAML config files.")
            data = yaml.safe_load(f) or {}
        elif config_path.suffix == ".json":
            data = json.load(f)
        else:
            raise ValueError(f"Unsupported config format: {config_path.suffix}")

    rules = {}
    if "rules" in data:
        for rule_id, rule_data in data["rules"].items():
            rules[rule_id] = RuleConfig(
                enabled=rule_data.get("enabled", True),
                severity_override=rule_data.get("severity_override", {}),
            )

    allow_lists = data.get("allow_lists", {})

    return ScannerConfig(rules=rules, allow_lists=allow_lists)

