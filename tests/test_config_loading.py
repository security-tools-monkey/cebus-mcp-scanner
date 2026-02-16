from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_scanner.config import ScannerConfig, load_config
from mcp_scanner.settings import ScanMode, SeverityLevel


def test_load_config_json_roundtrip(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(
        json.dumps(
            {
                "rules": {
                    "RCE001": {
                        "enabled": False,
                        "severity_override": {"shared": "info"},
                    }
                },
                "allow_lists": {"http_hosts": ["example.com"]},
            }
        ),
        encoding="utf-8",
    )

    cfg = load_config(cfg_path)

    assert isinstance(cfg, ScannerConfig)
    assert cfg.is_rule_enabled("RCE001") is False
    assert cfg.is_rule_enabled("SOME_UNKNOWN_RULE") is True  # default enabled
    assert cfg.allow_lists["http_hosts"] == ["example.com"]
    assert cfg.get_severity_override("RCE001", ScanMode.SHARED) == SeverityLevel.INFO


def test_load_config_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "does_not_exist.yaml")


def test_load_config_unsupported_suffix_raises(tmp_path: Path) -> None:
    bad_path = tmp_path / "config.txt"
    bad_path.write_text("rules: {}", encoding="utf-8")

    with pytest.raises(ValueError):
        load_config(bad_path)


def test_get_severity_override_invalid_value_returns_none() -> None:
    cfg = ScannerConfig(
        rules={
            "RCE001": {
                # This mirrors the internal shape RuleConfig expects,
                # but we only care that parsing invalid values yields None.
                # load_config() would normally build RuleConfig objects.
            }
        }
    )

    # Directly create a valid structure via load_config-style behavior:
    # easiest is to just reassign a minimal RuleConfig-like object.
    from mcp_scanner.config import RuleConfig

    cfg.rules["RCE001"] = RuleConfig(severity_override={ScanMode.SHARED.value: "not-a-level"})

    assert cfg.get_severity_override("RCE001", ScanMode.SHARED) is None


def test_load_config_yaml_if_available(tmp_path: Path) -> None:
    yaml = pytest.importorskip("yaml")

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "rules": {"RCE001": {"enabled": True, "severity_override": {"shared": "medium"}}},
                "allow_lists": {"paths": ["./safe"]},
            }
        ),
        encoding="utf-8",
    )

    cfg = load_config(cfg_path)
    assert cfg.get_severity_override("RCE001", ScanMode.SHARED) == SeverityLevel.MEDIUM
    assert cfg.allow_lists["paths"] == ["./safe"]
