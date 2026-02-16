from __future__ import annotations

import json
from pathlib import Path

from mcp_scanner.loader.project_loader import load_project


def test_load_project_parses_schema_manifest_mcp_json(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    (project_dir / "mcp.json").write_text(
        json.dumps(
            {
                "tools": [
                    {"name": "tool_a", "description": "A"},
                    {"name": "tool_b", "description": "B"},
                ],
                "server": {"name": "demo"},
                "env": {"MODE": "local"},
            }
        ),
        encoding="utf-8",
    )

    project = load_project(str(project_dir))
    assert project.root == project_dir.resolve()
    assert project.manifest is not None
    assert len(project.manifest.tools) == 2
    assert project.manifest.server == {"name": "demo"}
    assert project.manifest.env == {"MODE": "local"}


def test_load_project_falls_back_to_package_json_common_layout(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    (project_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "demo",
                "mcpServer": {
                    "server": {"name": "pkg"},
                    "tools": [{"name": "t1"}],
                },
            }
        ),
        encoding="utf-8",
    )

    project = load_project(str(project_dir))
    assert project.manifest is not None
    assert project.manifest.server == {"name": "pkg"}
    assert project.manifest.tools == [{"name": "t1"}]


def test_load_project_returns_manifest_none_when_no_indicators(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    project = load_project(str(project_dir))
    assert project.manifest is None
