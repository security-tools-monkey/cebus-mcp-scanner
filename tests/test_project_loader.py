from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from mcp_scanner.loader.archive_utils import extract_zip_to_tempdir, is_zip_input
from mcp_scanner.loader.project_loader import load_project


def _write_manifest(root: Path, *, tool_name: str = "tool_a") -> None:
    (root / "mcp.json").write_text(
        json.dumps(
            {
                "tools": [{"name": tool_name, "description": "A"}],
                "server": {"name": "demo"},
                "env": {"MODE": "local"},
            }
        ),
        encoding="utf-8",
    )


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


def test_is_zip_input_requires_zip_suffix_and_signature(tmp_path: Path) -> None:
    valid_zip = tmp_path / "project.zip"
    with zipfile.ZipFile(valid_zip, "w") as zf:
        zf.writestr("mcp.json", "{}")

    assert is_zip_input(valid_zip) is True

    fake_zip = tmp_path / "fake.zip"
    fake_zip.write_text("not a zip", encoding="utf-8")
    assert is_zip_input(fake_zip) is False

    non_zip_suffix = tmp_path / "archive.dat"
    with zipfile.ZipFile(non_zip_suffix, "w") as zf:
        zf.writestr("mcp.json", "{}")
    assert is_zip_input(non_zip_suffix) is False


def test_extract_zip_rejects_zip_slip(tmp_path: Path) -> None:
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../evil.txt", "nope")

    with pytest.raises(ValueError, match="Unsafe path"):
        with extract_zip_to_tempdir(zip_path):
            pass


def test_load_project_zip_with_single_root_directory(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    _write_manifest(project_dir, tool_name="zip_tool")

    zip_path = tmp_path / "project.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(project_dir / "mcp.json", arcname="project/mcp.json")

    folder_project = load_project(str(project_dir))
    project = load_project(str(zip_path))
    assert project.root.name == "project"
    assert project.manifest is not None
    assert project.manifest.tools == [{"name": "zip_tool", "description": "A"}]
    assert project.manifest == folder_project.manifest
    assert project.temp_dir is not None
    assert project.cleanup is not None

    project.cleanup()
    assert project.temp_dir.exists() is False


def test_load_project_zip_with_flat_root(tmp_path: Path) -> None:
    zip_path = tmp_path / "flat.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "mcp.json",
            json.dumps(
                {
                    "tools": [{"name": "flat_tool", "description": "A"}],
                    "server": {"name": "demo"},
                }
            ),
        )

    project = load_project(str(zip_path))
    assert project.root == project.temp_dir
    assert project.manifest is not None
    assert project.manifest.tools == [{"name": "flat_tool", "description": "A"}]
