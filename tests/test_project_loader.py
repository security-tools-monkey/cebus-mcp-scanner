from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from mcp_scanner.loader.archive_utils import extract_zip_to_tempdir, is_zip_input
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
