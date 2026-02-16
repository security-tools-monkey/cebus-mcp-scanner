from __future__ import annotations

from pathlib import Path

import pytest

from mcp_scanner.analyzers.multi_analyzer import MultiLanguageAnalyzer
from mcp_scanner.ast_common import ASTNode
from mcp_scanner.scanner import ScanResult, Scanner
from mcp_scanner.settings import ScanMode


@pytest.fixture()
def mini_project(tmp_path: Path) -> Path:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "mini.py").write_text(
        "def hello():\n    return 'hi'\n",
        encoding="utf-8",
    )
    return project_dir


def test_scanner_scan_returns_result_and_no_error_findings(
    mini_project: Path,
) -> None:
    scanner = Scanner(languages=["python"])
    result = scanner.scan(str(mini_project), ScanMode.SHARED)

    assert isinstance(result, ScanResult)
    assert all(not f.rule_id.endswith("_ERROR") for f in result.findings)


def test_multi_language_analyzer_iter_source_files_smoke(
    mini_project: Path,
) -> None:
    analyzer = MultiLanguageAnalyzer(root=str(mini_project), languages=["python"])
    source_files = list(analyzer.iter_source_files())

    assert len(source_files) == 1

    source_file = source_files[0]
    assert isinstance(source_file.content, str)
    assert isinstance(source_file.tree, ASTNode)
    assert source_file.language
