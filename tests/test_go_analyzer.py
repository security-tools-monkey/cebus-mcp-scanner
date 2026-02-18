from __future__ import annotations

from pathlib import Path
import shutil

import pytest

from mcp_scanner.analyzers.go_analyzer import GoAnalyzer
from mcp_scanner.ast_common import CallNode, walk_ast


def _collect_call_callees(source_root) -> list[str]:
    return [
        node.callee
        for node in walk_ast(source_root)
        if isinstance(node, CallNode)
    ]


def _skip_if_go_unavailable() -> None:
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_languages")
    if shutil.which("go") is None:
        pytest.skip("Go toolchain not available")


def test_go_analyzer_maps_calls_to_unified_ast(tmp_path: Path) -> None:
    _skip_if_go_unavailable()

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    go_file = project_dir / "mini.go"
    go_file.write_text(
        "package main\n"
        "import (\n"
        "  \"net/http\"\n"
        "  \"os/exec\"\n"
        ")\n"
        "func main() {\n"
        "  http.Get(\"https://example.com\")\n"
        "  exec.Command(\"ls\")\n"
        "}\n",
        encoding="utf-8",
    )

    analyzer = GoAnalyzer(project_dir)
    source_file = analyzer.load_source_file(str(go_file))

    assert source_file.language == "go"
    assert source_file.tree.node_type == "module"

    callees = _collect_call_callees(source_file.tree)
    assert any(callee in {"http.Get", "exec.Command"} for callee in callees)
