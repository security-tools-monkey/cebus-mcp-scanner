from __future__ import annotations

from pathlib import Path

import pytest

from mcp_scanner.analyzers.js_ts_analyzer import JavaScriptAnalyzer, TypeScriptAnalyzer
from mcp_scanner.ast_common import CallNode, walk_ast


def _collect_call_callees(source_root) -> list[str]:
    return [
        node.callee
        for node in walk_ast(source_root)
        if isinstance(node, CallNode)
    ]


def test_javascript_analyzer_maps_calls_to_unified_ast(tmp_path: Path) -> None:
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_languages")

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    js_file = project_dir / "mini.js"
    js_file.write_text(
        "const child_process = require('child_process');\n"
        "child_process.exec('ls');\n"
        "fetch('https://example.com');\n",
        encoding="utf-8",
    )

    analyzer = JavaScriptAnalyzer(project_dir)
    source_file = analyzer.load_source_file(str(js_file))

    assert source_file.language == "javascript"
    assert source_file.tree.node_type == "module"

    callees = _collect_call_callees(source_file.tree)
    assert any(callee in {"child_process.exec", "fetch"} for callee in callees)


def test_typescript_analyzer_maps_calls_to_unified_ast(tmp_path: Path) -> None:
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_languages")

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    ts_file = project_dir / "mini.ts"
    ts_file.write_text(
        "import { exec } from 'child_process';\n"
        "const url: string = 'https://example.com';\n"
        "exec('ls');\n"
        "fetch(url);\n",
        encoding="utf-8",
    )

    analyzer = TypeScriptAnalyzer(project_dir)
    source_file = analyzer.load_source_file(str(ts_file))

    assert source_file.language == "typescript"
    assert source_file.tree.node_type == "module"

    callees = _collect_call_callees(source_file.tree)
    assert any(callee in {"exec", "fetch"} for callee in callees)
