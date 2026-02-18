from __future__ import annotations

from pathlib import Path
import shutil

import pytest

from mcp_scanner.analyzers.rust_analyzer import RustAnalyzer
from mcp_scanner.ast_common import CallNode, walk_ast


def _collect_call_callees(source_root) -> list[str]:
    return [
        node.callee
        for node in walk_ast(source_root)
        if isinstance(node, CallNode)
    ]


def _skip_if_rust_unavailable() -> None:
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_languages")

    try:
        from tree_sitter import Parser
        from tree_sitter_languages import get_language

        rust_lang = get_language("rust")
        parser = Parser()
        parser.set_language(rust_lang)
    except Exception:
        pytest.skip("Rust tree-sitter grammar not available")

    if shutil.which("rustc") is None and shutil.which("cargo") is None:
        pytest.skip("Rust toolchain not available")


def test_rust_analyzer_maps_calls_to_unified_ast(tmp_path: Path) -> None:
    _skip_if_rust_unavailable()

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    rust_file = project_dir / "mini.rs"
    rust_file.write_text(
        "use std::process::Command;\n"
        "fn main() {\n"
        "  Command::new(\"ls\");\n"
        "  reqwest::get(\"https://example.com\");\n"
        "}\n",
        encoding="utf-8",
    )

    analyzer = RustAnalyzer(project_dir)
    source_file = analyzer.load_source_file(str(rust_file))

    assert source_file.language == "rust"
    assert source_file.tree.node_type == "module"

    callees = _collect_call_callees(source_file.tree)
    assert any(callee in {"Command::new", "reqwest::get"} for callee in callees)
