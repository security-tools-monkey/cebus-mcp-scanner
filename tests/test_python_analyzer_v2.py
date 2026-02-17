from __future__ import annotations

from pathlib import Path

from mcp_scanner.analyzers.python_analyzer_v2 import PythonAnalyzer


def test_python_analyzer_v2_syntax_error_returns_minimal_unified_ast(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    bad_file = project_dir / "bad.py"
    bad_file.write_text("def x(:\n    pass\n", encoding="utf-8")

    analyzer = PythonAnalyzer(project_dir)
    sf = analyzer.load_source_file(str(bad_file))

    assert sf.language == "python"
    assert sf.tree is not None
    assert getattr(sf.tree, "node_type", None) == "module"
    assert sf.raw_ast is None  # on SyntaxError path, raw_ast should not be set
