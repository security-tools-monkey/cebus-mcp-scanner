from __future__ import annotations

from pathlib import Path

from mcp_scanner.analyzers.analyzer_adapter import AnalyzerAdapter
from mcp_scanner.analyzers.multi_analyzer import MultiLanguageAnalyzer
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


def test_analyzer_adapter_open_file_uses_cache_after_iteration(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    f = project_dir / "a.py"
    content = "print('hello')\n"
    f.write_text(content, encoding="utf-8")

    multi = MultiLanguageAnalyzer(root=project_dir, languages=["python"])
    adapter = AnalyzerAdapter(multi)

    # Populate adapter cache
    source_files = list(adapter.iter_source_files())
    assert len(source_files) == 1

    # Now open_file should be served from cache (functionally: same content)
    got = adapter.open_file(str(f))
    assert got == content
