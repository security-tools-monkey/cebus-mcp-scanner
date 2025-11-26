"""
Python language analyzer implementing the new LanguageAnalyzer interface.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Iterable

from .base import LanguageAnalyzer
from .python_mapper import PythonASTMapper
from ..ast_common import SourceFile, ASTNode

EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    "venv",
    ".venv",
    "node_modules",
    "dist",
    "build",
}


class PythonAnalyzer(LanguageAnalyzer):
    """Python language analyzer using unified AST."""

    @property
    def language(self) -> str:
        return "python"

    def iter_source_files(self) -> Iterable[str]:
        """Iterate over Python source files."""
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
            for filename in filenames:
                if filename.endswith(".py"):
                    yield str(Path(dirpath) / filename)

    def load_source_file(self, path: str) -> SourceFile:
        """Load and parse a Python source file."""
        content = self.open_file(path)
        try:
            py_tree = ast.parse(content, filename=path)
            unified_tree = PythonASTMapper.map_module(py_tree)
        except SyntaxError:
            # On syntax error, create a minimal tree
            unified_tree = ASTNode(
                node_type="module",
                line=None,
                language="python",
            )

        return SourceFile(
            path=Path(path),
            content=content,
            language="python",
            tree=unified_tree,
            raw_ast=py_tree if 'py_tree' in locals() else None,
        )

    def parse_to_unified_ast(self, content: str, path: str) -> ASTNode:
        """Parse Python code to unified AST."""
        try:
            py_tree = ast.parse(content, filename=path)
            return PythonASTMapper.map_module(py_tree)
        except SyntaxError:
            return ASTNode(
                node_type="module",
                line=None,
                language="python",
            )


