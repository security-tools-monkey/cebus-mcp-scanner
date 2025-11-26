from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..ast_common import SourceFile, ASTNode
from ..rules.base import Analyzer

EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    "venv",
    ".venv",
    "node_modules",
    "dist",
    "build",
}


@dataclass
class PythonFile:
    path: Path
    content: str
    tree: ast.AST | ASTNode  # Can be Python AST or unified AST


class ProjectAnalyzer(Analyzer):
    """
    Legacy Python-only analyzer.
    
    Maintains backward compatibility while also implementing the new interface.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()

    def iter_source_files(self) -> Iterable[SourceFile]:
        """New interface: iterate over source files."""
        for path_str in self.iter_python_files():
            source_file = self.load_python_file(path_str)
            # Convert to SourceFile format
            # For legacy analyzer, tree is Python AST, not unified
            yield SourceFile(
                path=source_file.path,
                content=source_file.content,
                language="python",
                tree=source_file.tree,  # Python AST in legacy mode
                raw_ast=source_file.tree if isinstance(source_file.tree, ast.AST) else None,
            )

    def iter_python_files(self) -> Iterable[str]:
        """Legacy method: iterate over Python file paths."""
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
            for filename in filenames:
                if filename.endswith(".py"):
                    yield str(Path(dirpath) / filename)

    def open_file(self, path: str) -> str:
        """Get raw file content."""
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def load_python_file(self, path: str) -> PythonFile:
        """Legacy method: load Python file with Python AST."""
        content = self.open_file(path)
        try:
            tree = ast.parse(content, filename=path)
        except SyntaxError:
            # On syntax error, create a minimal tree
            tree = ast.Module(body=[], type_ignores=[])
        return PythonFile(path=Path(path), content=content, tree=tree)

