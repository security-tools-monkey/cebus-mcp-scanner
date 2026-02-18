"""
Rust language analyzer (skeleton) implementing the LanguageAnalyzer interface.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable, Optional

from .base import LanguageAnalyzer
from .language_detector import EXCLUDED_DIRS
from ..ast_common import SourceFile, ASTNode
from .rust_mapper import RustASTMapper

try:
    from tree_sitter import Parser  # type: ignore
    from tree_sitter_languages import get_language  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Parser = None  # type: ignore[assignment]
    get_language = None  # type: ignore[assignment]


class RustAnalyzer(LanguageAnalyzer):
    """Rust language analyzer using tree-sitter."""

    def __init__(self, root: str | Path) -> None:
        super().__init__(root)
        self._parser: Optional[Any] = None

        if Parser is None or get_language is None:  # pragma: no cover
            return

        try:
            rust_lang = get_language("rust")
            parser = Parser()
            parser.set_language(rust_lang)
            self._parser = parser
        except Exception:
            self._parser = None

    @property
    def language(self) -> str:
        return "rust"

    def iter_source_files(self) -> Iterable[str]:
        """Iterate over Rust source files."""
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
            for filename in filenames:
                if filename.endswith(".rs"):
                    yield str(Path(dirpath) / filename)

    def load_source_file(self, path: str) -> SourceFile:
        """Load and parse a Rust source file."""
        content = self.open_file(path)
        tree = self.parse_to_unified_ast(content, path)
        return SourceFile(
            path=Path(path),
            content=content,
            language="rust",
            tree=tree,
            raw_ast=None,
        )

    def parse_to_unified_ast(self, content: str, path: str) -> ASTNode:
        """
        Parse Rust code to a minimal unified AST.

        Returns an empty module AST if parsing fails or dependencies are missing.
        """
        if not self._parser:
            return ASTNode(
                node_type="module",
                line=None,
                column=None,
                language="rust",
                raw_node=None,
            )

        try:
            tree = self._parser.parse(bytes(content, "utf-8"))
            return RustASTMapper.map_module(tree.root_node, content, "rust")
        except Exception:  # pragma: no cover
            return ASTNode(
                node_type="module",
                line=None,
                column=None,
                language="rust",
                raw_node=None,
            )
