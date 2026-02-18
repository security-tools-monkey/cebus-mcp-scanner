"""
JavaScript / TypeScript analyzers using tree-sitter.

These analyzers implement the LanguageAnalyzer interface and produce a unified
AST so that existing rules can work across JS/TS codebases.

Dependencies (not installed by default):
- tree-sitter
- tree-sitter-languages  (https://github.com/grantjenks/python-tree-sitter-languages)

If these dependencies are not available at runtime, the analyzers will
gracefully degrade by returning an empty module AST, and MultiLanguageAnalyzer
will still function for other languages.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Optional, Any

from .base import LanguageAnalyzer
from .js_ts_mapper import JSTsASTMapper
from ..ast_common import ASTNode, SourceFile


try:  # pragma: no cover - optional dependency
    from tree_sitter import Parser  # type: ignore
    from tree_sitter_languages import get_language  # type: ignore
except Exception:  # pragma: no cover
    Parser = None  # type: ignore[assignment]
    get_language = None  # type: ignore[assignment]


JS_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs"}
TS_EXTENSIONS = {".ts", ".tsx", ".mts", ".cts"}

EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    "venv",
    ".venv",
    "node_modules",
    "dist",
    "build",
    ".next",
}


class _BaseJSTSAnalyzer(LanguageAnalyzer):
    """Shared functionality for JS / TS analyzers."""

    def __init__(self, root: str | Path, ts_language_name: str, language_id: str) -> None:
        super().__init__(root)
        self._language = language_id
        self._ts_language_name = ts_language_name
        self._parser: Optional[Any] = None

        if Parser is None or get_language is None:  # pragma: no cover
            # Dependencies unavailable; analyzer will return empty ASTs
            return

        try:
            ts_lang = get_language(ts_language_name)
            parser = Parser()
            parser.set_language(ts_lang)
            self._parser = parser
        except Exception:
            # If tree-sitter setup fails, gracefully degrade
            self._parser = None

    @property
    def language(self) -> str:
        return self._language

    def iter_source_files(self) -> Iterable[str]:
        exts = JS_EXTENSIONS if self._language == "javascript" else TS_EXTENSIONS
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
            for filename in filenames:
                if Path(filename).suffix in exts:
                    yield str(Path(dirpath) / filename)

    def load_source_file(self, path: str) -> SourceFile:
        content = self.open_file(path)
        tree = self.parse_to_unified_ast(content, path)
        return SourceFile(
            path=Path(path),
            content=content,
            language=self._language,
            tree=tree,
            raw_ast=None,
        )

    def parse_to_unified_ast(self, content: str, path: str) -> ASTNode:
        if not self._parser:
            # Dependencies missing or parser init failed; return empty module
            return ASTNode(
                node_type="module",
                line=None,
                column=None,
                language=self._language,
                raw_node=None,
            )

        try:
            tree = self._parser.parse(bytes(content, "utf-8"))
            root_node = tree.root_node
            return JSTsASTMapper.map_module(root_node, content, self._language)
        except Exception:  # pragma: no cover
            return ASTNode(
                node_type="module",
                line=None,
                column=None,
                language=self._language,
                raw_node=None,
            )


class JavaScriptAnalyzer(_BaseJSTSAnalyzer):
    """JavaScript analyzer using tree-sitter."""

    def __init__(self, root: str | Path) -> None:
        super().__init__(root, ts_language_name="javascript", language_id="javascript")


class TypeScriptAnalyzer(_BaseJSTSAnalyzer):
    """TypeScript analyzer using tree-sitter."""

    def __init__(self, root: str | Path) -> None:
        super().__init__(root, ts_language_name="typescript", language_id="typescript")
