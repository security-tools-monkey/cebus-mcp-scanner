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
from ..ast_common import (
    ASTNode,
    CallNode,
    LiteralNode,
    VariableNode,
    SourceFile,
)


try:  # pragma: no cover - optional dependency
    from tree_sitter import Parser  # type: ignore
    from tree_sitter_languages import get_language  # type: ignore
except Exception:  # pragma: no cover
    Parser = None  # type: ignore[assignment]
    get_language = None  # type: ignore[assignment]


JS_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs"}
TS_EXTENSIONS = {".ts", ".tsx"}

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


class JSTsASTMapper:
    """
    Mapper from tree-sitter JS/TS AST to unified AST.

    This is intentionally conservative: it focuses on the constructs that
    security rules care about most (function calls, literals, identifiers).
    """

    @staticmethod
    def map_module(root: Any, source: str, language: str) -> ASTNode:
        node = ASTNode(
            node_type="module",
            line=None,
            column=None,
            language=language,
            raw_node=root,
        )
        for child in root.children:
            child_node = JSTsASTMapper.map_node(child, source, language, parent=node)
            if child_node is not None:
                node.children.append(child_node)
        return node

    @staticmethod
    def map_node(ts_node: Any, source: str, language: str, parent: Optional[ASTNode] = None) -> Optional[ASTNode]:
        node_type = ts_node.type
        line, col = JSTsASTMapper._position(ts_node)

        # Function / method calls
        if node_type in {"call_expression", "new_expression"}:
            callee_node = JSTsASTMapper._find_callee_node(ts_node)
            callee_name = JSTsASTMapper._node_text(callee_node, source) if callee_node else "<unknown>"
            call_node = CallNode(
                callee=callee_name,
                arguments=[],
                keyword_arguments={},
                line=line,
                column=col,
                parent=parent,
                language=language,
                raw_node=ts_node,
            )

            # Map arguments (best-effort)
            arg_nodes = JSTsASTMapper._find_argument_nodes(ts_node)
            for arg_ts in arg_nodes:
                arg_node = JSTsASTMapper.map_node(arg_ts, source, language, parent=call_node)
                if arg_node is not None:
                    call_node.arguments.append(arg_node)
            return call_node

        # Literals
        if node_type in {"string", "string_fragment", "template_string"}:
            text = JSTsASTMapper._node_text(ts_node, source)
            value = JSTsASTMapper._strip_string_quotes(text)
            return LiteralNode(
                value=value,
                literal_type="string",
                line=line,
                column=col,
                parent=parent,
                language=language,
                raw_node=ts_node,
            )

        if node_type in {"number"}:
            text = JSTsASTMapper._node_text(ts_node, source)
            return LiteralNode(
                value=text,
                literal_type="number",
                line=line,
                column=col,
                parent=parent,
                language=language,
                raw_node=ts_node,
            )

        if node_type in {"true", "false"}:
            value = node_type == "true"
            return LiteralNode(
                value=value,
                literal_type="boolean",
                line=line,
                column=col,
                parent=parent,
                language=language,
                raw_node=ts_node,
            )

        if node_type in {"null"}:
            return LiteralNode(
                value=None,
                literal_type="null",
                line=line,
                column=col,
                parent=parent,
                language=language,
                raw_node=ts_node,
            )

        # Identifiers / variables
        if node_type in {"identifier"}:
            name = JSTsASTMapper._node_text(ts_node, source)
            return VariableNode(
                name=name,
                line=line,
                column=col,
                parent=parent,
                language=language,
                raw_node=ts_node,
            )

        # Generic node: recurse into children but don't specialize
        node = ASTNode(
            node_type=node_type,
            line=line,
            column=col,
            parent=parent,
            language=language,
            raw_node=ts_node,
        )
        for child in ts_node.children:
            child_node = JSTsASTMapper.map_node(child, source, language, parent=node)
            if child_node is not None:
                node.children.append(child_node)
        return node

    @staticmethod
    def _position(ts_node: Any) -> tuple[int | None, int | None]:
        try:
            row, col = ts_node.start_point  # (row, column), 0-based
            return row + 1, col + 1
        except Exception:  # pragma: no cover
            return None, None

    @staticmethod
    def _node_text(ts_node: Any, source: str) -> str:
        try:
            return source[ts_node.start_byte : ts_node.end_byte]
        except Exception:  # pragma: no cover
            return ""

    @staticmethod
    def _find_callee_node(ts_node: Any) -> Optional[Any]:
        # For call_expression/new_expression, the callee is usually the first child
        # that is an identifier or member_expression
        for child in ts_node.children:
            if child.type in {"identifier", "member_expression"}:
                return child
        return ts_node.children[0] if ts_node.children else None

    @staticmethod
    def _find_argument_nodes(ts_node: Any) -> list[Any]:
        # Heuristic: look for "arguments" child or argument_list-like nodes
        args: list[Any] = []
        for child in ts_node.children:
            if child.type in {"arguments", "argument_list"}:
                args.extend(child.children)
        return [n for n in args if n.type not in {",", "(", ")"}]

    @staticmethod
    def _strip_string_quotes(text: str) -> str:
        if len(text) >= 2 and text[0] in {"'", '"', "`"} and text[-1] == text[0]:
            return text[1:-1]
        return text


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



