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
    ImportNode,
    AssignmentNode,
    AttributeNode,
    SourceFile,
)


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
            callee_name = JSTsASTMapper._build_callee_name(callee_node, source) if callee_node else "<unknown>"
            if not callee_name:
                callee_name = "<unknown>"
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

        # Attribute access
        if node_type in {"member_expression"}:
            obj_node = JSTsASTMapper._find_member_object(ts_node)
            prop_node = JSTsASTMapper._find_member_property(ts_node)
            value_node = JSTsASTMapper.map_node(obj_node, source, language, parent=None) if obj_node else None
            attr_name = JSTsASTMapper._build_callee_name(prop_node, source) if prop_node else ""
            attr_node = AttributeNode(
                value=value_node,
                attr=attr_name or "",
                line=line,
                column=col,
                parent=parent,
                language=language,
                raw_node=ts_node,
            )
            if value_node is not None:
                value_node.parent = attr_node
            return attr_node

        # Imports
        if node_type in {"import_statement", "import_clause"}:
            return JSTsASTMapper._map_import(ts_node, source, language, parent)

        # Variable declarations / assignments
        if node_type in {"variable_declaration", "lexical_declaration"}:
            return JSTsASTMapper._map_assignment(ts_node, source, language, parent)

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
        if node_type in {"identifier", "property_identifier", "private_property_identifier"}:
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
    def _child_by_field(ts_node: Any, field: str) -> Optional[Any]:
        try:
            return ts_node.child_by_field_name(field)
        except Exception:  # pragma: no cover
            return None

    @staticmethod
    def _find_member_object(ts_node: Any) -> Optional[Any]:
        obj = JSTsASTMapper._child_by_field(ts_node, "object")
        if obj is not None:
            return obj
        for child in ts_node.children:
            if child.type not in {".", "?.", "?"}:
                return child
        return None

    @staticmethod
    def _find_member_property(ts_node: Any) -> Optional[Any]:
        prop = JSTsASTMapper._child_by_field(ts_node, "property")
        if prop is not None:
            return prop
        for child in reversed(ts_node.children):
            if child.type not in {".", "?.", "?"}:
                return child
        return None

    @staticmethod
    def _find_callee_node(ts_node: Any) -> Optional[Any]:
        # For call_expression/new_expression, the callee is usually the first child
        # that is an identifier or member_expression
        for child in ts_node.children:
            if child.type in {"identifier", "member_expression", "optional_member_expression"}:
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
    def _build_callee_name(ts_node: Optional[Any], source: str) -> str:
        if ts_node is None:
            return ""
        node_type = ts_node.type
        if node_type in {"identifier", "property_identifier", "private_property_identifier"}:
            return JSTsASTMapper._node_text(ts_node, source)
        if node_type in {"this", "super"}:
            return node_type
        if node_type in {"member_expression", "optional_member_expression"}:
            obj_node = JSTsASTMapper._find_member_object(ts_node)
            prop_node = JSTsASTMapper._find_member_property(ts_node)
            obj_name = JSTsASTMapper._build_callee_name(obj_node, source)
            prop_name = JSTsASTMapper._build_callee_name(prop_node, source)
            if obj_name and prop_name:
                return f"{obj_name}.{prop_name}"
            return obj_name or prop_name
        if node_type == "subscript_expression":
            obj_node = JSTsASTMapper._child_by_field(ts_node, "object")
            idx_node = JSTsASTMapper._child_by_field(ts_node, "index")
            obj_name = JSTsASTMapper._build_callee_name(obj_node, source)
            idx_name = JSTsASTMapper._string_literal_value(idx_node, source) if idx_node else ""
            if obj_name and idx_name:
                return f"{obj_name}.{idx_name}"
            return obj_name
        return JSTsASTMapper._node_text(ts_node, source)

    @staticmethod
    def _string_literal_value(ts_node: Optional[Any], source: str) -> Optional[str]:
        if ts_node is None:
            return None
        if ts_node.type in {"string", "string_fragment", "template_string"}:
            return JSTsASTMapper._strip_string_quotes(JSTsASTMapper._node_text(ts_node, source))
        return None

    @staticmethod
    def _map_import(ts_node: Any, source: str, language: str, parent: Optional[ASTNode]) -> ImportNode:
        module = JSTsASTMapper._find_import_module(ts_node, source)
        imports, alias = JSTsASTMapper._parse_import_clause(ts_node, source)
        return ImportNode(
            module=module,
            imports=imports,
            alias=alias,
            line=JSTsASTMapper._position(ts_node)[0],
            column=JSTsASTMapper._position(ts_node)[1],
            parent=parent,
            language=language,
            raw_node=ts_node,
        )

    @staticmethod
    def _find_import_module(ts_node: Any, source: str) -> str:
        for node in [ts_node, getattr(ts_node, "parent", None)]:
            if not node:
                continue
            for child in node.children:
                if child.type in {"string", "string_fragment", "template_string"}:
                    text = JSTsASTMapper._node_text(child, source)
                    return JSTsASTMapper._strip_string_quotes(text)
        return ""

    @staticmethod
    def _parse_import_clause(ts_node: Any, source: str) -> tuple[list[str], Optional[str]]:
        imports: list[str] = []
        alias: Optional[str] = None

        clause = ts_node
        if ts_node.type == "import_statement":
            for child in ts_node.children:
                if child.type == "import_clause":
                    clause = child
                    break
            else:
                return imports, alias

        for child in clause.children:
            if child.type == "identifier":
                alias = JSTsASTMapper._node_text(child, source)
            elif child.type == "namespace_import":
                name_node = JSTsASTMapper._child_by_field(child, "name")
                if name_node:
                    alias = JSTsASTMapper._node_text(name_node, source)
                if "*" not in imports:
                    imports.append("*")
            elif child.type == "named_imports":
                for spec in child.children:
                    if spec.type != "import_specifier":
                        continue
                    name_node = JSTsASTMapper._child_by_field(spec, "name")
                    if name_node is None:
                        for sub in spec.children:
                            if sub.type == "identifier":
                                name_node = sub
                                break
                    if name_node is not None:
                        imports.append(JSTsASTMapper._node_text(name_node, source))
        return imports, alias

    @staticmethod
    def _map_assignment(ts_node: Any, source: str, language: str, parent: Optional[ASTNode]) -> AssignmentNode:
        declarator = None
        for child in ts_node.children:
            if child.type == "variable_declarator":
                declarator = child
                break

        target_node: Optional[ASTNode] = None
        value_node: Optional[ASTNode] = None
        value_ts: Optional[Any] = None
        if declarator is not None:
            target_ts = JSTsASTMapper._child_by_field(declarator, "name") or JSTsASTMapper._child_by_field(declarator, "id")
            value_ts = JSTsASTMapper._child_by_field(declarator, "value") or JSTsASTMapper._child_by_field(declarator, "initializer")
            if target_ts is not None:
                target_node = JSTsASTMapper.map_node(target_ts, source, language, parent=None)
            if value_ts is not None:
                value_node = JSTsASTMapper.map_node(value_ts, source, language, parent=None)

        assign_node = AssignmentNode(
            target=target_node,
            value=value_node,
            line=JSTsASTMapper._position(ts_node)[0],
            column=JSTsASTMapper._position(ts_node)[1],
            parent=parent,
            language=language,
            raw_node=ts_node,
        )

        if target_node is not None:
            target_node.parent = assign_node
        if value_node is not None:
            value_node.parent = assign_node

        # Best-effort require("module") aliasing
        if value_ts is not None and value_ts.type == "call_expression":
            callee = JSTsASTMapper._find_callee_node(value_ts)
            callee_name = JSTsASTMapper._build_callee_name(callee, source)
            if callee_name == "require":
                args = JSTsASTMapper._find_argument_nodes(value_ts)
                module_name = JSTsASTMapper._string_literal_value(args[0], source) if args else None
                alias_name = JSTsASTMapper._extract_identifier_name(target_node)
                if module_name:
                    import_node = ImportNode(
                        module=module_name,
                        imports=[],
                        alias=alias_name,
                        line=JSTsASTMapper._position(value_ts)[0],
                        column=JSTsASTMapper._position(value_ts)[1],
                        parent=assign_node,
                        language=language,
                        raw_node=value_ts,
                    )
                    assign_node.value = import_node

        return assign_node

    @staticmethod
    def _extract_identifier_name(node: Optional[ASTNode]) -> Optional[str]:
        if node is None:
            return None
        if isinstance(node, VariableNode):
            return node.name
        if isinstance(node, AttributeNode) and node.attr:
            return node.attr
        return None
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

