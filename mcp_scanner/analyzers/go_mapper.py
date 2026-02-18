"""
Mapper from Go tree-sitter AST to unified AST.
"""

from __future__ import annotations

from typing import Any, Optional

from ..ast_common import (
    ASTNode,
    AttributeNode,
    CallNode,
    ImportNode,
    LiteralNode,
    VariableNode,
)


class GoASTMapper:
    """
    Mapper from tree-sitter Go AST to unified AST.

    This mapper is intentionally conservative: it only specializes nodes
    that are required by existing rules, and it should never crash on
    unknown nodes.
    """

    _IDENTIFIER_TYPES = {
        "identifier",
        "field_identifier",
        "package_identifier",
        "type_identifier",
        "blank_identifier",
    }

    _STRING_LITERAL_TYPES = {
        "interpreted_string_literal",
        "raw_string_literal",
    }

    _INT_LITERAL_TYPES = {
        "int_literal",
    }

    _FLOAT_LITERAL_TYPES = {
        "float_literal",
    }

    _BOOL_LITERAL_TYPES = {
        "true",
        "false",
    }

    @staticmethod
    def map_module(root: Any, source: str, language: str = "go") -> ASTNode:
        node = ASTNode(
            node_type="module",
            line=None,
            column=None,
            language=language,
            raw_node=root,
        )
        for child in getattr(root, "children", []):
            child_node = GoASTMapper.map_node(child, source, language, parent=node)
            if child_node is not None:
                node.children.append(child_node)
        return node

    @staticmethod
    def map_node(
        ts_node: Any,
        source: str,
        language: str = "go",
        parent: Optional[ASTNode] = None,
    ) -> Optional[ASTNode]:
        try:
            node_type = ts_node.type
        except Exception:  # pragma: no cover - defensive
            return None

        line, col = GoASTMapper._position(ts_node)

        try:
            # Function calls
            if node_type == "call_expression":
                callee_node = GoASTMapper._child_by_field(ts_node, "function")
                if callee_node is None:
                    callee_node = GoASTMapper._find_callee_node(ts_node)
                callee_name = GoASTMapper._build_callee_name(callee_node, source) or "<unknown>"

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

                for arg_ts in GoASTMapper._find_argument_nodes(ts_node):
                    arg_node = GoASTMapper.map_node(arg_ts, source, language, parent=call_node)
                    if arg_node is not None:
                        call_node.arguments.append(arg_node)

                return call_node

            # Selector expressions (pkg.Func, obj.Field)
            if node_type == "selector_expression":
                value_ts = GoASTMapper._selector_operand(ts_node)
                attr_ts = GoASTMapper._selector_field(ts_node)
                value_node = GoASTMapper.map_node(value_ts, source, language, parent=None) if value_ts else None
                attr_name = GoASTMapper._build_callee_name(attr_ts, source) or ""
                attr_node = AttributeNode(
                    value=value_node,
                    attr=attr_name,
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
            if node_type == "import_spec":
                return GoASTMapper._map_import(ts_node, source, language, parent)

            # Literals: strings
            if node_type in GoASTMapper._STRING_LITERAL_TYPES:
                text = GoASTMapper._node_text(ts_node, source)
                value = GoASTMapper._strip_string_quotes(text)
                return LiteralNode(
                    value=value,
                    literal_type="string",
                    line=line,
                    column=col,
                    parent=parent,
                    language=language,
                    raw_node=ts_node,
                )

            # Literals: numbers
            if node_type in GoASTMapper._INT_LITERAL_TYPES:
                text = GoASTMapper._node_text(ts_node, source)
                value = GoASTMapper._parse_int(text)
                return LiteralNode(
                    value=value,
                    literal_type="number",
                    line=line,
                    column=col,
                    parent=parent,
                    language=language,
                    raw_node=ts_node,
                )

            if node_type in GoASTMapper._FLOAT_LITERAL_TYPES:
                text = GoASTMapper._node_text(ts_node, source)
                value = GoASTMapper._parse_float(text)
                return LiteralNode(
                    value=value,
                    literal_type="number",
                    line=line,
                    column=col,
                    parent=parent,
                    language=language,
                    raw_node=ts_node,
                )

            # Literals: booleans
            if node_type in GoASTMapper._BOOL_LITERAL_TYPES:
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

            # Identifiers / variables
            if node_type in GoASTMapper._IDENTIFIER_TYPES:
                name = GoASTMapper._node_text(ts_node, source)
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
            for child in getattr(ts_node, "children", []):
                child_node = GoASTMapper.map_node(child, source, language, parent=node)
                if child_node is not None:
                    node.children.append(child_node)
            return node
        except Exception:  # pragma: no cover - best-effort
            node = ASTNode(
                node_type=node_type,
                line=line,
                column=col,
                parent=parent,
                language=language,
                raw_node=ts_node,
            )
            return node

    @staticmethod
    def _position(ts_node: Any) -> tuple[int | None, int | None]:
        try:
            row, col = ts_node.start_point  # (row, column), 0-based
            return row + 1, col + 1
        except Exception:  # pragma: no cover
            return None, None

    @staticmethod
    def _node_text(ts_node: Optional[Any], source: str) -> str:
        if ts_node is None:
            return ""
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
    def _strip_string_quotes(text: str) -> str:
        if len(text) >= 2 and text[0] in {"'", '"', "`"} and text[-1] == text[0]:
            return text[1:-1]
        return text

    @staticmethod
    def _parse_int(text: str) -> int | str:
        try:
            return int(text, 0)
        except Exception:
            return text

    @staticmethod
    def _parse_float(text: str) -> float | str:
        try:
            return float(text)
        except Exception:
            return text

    @staticmethod
    def _find_callee_node(ts_node: Any) -> Optional[Any]:
        for child in getattr(ts_node, "children", []):
            if child.type in {"identifier", "selector_expression"}:
                return child
        return ts_node.children[0] if getattr(ts_node, "children", []) else None

    @staticmethod
    def _find_argument_nodes(ts_node: Any) -> list[Any]:
        args: list[Any] = []
        arg_list = GoASTMapper._child_by_field(ts_node, "arguments")
        if arg_list is None:
            for child in getattr(ts_node, "children", []):
                if child.type in {"argument_list"}:
                    arg_list = child
                    break
        if arg_list is not None:
            for child in getattr(arg_list, "children", []):
                if child.type in {",", "(", ")", "..."}:
                    continue
                args.append(child)
        return args

    @staticmethod
    def _selector_operand(ts_node: Any) -> Optional[Any]:
        operand = GoASTMapper._child_by_field(ts_node, "operand")
        if operand is not None:
            return operand
        for child in getattr(ts_node, "children", []):
            if child.type not in {".", "field_identifier"}:
                return child
        return None

    @staticmethod
    def _selector_field(ts_node: Any) -> Optional[Any]:
        field = GoASTMapper._child_by_field(ts_node, "field")
        if field is not None:
            return field
        for child in reversed(getattr(ts_node, "children", [])):
            if child.type in GoASTMapper._IDENTIFIER_TYPES:
                return child
        return None

    @staticmethod
    def _build_callee_name(ts_node: Optional[Any], source: str) -> str:
        if ts_node is None:
            return ""
        node_type = ts_node.type
        if node_type in GoASTMapper._IDENTIFIER_TYPES:
            return GoASTMapper._node_text(ts_node, source)
        if node_type == "selector_expression":
            obj_node = GoASTMapper._selector_operand(ts_node)
            field_node = GoASTMapper._selector_field(ts_node)
            obj_name = GoASTMapper._build_callee_name(obj_node, source)
            field_name = GoASTMapper._build_callee_name(field_node, source)
            if obj_name and field_name:
                return f"{obj_name}.{field_name}"
            return obj_name or field_name
        return GoASTMapper._node_text(ts_node, source)

    @staticmethod
    def _map_import(ts_node: Any, source: str, language: str, parent: Optional[ASTNode]) -> ImportNode:
        path_node = GoASTMapper._child_by_field(ts_node, "path")
        name_node = GoASTMapper._child_by_field(ts_node, "name")
        module_text = GoASTMapper._node_text(path_node, source)
        module = GoASTMapper._strip_string_quotes(module_text)
        alias_text = GoASTMapper._node_text(name_node, source) if name_node is not None else ""
        alias = alias_text or None

        return ImportNode(
            module=module,
            imports=[],
            alias=alias,
            line=GoASTMapper._position(ts_node)[0],
            column=GoASTMapper._position(ts_node)[1],
            parent=parent,
            language=language,
            raw_node=ts_node,
        )
