"""
Mapper from Rust tree-sitter AST to unified AST.
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


class RustASTMapper:
    """
    Mapper from tree-sitter Rust AST to unified AST.

    This mapper is intentionally minimal: it preserves the tree structure
    and never crashes on unknown nodes. Specialized mappings are added
    in later phases.
    """

    _IDENTIFIER_TYPES = {
        "identifier",
        "field_identifier",
        "type_identifier",
        "self",
        "super",
        "crate",
    }

    _STRING_LITERAL_TYPES = {
        "string_literal",
        "raw_string_literal",
        "byte_string_literal",
    }

    _NUMBER_LITERAL_TYPES = {
        "integer_literal",
        "int_literal",
        "float_literal",
        "number_literal",
    }

    _BOOL_LITERAL_TYPES = {
        "true",
        "false",
        "boolean_literal",
    }

    _PATH_TYPES = {
        "path",
        "scoped_identifier",
        "scoped_type_identifier",
    }

    _FIELD_ACCESS_TYPES = {
        "field_expression",
    }

    @staticmethod
    def map_module(root: Any, source: str, language: str = "rust") -> ASTNode:
        node = ASTNode(
            node_type="module",
            line=None,
            column=None,
            language=language,
            raw_node=root,
        )
        for child in getattr(root, "children", []):
            child_node = RustASTMapper.map_node(child, source, language, parent=node)
            if child_node is not None:
                node.children.append(child_node)
        return node

    @staticmethod
    def map_node(
        ts_node: Any,
        source: str,
        language: str = "rust",
        parent: Optional[ASTNode] = None,
    ) -> Optional[ASTNode]:
        try:
            node_type = ts_node.type
        except Exception:  # pragma: no cover - defensive
            return None

        line, col = RustASTMapper._position(ts_node)

        try:
            # Function calls + macro invocations
            if node_type in {"call_expression", "macro_invocation"}:
                callee_ts = RustASTMapper._find_callee_node(ts_node)
                callee_name = RustASTMapper._build_callee_name(callee_ts, source) or "<unknown>"
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

                for arg_ts in RustASTMapper._find_argument_nodes(ts_node):
                    arg_node = RustASTMapper.map_node(arg_ts, source, language, parent=call_node)
                    if arg_node is not None:
                        call_node.arguments.append(arg_node)
                return call_node

            # Path / field access
            if node_type in RustASTMapper._FIELD_ACCESS_TYPES:
                value_ts = RustASTMapper._field_expression_value(ts_node)
                field_ts = RustASTMapper._field_expression_field(ts_node)
                value_node = RustASTMapper.map_node(value_ts, source, language, parent=None) if value_ts else None
                attr_name = RustASTMapper._build_callee_name(field_ts, source) if field_ts else ""
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

            if node_type in RustASTMapper._PATH_TYPES:
                segments = RustASTMapper._collect_path_segments(ts_node, source)
                if segments:
                    return RustASTMapper._attribute_from_segments(
                        segments,
                        line,
                        col,
                        parent,
                        language,
                        ts_node,
                    )

            # Imports
            if node_type == "use_declaration":
                return RustASTMapper._map_use_declaration(ts_node, source, language, parent)

            # Literals: strings
            if node_type in RustASTMapper._STRING_LITERAL_TYPES:
                text = RustASTMapper._node_text(ts_node, source)
                value = RustASTMapper._strip_string_quotes(text)
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
            if node_type in RustASTMapper._NUMBER_LITERAL_TYPES:
                text = RustASTMapper._node_text(ts_node, source)
                value = RustASTMapper._parse_number(text)
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
            if node_type in RustASTMapper._BOOL_LITERAL_TYPES:
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
            if node_type in RustASTMapper._IDENTIFIER_TYPES:
                name = RustASTMapper._node_text(ts_node, source)
                return VariableNode(
                    name=name,
                    line=line,
                    column=col,
                    parent=parent,
                    language=language,
                    raw_node=ts_node,
                )

            node = ASTNode(
                node_type=node_type,
                line=line,
                column=col,
                parent=parent,
                language=language,
                raw_node=ts_node,
            )
            for child in getattr(ts_node, "children", []):
                child_node = RustASTMapper.map_node(child, source, language, parent=node)
                if child_node is not None:
                    node.children.append(child_node)
            return node
        except Exception:  # pragma: no cover - best-effort
            return ASTNode(
                node_type=node_type,
                line=line,
                column=col,
                parent=parent,
                language=language,
                raw_node=ts_node,
            )

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
        if len(text) >= 2 and text[0] in {"'", '"'} and text[-1] == text[0]:
            return text[1:-1]
        return text

    @staticmethod
    def _parse_number(text: str) -> int | float | str:
        cleaned = text.replace("_", "")
        for suffix in ("u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64"):
            if cleaned.endswith(suffix):
                cleaned = cleaned[: -len(suffix)]
                break
        try:
            if "." in cleaned or "e" in cleaned.lower():
                return float(cleaned)
            return int(cleaned, 0)
        except Exception:
            return text

    @staticmethod
    def _find_callee_node(ts_node: Any) -> Optional[Any]:
        if ts_node.type == "call_expression":
            callee = RustASTMapper._child_by_field(ts_node, "function")
            if callee is not None:
                return callee
        if ts_node.type == "macro_invocation":
            callee = RustASTMapper._child_by_field(ts_node, "macro")
            if callee is not None:
                return callee
        for child in getattr(ts_node, "children", []):
            if child.type in {"identifier", "path", "scoped_identifier", "scoped_type_identifier", "field_expression"}:
                return child
        return ts_node.children[0] if getattr(ts_node, "children", []) else None

    @staticmethod
    def _find_argument_nodes(ts_node: Any) -> list[Any]:
        args: list[Any] = []
        if ts_node.type == "call_expression":
            arg_list = RustASTMapper._child_by_field(ts_node, "arguments")
            if arg_list is None:
                for child in getattr(ts_node, "children", []):
                    if child.type in {"arguments", "argument_list"}:
                        arg_list = child
                        break
            if arg_list is not None:
                for child in getattr(arg_list, "children", []):
                    if child.type in {",", "(", ")", "}"}:
                        continue
                    args.append(child)
        elif ts_node.type == "macro_invocation":
            token_tree = RustASTMapper._child_by_field(ts_node, "token_tree")
            if token_tree is None:
                for child in getattr(ts_node, "children", []):
                    if child.type == "token_tree":
                        token_tree = child
                        break
            if token_tree is not None:
                for child in getattr(token_tree, "children", []):
                    if child.type in {",", "(", ")", "{", "}", "[", "]"}:
                        continue
                    args.append(child)
        return args

    @staticmethod
    def _field_expression_value(ts_node: Any) -> Optional[Any]:
        value = RustASTMapper._child_by_field(ts_node, "value")
        if value is not None:
            return value
        for child in getattr(ts_node, "children", []):
            if child.type not in {".", "field_identifier"}:
                return child
        return None

    @staticmethod
    def _field_expression_field(ts_node: Any) -> Optional[Any]:
        field = RustASTMapper._child_by_field(ts_node, "field")
        if field is not None:
            return field
        for child in reversed(getattr(ts_node, "children", [])):
            if child.type in RustASTMapper._IDENTIFIER_TYPES:
                return child
        return None

    @staticmethod
    def _collect_path_segments(ts_node: Optional[Any], source: str) -> list[str]:
        if ts_node is None:
            return []
        node_type = ts_node.type
        if node_type in RustASTMapper._IDENTIFIER_TYPES:
            text = RustASTMapper._node_text(ts_node, source)
            return [text] if text else []
        if node_type == "path":
            segments: list[str] = []
            for child in getattr(ts_node, "children", []):
                if child.type in {"path_segment", "identifier", "type_identifier"}:
                    seg_text = RustASTMapper._node_text(child, source)
                    if seg_text:
                        segments.append(seg_text)
                elif child.type in RustASTMapper._IDENTIFIER_TYPES:
                    seg_text = RustASTMapper._node_text(child, source)
                    if seg_text:
                        segments.append(seg_text)
            if segments:
                return segments
        if node_type in {"scoped_identifier", "scoped_type_identifier"}:
            path_node = RustASTMapper._child_by_field(ts_node, "path")
            name_node = RustASTMapper._child_by_field(ts_node, "name")
            segments = RustASTMapper._collect_path_segments(path_node, source)
            name_text = RustASTMapper._node_text(name_node, source) if name_node is not None else ""
            if name_text:
                segments.append(name_text)
            return segments
        if node_type == "field_expression":
            value_node = RustASTMapper._field_expression_value(ts_node)
            field_node = RustASTMapper._field_expression_field(ts_node)
            segments = RustASTMapper._collect_path_segments(value_node, source)
            field_text = RustASTMapper._build_callee_name(field_node, source)
            if field_text:
                segments.append(field_text)
            return segments
        return []

    @staticmethod
    def _attribute_from_segments(
        segments: list[str],
        line: int | None,
        col: int | None,
        parent: Optional[ASTNode],
        language: str,
        raw_node: Any,
    ) -> ASTNode:
        base = VariableNode(
            name=segments[0],
            line=line,
            column=col,
            parent=None,
            language=language,
            raw_node=None,
        )
        current: ASTNode = base
        for segment in segments[1:]:
            attr_node = AttributeNode(
                value=current,
                attr=segment,
                line=line,
                column=col,
                parent=None,
                language=language,
                raw_node=None,
            )
            current.parent = attr_node
            current = attr_node
        current.parent = parent
        if isinstance(current, AttributeNode):
            current.raw_node = raw_node
        else:
            current.raw_node = raw_node
        return current

    @staticmethod
    def _build_callee_name(ts_node: Optional[Any], source: str) -> str:
        if ts_node is None:
            return ""
        node_type = ts_node.type
        if node_type in RustASTMapper._IDENTIFIER_TYPES:
            return RustASTMapper._node_text(ts_node, source)
        if node_type == "field_expression":
            value_node = RustASTMapper._field_expression_value(ts_node)
            field_node = RustASTMapper._field_expression_field(ts_node)
            value_name = RustASTMapper._build_callee_name(value_node, source)
            field_name = RustASTMapper._build_callee_name(field_node, source)
            if value_name and field_name:
                return f"{value_name}.{field_name}"
            return value_name or field_name
        if node_type in {"path", "scoped_identifier", "scoped_type_identifier"}:
            segments = RustASTMapper._collect_path_segments(ts_node, source)
            return "::".join([seg for seg in segments if seg])
        return RustASTMapper._node_text(ts_node, source)

    @staticmethod
    def _map_use_declaration(ts_node: Any, source: str, language: str, parent: Optional[ASTNode]) -> ImportNode:
        module = ""
        imports: list[str] = []
        alias: Optional[str] = None

        use_tree = None
        for child in getattr(ts_node, "children", []):
            if child.type in {"use_tree", "scoped_use_list", "use_list", "path", "scoped_identifier"}:
                use_tree = child
                break

        paths = RustASTMapper._collect_use_paths(use_tree, source)
        if paths:
            module = "::".join(paths[0][:-1]) if len(paths[0]) > 1 else ""
            imports = [path[-1] for path in paths if path]

        alias_node = RustASTMapper._find_use_alias(ts_node)
        if alias_node is not None:
            alias_text = RustASTMapper._node_text(alias_node, source)
            alias = alias_text or None

        return ImportNode(
            module=module,
            imports=imports,
            alias=alias,
            line=RustASTMapper._position(ts_node)[0],
            column=RustASTMapper._position(ts_node)[1],
            parent=parent,
            language=language,
            raw_node=ts_node,
        )

    @staticmethod
    def _collect_use_paths(ts_node: Optional[Any], source: str) -> list[list[str]]:
        if ts_node is None:
            return []
        node_type = ts_node.type
        if node_type in {"identifier", "path", "scoped_identifier", "scoped_type_identifier"}:
            segments = RustASTMapper._collect_path_segments(ts_node, source)
            return [segments] if segments else []
        if node_type in {"use_tree"}:
            path_node = RustASTMapper._child_by_field(ts_node, "path")
            list_node = RustASTMapper._child_by_field(ts_node, "list")
            if list_node is None:
                for child in getattr(ts_node, "children", []):
                    if child.type in {"use_list", "scoped_use_list"}:
                        list_node = child
                        break
            prefix = RustASTMapper._collect_path_segments(path_node, source)
            if list_node is None:
                leaf = RustASTMapper._child_by_field(ts_node, "name")
                if leaf is None:
                    for child in getattr(ts_node, "children", []):
                        if child.type in {"identifier", "path", "scoped_identifier"}:
                            leaf = child
                            break
                leaf_segments = RustASTMapper._collect_path_segments(leaf, source)
                combined = prefix + leaf_segments if prefix else leaf_segments
                return [combined] if combined else []
            results: list[list[str]] = []
            for child in getattr(list_node, "children", []):
                if child.type == ",":
                    continue
                for path in RustASTMapper._collect_use_paths(child, source):
                    results.append(prefix + path)
            return results
        if node_type in {"scoped_use_list", "use_list"}:
            results: list[list[str]] = []
            prefix: list[str] = []
            if node_type == "scoped_use_list":
                path_node = RustASTMapper._child_by_field(ts_node, "path")
                prefix = RustASTMapper._collect_path_segments(path_node, source)
            for child in getattr(ts_node, "children", []):
                if child.type in {",", "{", "}", ":"}:
                    continue
                for path in RustASTMapper._collect_use_paths(child, source):
                    results.append(prefix + path)
            return results
        return []

    @staticmethod
    def _find_use_alias(ts_node: Any) -> Optional[Any]:
        for child in getattr(ts_node, "children", []):
            if child.type == "use_alias":
                name_node = RustASTMapper._child_by_field(child, "alias")
                if name_node is not None:
                    return name_node
                for sub in getattr(child, "children", []):
                    if sub.type in RustASTMapper._IDENTIFIER_TYPES:
                        return sub
            if child.type in {"identifier", "scoped_identifier"}:
                continue
        return None
