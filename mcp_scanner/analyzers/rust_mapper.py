"""
Mapper from Rust tree-sitter AST to unified AST.
"""

from __future__ import annotations

from typing import Any, Optional

from ..ast_common import ASTNode


class RustASTMapper:
    """
    Mapper from tree-sitter Rust AST to unified AST.

    This mapper is intentionally minimal: it preserves the tree structure
    and never crashes on unknown nodes. Specialized mappings are added
    in later phases.
    """

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
