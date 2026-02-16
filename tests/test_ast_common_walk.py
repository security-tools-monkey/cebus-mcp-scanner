from __future__ import annotations

from mcp_scanner.ast_common import ASTNode, walk_ast


def test_walk_ast_depth_first_includes_root_and_children() -> None:
    root = ASTNode(node_type="module")
    a = ASTNode(node_type="child_a")
    b = ASTNode(node_type="child_b")
    c = ASTNode(node_type="child_c")

    root.children = [a, b]
    b.children = [c]

    nodes = walk_ast(root)
    types = [n.node_type for n in nodes]

    assert types == ["module", "child_a", "child_b", "child_c"]
