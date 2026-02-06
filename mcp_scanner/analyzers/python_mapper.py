"""
Mapper from Python AST to unified AST.
"""

from __future__ import annotations

import ast
from typing import List, Optional

from ..ast_common import (
    ASTNode,
    AttributeNode,
    BinaryOpNode,
    CallNode,
    LiteralNode,
    VariableNode,
    ImportNode,
    AssignmentNode,
)


class PythonASTMapper:
    """Converts Python AST nodes to unified AST nodes."""

    @staticmethod
    def map_node(py_node: ast.AST, parent: Optional[ASTNode] = None) -> ASTNode:
        """
        Map a Python AST node to a unified AST node.
        
        Args:
            py_node: Python AST node
            parent: Parent unified AST node (for building tree structure)
            
        Returns:
            Unified AST node
        """
        line = getattr(py_node, "lineno", None)
        col = getattr(py_node, "col_offset", None)

        if isinstance(py_node, ast.Call):
            return PythonASTMapper._map_call(py_node, line, col, parent)
        elif isinstance(py_node, ast.Constant):
            return PythonASTMapper._map_constant(py_node, line, col, parent)
        elif isinstance(py_node, ast.Name):
            return PythonASTMapper._map_name(py_node, line, col, parent)
        elif isinstance(py_node, ast.Attribute):
            return PythonASTMapper._map_attribute(py_node, line, col, parent)
        elif isinstance(py_node, (ast.Import, ast.ImportFrom)):
            return PythonASTMapper._map_import(py_node, line, col, parent)
        elif isinstance(py_node, ast.Assign):
            return PythonASTMapper._map_assign(py_node, line, col, parent)
        elif isinstance(py_node, ast.BinOp):
            return PythonASTMapper._map_binop(py_node, line, col, parent)
        else:
            # Generic node for unmapped types
            node = ASTNode(
                node_type=type(py_node).__name__.lower(),
                line=line,
                column=col,
                parent=parent,
                language="python",
                raw_node=py_node,
            )
            # Recursively map children
            for child in ast.iter_child_nodes(py_node):
                child_node = PythonASTMapper.map_node(child, node)
                node.children.append(child_node)
            return node

    @staticmethod
    def _map_call(py_node: ast.Call, line: int | None, col: int | None, parent: Optional[ASTNode]) -> CallNode:
        """Map Python Call node to CallNode."""
        # Get callee name
        callee_name = PythonASTMapper._get_full_name(py_node.func)
        if not callee_name:
            callee_name = "<unknown>"

        # Map arguments
        args = [PythonASTMapper.map_node(arg) for arg in py_node.args]
        kwargs = {}
        for kw in py_node.keywords:
            if kw.arg:
                kwargs[kw.arg] = PythonASTMapper.map_node(kw.value)

        call_node = CallNode(
            callee=callee_name,
            arguments=args,
            keyword_arguments=kwargs,
            line=line,
            column=col,
            parent=parent,
            language="python",
            raw_node=py_node,
        )

        # Set parent for children
        for arg in args:
            arg.parent = call_node
        for kw_node in kwargs.values():
            kw_node.parent = call_node

        return call_node

    @staticmethod
    def _map_constant(py_node: ast.Constant, line: int | None, col: int | None, parent: Optional[ASTNode]) -> LiteralNode:
        """Map Python Constant node to LiteralNode."""
        value = py_node.value
        if isinstance(value, str):
            literal_type = "string"
        elif isinstance(value, (int, float)):
            literal_type = "number"
        elif isinstance(value, bool):
            literal_type = "boolean"
        elif value is None:
            literal_type = "null"
        else:
            literal_type = type(value).__name__

        return LiteralNode(
            value=value,
            literal_type=literal_type,
            line=line,
            column=col,
            parent=parent,
            language="python",
            raw_node=py_node,
        )

    @staticmethod
    def _map_name(py_node: ast.Name, line: int | None, col: int | None, parent: Optional[ASTNode]) -> VariableNode:
        """Map Python Name node to VariableNode."""
        return VariableNode(
            name=py_node.id,
            line=line,
            column=col,
            parent=parent,
            language="python",
            raw_node=py_node,
        )

    @staticmethod
    def _map_attribute(py_node: ast.Attribute, line: int | None, col: int | None, parent: Optional[ASTNode]) -> AttributeNode:
        """Map Python Attribute node to AttributeNode."""
        obj_node = PythonASTMapper.map_node(py_node.value)
        attr_node = AttributeNode(
            value=obj_node,
            attr=py_node.attr,
            line=line,
            column=col,
            parent=parent,
            language="python",
            raw_node=py_node,
        )
        obj_node.parent = attr_node
        return attr_node

    @staticmethod
    def _map_import(py_node: ast.Import | ast.ImportFrom, line: int | None, col: int | None, parent: Optional[ASTNode]) -> ImportNode:
        """Map Python Import/ImportFrom node to ImportNode."""
        if isinstance(py_node, ast.Import):
            # import module
            # import module as alias
            if py_node.names:
                module = py_node.names[0].name.split(".")[0]
                imports = [name.name for name in py_node.names]
                alias = py_node.names[0].asname
            else:
                module = ""
                imports = []
                alias = None
        else:
            # from module import name
            module = py_node.module or ""
            imports = [alias.name for alias in py_node.names] if py_node.names else []
            alias = py_node.names[0].asname if py_node.names and py_node.names[0].asname else None

        return ImportNode(
            module=module,
            imports=imports,
            alias=alias,
            line=line,
            column=col,
            parent=parent,
            language="python",
            raw_node=py_node,
        )

    @staticmethod
    def _map_assign(py_node: ast.Assign, line: int | None, col: int | None, parent: Optional[ASTNode]) -> AssignmentNode:
        """Map Python Assign node to AssignmentNode."""
        # Take first target (Python allows multiple targets)
        target = PythonASTMapper.map_node(py_node.targets[0]) if py_node.targets else ASTNode(node_type="unknown", language="python")
        value = PythonASTMapper.map_node(py_node.value)

        assign_node = AssignmentNode(
            target=target,
            value=value,
            line=line,
            column=col,
            parent=parent,
            language="python",
            raw_node=py_node,
        )

        target.parent = assign_node
        value.parent = assign_node

        return assign_node

    @staticmethod
    def _map_binop(py_node: ast.BinOp, line: int | None, col: int | None, parent: Optional[ASTNode]) -> BinaryOpNode:
        """Map Python BinOp node to BinaryOpNode."""
        op_map = {
            ast.Add: "+",
            ast.Sub: "-",
            ast.Mult: "*",
            ast.Div: "/",
            ast.Mod: "%",
            ast.Pow: "**",
            ast.LShift: "<<",
            ast.RShift: ">>",
            ast.BitOr: "|",
            ast.BitXor: "^",
            ast.BitAnd: "&",
            ast.FloorDiv: "//",
            ast.Eq: "==",
            ast.NotEq: "!=",
            ast.Lt: "<",
            ast.LtE: "<=",
            ast.Gt: ">",
            ast.GtE: ">=",
            ast.Is: "is",
            ast.IsNot: "is not",
            ast.In: "in",
            ast.NotIn: "not in",
        }

        operator = op_map.get(type(py_node.op), str(py_node.op))
        left = PythonASTMapper.map_node(py_node.left)
        right = PythonASTMapper.map_node(py_node.right)

        binop_node = BinaryOpNode(
            operator=operator,
            left=left,
            right=right,
            line=line,
            column=col,
            parent=parent,
            language="python",
            raw_node=py_node,
        )

        left.parent = binop_node
        right.parent = binop_node

        return binop_node

    @staticmethod
    def _get_full_name(node: ast.AST) -> str | None:
        """
        Get full qualified name from Python AST node.
        Similar to the original _get_full_name in rules.
        """
        if isinstance(node, ast.Attribute):
            value = PythonASTMapper._get_full_name(node.value)
            if value:
                return f"{value}.{node.attr}"
            return node.attr
        if isinstance(node, ast.Name):
            return node.id
        return None

    @staticmethod
    def map_module(py_tree: ast.Module) -> ASTNode:
        """
        Map a Python Module AST to unified AST.
        
        Args:
            py_tree: Python ast.Module node
            
        Returns:
            Root unified AST node
        """
        root = ASTNode(
            node_type="module",
            line=None,
            language="python",
            raw_node=py_tree,
        )

        for child in ast.iter_child_nodes(py_tree):
            child_node = PythonASTMapper.map_node(child, root)
            root.children.append(child_node)

        return root


