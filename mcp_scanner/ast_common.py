"""
Unified AST abstraction for multi-language support.

This module provides language-agnostic AST node types that all language
parsers map their native ASTs to. Rules operate on these unified nodes
instead of language-specific AST structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional


@dataclass
class SourceFile:
    """Unified representation of a source file."""

    path: Path
    content: str
    language: str  # "python", "javascript", "typescript", "go"
    tree: "ASTNode"  # Root of unified AST
    raw_ast: Any = None  # Optional: language-specific AST for advanced use cases


@dataclass
class ASTNode:
    """Base class for all AST nodes."""

    node_type: str  # "call", "literal", "variable", "import", "assignment", etc.
    line: int | None = None
    column: int | None = None
    parent: Optional["ASTNode"] = None
    children: List["ASTNode"] = field(default_factory=list)
    language: str = ""  # Original language for context
    raw_node: Any = None  # Optional: language-specific node for advanced use cases


@dataclass
class CallNode(ASTNode):
    """Represents a function/method call."""

    callee: str  # Full qualified name: "os.system", "child_process.exec", "exec.Command"
    arguments: List[ASTNode] = field(default_factory=list)
    keyword_arguments: dict[str, ASTNode] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.node_type = "call"


@dataclass
class LiteralNode(ASTNode):
    """Represents a literal value."""

    value: Any
    literal_type: str  # "string", "number", "boolean", "null", etc.

    def __post_init__(self) -> None:
        self.node_type = "literal"


@dataclass
class VariableNode(ASTNode):
    """Represents a variable reference."""

    name: str

    def __post_init__(self) -> None:
        self.node_type = "variable"


@dataclass
class ImportNode(ASTNode):
    """Represents an import statement."""

    module: str
    imports: List[str] = field(default_factory=list)  # What's imported from the module
    alias: Optional[str] = None  # Import alias if any

    def __post_init__(self) -> None:
        self.node_type = "import"


@dataclass
class AssignmentNode(ASTNode):
    """Represents an assignment statement."""

    target: ASTNode  # What's being assigned to
    value: ASTNode  # What's being assigned

    def __post_init__(self) -> None:
        self.node_type = "assignment"


@dataclass
class BinaryOpNode(ASTNode):
    """Represents a binary operation."""

    operator: str  # "+", "-", "==", "in", etc.
    left: ASTNode
    right: ASTNode

    def __post_init__(self) -> None:
        self.node_type = "binary_op"


@dataclass
class AttributeNode(ASTNode):
    """Represents an attribute access (e.g., obj.attr)."""

    object: ASTNode  # The object being accessed
    attribute: str  # The attribute name

    def __post_init__(self) -> None:
        self.node_type = "attribute"


def walk_ast(node: ASTNode) -> List[ASTNode]:
    """
    Recursively walk unified AST, returning all nodes in depth-first order.
    
    Args:
        node: Root AST node to walk
        
    Returns:
        List of all nodes in the tree
    """
    result = [node]
    for child in node.children:
        result.extend(walk_ast(child))
    return result


