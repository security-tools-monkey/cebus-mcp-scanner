"""
Base classes for language-specific analyzers.
"""

from __future__ import annotations

import abc
from pathlib import Path
from typing import Iterable

from ..ast_common import SourceFile, ASTNode


class LanguageAnalyzer(abc.ABC):
    """Base class for language-specific analyzers."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    @property
    @abc.abstractmethod
    def language(self) -> str:
        """Return language identifier: 'python', 'javascript', 'typescript', 'go'."""
        ...

    @abc.abstractmethod
    def iter_source_files(self) -> Iterable[str]:
        """
        Iterate over source file paths for this language.
        
        Yields:
            Absolute paths to source files
        """
        ...

    @abc.abstractmethod
    def load_source_file(self, path: str) -> SourceFile:
        """
        Load and parse a source file, returning unified AST.
        
        Args:
            path: Absolute path to source file
            
        Returns:
            SourceFile with unified AST tree
        """
        ...

    @abc.abstractmethod
    def parse_to_unified_ast(self, content: str, path: str) -> ASTNode:
        """
        Convert language-specific AST to unified AST.
        
        Args:
            content: Source code content
            path: File path (for error reporting)
            
        Returns:
            Root ASTNode of unified AST
        """
        ...

    def open_file(self, path: str) -> str:
        """Get raw file content."""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()


