"""
Rule framework: Rule interface, metadata, ScanContext, and analyzer contract for rule execution.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable, Optional

from ..settings import ScanMode, Severity
from ..core_types import Finding

if TYPE_CHECKING:
    from ..config import ScannerConfig
    from ..ast_common import SourceFile


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    name: str
    category: str
    description: str
    owasp_llm_top10_ids: list[str]
    owasp_top10_ids: list[str]
    ml_top10_ids: list[str]


class Rule(abc.ABC):
    metadata: RuleMetadata

    @abc.abstractmethod
    def scan(self, context: "ScanContext") -> Iterable[Finding]:
        ...

    @abc.abstractmethod
    def severity_for_mode(self, mode: ScanMode) -> Severity:
        ...


@dataclass
class ScanContext:
    project_root: str
    mode: ScanMode
    analyzer: "Analyzer"
    config: Optional["ScannerConfig"] = None  # type: ignore


class Analyzer(abc.ABC):
    """
    Language-agnostic analyzer interface.
    
    Supports both new multi-language interface and legacy Python-only interface
    for backward compatibility.
    """

    # New multi-language interface
    @abc.abstractmethod
    def iter_source_files(self) -> Iterable["SourceFile"]:
        """
        Iterate over all source files (all languages).
        
        Yields:
            SourceFile objects with unified AST
        """
        ...

    def get_files_by_language(self, language: str) -> Iterable["SourceFile"]:
        """
        Get files for a specific language.
        
        Args:
            language: Language identifier
            
        Yields:
            SourceFile objects for the specified language
        """
        for source_file in self.iter_source_files():
            if source_file.language == language:
                yield source_file

    @abc.abstractmethod
    def open_file(self, path: str) -> str:
        """Get raw file content."""
        ...

    # Legacy Python-only interface (for backward compatibility)
    def iter_python_files(self) -> Iterable[str]:
        """
        Legacy method: iterate over Python file paths.
        Implemented in terms of new interface for compatibility.
        """
        for source_file in self.get_files_by_language("python"):
            yield str(source_file.path)

    def load_python_file(self, path: str):
        """
        Legacy method: load Python file.
        Implemented in terms of new interface for compatibility.
        """
        # Find the source file by path
        for source_file in self.get_files_by_language("python"):
            if str(source_file.path) == path:
                # Return a compatible object for old rules
                from dataclasses import dataclass
                from pathlib import Path

                @dataclass
                class PythonFile:
                    path: Path
                    content: str
                    tree: any  # Unified AST tree

                return PythonFile(
                    path=source_file.path,
                    content=source_file.content,
                    tree=source_file.tree,
                )
        raise FileNotFoundError(f"Python file not found: {path}")

