"""
Adapter to make MultiLanguageAnalyzer compatible with Analyzer interface.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .multi_analyzer import MultiLanguageAnalyzer
from ..ast_common import SourceFile
from ..rules.base import Analyzer


class AnalyzerAdapter(Analyzer):
    """
    Adapter that wraps MultiLanguageAnalyzer to implement the Analyzer interface.
    
    This allows the new multi-language system to work with existing rules
    while they are being migrated.
    """

    def __init__(self, multi_analyzer: MultiLanguageAnalyzer) -> None:
        self.multi_analyzer = multi_analyzer
        # Cache source files for legacy methods
        self._source_files_cache: dict[str, SourceFile] = {}

    def iter_source_files(self) -> Iterable[SourceFile]:
        """Iterate over all source files."""
        for source_file in self.multi_analyzer.iter_all_source_files():
            # Cache for legacy methods
            self._source_files_cache[str(source_file.path)] = source_file
            yield source_file

    def get_files_by_language(self, language: str) -> Iterable[SourceFile]:
        """Get files for a specific language."""
        for source_file in self.multi_analyzer.get_files_by_language(language):
            self._source_files_cache[str(source_file.path)] = source_file
            yield source_file

    def open_file(self, path: str) -> str:
        """Get raw file content."""
        # Check cache first
        if path in self._source_files_cache:
            return self._source_files_cache[path].content
        
        # Find the analyzer that handles this file
        for source_file in self.multi_analyzer.iter_all_source_files():
            if str(source_file.path) == path:
                self._source_files_cache[path] = source_file
                return source_file.content
        raise FileNotFoundError(f"File not found: {path}")

    def load_python_file(self, path: str):
        """
        Legacy method: load Python file.
        Returns a compatible object for old rules.
        """
        # Check cache first
        if path in self._source_files_cache:
            source_file = self._source_files_cache[path]
        else:
            # Find the file
            source_file = None
            for sf in self.multi_analyzer.get_files_by_language("python"):
                if str(sf.path) == path:
                    source_file = sf
                    self._source_files_cache[path] = sf
                    break
        
        if not source_file or source_file.language != "python":
            raise FileNotFoundError(f"Python file not found: {path}")

        # Return a compatible object for old rules
        from dataclasses import dataclass

        @dataclass
        class PythonFile:
            path: Path
            content: str
            tree: any  # Unified AST tree (or Python AST if available)

        return PythonFile(
            path=source_file.path,
            content=source_file.content,
            tree=source_file.tree,  # Unified AST - old rules will need to adapt
        )

