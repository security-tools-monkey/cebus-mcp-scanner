"""
Multi-language analyzer orchestrator.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional

from .base import LanguageAnalyzer
from .language_detector import detect_languages, EXCLUDED_DIRS
from .python_analyzer_v2 import PythonAnalyzer
from ..ast_common import SourceFile
from ..logging_utils import ScanLogger, VerbosityLevel


class MultiLanguageAnalyzer:
    """
    Orchestrates multiple language analyzers.
    
    Provides a unified interface for scanning projects with multiple languages.
    """

    def __init__(
        self,
        root: str | Path,
        languages: List[str] | None = None,
        logger: Optional[ScanLogger] = None,
    ) -> None:
        """
        Initialize multi-language analyzer.
        
        Args:
            root: Project root directory
            languages: Explicit list of languages to analyze, or None for auto-detect
            logger: Optional logger for verbose output
        """
        self.root = Path(root).resolve()
        self.logger = logger or ScanLogger(verbosity=VerbosityLevel.QUIET)
        self.analyzers: List[LanguageAnalyzer] = []

        if languages:
            self._init_analyzers(languages)
        else:
            detected = detect_languages(self.root)
            self.logger.debug(f"Auto-detected languages: {detected}")
            self._init_analyzers(detected)

    def _init_analyzers(self, languages: List[str]) -> None:
        """Initialize analyzers for specified languages."""
        for lang in languages:
            analyzer = self._create_analyzer(lang)
            if analyzer:
                self.analyzers.append(analyzer)
                self.logger.debug(f"Initialized {lang} analyzer")

    def _create_analyzer(self, language: str) -> LanguageAnalyzer | None:
        """Create analyzer instance for a language."""
        if language == "python":
            return PythonAnalyzer(self.root)
        # TODO: Add other languages in future phases
        # elif language == "javascript":
        #     return JavaScriptAnalyzer(self.root)
        # elif language == "typescript":
        #     return TypeScriptAnalyzer(self.root)
        # elif language == "go":
        #     return GoAnalyzer(self.root)
        else:
            self.logger.debug(f"No analyzer available for language: {language}")
            return None

    def iter_all_source_files(self) -> Iterable[SourceFile]:
        """
        Iterate over all source files across all languages.
        
        Yields:
            SourceFile objects for all detected source files
        """
        for analyzer in self.analyzers:
            for path in analyzer.iter_source_files():
                try:
                    source_file = analyzer.load_source_file(path)
                    yield source_file
                except Exception as e:
                    self.logger.debug(f"Error loading {path}: {e}")
                    continue

    def get_files_by_language(self, language: str) -> Iterable[SourceFile]:
        """
        Get source files for a specific language.
        
        Args:
            language: Language identifier
            
        Yields:
            SourceFile objects for the specified language
        """
        analyzer = next((a for a in self.analyzers if a.language == language), None)
        if analyzer:
            for path in analyzer.iter_source_files():
                try:
                    yield analyzer.load_source_file(path)
                except Exception as e:
                    self.logger.debug(f"Error loading {path}: {e}")
                    continue

    def get_supported_languages(self) -> List[str]:
        """Get list of languages currently being analyzed."""
        return [a.language for a in self.analyzers]


