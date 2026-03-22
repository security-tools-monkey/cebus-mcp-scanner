"""
Language detection utilities for auto-detecting project languages.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Set, TYPE_CHECKING

EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    "venv",
    ".venv",
    "node_modules",
    "dist",
    "build",
    ".next",
    "target",  # Rust/Go build dirs
    "vendor",  # Go vendor dir
}

DEFAULT_LANGUAGE_SUFFIXES: Dict[str, Set[str]] = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx", ".mts", ".cts"},
    "go": {".go"},
    "rust": {".rs"},
}

if TYPE_CHECKING:
    from ..config import ScannerConfig


def _normalize_suffixes(suffixes: Dict[str, List[str]] | None) -> Dict[str, Set[str]]:
    if not suffixes:
        return {}
    normalized: Dict[str, Set[str]] = {}
    for language, values in suffixes.items():
        cleaned: Set[str] = set()
        for value in values:
            if not value:
                continue
            suffix = value.lower()
            if not suffix.startswith("."):
                suffix = f".{suffix}"
            cleaned.add(suffix)
        normalized[language.lower()] = cleaned
    return normalized


def detect_languages(root: Path, config: "ScannerConfig | None" = None) -> List[str]:
    """
    Auto-detect languages in project by examining file extensions and config files.
    
    Args:
        root: Project root directory
        
    Returns:
        List of detected language identifiers
    """
    languages: Set[str] = set()
    root_path = Path(root).resolve()

    suffix_overrides = _normalize_suffixes(
        config.language_suffixes if config else None
    )
    suffixes_by_language = {**DEFAULT_LANGUAGE_SUFFIXES, **suffix_overrides}

    # Check for language-specific files
    for file_path in root_path.rglob("*"):
        # Skip excluded directories
        if any(excluded in file_path.parts for excluded in EXCLUDED_DIRS):
            continue

        if file_path.is_file():
            suffix = file_path.suffix.lower()
            name = file_path.name.lower()

            # Python
            if suffix in suffixes_by_language.get("python", set()):
                languages.add("python")

            # JavaScript
            if (
                suffix in suffixes_by_language.get("javascript", set())
                and name != "tsconfig.json"
            ):
                # Only add JS if TypeScript not already detected
                if "typescript" not in languages:
                    languages.add("javascript")

            # TypeScript
            if (
                suffix in suffixes_by_language.get("typescript", set())
                or name == "tsconfig.json"
            ):
                languages.add("typescript")
                # TypeScript projects typically also have JS files
                languages.discard("javascript")

            # Go
            if suffix in suffixes_by_language.get("go", set()):
                languages.add("go")

            # Rust
            if suffix in suffixes_by_language.get("rust", set()):
                languages.add("rust")

    # Check for language-specific config files
    config_indicators = {
        "package.json": "javascript",  # Could be JS or TS, but TS has tsconfig.json
        "go.mod": "go",
        "go.sum": "go",
        "Cargo.toml": "rust",
        "Cargo.lock": "rust",
        "requirements.txt": "python",
        "pyproject.toml": "python",
        "setup.py": "python",
    }

    for config_file, lang in config_indicators.items():
        if (root_path / config_file).exists():
            languages.add(lang)

    # Default fallback to Python if nothing detected
    return sorted(languages) if languages else ["python"]
