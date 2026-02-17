"""
Language detection utilities for auto-detecting project languages.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Set

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


def detect_languages(root: Path) -> List[str]:
    """
    Auto-detect languages in project by examining file extensions and config files.
    
    Args:
        root: Project root directory
        
    Returns:
        List of detected language identifiers
    """
    languages: Set[str] = set()
    root_path = Path(root).resolve()

    # Check for language-specific files
    for file_path in root_path.rglob("*"):
        # Skip excluded directories
        if any(excluded in file_path.parts for excluded in EXCLUDED_DIRS):
            continue

        if file_path.is_file():
            suffix = file_path.suffix.lower()
            name = file_path.name.lower()

            # Python
            # TODO: make suffix list configurable
            if suffix == ".py":
                languages.add("python")

            # JavaScript
            # TODO: make suffix list configurable
            if suffix in {".js", ".jsx", ".mjs", ".cjs"} and name != "tsconfig.json":
                # Only add JS if TypeScript not already detected
                if "typescript" not in languages:
                    languages.add("javascript")

            # TypeScript
            # TODO: make suffix list configurable
            if suffix in {".ts", ".tsx", ".mts", ".cts"} or name == "tsconfig.json":
                languages.add("typescript")
                # TypeScript projects typically also have JS files
                languages.discard("javascript")

            # Go
            # TODO: make suffix list configurable
            if suffix == ".go":
                languages.add("go")

    # Check for language-specific config files
    config_indicators = {
        "package.json": "javascript",  # Could be JS or TS, but TS has tsconfig.json
        "go.mod": "go",
        "go.sum": "go",
        "requirements.txt": "python",
        "pyproject.toml": "python",
        "setup.py": "python",
    }

    for config_file, lang in config_indicators.items():
        if (root_path / config_file).exists():
            languages.add(lang)

    # Default fallback to Python if nothing detected
    return sorted(languages) if languages else ["python"]

