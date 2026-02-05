"""
Project loader: resolves scan root and extracts MCP metadata/manifests into ProjectMetadata.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


@dataclass
class MCPManifest:
    """Structured representation of MCP manifest."""
    tools: List[Dict[str, Any]]
    server: Optional[Dict[str, Any]] = None
    endpoints: Optional[List[str]] = None
    env: Optional[Dict[str, str]] = None
    raw: Dict[str, Any] = None


@dataclass
class ProjectMetadata:
    root: Path
    manifest: Optional[MCPManifest]


def _parse_schema_manifest(data: Dict[str, Any]) -> MCPManifest:
    """Parse schema-specified MCP manifest format."""
    tools = []
    if "tools" in data:
        if isinstance(data["tools"], dict):
            tools = list(data["tools"].values())
        elif isinstance(data["tools"], list):
            tools = data["tools"]
    
    return MCPManifest(
        tools=tools,
        server=data.get("server"),
        endpoints=data.get("endpoints"),
        env=data.get("env"),
        raw=data,
    )


def _parse_common_layout(root: Path) -> Optional[MCPManifest]:
    """Parse common MCP server layouts (package.json, pyproject.toml, etc.)."""
    # Check for package.json with MCP-related fields
    package_json = root / "package.json"
    if package_json.exists():
        try:
            with open(package_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "mcp" in data or "mcpServer" in data:
                    mcp_data = data.get("mcp") or data.get("mcpServer") or {}
                    return MCPManifest(
                        tools=mcp_data.get("tools", []),
                        server=mcp_data.get("server"),
                        raw=data,
                    )
        except Exception:  # pragma: no cover
            pass
    
    # Check for pyproject.toml with MCP tool definitions
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore
            except ImportError:
                tomllib = None
        
        if tomllib:
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
                if "tool" in data and "mcp" in data["tool"]:
                    mcp_data = data["tool"]["mcp"]
                    return MCPManifest(
                        tools=mcp_data.get("tools", []),
                        server=mcp_data.get("server"),
                        raw=data,
                    )
        else:
            # Fallback: try parsing as text for basic detection
            with open(pyproject, "r", encoding="utf-8") as f:
                content = f.read()
                if "mcp" in content.lower() or "[tool.mcp]" in content:
                    return MCPManifest(tools=[], raw={"detected": "pyproject.toml"})
    
    return None


def load_manifest(root: Path) -> Optional[MCPManifest]:
    """Load MCP manifest from schema-specified or common layouts."""
    # First, try schema-specified formats (mcp.json, mcp.yaml)
    # TODO: Add support for additional manifest formats
    for candidate in ("mcp.json", "mcp.yaml", "mcp.yml", "manifest.json"):
        path = root / candidate
        if path.exists():
            with open(path, "r", encoding="utf-8") as handle:
                if path.suffix == ".json":
                    data = json.load(handle)
                    return _parse_schema_manifest(data)
                if yaml is not None:
                    data = yaml.safe_load(handle)
                    if data:
                        return _parse_schema_manifest(data)
                    raise RuntimeError("PyYAML not installed but YAML manifest encountered.")
    
    # Fallback to common layouts
    return _parse_common_layout(root)


def load_project(path: str) -> ProjectMetadata:
    root = Path(path).resolve()
    manifest = load_manifest(root)
    return ProjectMetadata(root=root, manifest=manifest)

