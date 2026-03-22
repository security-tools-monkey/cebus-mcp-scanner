from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

import pytest

try:
    import pydantic  # type: ignore
except ImportError:  # pragma: no cover - exercised when pydantic isn't installed
    import sys
    import types
    from typing import get_args, get_origin, get_type_hints, Union, Literal

    pydantic = types.ModuleType("pydantic")

    _REQUIRED = object()

    class ValidationError(Exception):
        def __init__(self, errors: list[dict]) -> None:
            super().__init__("Validation failed")
            self._errors = errors

        def errors(self) -> list[dict]:
            return self._errors

    def Field(default=_REQUIRED, **_kwargs):  # type: ignore[override]
        if default is ...:
            return _REQUIRED
        return default

    class BaseModel:
        def __init__(self, **data):
            errors: list[dict] = []
            try:
                annotations = get_type_hints(self.__class__, include_extras=True)
            except TypeError:
                annotations = get_type_hints(self.__class__)
            except Exception:
                annotations = getattr(self.__class__, "__annotations__", {})
            for field, annotation in annotations.items():
                if field in data:
                    value = data[field]
                else:
                    default = getattr(self.__class__, field, _REQUIRED)
                    if default is _REQUIRED:
                        errors.append(
                            {
                                "loc": (field,),
                                "msg": "Field required",
                                "type": "missing",
                            }
                        )
                        continue
                    value = default
                if not _validate_value(value, annotation):
                    errors.append(
                        {
                            "loc": (field,),
                            "msg": "Invalid value",
                            "type": "value_error",
                        }
                    )
                    continue
                setattr(self, field, value)
            if errors:
                raise ValidationError(errors)

    def _validate_value(value, annotation) -> bool:
        origin = get_origin(annotation)
        args = get_args(annotation)

        if origin is None:
            if annotation is None or annotation is type(None):
                return value is None
            if annotation is bool:
                return isinstance(value, bool)
            if annotation is str:
                return isinstance(value, str)
            return True

        if origin is list:
            if not isinstance(value, list):
                return False
            if not args:
                return True
            return all(_validate_value(item, args[0]) for item in value)

        if origin is dict:
            if not isinstance(value, dict):
                return False
            if len(args) != 2:
                return True
            key_type, val_type = args
            return all(
                _validate_value(k, key_type) and _validate_value(v, val_type)
                for k, v in value.items()
            )

        if origin is type(None):
            return value is None

        if origin is Union:
            return any(_validate_value(value, arg) for arg in args)

        if origin is Literal:
            return value in args

        return True

    pydantic.BaseModel = BaseModel
    pydantic.Field = Field
    pydantic.ValidationError = ValidationError
    sys.modules["pydantic"] = pydantic

try:
    import mcp  # type: ignore
except ImportError:  # pragma: no cover - exercised when mcp isn't installed
    import sys
    import types
    from dataclasses import dataclass

    mcp = types.ModuleType("mcp")
    server = types.ModuleType("mcp.server")
    fastmcp = types.ModuleType("mcp.server.fastmcp")
    types_mod = types.ModuleType("mcp.types")

    @dataclass
    class TextContent:
        type: str
        text: str

    @dataclass
    class CallToolResult:
        content: list[TextContent]
        structuredContent: dict | None = None
        structured_content: dict | None = None

        def model_dump(self) -> dict:
            return {
                "content": self.content,
                "structuredContent": self.structuredContent,
                "structured_content": self.structured_content,
            }

    class FastMCP:
        def __init__(self, name: str, **_kwargs: Any) -> None:
            self.name = name
            self._tools: dict[str, Any] = {}

        def tool(self):
            def decorator(func):
                self._tools[func.__name__] = func
                return func

            return decorator

        def get_tools(self):
            return [{"name": name} for name in self._tools.keys()]

        def run(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover
            return None

    fastmcp.FastMCP = FastMCP
    types_mod.CallToolResult = CallToolResult
    types_mod.TextContent = TextContent

    sys.modules["mcp"] = mcp
    sys.modules["mcp.server"] = server
    sys.modules["mcp.server.fastmcp"] = fastmcp
    sys.modules["mcp.types"] = types_mod

from mcp_scanner.mcp_server import get_recommendations, list_rules, mcp, scan_project


def _structured_content(result: Any) -> dict:
    for attr in ("structuredContent", "structured_content"):
        if hasattr(result, attr):
            value = getattr(result, attr)
            if value is not None:
                return value
    if hasattr(result, "model_dump"):
        data = result.model_dump()
        return data.get("structuredContent") or data.get("structured_content") or {}
    return {}


def _tool_names() -> list[str]:
    tools: Any = None
    if hasattr(mcp, "get_tools"):
        tools = mcp.get_tools()
    elif hasattr(mcp, "tools"):
        tools = getattr(mcp, "tools")
    elif hasattr(mcp, "_tool_manager"):
        manager = getattr(mcp, "_tool_manager")
        if hasattr(manager, "get_tools"):
            tools = manager.get_tools()
        elif hasattr(manager, "tools"):
            tools = getattr(manager, "tools")

    if tools is None:
        return []
    if isinstance(tools, dict):
        return list(tools.keys())
    if isinstance(tools, Iterable):
        names: list[str] = []
        for tool in tools:
            if isinstance(tool, dict) and "name" in tool:
                names.append(tool["name"])
            elif hasattr(tool, "name"):
                names.append(tool.name)
        return names
    return []


def _write_project_file(tmp_path: Path, content: str, filename: str = "module.py") -> Path:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def test_mcp_tool_discovery_lists_required_tools() -> None:
    names = _tool_names()
    if not names:
        pytest.skip("FastMCP tool registry not accessible in this SDK version.")
    assert "scan_project" in names
    assert "list_rules" in names
    assert "get_recommendations" in names


def test_list_rules_returns_expected_metadata_fields() -> None:
    result = list_rules()
    payload = _structured_content(result)

    assert payload["ok"] is True
    assert payload["content_type"] == "application/json"
    assert isinstance(payload["data"], list)
    rule = payload["data"][0]
    assert "rule_id" in rule
    assert "name" in rule
    assert "category" in rule
    assert "severity_local" in rule
    assert "severity_shared" in rule


def test_scan_project_returns_findings_and_summary(tmp_path: Path) -> None:
    project_dir = _write_project_file(
        tmp_path,
        "import os\n\n"
        "def run() -> None:\n"
        "    os.system('ls')\n",
    )
    result = scan_project(
        path=str(project_dir),
        mode="shared",
        output_format="json",
        fail_on="low",
    )
    payload = _structured_content(result)

    assert payload["ok"] is True
    assert payload["tool"] == "scan_project"
    assert payload["summary"]["total"] >= 1
    assert isinstance(payload["findings"], list)
    assert payload["blocking"] is True

    body = json.loads(payload["body"])
    assert isinstance(body, list)
    assert any(item["rule_id"] == "RCE001" for item in body)


def test_get_recommendations_rule_specific_and_general() -> None:
    specific = get_recommendations(rule_id="RCE001")
    specific_payload = _structured_content(specific)
    assert specific_payload["ok"] is True
    assert "RCE001" in specific_payload["body"]

    general = get_recommendations()
    general_payload = _structured_content(general)
    assert general_payload["ok"] is True
    assert "MCP Security Best Practices" in general_payload["body"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mode": "invalid"},
        {"output_format": "xml"},
    ],
)
def test_scan_project_invalid_params_return_structured_error(tmp_path: Path, kwargs: dict) -> None:
    project_dir = _write_project_file(tmp_path, "print('ok')\n")
    result = scan_project(path=str(project_dir), **kwargs)
    payload = _structured_content(result)

    assert payload["ok"] is False
    assert payload["error"]["code"] == "validation_error"


def test_scan_project_invalid_path_returns_structured_error() -> None:
    result = scan_project(path="/tmp/does-not-exist")
    payload = _structured_content(result)

    assert payload["ok"] is False
    assert payload["error"]["code"] == "validation_error"


def test_get_recommendations_invalid_context_returns_structured_error() -> None:
    result = get_recommendations(context={"count": 1})
    payload = _structured_content(result)

    assert payload["ok"] is False
    assert payload["error"]["code"] == "validation_error"
