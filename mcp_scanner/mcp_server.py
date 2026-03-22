from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, ValidationError

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent

from .integrations.mcp_tool import MCPScannerTool


ScanModeLiteral = Literal["local", "shared"]
OutputFormatLiteral = Literal["json", "sarif", "markdown"]
LanguageLiteral = Literal["python", "javascript", "typescript", "go", "rust"]
FailOnLiteral = Literal["info", "low", "medium", "high"]


class MCPToolResult(BaseModel):
    content_type: str = Field(..., description="MIME type for the response body.")
    body: str = Field(..., description="Serialized payload for the response.")


class ScanProjectRequest(BaseModel):
    path: str = Field(..., description="Project root or .zip archive path.")
    mode: ScanModeLiteral = Field("local", description="Scan mode: local or shared.")
    output_format: OutputFormatLiteral = Field(
        "json", description="Output format: json, sarif, or markdown."
    )
    config_path: Optional[str] = Field(
        None, description="Optional path to a scanner config file."
    )
    keep_extracted: bool = Field(
        False, description="Keep extracted zip contents on disk."
    )
    languages: Optional[list[LanguageLiteral]] = Field(
        None, description="Optional list of languages to scan."
    )
    fail_on: Optional[FailOnLiteral] = Field(
        None, description="Optional severity threshold for blocking status."
    )


class GetRecommendationsRequest(BaseModel):
    rule_id: Optional[str] = Field(None, description="Rule ID to scope guidance.")
    file_path: Optional[str] = Field(None, description="Contextual file path.")
    context: Optional[dict[str, str]] = Field(
        None, description="Additional context fields for recommendations."
    )


mcp = FastMCP(
    name="Cebus MCP Security Scanner",
    instructions="Static security scanning for MCP servers and tools.",
)
_tool = MCPScannerTool()


def _error_result(
    code: str,
    message: str,
    details: Optional[dict[str, Any]] = None,
    tool_name: Optional[str] = None,
) -> CallToolResult:
    body = {
        "ok": False,
        "tool": tool_name,
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        },
    }
    content = [
        TextContent(
            type="text",
            text=f"Error: {message}",
        )
    ]
    return CallToolResult(content=content, structuredContent=body)


def _success_result(
    tool_name: str,
    result: MCPToolResult,
    *,
    summary: Optional[dict[str, Any]] = None,
    findings: Optional[list[dict[str, Any]]] = None,
    blocking: Optional[bool] = None,
) -> CallToolResult:
    structured: dict[str, Any] = {
        "ok": True,
        "tool": tool_name,
        "content_type": result.content_type,
        "body": result.body,
        "summary": summary,
        "findings": findings,
        "blocking": blocking,
    }
    if result.content_type.endswith("json"):
        try:
            import json

            structured["data"] = json.loads(result.body)
        except Exception:
            structured["data"] = None
    content = [TextContent(type="text", text=result.body)]
    return CallToolResult(content=content, structuredContent=structured)


def _validate_path_exists(path: str, label: str) -> Optional[CallToolResult]:
    import os

    if not os.path.exists(path):
        return _error_result(
            code="validation_error",
            message=f"{label} does not exist: {path}",
            details={"field": label, "value": path},
            tool_name="scan_project",
        )
    return None


@mcp.tool()
def list_rules() -> CallToolResult:
    try:
        result = _tool.list_rules()
        return _success_result("list_rules", MCPToolResult(content_type=result.content_type, body=result.body))
    except Exception as exc:
        return _error_result(
            "internal_error",
            f"Failed to list rules: {exc}",
            tool_name="list_rules",
        )


@mcp.tool()
def scan_project(
    path: str,
    mode: str = "local",
    output_format: str = "json",
    config_path: Optional[str] = None,
    keep_extracted: bool = False,
    languages: Optional[list[str]] = None,
    fail_on: Optional[str] = None,
) -> CallToolResult:
    try:
        request = ScanProjectRequest(
            path=path,
            mode=mode,
            output_format=output_format,
            config_path=config_path,
            keep_extracted=keep_extracted,
            languages=languages,
            fail_on=fail_on,
        )
    except ValidationError as exc:
        return _error_result(
            "validation_error",
            "Invalid scan parameters.",
            exc.errors(),
            tool_name="scan_project",
        )

    invalid = _validate_path_exists(request.path, "path")
    if invalid:
        return invalid
    if request.config_path:
        invalid = _validate_path_exists(request.config_path, "config_path")
        if invalid:
            return invalid
    try:
        result = _tool.scan_project(
            path=request.path,
            mode=request.mode,
            output_format=request.output_format,
            config_path=request.config_path,
            keep_extracted=request.keep_extracted,
            languages=list(request.languages) if request.languages else None,
            fail_on=request.fail_on,
        )
        return _success_result(
            "scan_project",
            MCPToolResult(content_type=result.content_type, body=result.body),
            summary=result.summary,
            findings=result.findings,
            blocking=result.blocking,
        )
    except Exception as exc:
        return _error_result(
            "internal_error",
            f"Scan failed: {exc}",
            tool_name="scan_project",
        )


@mcp.tool()
def get_recommendations(
    rule_id: Optional[str] = None,
    file_path: Optional[str] = None,
    context: Optional[dict[str, str]] = None,
) -> CallToolResult:
    try:
        request = GetRecommendationsRequest(
            rule_id=rule_id,
            file_path=file_path,
            context=context,
        )
    except ValidationError as exc:
        return _error_result(
            "validation_error",
            "Invalid recommendation parameters.",
            exc.errors(),
            tool_name="get_recommendations",
        )
    try:
        result = _tool.get_recommendations(
            rule_id=request.rule_id,
            file_path=request.file_path,
            context=request.context,
        )
        return _success_result("get_recommendations", MCPToolResult(content_type=result.content_type, body=result.body))
    except Exception as exc:
        return _error_result(
            "internal_error",
            f"Failed to get recommendations: {exc}",
            tool_name="get_recommendations",
        )


def run() -> None:
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    run()
