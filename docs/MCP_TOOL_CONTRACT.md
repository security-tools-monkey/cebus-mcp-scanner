# MCP Tool Contract (Scanner Parity)

This document defines the stable MCP tool contract for the Cebus MCP Security Scanner. These MCP actions mirror the current CLI and `MCPScannerTool` capabilities and are intended for IDE or agent integrations.

## Versioning & Stability
- Contract version: 1
- Tool names and input/output fields are stable across minor releases.
- New fields may be added with defaults, but existing fields and meanings must not change in minor releases.

This contract reflects the production MCP server interface exposed by `mcp_scanner.mcp_server` and is the stable surface for IDE integrations.

## Tool Catalog
Canonical tool names (stable):
- `scan_project`
- `list_rules`
- `get_recommendations`

The tool catalog mirrors CLI actions:
- `scan_project` corresponds to `mcp-scanner scan`
- `list_rules` corresponds to `mcp-scanner list-rules`
- `get_recommendations` corresponds to `mcp-scanner get-recommendations`

## Tool Schemas
### Error schema (all tools)
On validation or internal errors, responses use the same top-level shape with `ok=false`.

```json
{
  "ok": false,
  "tool": "string | null",
  "error": {
    "code": "validation_error | internal_error",
    "message": "string",
    "details": "object"
  }
}
```


### `scan_project`
Run a scan against a project directory or a `.zip` archive.

**Inputs**
```json
{
  "path": "string",
  "mode": "local | shared",
  "output_format": "json | sarif | markdown",
  "config_path": "string | null",
  "keep_extracted": "boolean",
  "languages": "array[string] | null",
  "fail_on": "info | low | medium | high | null"
}
```

**Input defaults**
- `path`: required
- `mode`: `"local"` (matches CLI default)
- `output_format`: `"json"` (matches MCP tool default)
- `config_path`: `null`
- `keep_extracted`: `false`
- `languages`: `null`
- `fail_on`: `null`

**Supported languages**
- `python`, `javascript`, `typescript`, `go`, `rust`

**Outputs**
```json
{
  "ok": "boolean",
  "tool": "string",
  "content_type": "string",
  "body": "string",
  "summary": "object | null",
  "findings": "array | null",
  "blocking": "boolean | null",
  "data": "object | array | null",
  "error": "object | null"
}
```

**Output semantics**
- `content_type` is one of:
  - `application/json` for JSON findings
  - `application/sarif+json` for SARIF
  - `text/markdown` for Markdown
- `body` is the serialized payload for the chosen output format.
- `data` is a parsed JSON object/array when `content_type` ends with `json`, otherwise `null`.
- `summary` includes totals and severity counts.
- `findings` is a machine-readable array of findings, regardless of `output_format`.
- `blocking` is only set when `fail_on` is provided.
- `error` is `null` for successful responses.

**Parity expectations**
- `scan_project` must surface the same findings as the CLI for the same `path`, `mode`, and rule configuration.
- Output format selection must match the scanner reporting used by the CLI.

### `list_rules`
List all available security rules and their metadata.

**Inputs**
```json
{}
```

**Outputs**
```json
{
  "ok": "boolean",
  "tool": "string",
  "content_type": "application/json",
  "body": "string",
  "summary": "object | null",
  "findings": "array | null",
  "blocking": "boolean | null",
  "data": "array",
  "error": "object | null"
}
```

**Body schema**
```json
[
  {
    "rule_id": "string",
    "name": "string",
    "category": "string",
    "severity_local": "low | medium | high | critical",
    "severity_shared": "low | medium | high | critical",
    "owasp_llm_top10_ids": ["string"],
    "owasp_top10_ids": ["string"]
  }
]
```

**Parity expectations**
- The rule list and metadata must match `mcp-scanner list-rules`.
- Severity values must align with `ScanMode.LOCAL` and `ScanMode.SHARED`.

### `get_recommendations`
Return best-practice guidance for a rule or general MCP security guidance.

**Inputs**
```json
{
  "rule_id": "string | null",
  "file_path": "string | null",
  "context": "object | null"
}
```

**Input defaults**
- `rule_id`: `null`
- `file_path`: `null`

**Outputs**
```json
{
  "ok": "boolean",
  "tool": "string",
  "content_type": "text/markdown",
  "body": "string",
  "summary": "object | null",
  "findings": "array | null",
  "blocking": "boolean | null",
  "data": "object | array | null",
  "error": "object | null"
}
```

**Output semantics**
- If `rule_id` is provided and found, the body includes rule-specific recommendations.
- If `rule_id` is missing or unknown, the body includes general MCP security best practices.

**Parity expectations**
- Rule-specific guidance must track the scanner rule metadata and recommendations used by the CLI.

## Backward Compatibility Notes
- Existing clients must continue to work with contract version 1.
- New optional fields may be added to outputs, but existing fields must not be removed or renamed.
