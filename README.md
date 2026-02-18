# Cebus MCP Security Scanner

A Python CLI tool that performs **static** and **config-based** security checks of MCP servers and tools. Designed to quickly highlight risky patterns, especially for **shared / multi-tenant / remote deployments**, while staying lenient for **local / personal setups**.

## Features

- **Mode-aware scanning**: `local` mode for trusted environments, `shared` mode for multi-tenant deployments
- **Static analysis**: No code execution, safe for CI/CD pipelines
- **Multiple output formats**: Console, JSON, SARIF, Markdown
- **OWASP mappings**: Each rule includes OWASP LLM Top 10, OWASP Top 10, and ML Top 10 mappings
- **Configurable rules**: YAML/JSON config files to enable/disable rules and adjust severities
- **MCP manifest support**: Parses both schema-specified (mcp.json/yaml) and common layouts (package.json, pyproject.toml)
- **MCP integration**: Available as an MCP tool for programmatic access
- **17 security rules**: Comprehensive coverage of MCP-specific security risks

## Installation

```bash
pip install -e .
```

### Optional JS/TS Support

JavaScript/TypeScript parsing uses optional tree-sitter dependencies. Install the extra to enable it:

```bash
pip install -e ".[js_ts]"
```

If the extra is not installed, JS/TS analyzers gracefully return an empty module AST, and scans continue for other languages.

### Optional Go Support

Go parsing will use tree-sitter (via `tree-sitter` + `tree-sitter-languages`). Install the extra to enable Go analysis when the analyzer is available:

```bash
pip install -e ".[go]"
```

If the extra is not installed, the Go analyzer will gracefully return an empty module AST, and scans will continue for other languages.

### Optional Rust Support (planned)

Rust support will use tree-sitter (via `tree-sitter` + `tree-sitter-languages`). Install the extra to enable Rust analysis when the analyzer is available:

```bash
pip install -e ".[rust]"
```

If the extra is not installed, Rust analysis will be skipped and scans will continue for other languages.

## Usage

### Basic Scan

```bash
# Scan in local mode (default)
mcp-scanner scan --path /path/to/mcp/project

# Scan in shared mode (stricter)
mcp-scanner scan --path /path/to/mcp/project --mode shared

# Output as JSON
mcp-scanner scan --path /path/to/mcp/project --output json

# Fail on medium or higher severity
mcp-scanner scan --path /path/to/mcp/project --fail-on medium

# Use custom configuration file
mcp-scanner scan --path /path/to/mcp/project --config config.yaml
```

### Zip Input

Acceptable input paths:
- Project folder
- `.zip` archive containing the project

```bash
# Scan a zipped project
mcp-scanner scan --path /path/to/project.zip

# Keep extracted contents for debugging
mcp-scanner scan --path /path/to/project.zip --keep-extracted
```

Extraction limits and safety notes:
- Rejects unsafe zip paths (absolute paths or `..` segments)
- Max files: 1000
- Max file size: 10 MB
- Max total extracted size: 50 MB
- By default, zip contents extract to a temporary directory and are cleaned up after the scan

### JS/TS Scan

```bash
# Enable JS/TS parsing (one-time install)
pip install -e ".[js_ts]"

# Scan a JS/TS project (languages auto-detected)
mcp-scanner scan --path /path/to/js-ts-project --verbosity verbose
```

In verbose mode, the scanner logs the detected languages so you can confirm JS/TS parsing is active.

### Go Scan

```bash
# Enable Go parsing (one-time install)
pip install -e ".[go]"

# Scan a Go project (languages auto-detected)
mcp-scanner scan --path /path/to/go-project --verbosity verbose
```

In verbose mode, the scanner logs the detected languages so you can confirm Go parsing is active.
For a minimal Go sample, see `tests/assets/go_example.go`.

### List Available Rules

```bash
mcp-scanner list-rules
```

### Get Recommendations

```bash
mcp-scanner get-recommendations --rule-id SSRF001
```

## Modes

### Local Mode
- Assumes trusted single user / dev box
- Highlights risky patterns as `info` / `low` severity
- Accepts "dangerous but intentional" tools (shell/HTTP) as not blockers

### Shared Mode
- Assumes untrusted users and/or multi-tenant environment
- Escalates findings: injections, arbitrary network, RCE-style tools → `high`
- Stricter expectations: auth, isolation, allow-lists, logging hygiene

## Current Rules

### RCE / Excessive Rights
- **RCE001**: Unbounded Shell Execution
- **RCE002**: Arbitrary File Access

### SSRF & Network Access
- **SSRF001**: HTTP Client Without Allow-List
- **SSRF002**: Arbitrary Port / Protocol

### Sensitive Data Exposure
- **SENS001**: Secrets in Repository
- **SENS002**: Over-Logging of Sensitive Data
- **SENS003**: Unredacted Internal URLs / Paths

### Prompt Injection & Excessive Agency
- **PROMPT001**: Unconstrained Tool Execution from Model Output
- **PROMPT002**: Missing Guardrails Around Tool-Calling Prompts
- **PROMPT003**: System Prompt / Config Leakage

### AuthN / AuthZ & Multi-Tenancy
- **AUTH001**: No Authentication on Powerful Endpoints
- **AUTH002**: Missing Per-Tenant Isolation
- **AUTH003**: Hard-coded Trusted Users Logic

### Config & Transport Security
- **TRANSPORT001**: Insecure HTTP
- **TRANSPORT002**: Overly Permissive CORS

### Resource Abuse / Unbounded Consumption
- **RESOURCE001**: No Timeout on HTTP Calls
- **RESOURCE002**: No Input Size Limits

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=mcp_scanner
```

## Architecture

- `loader/`: MCP config parsing
- `analyzers/`: AST analysis, regex scanning
- `rules/`: Each rule as a class implementing the Rule interface
- `reporting/`: Console, JSON, SARIF output formatters
- `integrations/`: MCP tool integration
- `cli.py`: Command-line interface

## License

MIT
