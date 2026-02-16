# Cebus MCP Scanner Architecture

## Overview
Cebus MCP Scanner is a static-analysis engine aimed at MCP (Model Context Protocol) servers and tools. It walks a project tree, loads MCP manifests if available, and inspects sources with a set of heuristic security rules that target common LLM/MCP risks (prompt-injection guardrails, arbitrary tool execution, SSRF, over-logging, etc.). The scanner is exposed through:
- a direct Python `Scanner` class
- a Typer CLI (via `mcp_scanner.cli`)
- an MCP tool facade (`MCPScannerTool`) that other agents can invoke to list rules, scan projects, or fetch remediation guidance
- reporting modules to emit JSON/SARIF/markdown outputs

## High-Level Flow

ASCII overview:
```
┌───────────────┐        ┌──────────────────┐        ┌──────────────────────┐
│ Entry Points  │        │ Scanner          │        │ Reporting            │
│ - CLI         │        │ - loads config   │        │ - JSON / SARIF / CLI │
│ - MCP tool    │───────▶│ - constructs     │───────▶│ - surfaces findings  │
│ - Python API  │        │   ScanContext    │        │                      │
└──────┬────────┘        │ - runs rules     │        └──────────┬───────────┘
       │                 └─────────┬────────┘                   │
       │                           │                            │
       │                 ┌─────────▼────────┐        ┌──────────▼──────────┐
       │                 │ Project Analyzer │        │ Config / Allow Lists│
       │                 │ - walks sources  │        │ - rule toggles       │
       │                 │   (multi-lang)   │        │ - severity overrides │
       │                 └─────────┬────────┘        └──────────┬───────────┘
       │                           │                            │
       │                 ┌─────────▼────────┐        ┌──────────▼──────────┐
       │                 │ Ruleset          │        │ Loader               │
       └────────────────▶│ - security rule  │        │ - project metadata   │
                         │   heuristics     │        │ - MCP manifest parse │
                         └──────────────────┘        └──────────────────────┘
```

Mermaid equivalent:

```mermaid
flowchart LR
    subgraph EntryPoints[Entry Points]
        CLI[CLI (typer, mcp_scanner.cli)]
        MCPTool[MCP tool (MCPScannerTool)]
        PyAPI[Python API (Scanner)]
    end

    subgraph ScannerCore[Scanner Core]
        Scanner[Scanner\n- loads config\n- constructs ScanContext\n- runs rules]
        Analyzer[MultiLanguageAnalyzer / ProjectAnalyzer\n- walks source files\n- builds AST]
        Config[ScannerConfig\n- rule toggles\n- severity overrides\n- allow-lists]
        Rules[Rule set\n- security heuristics]
        Loader[Project loader\n- load_project\n- MCP manifest]
    end

    subgraph Reporting[Reporting]
        Console[Console renderer]
        JSONR[JSON report]
        SARIFR[SARIF report]
        MarkdownR[Markdown (CLI/MCP)]
    end

    EntryPoints --> Scanner
    Scanner --> Loader
    Scanner --> Analyzer
    Scanner --> Config
    Scanner --> Rules
    Rules --> Scanner
    Scanner --> Reporting
    Reporting --> Console
    Reporting --> JSONR
    Reporting --> SARIFR
    Reporting --> MarkdownR
```

## Execution Flow: CLI to Report

This diagram shows the detailed code path from “user runs the tool” to “project analyzed, report generated”.

```mermaid
flowchart TD
    User["User runs:\n mcp-scanner scan\n or\n python -m mcp_scanner.cli scan"] --> CLIEntry[cli.py: typer app]

    CLIEntry -->|parse options (--path, --mode, --output, --config, --verbosity)| CLIScan[cli.scan()]
    CLIScan -->|load config (optional)| LoadCfg[config.load_config()]
    CLIScan -->|construct| ScannerInit[scanner.Scanner(...)]

    ScannerInit -->|scan(path, mode)| ScannerScan[scanner.Scanner.scan()]
    ScannerScan -->|resolve root| LoadProject[loader.project_loader.load_project()]
    LoadProject --> ProjectMeta[ProjectMetadata\n+ MCPManifest]

    ScannerScan -->|init analyzers| AnalyzerSel{use_legacy_analyzer?}
    AnalyzerSel -->|Yes| LegacyAnalyzer[ProjectAnalyzer (python_analyzer.py)]
    AnalyzerSel -->|No| MultiAnalyzer[multi_analyzer.MultiLanguageAnalyzer]

    MultiAnalyzer -->|auto-detect / languages| LangDetect[language_detector.detect_languages()]

    ScannerScan -->|build| ScanCtx[ScanContext\n(project_root, mode, analyzer, config)]
    ScannerScan -->|iterate rules| RuleLoop{{for rule in all_rules()}}

    RuleLoop -->|skip if disabled| RuleSkip[config.is_rule_enabled(rule_id)]
    RuleLoop -->|run| RuleScan[rule.scan(ScanContext)]
    RuleScan -->|analyzer.iter_source_files() / iter_python_files()| SrcIter[walk files + AST]
    SrcIter --> Findings[Finding objects]

    RuleScan -->|exception| RuleError[emit <RULE>_ERROR Finding]

    Findings --> Collect[FindingsCollection]
    Collect -->|apply overrides| SeverityOverride[config.get_severity_override()]
    SeverityOverride --> CollectDone[final FindingsCollection]

    CollectDone --> HasBlocking[ScanResult.has_blocking_findings(fail_on)]

    CLIScan -->|format output| OutputSel{output format}
    OutputSel -->|console| ConsoleOut[reporting.console.render_console()]
    OutputSel -->|json| JSONOut[reporting.json_report.generate_json()]
    OutputSel -->|sarif| SARIFOut[reporting.sarif.generate_sarif()]
    OutputSel -->|markdown| MDOut[cli._generate_markdown()]

    ConsoleOut --> ExitCode
    JSONOut --> ExitCode
    SARIFOut --> ExitCode
    MDOut --> ExitCode

    HasBlocking -->|True (>= fail_on)| ExitNonZero["CLI exits with code 1"]
    HasBlocking -->|False| ExitZero["CLI exits with code 0"]

    ExitCode --> ExitNonZero
    ExitCode --> ExitZero
```

## Component Summary

- `mcp_scanner.loader.project_loader`: resolves project root and extracts MCP manifest context (`ProjectMetadata`) to accompany scan results.
- `mcp_scanner.analyzers.python_analyzer` / `mcp_scanner.analyzers.multi_analyzer`: walk source files under the target root (excluding common build/venv dirs), return parsed ASTs (Python AST or unified AST) used by rules.
- `mcp_scanner.rules.base`: defines the `Rule` interface, metadata, and `ScanContext` carrying mode/analyzer/config objects.
- `mcp_scanner.rules.security_rules`: concrete rule suite covering RCE/SSRF/prompts/auth/transport/resource categories. Each rule inspects AST or raw content to emit `Finding` objects with severity tuned by `ScanMode` (LOCAL vs SHARED).
- `mcp_scanner.config`: handles enable/disable per rule plus per-mode severity overrides, and allow-lists for future suppression logic.
- `mcp_scanner.scanner.Scanner`: orchestrates rule execution, applies config overrides, collects findings, and captures rule failures as `_ERROR` findings.
- `mcp_scanner.reporting`: converts finding collections into console-rich output, JSON summaries, or SARIF for integrations.
- `mcp_scanner.integrations.mcp_tool.MCPScannerTool`: light-weight adapter to expose `Scanner` capabilities through MCP actions (`list_rules`, `scan_project`, `get_recommendations`).

## How the Tool Works

1. **Invocation**: via CLI (Typer command), direct Python API, or MCP action.
2. **Project Load**: `load_project` resolves the root directory and attempts to parse MCP manifests (`mcp.json`, `mcp.yaml`, package.json, `pyproject.toml`). This metadata accompanies scan results but rules currently operate directly on code.
3. **Analyzer Setup**: `MultiLanguageAnalyzer` (or legacy `ProjectAnalyzer`) enumerates source files and builds ASTs for rule consumption.
4. **ScanContext Construction**: includes project root, scan mode (`LOCAL` or `SHARED`), analyzer, and active `ScannerConfig`.
5. **Rule Execution**:
   - Disabled rules are skipped.
   - Each rule runs `scan(context)` and yields `Finding` objects capturing file, line, severity, and remediation guidance.
   - Severity overrides from configuration are applied post-scan, allowing per-mode downgrades/upgrades.
   - Exceptions raised by rules are caught; the scanner emits a synthetic `<RULE>_ERROR` finding so pipelines surface rule health issues.
6. **Reporting**: Consumers format `FindingsCollection` through console/JSON/SARIF emitters or, in the MCP facade, convert to markdown for chat output.

