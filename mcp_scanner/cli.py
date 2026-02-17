"""
Typer-based CLI for running scans, listing rules, and printing recommendations.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from .config import ScannerConfig, load_config
from .logging_utils import ScanLogger, VerbosityLevel
from .reporting.console import render_console
from .reporting.json_report import generate_json
from .reporting.sarif import generate_sarif
from .rules.security_rules import all_rules
from .scanner import Scanner
from .settings import DEFAULT_FAIL_ON, ScanMode, SeverityLevel

app = typer.Typer(help="MCP Security Scanner CLI")
console = Console()


def _parse_mode(mode: str) -> ScanMode:
    try:
        return ScanMode(mode)
    except ValueError as exc:  # pragma: no cover - handled by typer
        raise typer.BadParameter(str(exc)) from exc


def _parse_severity(level: str) -> SeverityLevel:
    try:
        return SeverityLevel(level)
    except ValueError as exc:  # pragma: no cover
        raise typer.BadParameter(str(exc)) from exc


def _parse_verbosity(value: str) -> VerbosityLevel:
    try:
        return VerbosityLevel(value.lower())
    except ValueError as exc:
        raise typer.BadParameter(
            "Verbosity must be one of quiet, normal, verbose."
        ) from exc


@app.command()
def scan(
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Path to MCP project root or .zip archive.",
        exists=True,
    ),
    mode: str = typer.Option(
        ScanMode.LOCAL.value,
        "--mode",
        "-m",
        help="Scanning mode: local or shared.",
    ),
    output_format: str = typer.Option(
        "console",
        "--output",
        "-o",
        help="Output format: console, json, sarif, markdown.",
    ),
    fail_on: str = typer.Option(
        DEFAULT_FAIL_ON.value,
        "--fail-on",
        help="Fail when findings reach this severity level.",
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        help="Path to custom rule configuration file (YAML or JSON).",
    ),
    verbosity: str = typer.Option(
        VerbosityLevel.QUIET.value,
        "--verbosity",
        "-v",
        help="Verbosity level: quiet (default), normal, verbose.",
        show_default=True,
    ),
    keep_extracted: bool = typer.Option(
        False,
        "--keep-extracted",
        help="Keep extracted zip contents on disk for debugging.",
        show_default=True,
    ),
) -> None:
    """Run a scan against an MCP project."""
    scan_mode = _parse_mode(mode)
    threshold = _parse_severity(fail_on)
    verbosity_level = _parse_verbosity(verbosity)
    
    # Load config if provided
    scanner_config = None
    if config:
        try:
            scanner_config = load_config(config)
        except Exception as e:
            console.print(f"[red]Error loading config: {e}[/red]")
            raise typer.Exit(code=1)
    
    logger = ScanLogger(verbosity=verbosity_level, emit=console.print)
    scanner = Scanner(config=scanner_config, logger=logger)
    result = scanner.scan(str(path), scan_mode, keep_extracted=keep_extracted)

    findings = list(result.findings)

    # Select output format
    if output_format == "console":
        render_console(findings)
    elif output_format == "json":
        console.print(generate_json(findings))
    elif output_format == "sarif":
        console.print(generate_sarif(findings))
    elif output_format == "markdown":
        console.print(_generate_markdown(findings))
    else:
        raise typer.BadParameter("Unsupported output format.")

    if result.has_blocking_findings(threshold):
        raise typer.Exit(code=1)


def _generate_markdown(findings):
    if not findings:
        return "### Findings\n\nNo issues detected."
    lines = ["### Findings"]
    for finding in findings:
        location = finding.file_path or "<unknown>"
        if finding.line:
            location = f"{location}:{finding.line}"
        lines.append(
            f"- **{finding.severity.level.value.upper()}** `{finding.rule_id}` "
            f"({finding.category}) at `{location}`: {finding.message}"
        )
        lines.append(f"  - Why it matters: {finding.why_it_matters}")
        lines.append(f"  - Recommendation: {finding.recommendation}")
    return "\n".join(lines)


@app.command("list-rules")
def list_rules() -> None:
    """List all available rules and their metadata."""
    rules = all_rules()
    payload = [
        {
            "rule_id": rule.metadata.rule_id,
            "name": rule.metadata.name,
            "category": rule.metadata.category,
            "description": rule.metadata.description,
            "owasp_llm_top10_ids": rule.metadata.owasp_llm_top10_ids,
            "owasp_top10_ids": rule.metadata.owasp_top10_ids,
            "ml_top10_ids": rule.metadata.ml_top10_ids,
        }
        for rule in rules
    ]
    console.print_json(json.dumps(payload))


@app.command("get-recommendations")
def get_recommendations(
    rule_id: Optional[str] = typer.Option(None, "--rule-id"),
) -> None:
    """Provide best-practice recommendations for a rule."""
    rules = {rule.metadata.rule_id: rule for rule in all_rules()}
    if rule_id and rule_id in rules:
        rule = rules[rule_id]
        console.print(
            f"### {rule.metadata.rule_id} - {rule.metadata.name}\n\n"
            f"{rule.metadata.description}\n\n"
            "- Ensure guardrails constrain tool invocation paths.\n"
            "- Restrict risky tool usage in shared environments.\n"
        )
        return

    console.print(
        "### General Recommendations\n\n"
        "- Enforce authentication for high-impact MCP endpoints.\n"
        "- Apply network allow-lists for outbound HTTP tools.\n"
        "- Avoid exposing prompts, secrets, or internal topology in responses.\n"
    )


def run() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    run()
