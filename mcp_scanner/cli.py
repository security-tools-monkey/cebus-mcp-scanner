"""
Typer-based CLI for running scans, listing rules, and printing recommendations.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
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
_VALID_OUTPUT_FORMATS = ("console", "json", "sarif", "markdown", "md")
_HASH_PLACEHOLDER = "{hash}"


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


def _parse_formats(raw_formats: list[str]) -> list[str]:
    if not raw_formats:
        return ["console"]

    formats: list[str] = []
    for entry in raw_formats:
        if entry is None:
            continue
        parts = [part.strip().lower() for part in entry.split(",")]
        for part in parts:
            if not part:
                continue
            formats.append("markdown" if part == "md" else part)

    if not formats:
        return ["console"]

    invalid = sorted({fmt for fmt in formats if fmt not in _VALID_OUTPUT_FORMATS})
    if invalid:
        valid_values = ", ".join(_VALID_OUTPUT_FORMATS)
        invalid_values = ", ".join(invalid)
        raise typer.BadParameter(
            f"Unsupported output format(s): {invalid_values}. "
            f"Valid values: {valid_values}."
        )

    return formats


def _ensure_parent_dir(destination: Path) -> None:
    parent = destination.parent if destination.parent != Path("") else Path(".")
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise typer.BadParameter(
            f"Unable to create output directory '{parent}': {exc}"
        ) from exc
    if not parent.is_dir():
        raise typer.BadParameter(f"Output directory is not a directory: '{parent}'")
    if destination.exists() and destination.is_dir():
        raise typer.BadParameter(f"Output path is a directory: '{destination}'")


def _hash_file(path: Path) -> str:
    hasher = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _hash_directory(path: Path) -> str:
    hasher = hashlib.md5()
    file_paths: list[Path] = []
    for root, _, files in os.walk(path):
        for filename in files:
            file_paths.append(Path(root) / filename)

    for file_path in sorted(file_paths, key=lambda p: str(p.relative_to(path))):
        relative = file_path.relative_to(path).as_posix()
        hasher.update(relative.encode("utf-8"))
        hasher.update(b"\0")
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
    return hasher.hexdigest()


def _hash_scan_target(path: Path) -> str:
    if path.is_dir():
        return _hash_directory(path)
    if path.is_file():
        return _hash_file(path)
    raise typer.BadParameter(f"Scan path is not a file or directory: '{path}'")


def _apply_hash_to_path(destination: Path, hash_value: str) -> Path:
    destination_str = str(destination)
    if _HASH_PLACEHOLDER in destination_str:
        return Path(destination_str.replace(_HASH_PLACEHOLDER, hash_value))

    suffix = "".join(destination.suffixes)
    name = destination.name
    stem = name[: -len(suffix)] if suffix else name
    hashed_name = f"{stem}-{hash_value}{suffix}"
    return destination.with_name(hashed_name)


def _write_report_file(payload: str, destination: Path) -> Path:
    _ensure_parent_dir(destination)

    tmp_file = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=destination.parent,
        delete=False,
    )
    tmp_path = Path(tmp_file.name)
    try:
        with tmp_file:
            tmp_file.write(payload)
        os.replace(tmp_path, destination)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    return destination


def _resolve_output_path(
    default_dir: Path,
    filename: str,
    override: Optional[Path],
    hash_value: str,
) -> Path:
    destination = override if override is not None else default_dir / filename
    destination = _apply_hash_to_path(destination, hash_value)
    _ensure_parent_dir(destination)
    return destination


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
    output_formats: list[str] = typer.Option(
        ["console"],
        "--output-format",
        "--format",
        "--output",
        "-o",
        help="Output format(s): console, json, sarif, markdown.",
    ),
    output_dir: Path = typer.Option(
        Path("reports"),
        "--output-dir",
        help="Directory for JSON/SARIF/Markdown report files.",
    ),
    json_out: Optional[Path] = typer.Option(
        None,
        "--json-out",
        help="Override JSON report output path.",
    ),
    sarif_out: Optional[Path] = typer.Option(
        None,
        "--sarif-out",
        help="Override SARIF report output path.",
    ),
    markdown_out: Optional[Path] = typer.Option(
        None,
        "--markdown-out",
        "--md-out",
        help="Override Markdown report output path.",
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
    formats = _parse_formats(output_formats)

    needs_file_output = any(
        fmt in {"json", "sarif", "markdown"} for fmt in formats
    )
    hash_value = _hash_scan_target(path) if needs_file_output else ""
    
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

    # Select output format(s)
    for output_format in formats:
        if output_format == "console":
            render_console(findings)
        elif output_format == "json":
            path = _resolve_output_path(
                output_dir,
                "scan-report.json",
                json_out,
                hash_value,
            )
            _write_report_file(generate_json(findings), path)
            console.print(f"Wrote JSON report to {path}")
        elif output_format == "sarif":
            path = _resolve_output_path(
                output_dir,
                "scan-report.sarif",
                sarif_out,
                hash_value,
            )
            _write_report_file(generate_sarif(findings), path)
            console.print(f"Wrote SARIF report to {path}")
        elif output_format == "markdown":
            path = _resolve_output_path(
                output_dir,
                "scan-report.md",
                markdown_out,
                hash_value,
            )
            _write_report_file(_generate_markdown(findings), path)
            console.print(f"Wrote Markdown report to {path}")

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
