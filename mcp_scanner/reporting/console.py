from __future__ import annotations

from typing import Iterable

from rich.console import Console
from rich.table import Table

from ..core_types import Finding


def render_console(findings: Iterable[Finding]) -> None:
    console = Console()
    table = Table(title="MCP Security Scanner Findings")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Rule")
    table.add_column("Location")
    table.add_column("Message")

    for finding in findings:
        location = finding.file_path or "<unknown>"
        if finding.line:
            location = f"{location}:{finding.line}"

        table.add_row(
            finding.severity.level.value.upper(),
            finding.category,
            finding.rule_id,
            location,
            finding.message,
        )

    if len(table.rows) == 0:
        console.print("[green]No findings detected.[/green]")
        return

    console.print(table)

