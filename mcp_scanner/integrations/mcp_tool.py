from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from ..reporting.json_report import generate_json
from ..reporting.sarif import generate_sarif
from ..rules.security_rules import all_rules
from ..scanner import Scanner
from ..settings import ScanMode


@dataclass
class MCPActionResult:
    content_type: str
    body: str


class MCPScannerTool:
    """
    Minimal stub for MCP tool integration.
    """

    def __init__(self) -> None:
        self._scanner = Scanner()
        self._rules = all_rules()

    def list_rules(self) -> MCPActionResult:
        payload = [
            {
                "rule_id": rule.metadata.rule_id,
                "name": rule.metadata.name,
                "category": rule.metadata.category,
                "severity_local": rule.severity_for_mode(ScanMode.LOCAL).level.value,
                "severity_shared": rule.severity_for_mode(ScanMode.SHARED).level.value,
                "owasp_llm_top10_ids": rule.metadata.owasp_llm_top10_ids,
                "owasp_top10_ids": rule.metadata.owasp_top10_ids,
                "ml_top10_ids": rule.metadata.ml_top10_ids,
            }
            for rule in self._rules
        ]
        import json

        return MCPActionResult(
            content_type="application/json", body=json.dumps(payload, indent=2)
        )

    def scan_project(
        self,
        path: str,
        mode: str = ScanMode.LOCAL.value,
        output_format: str = "json",
    ) -> MCPActionResult:
        scan_mode = ScanMode(mode)
        result = self._scanner.scan(path, scan_mode)
        findings = list(result.findings)

        if output_format == "json":
            return MCPActionResult("application/json", generate_json(findings))
        if output_format == "sarif":
            return MCPActionResult("application/sarif+json", generate_sarif(findings))
        if output_format == "markdown":
            lines = ["### MCP Scan Findings"]
            for finding in findings:
                location = finding.file_path or "<unknown>"
                if finding.line:
                    location = f"{location}:{finding.line}"
                lines.append(
                    f"- **{finding.severity.level.value.upper()}** {finding.rule_id} at `{location}` – {finding.message}"
                )
            return MCPActionResult("text/markdown", "\n".join(lines))
        raise ValueError("Unsupported output format.")

    def get_recommendations(
        self,
        rule_id: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> MCPActionResult:
        if rule_id:
            rule = next((r for r in self._rules if r.metadata.rule_id == rule_id), None)
            if rule:
                content = (
                    f"### {rule.metadata.rule_id} - {rule.metadata.name}\n\n"
                    f"{rule.metadata.description}\n\n"
                    "- Apply principle of least privilege for tool inputs.\n"
                    "- Implement allow-lists for external interactions.\n"
                )
                return MCPActionResult("text/markdown", content)
        content = (
            "### MCP Security Best Practices\n\n"
            "- Enforce authentication and role checks for shared deployments.\n"
            "- Avoid logging sensitive tokens, prompts, or tool payloads.\n"
            "- Define network and filesystem boundaries for MCP tools.\n"
        )
        return MCPActionResult("text/markdown", content)

