from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path
from typing import Iterable

import pytest

from mcp_scanner.config import RuleConfig, ScannerConfig
from mcp_scanner.loader.project_loader import ProjectMetadata
from mcp_scanner.rules.base import Rule, RuleMetadata, ScanContext
from mcp_scanner.scanner import ScanResult, Scanner
from mcp_scanner.settings import ScanMode, Severity, SeverityLevel
from mcp_scanner.core_types import Finding, FindingsCollection
from mcp_scanner.integrations.mcp_tool import MCPScannerTool


def _write_project_file(tmp_path: Path, content: str, filename: str = "module.py") -> Path:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def test_scanner_respects_disabled_rules(tmp_path: Path) -> None:
    project_dir = _write_project_file(
        tmp_path,
        "import os\n\n"
        "def run() -> None:\n"
        "    os.system('ls')\n",
    )

    config = ScannerConfig(rules={"RCE001": RuleConfig(enabled=False)})
    scanner = Scanner(config=config)

    result = scanner.scan(str(project_dir), ScanMode.SHARED)
    assert all(f.rule_id != "RCE001" for f in result.findings)


def test_scanner_applies_severity_override(tmp_path: Path) -> None:
    project_dir = _write_project_file(
        tmp_path,
        "import os\n\n"
        "def run() -> None:\n"
        "    os.system('ls')\n",
    )

    config = ScannerConfig(
        rules={
            "RCE001": RuleConfig(
                severity_override={ScanMode.SHARED.value: SeverityLevel.INFO.value}
            )
        }
    )
    scanner = Scanner(config=config)

    result = scanner.scan(str(project_dir), ScanMode.SHARED)
    finding = next(f for f in result.findings if f.rule_id == "RCE001")

    assert finding.severity.level == SeverityLevel.INFO


def test_scan_result_threshold_checks(tmp_path: Path) -> None:
    severity = Severity(level=SeverityLevel.MEDIUM, message="test")
    finding = Finding(
        rule_id="TEST001",
        message="demo",
        file_path="module.py",
        line=1,
        category="Demo",
        severity=severity,
        why_it_matters="Because",
        recommendation="Fix it",
    )
    findings = FindingsCollection([finding])
    project = ProjectMetadata(root=tmp_path, manifest=None)
    result = ScanResult(findings=findings, project=project)

    assert result.has_blocking_findings(SeverityLevel.LOW) is True
    assert result.has_blocking_findings(SeverityLevel.HIGH) is False


class ExplodingRule(Rule):
    metadata = RuleMetadata(
        rule_id="TEST_ERR",
        name="Exploding Rule",
        category="Internal",
        description="Always raises to exercise error handling.",
        owasp_llm_top10_ids=[],
        owasp_top10_ids=[],
        ml_top10_ids=[],
    )

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        raise RuntimeError("boom")

    def severity_for_mode(self, mode: ScanMode) -> Severity:
        return Severity(level=SeverityLevel.HIGH, message="exploded")


def test_scanner_emits_error_finding(tmp_path: Path) -> None:
    project_dir = _write_project_file(tmp_path, "print('ok')\n", "app.py")
    scanner = Scanner(rules=[ExplodingRule()])

    result = scanner.scan(str(project_dir), ScanMode.SHARED)
    findings = list(result.findings)

    assert len(findings) == 1
    assert findings[0].rule_id == "TEST_ERR_ERROR"
    assert findings[0].severity.level == SeverityLevel.HIGH
    assert "Rule execution failed" in findings[0].message


def test_scanner_cleans_up_zip_temp_dir(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "app.py").write_text("print('ok')\n", encoding="utf-8")

    zip_path = tmp_path / "project.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(project_dir / "app.py", arcname="project/app.py")

    scanner = Scanner(rules=[ExplodingRule()])
    result = scanner.scan(str(zip_path), ScanMode.SHARED)

    assert result.project.temp_dir is not None
    assert result.project.temp_dir.exists() is False


def test_scanner_does_not_cleanup_folder_project(tmp_path: Path) -> None:
    project_dir = _write_project_file(tmp_path, "print('ok')\n")
    scanner = Scanner(rules=[])

    result = scanner.scan(str(project_dir), ScanMode.SHARED)

    assert result.project.temp_dir is None
    assert project_dir.exists() is True


def test_scanner_keeps_zip_temp_dir_when_requested(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "app.py").write_text("print('ok')\n", encoding="utf-8")

    zip_path = tmp_path / "project.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(project_dir / "app.py", arcname="project/app.py")

    scanner = Scanner(rules=[ExplodingRule()])
    result = scanner.scan(str(zip_path), ScanMode.SHARED, keep_extracted=True)

    assert result.project.temp_dir is not None
    assert result.project.temp_dir.exists() is True

    shutil.rmtree(result.project.temp_dir, ignore_errors=True)


def test_mcp_tool_lists_rules() -> None:
    tool = MCPScannerTool()
    response = tool.list_rules()
    payload = json.loads(response.body)

    assert response.content_type == "application/json"
    assert any(rule["rule_id"] == "RCE001" for rule in payload)


def test_mcp_tool_markdown_output(tmp_path: Path) -> None:
    project_dir = _write_project_file(
        tmp_path,
        "import requests\n\n"
        "def fetch(url):\n"
        "    return requests.get(url)\n",
        "client.py",
    )
    tool = MCPScannerTool()

    response = tool.scan_project(
        str(project_dir),
        mode=ScanMode.SHARED.value,
        output_format="markdown",
    )

    assert response.content_type == "text/markdown"
    assert "SSRF001" in response.body


def test_mcp_tool_rejects_unknown_format(tmp_path: Path) -> None:
    project_dir = _write_project_file(tmp_path, "print('ok')\n")
    tool = MCPScannerTool()

    with pytest.raises(ValueError):
        tool.scan_project(str(project_dir), output_format="xml")
