from __future__ import annotations

import json

from mcp_scanner.core_types import Finding
from mcp_scanner.reporting.json_report import generate_json
from mcp_scanner.reporting.sarif import generate_sarif
from mcp_scanner.settings import Severity, SeverityLevel


def _one_finding() -> Finding:
    return Finding(
        rule_id="TEST001",
        message="demo",
        file_path="src/app.py",
        line=3,
        category="Demo",
        severity=Severity(level=SeverityLevel.LOW, message="low"),
        why_it_matters="because",
        recommendation="do x",
        owasp_llm_top10_ids=["LLM01"],
        owasp_top10_ids=["A01"],
        ml_top10_ids=[],
    )


def test_generate_json_is_valid_json_and_has_expected_keys() -> None:
    payload = generate_json([_one_finding()])
    data = json.loads(payload)

    assert isinstance(data, list)
    assert data[0]["rule_id"] == "TEST001"
    assert data[0]["severity"] == "low"
    assert data[0]["file"] == "src/app.py"


def test_generate_sarif_is_valid_json_and_contains_runs_results() -> None:
    payload = generate_sarif([_one_finding()])
    data = json.loads(payload)

    assert data["version"] == "2.1.0"
    assert "runs" in data and isinstance(data["runs"], list)
    run0 = data["runs"][0]
    assert "results" in run0 and len(run0["results"]) == 1
    assert run0["results"][0]["ruleId"] == "TEST001"


def test_cli_writes_default_report_files(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("mcp_scanner.cli.render_console", lambda _: None)
    monkeypatch.setattr("mcp_scanner.cli.Scanner.scan", _scan_empty_result(tmp_path))

    reports_dir = tmp_path / "reports"
    project_dir, hash_value = _invoke_scan(
        tmp_path,
        output_formats=["json", "sarif", "markdown"],
        output_dir=reports_dir,
    )

    assert (reports_dir / f"scan-report-{hash_value}.json").exists()
    assert (reports_dir / f"scan-report-{hash_value}.sarif").exists()
    assert (reports_dir / f"scan-report-{hash_value}.md").exists()


def test_cli_respects_output_overrides(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("mcp_scanner.cli.render_console", lambda _: None)
    monkeypatch.setattr("mcp_scanner.cli.Scanner.scan", _scan_empty_result(tmp_path))

    json_out = tmp_path / "custom" / "report.json"
    sarif_out = tmp_path / "reports" / "scan.sarif"
    markdown_out = tmp_path / "notes" / "report.md"

    project_dir, hash_value = _invoke_scan(
        tmp_path,
        output_formats=["json", "sarif", "markdown"],
        json_out=json_out,
        sarif_out=sarif_out,
        markdown_out=markdown_out,
    )

    assert (json_out.parent / f"{json_out.stem}-{hash_value}{json_out.suffix}").exists()
    assert (sarif_out.parent / f"{sarif_out.stem}-{hash_value}{sarif_out.suffix}").exists()
    assert (
        markdown_out.parent
        / f"{markdown_out.stem}-{hash_value}{markdown_out.suffix}"
    ).exists()


def _scan_empty_result(tmp_path):
    from mcp_scanner.core_types import FindingsCollection
    from mcp_scanner.loader.project_loader import ProjectMetadata
    from mcp_scanner.scanner import ScanResult

    project = ProjectMetadata(root=tmp_path, manifest=None)

    def _scan(_self, _path, _mode, keep_extracted=False):
        return ScanResult(findings=FindingsCollection([]), project=project)

    return _scan


def _invoke_scan(tmp_path, **kwargs):
    from mcp_scanner.cli import scan as cli_scan
    from mcp_scanner.cli import _hash_scan_target
    from mcp_scanner.settings import DEFAULT_FAIL_ON
    from mcp_scanner.logging_utils import VerbosityLevel

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "sample.txt").write_text("hello", encoding="utf-8")
    kwargs.setdefault("output_dir", tmp_path / "reports")
    kwargs.setdefault("json_out", None)
    kwargs.setdefault("sarif_out", None)
    kwargs.setdefault("markdown_out", None)
    kwargs.setdefault("config", None)
    kwargs.setdefault("keep_extracted", False)
    cli_scan(
        path=project_dir,
        mode="local",
        fail_on=DEFAULT_FAIL_ON.value,
        verbosity=VerbosityLevel.QUIET.value,
        **kwargs,
    )
    return project_dir, _hash_scan_target(project_dir)
