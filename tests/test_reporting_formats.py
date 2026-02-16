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
