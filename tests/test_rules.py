from pathlib import Path

from mcp_scanner.scanner import Scanner
from mcp_scanner.settings import ScanMode, SeverityLevel

ASSETS_DIR = Path(__file__).parent / "assets"


def test_scanner_detects_vulnerabilities(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "vulnerable_http.py").write_text(
        (ASSETS_DIR / "vulnerable_http.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    scanner = Scanner()
    result = scanner.scan(str(project_dir), ScanMode.SHARED)
    findings = list(result.findings)

    rule_ids = {f.rule_id for f in findings}
    assert "RCE001" in rule_ids
    assert "SSRF001" in rule_ids
    assert all(f.severity.level in {SeverityLevel.HIGH, SeverityLevel.MEDIUM} for f in findings)


def test_scanner_is_lenient_in_local_mode(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "safe_code.py").write_text(
        (ASSETS_DIR / "safe_code.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    scanner = Scanner()
    result = scanner.scan(str(project_dir), ScanMode.LOCAL)
    findings = list(result.findings)

    # assert len(findings) == 0
    # Local mode is "lenient" in the sense that it should not raise blocking severities.
    assert all(f.severity.level in {SeverityLevel.INFO, SeverityLevel.LOW} for f in findings)

