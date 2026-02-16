"""
Core scan orchestrator: loads project context, runs rules, and returns a ScanResult.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional

from .analyzers.multi_analyzer import MultiLanguageAnalyzer
from .config import ScannerConfig
from .logging_utils import ScanLogger, VerbosityLevel
from .loader.project_loader import ProjectMetadata, load_project
from .rules.base import Rule, ScanContext
from .rules.security_rules import all_rules
from .settings import ScanMode, SeverityLevel
from .core_types import Finding, FindingsCollection


@dataclass
class ScanResult:
    findings: FindingsCollection
    project: ProjectMetadata

    def has_blocking_findings(self, fail_on: SeverityLevel) -> bool:
        return any(f.severity_threshold_passes(fail_on) for f in self.findings)


class Scanner:
    def __init__(
        self,
        rules: Iterable[Rule] | None = None,
        config: Optional[ScannerConfig] = None,
        logger: Optional[ScanLogger] = None,
        languages: List[str] | None = None,
    ) -> None:
        """
        Initialize scanner.
        
        Args:
            rules: Custom rule set, or None for all rules
            config: Scanner configuration
            logger: Optional logger for verbose output
            languages: Explicit list of languages to scan, or None for auto-detect
        """
        self.rules: List[Rule] = list(rules) if rules is not None else all_rules()
        self.config = config or ScannerConfig()
        self.logger = logger or ScanLogger(verbosity=VerbosityLevel.QUIET)
        self.languages = languages

    def scan(self, path: str, mode: ScanMode) -> ScanResult:
        self.logger.info(f"Starting scan path={path} mode={mode.value}")
        project = load_project(path)
        
        multi_analyzer = MultiLanguageAnalyzer(
            root=str(project.root),
            languages=self.languages,
            logger=self.logger,
        )
        analyzer = multi_analyzer
        supported_langs = multi_analyzer.get_supported_languages()
        if supported_langs:
            self.logger.debug(f"Scanning languages: {supported_langs}")
        
        context = ScanContext(
            project_root=str(project.root),
            mode=mode,
            analyzer=analyzer,
            config=self.config,
        )

        findings = FindingsCollection()
        for rule in self.rules:
            # Skip disabled rules
            if not self.config.is_rule_enabled(rule.metadata.rule_id):
                self.logger.debug(
                    f"Skipping disabled rule {rule.metadata.rule_id} ({rule.metadata.name})"
                )
                continue

            self.logger.debug(f"Running rule {rule.metadata.rule_id}")
            try:
                rule_findings = list(rule.scan(context))
                # Apply severity overrides from config
                for finding in rule_findings:
                    override = self.config.get_severity_override(
                        finding.rule_id, mode
                    )
                    if override:
                        from .settings import Severity

                        finding.severity = Severity(
                            level=override, message=finding.severity.message
                        )
                findings.extend(rule_findings)
                if rule_findings:
                    self.logger.debug(
                        f"Rule {rule.metadata.rule_id} produced {len(rule_findings)} finding(s)"
                    )
                else:
                    self.logger.debug(f"Rule {rule.metadata.rule_id} passed cleanly")
            except Exception as exc:  # pragma: no cover
                self.logger.error(
                    f"Rule {rule.metadata.rule_id} failed with error: {exc}"
                )
                findings.add(
                    Finding(
                        rule_id=f"{rule.metadata.rule_id}_ERROR",
                        message=f"Rule execution failed: {exc}",
                        file_path=None,
                        line=None,
                        category="Scanner Internal",
                        severity=rule.severity_for_mode(mode),
                        why_it_matters="Rule failed to execute; manual review required.",
                        recommendation="Inspect scanner logs and rule implementation.",
                        owasp_llm_top10_ids=rule.metadata.owasp_llm_top10_ids,
                        owasp_top10_ids=rule.metadata.owasp_top10_ids,
                        ml_top10_ids=rule.metadata.ml_top10_ids,
                    )
                )

        self.logger.info(f"Scan finished. Total findings: {len(findings)}")
        return ScanResult(findings=findings, project=project)
