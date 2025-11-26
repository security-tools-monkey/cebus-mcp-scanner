from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List

from .settings import ScanMode, Severity, SeverityLevel


@dataclass
class Finding:
    rule_id: str
    message: str
    file_path: str | None
    line: int | None
    category: str
    severity: Severity
    why_it_matters: str
    recommendation: str
    owasp_llm_top10_ids: List[str] = field(default_factory=list)
    owasp_top10_ids: List[str] = field(default_factory=list)
    ml_top10_ids: List[str] = field(default_factory=list)

    def severity_threshold_passes(self, fail_on: SeverityLevel) -> bool:
        order = [SeverityLevel.INFO, SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH]
        return order.index(self.severity.level) >= order.index(fail_on)


class FindingsCollection:
    def __init__(self, findings: Iterable[Finding] | None = None) -> None:
        self._findings: List[Finding] = list(findings or [])

    def add(self, finding: Finding) -> None:
        self._findings.append(finding)

    def extend(self, findings: Iterable[Finding]) -> None:
        for finding in findings:
            self.add(finding)

    def __iter__(self):
        yield from self._findings

    def __len__(self) -> int:
        return len(self._findings)

    def filter_by_mode(self, mode: ScanMode) -> "FindingsCollection":
        # Hook for future mode-aware filtering if needed.
        return FindingsCollection(self._findings)

