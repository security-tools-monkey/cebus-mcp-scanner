from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ScanMode(str, Enum):
    LOCAL = "local"
    SHARED = "shared"


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Severity:
    """
    Mode-aware severity that carries narrative context for output/reporting.
    """

    level: SeverityLevel
    message: str


DEFAULT_FAIL_ON = SeverityLevel.HIGH

