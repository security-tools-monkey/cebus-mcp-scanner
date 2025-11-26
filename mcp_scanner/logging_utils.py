from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable


class VerbosityLevel(str, Enum):
    QUIET = "quiet"
    NORMAL = "normal"
    VERBOSE = "verbose"


Emitter = Callable[[str], None]


@dataclass
class ScanLogger:
    verbosity: VerbosityLevel = VerbosityLevel.QUIET
    emit: Emitter = print

    def debug(self, message: str) -> None:
        if self.verbosity is VerbosityLevel.VERBOSE:
            self.emit(f"[verbose] {message}")

    def info(self, message: str) -> None:
        if self.verbosity in (VerbosityLevel.NORMAL, VerbosityLevel.VERBOSE):
            self.emit(f"[info] {message}")

    def warning(self, message: str) -> None:
        if self.verbosity is VerbosityLevel.QUIET:
            # Even in quiet mode, surface warnings
            self.emit(f"[warn] {message}")
        else:
            self.emit(f"[warn] {message}")

    def error(self, message: str) -> None:
        self.emit(f"[error] {message}")


