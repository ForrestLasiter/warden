"""Core data models shared across engines, scanner, and UI.

Everything an engine produces is a ``Finding``. Everything the scanner
produces for one file is a ``FileResult``. A whole scan is a ``ScanReport``.
These are plain dataclasses so they serialize cleanly to JSON for the CLI,
the GUI, and stored history.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class Severity(enum.IntEnum):
    """Ordered so the worst finding on a file is simply ``max(...)``."""

    CLEAN = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]


@dataclass(slots=True)
class Finding:
    """A single detection produced by one engine for one file."""

    engine: str            # which engine raised it ("yara", "hash", "heuristics", "clamav")
    name: str              # rule/signature/heuristic name
    severity: Severity
    description: str = ""
    # Free-form engine detail (matched strings, offsets, hash source, PE flags...)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = int(self.severity)
        d["severity_label"] = self.severity.label
        return d


@dataclass(slots=True)
class FileResult:
    """Aggregated result for a single scanned file."""

    path: str
    size: int = 0
    sha256: str | None = None
    findings: list[Finding] = field(default_factory=list)
    scanned: bool = False
    error: str | None = None

    @property
    def verdict(self) -> Severity:
        if not self.findings:
            return Severity.CLEAN
        return max(f.severity for f in self.findings)

    @property
    def is_threat(self) -> bool:
        return self.verdict >= Severity.MEDIUM

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "scanned": self.scanned,
            "error": self.error,
            "verdict": int(self.verdict),
            "verdict_label": self.verdict.label,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass(slots=True)
class ScanReport:
    """The full result of one scan run."""

    root: str
    started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished: str | None = None
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    errors: int = 0
    engines: list[str] = field(default_factory=list)
    results: list[FileResult] = field(default_factory=list)

    @property
    def threats(self) -> list[FileResult]:
        return [r for r in self.results if r.is_threat]

    @property
    def duration_seconds(self) -> float | None:
        if not self.finished:
            return None
        a = datetime.fromisoformat(self.started)
        b = datetime.fromisoformat(self.finished)
        return (b - a).total_seconds()

    def counts_by_verdict(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.results:
            out[r.verdict.label] = out.get(r.verdict.label, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "started": self.started,
            "finished": self.finished,
            "duration_seconds": self.duration_seconds,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "bytes_scanned": self.bytes_scanned,
            "errors": self.errors,
            "engines": self.engines,
            "counts_by_verdict": self.counts_by_verdict(),
            "threats": len(self.threats),
            "results": [r.to_dict() for r in self.results],
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_data_dir() -> Path:
    """Per-user location for quarantine, history, and config."""
    base = Path.home() / ".warden"
    return base
