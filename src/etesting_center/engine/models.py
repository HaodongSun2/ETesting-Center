from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


RiskLevel = str


@dataclass(slots=True)
class Finding:
    engine: str
    rule: str
    severity: RiskLevel
    confidence: int
    description: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class FileResult:
    path: str
    size: int
    md5: str
    sha256: str
    file_type: str
    risk: RiskLevel
    score: int
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class ScanSummary:
    scanned: int = 0
    skipped: int = 0
    safe: int = 0
    suspicious: int = 0
    malicious: int = 0
    errors: int = 0


@dataclass(slots=True)
class ScanReport:
    target: str
    started_at: str
    finished_at: str
    yara_enabled: bool
    summary: ScanSummary
    results: list[FileResult]


def classify_score(score: int) -> RiskLevel:
    if score >= 80:
        return "malicious"
    if score >= 35:
        return "suspicious"
    return "safe"


def is_probably_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False
