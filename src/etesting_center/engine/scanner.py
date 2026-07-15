from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .hash_db import HashDatabase
from .hashing import file_hashes, sample_bytes
from .heuristics import detect_file_type, heuristic_findings
from .models import FileResult, Finding, ScanReport, ScanSummary, classify_score, is_probably_file
from .yara_support import YaraScanner

ProgressCallback = Callable[[int, int, str], None]


class Scanner:
    def __init__(self, data_dir: Path, max_workers: int | None = None) -> None:
        self.data_dir = data_dir
        self.hash_db = HashDatabase.load(data_dir / "hashes.json")
        self.yara = YaraScanner(data_dir / "rules")
        self.max_workers = max_workers or 4

    def collect_targets(self, target: Path) -> list[Path]:
        if is_probably_file(target):
            return [target]
        if not target.exists() or not target.is_dir():
            return []
        files: list[Path] = []
        for path in target.rglob("*"):
            if is_probably_file(path):
                files.append(path)
        return files

    def scan(self, target: Path, progress: ProgressCallback | None = None) -> ScanReport:
        started = datetime.now(timezone.utc)
        files = self.collect_targets(target)
        results: list[FileResult] = []
        summary = ScanSummary()
        total = len(files)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {executor.submit(self.scan_file, path): path for path in files}
            for index, future in enumerate(as_completed(future_map), start=1):
                path = future_map[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = FileResult(
                        path=str(path),
                        size=0,
                        md5="",
                        sha256="",
                        file_type="unknown",
                        risk="suspicious",
                        score=20,
                        findings=[],
                        error=str(exc),
                    )
                results.append(result)
                self._update_summary(summary, result)
                if progress:
                    progress(index, total, str(path))

        results.sort(key=lambda item: (risk_sort_key(item.risk), -item.score, item.path))
        finished = datetime.now(timezone.utc)
        return ScanReport(
            target=str(target),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            yara_enabled=self.yara.enabled and self.yara.error is None,
            summary=summary,
            results=results,
        )

    def scan_file(self, path: Path) -> FileResult:
        stat = path.stat()
        data = sample_bytes(path)
        md5, sha256 = file_hashes(path)
        findings: list[Finding] = []

        hash_finding = self.hash_db.match(md5, sha256)
        if hash_finding:
            findings.append(hash_finding)

        findings.extend(heuristic_findings(path, data))
        findings.extend(self.yara.scan(path))

        score = score_findings(findings)
        risk = classify_score(score)
        return FileResult(
            path=str(path),
            size=stat.st_size,
            md5=md5,
            sha256=sha256,
            file_type=detect_file_type(path, data),
            risk=risk,
            score=score,
            findings=findings,
        )

    @staticmethod
    def _update_summary(summary: ScanSummary, result: FileResult) -> None:
        summary.scanned += 1
        if result.error:
            summary.errors += 1
        if result.risk == "malicious":
            summary.malicious += 1
        elif result.risk == "suspicious":
            summary.suspicious += 1
        else:
            summary.safe += 1


def score_findings(findings: Iterable[Finding]) -> int:
    score = 0
    for finding in findings:
        if finding.severity == "malicious":
            score += max(80, finding.confidence)
        elif finding.severity == "suspicious":
            score += finding.confidence
    return min(100, score)


def risk_sort_key(risk: str) -> int:
    return {"malicious": 0, "suspicious": 1, "safe": 2}.get(risk, 3)
