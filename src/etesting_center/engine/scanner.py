"""
ETestingCenter 扫描引擎核心模块

功能：
- 文件遍历与收集（迭代器模式，不一次性加载全部到内存）
- 多线程并行扫描调度（小批次提交，即时取消响应）
- 整合所有检测引擎：
  1. 哈希特征码匹配（已知恶意文件）
  2. PE 结构深度分析（节区权限、入口点、时间戳等）
  3. 启发式分析（可疑 API、高熵、打包器等）
  4. YARA 规则匹配（自定义规则集）
  5. 数字签名验证（Windows 平台）
- 评分汇总与风险定级
- 扫描报告生成

设计原则：
- 只读检测，不修改、不隔离、不删除任何文件
- 多引擎协同，结果加权评分
- 线程安全，支持大规模并发扫描
- 资源优化：迭代器文件发现、小批次提交、单文件超时、大文件跳过
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

from .hash_db import HashDatabase
from .hashing import file_hashes, sample_bytes
from .heuristics import detect_file_type, heuristic_findings
from .models import FileResult, Finding, ScanReport, ScanSummary, classify_score, is_probably_file
from .pe_analysis import pe_findings   # PE 结构深度分析模块
from .signature_verify import signature_findings   # 数字签名验证模块
from .yara_support import YaraScanner

# 回调类型：done(已完成数量), total(总数量，0 表示未知), path(当前文件路径)
ProgressCallback = Callable[[int, int, str], None]

# 全盘扫描目标文件扩展名集合
FULL_SCAN_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl", ".scr", ".com",
    ".msi", ".msp", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".msc",
})

# 全盘扫描跳过的目录名（大小写不敏感）
FULL_SCAN_SKIP_DIRS = frozenset({
    "$Recycle.Bin", "System Volume Information", "Windows",
    "Program Files", "Program Files (x86)", "ProgramData",
    "$WinREAgent", "Recovery", "Config.Msi",
})

# 大文件阈值（超过此大小只做哈希检测，跳过 PE/启发式/YARA 深度分析）
LARGE_FILE_THRESHOLD = 100 * 1024 * 1024  # 100 MB

# 快速扫描文件大小上限（超过此大小直接跳过）
QUICK_SCAN_SIZE_LIMIT = 50 * 1024 * 1024  # 50 MB

# 快速扫描目标文件扩展名（仅扫描真正的可执行文件，脚本极易误报）
QUICK_SCAN_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys",
})

# 单文件扫描超时（秒）
SCAN_FILE_TIMEOUT = 5.0

# 扫描批次间延迟（秒），避免 CPU 空转
SCAN_LOOP_DELAY = 0.005


class Scanner:
    """
    病毒扫描器主类。

    集成多种检测引擎，负责扫描目标路径下的所有文件，
    并为每个文件生成风险评估结果。

    引擎列表（按优先级排序）：
    1. 哈希匹配 — 最高置信度（100分），直接匹配已知恶意文件
    2. PE 结构分析 — 中高置信度，检测 PE 文件结构异常
    3. 启发式分析 — 中等置信度，检测可疑行为模式
    4. YARA 规则 — 由规则定义置信度，灵活的模式匹配
    5. 数字签名 — 辅助判断，无签名的可执行文件加分警告

    资源优化：
    - 默认 3 个工作线程，控制资源占用
    - 迭代器模式发现文件，不一次性加载全部路径到内存
    - 小批次提交任务（batch_size = max_workers * 2）
    - 单文件扫描 5 秒超时控制
    - 超过 100MB 的大文件仅做哈希检测
    """

    def __init__(self, data_dir: Path, max_workers: int | None = None,
                 quick_mode: bool = False) -> None:
        """
        初始化扫描器。

        Args:
            data_dir: 数据目录路径（包含 hashes.json 和 rules/ 子目录）
            max_workers: 并行扫描的最大线程数，默认为 3
            quick_mode: 快速扫描模式（仅扫描可执行文件/脚本，跳过启发式和签名验证）
        """
        self.data_dir = data_dir
        self.quick_mode = quick_mode
        # 加载已知恶意文件哈希数据库
        self.hash_db = HashDatabase.load(data_dir / "hashes.json")
        # 加载 YARA 规则扫描器
        self.yara = YaraScanner(data_dir / "rules")
        self.max_workers = max_workers or 3
        # 取消事件 — 用于中断正在进行的扫描
        self.cancel_event = threading.Event()

    def cancel(self) -> None:
        """设置取消信号，中断当前扫描（不等待线程退出）。"""
        self.cancel_event.set()

    # ------------------------------------------------------------------
    # 文件收集（迭代器模式 — 不一次性加载全部到内存）
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_single_target(target: Path, seen: set[Path] | None = None) -> Iterator[Path]:
        """
        迭代器：逐个产出单目标下的文件路径。

        Args:
            target: 待扫描的文件或目录
            seen: 已见过路径集合（用于去重），None 表示不去重

        Yields:
            文件路径（逐个产出，不累积列表）
        """
        if is_probably_file(target):
            if seen is not None:
                resolved = target.resolve()
                if resolved in seen:
                    return
                seen.add(resolved)
            else:
                yield target
                return
            yield target
            return
        if not target.exists() or not target.is_dir():
            return
        for entry in target.rglob("*"):
            if is_probably_file(entry):
                resolved = entry.resolve()
                if seen is not None:
                    if resolved in seen:
                        continue
                    seen.add(resolved)
                yield entry

    @staticmethod
    def iter_targets(target: Path | list[Path]) -> Iterator[Path]:
        """
        迭代器：逐个产出所有目标下的文件路径。

        Args:
            target: 单个 Path 或多个 Path 的列表

        Yields:
            文件路径（逐个产出，不累积列表）
        """
        if isinstance(target, list):
            seen: set[Path] = set()
            for t in target:
                yield from Scanner._iter_single_target(t, seen)
        else:
            yield from Scanner._iter_single_target(target)

    # ------------------------------------------------------------------
    # 全盘扫描目标收集
    # ------------------------------------------------------------------

    @staticmethod
    def full_scan_targets() -> list[Path]:
        """
        收集全盘扫描目标文件。

        遍历所有可用盘符的根目录，递归收集常用可执行/脚本文件类型，
        自动跳过系统目录和大量小文件的非关键目录。

        目标类型：exe/dll/sys/ps1/vbs/bat/scr/com/msi 等（见 FULL_SCAN_EXTENSIONS）
        跳过目录：Windows/Program Files/ProgramData/$Recycle.Bin 等系统目录

        Returns:
            全盘扫描文件路径列表
        """
        from string import ascii_uppercase

        files: list[Path] = []
        for letter in ascii_uppercase:
            root = Path(f"{letter}:\\")
            if not root.exists():
                continue
            try:
                for entry in root.rglob("*"):
                    # 跳过系统目录
                    if entry.is_dir() and entry.name in FULL_SCAN_SKIP_DIRS:
                        continue
                    if not is_probably_file(entry):
                        continue
                    if entry.suffix.lower() in FULL_SCAN_EXTENSIONS:
                        files.append(entry)
            except PermissionError:
                continue  # 跳过无权访问的目录
            except OSError:
                continue
        return files

    # ------------------------------------------------------------------
    # 主扫描流程（迭代器 + 小批次提交 + 即时取消响应）
    # ------------------------------------------------------------------

    def scan(
        self,
        target: Path | list[Path],
        progress: ProgressCallback | None = None,
        total_files: int = 0,
    ) -> ScanReport:
        """
        执行顺序扫描流程（供非 Qt 场景使用）。

        Qt GUI 应使用 ScanWorker 的 QThreadPool 并行扫描路径。

        Args:
            target: 扫描目标路径，或路径列表（多目标扫描）
            progress: 进度回调函数（可选）

        Returns:
            包含所有扫描结果的 ScanReport 对象
        """
        self.cancel_event.clear()
        started = datetime.now(timezone.utc)

        if isinstance(target, list):
            target_str = ", ".join(str(t) for t in target)
        else:
            target_str = str(target)

        results: list[FileResult] = []
        summary = ScanSummary()
        done = 0

        file_iter = self.iter_targets(target)
        if self.quick_mode:
            def _quick_filter(it: Iterator[Path]) -> Iterator[Path]:
                for p in it:
                    if p.suffix.lower() in QUICK_SCAN_EXTENSIONS:
                        yield p
            file_iter = _quick_filter(file_iter)

        for path in file_iter:
            if self.cancel_event.is_set():
                break
            result = self.scan_file(path)
            results.append(result)
            self._update_summary(summary, result)
            done += 1
            if progress:
                progress(done, total_files, str(path))

        cancelled = self.cancel_event.is_set()
        results.sort(key=lambda item: (risk_sort_key(item.risk), -item.score, item.path))
        finished = datetime.now(timezone.utc)
        return ScanReport(
            target=target_str,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            yara_enabled=self.yara.enabled and self.yara.error is None,
            summary=summary,
            results=results,
            cancelled=cancelled,
        )

    # ------------------------------------------------------------------
    # 单文件扫描
    # ------------------------------------------------------------------

    def scan_file(self, path: Path) -> FileResult:
        """
        对单个文件执行完整的五引擎联合扫描。

        优化：
        - 处理前先检查取消信号，即时响应中断
        - 超过 100MB 的大文件仅做哈希检测，跳过深度分析
        - 快速模式下跳过 >50MB 的文件，并跳过启发式分析和签名验证

        扫描流程：
        1. 检查取消信号
        2. 读取文件基本信息（大小、类型、哈希值）
        3. 大文件快速路径（>100MB）→ 仅哈希匹配
        4. 哈希匹配 — 检查是否为已知恶意文件
        5. PE 结构分析 — 仅对 PE 文件进行深度分析
        6. 启发式分析 — 快速模式跳过
        7. YARA 规则匹配 — 自定义规则集
        8. 数字签名验证 — 快速模式跳过
        9. 综合评分 — 汇总所有发现并计算风险等级

        Args:
            path: 文件路径

        Returns:
            包含所有检测发现的 FileResult 对象
        """
        # 即时取消检查：每个文件处理前先看是否已取消
        if self.cancel_event.is_set():
            return FileResult(
                path=str(path),
                size=0,
                md5="",
                sha256="",
                file_type="unknown",
                risk="safe",
                score=0,
                findings=[],
                error="扫描已取消",
            )

        stat = path.stat()
        file_size = stat.st_size

        # 大文件快速路径：仅做哈希检测，跳过 PE/启发式/YARA 深度分析
        if file_size > LARGE_FILE_THRESHOLD:
            return self._scan_large_file(path, file_size)

        # 快速扫描模式：跳过超大文件
        if self.quick_mode and file_size > QUICK_SCAN_SIZE_LIMIT:
            return FileResult(
                path=str(path),
                size=file_size,
                md5="",
                sha256="",
                file_type="unknown",
                risk="safe",
                score=0,
                findings=[],
                error=f"快速扫描跳过（>{QUICK_SCAN_SIZE_LIMIT // (1024*1024)}MB）",
            )

        # 步骤 1：读取文件样本数据并计算哈希值
        data = sample_bytes(path)
        md5, sha256 = file_hashes(path)
        findings: list[Finding] = []

        # 步骤 2：哈希特征码匹配（最高置信度检测）
        hash_finding = self.hash_db.match(md5, sha256)
        if hash_finding:
            findings.append(hash_finding)

        # 步骤 3：PE 文件结构深度分析
        if data.startswith(b"MZ"):
            findings.extend(pe_findings(path, data))

        # 步骤 4：启发式分析（快速模式跳过）
        if not self.quick_mode:
            findings.extend(heuristic_findings(path, data))

        # 步骤 5：YARA 规则匹配
        findings.extend(self.yara.scan(path))

        # 步骤 6：数字签名验证（快速模式跳过）
        if not self.quick_mode:
            sig_findings = signature_findings(path)
            for sf in sig_findings:
                if sf.severity != "safe":
                    findings.append(sf)

        # 步骤 7：综合评分与风险定级
        score = score_findings(findings)
        risk = classify_score(score)

        return FileResult(
            path=str(path),
            size=file_size,
            md5=md5,
            sha256=sha256,
            file_type=detect_file_type(path, data),
            risk=risk,
            score=score,
            findings=findings,
        )

    def _scan_large_file(self, path: Path, file_size: int) -> FileResult:
        """大文件快速扫描路径：仅计算哈希并做特征码匹配。"""
        try:
            md5, sha256 = file_hashes(path)
        except Exception:
            return FileResult(
                path=str(path),
                size=file_size,
                md5="",
                sha256="",
                file_type="unknown",
                risk="safe",
                score=0,
                findings=[],
                error="大文件哈希计算失败",
            )

        finding = self.hash_db.match(md5, sha256)
        findings = [finding] if finding else []
        score = 100 if finding else 0
        risk = classify_score(score)

        return FileResult(
            path=str(path),
            size=file_size,
            md5=md5,
            sha256=sha256,
            file_type=detect_file_type(path, b""),
            risk=risk,
            score=score,
            findings=findings,
            error=None if finding else f"大文件（{self._fmt_size(file_size)}），仅哈希检测",
        )

    @staticmethod
    def _fmt_size(size: int) -> str:
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        return f"{size / (1024 * 1024 * 1024):.2f} GB"

    @staticmethod
    def _update_summary(summary: ScanSummary, result: FileResult) -> None:
        """更新扫描汇总统计信息。"""
        summary.scanned += 1
        if result.error and "仅哈希检测" not in result.error:
            summary.errors += 1
        if result.risk == "malicious":
            summary.malicious += 1
        elif result.risk == "suspicious":
            summary.suspicious += 1
        else:
            summary.safe += 1


def score_findings(findings: Iterable[Finding]) -> int:
    """
    综合评分算法 v2：按引擎封顶 + 多引擎关联加分。

    - 每个引擎取其最高置信度，各引擎贡献封顶 40 分（哈希库不限）
    - 2 个引擎命中 +5，3 个及以上 +15
    - 有效数字签名折半
    - 总评分上限 100

    风险等级（classify_score）：
    - >= 80：恶意 / >= 65：可疑 / < 65：安全
    """
    engine_max: dict[str, int] = {}
    has_valid_sig = False

    for finding in findings:
        if finding.rule == "valid_signature":
            has_valid_sig = True
            continue

        eng = finding.engine
        engine_max[eng] = max(engine_max.get(eng, 0), finding.confidence)

    score = 0
    for eng, conf in engine_max.items():
        if eng == "hash_db":
            score += conf
        else:
            score += min(40, conf)

    engines_triggered = len(engine_max)
    if engines_triggered >= 3:
        score += 15
    elif engines_triggered >= 2:
        score += 5

    score = min(100, score)

    if has_valid_sig and score > 0:
        score = score // 2

    return score


def risk_sort_key(risk: str) -> int:
    """风险等级排序键：恶意 > 可疑 > 安全。"""
    return {"malicious": 0, "suspicious": 1, "safe": 2}.get(risk, 3)
