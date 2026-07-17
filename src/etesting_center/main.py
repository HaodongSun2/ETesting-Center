from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import (
    QEasingCurve,
    QObject,
    QPoint,
    QPropertyAnimation,
    QRunnable,
    QRectF,
    QSettings,
    QSize,
    QThread,
    QThreadPool,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QFont,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QStackedWidget,
)

from etesting_center import APP_NAME, APP_TAGLINE, APP_VERSION
from etesting_center.engine.models import ScanReport, ScanSummary
from etesting_center.engine.scanner import Scanner, risk_sort_key
from etesting_center.reports.writers import write_report

# ============================================================================
# Theme constants
# ============================================================================

LIGHT = {
    "bg": "#f7f8fa",
    "panel": "#ffffff",
    "primary": "#52a5f0",
    "primary_hover": "#3d93e0",
    "text": "#222222",
    "secondary": "#777777",
    "divider": "#e4e7ed",
    "sidebar_bg": "#ffffff",
    "sidebar_hover": "#f0f2f5",
    "sidebar_selected": "#e8f4fd",
    "sidebar_accent": "#52a5f0",
    "danger": "#e05555",
    "warning": "#e8a040",
    "success": "#4caf84",
    "card_bg": "#ffffff",
    "input_bg": "#ffffff",
    "input_border": "#d0d5dd",
    "ring_bg": "#e4e7ed",
    "ring_fg": "#52a5f0",
    "ring_safe": "#4caf84",
    "ring_danger": "#e05555",
    "shadow": "rgba(0,0,0,0.04)",
}

DARK = {
    "bg": "#161a23",
    "panel": "rgba(34,40,52,0.80)",
    "primary": "#40b4ff",
    "primary_hover": "#3399e6",
    "text": "#ffffff",
    "secondary": "#9098a7",
    "divider": "#2a2e3a",
    "sidebar_bg": "#1a1e28",
    "sidebar_hover": "#222834",
    "sidebar_selected": "#1a2d40",
    "sidebar_accent": "#40b4ff",
    "danger": "#f06060",
    "warning": "#f0a840",
    "success": "#50c090",
    "card_bg": "#1e2230",
    "input_bg": "#1a1e28",
    "input_border": "#363b48",
    "ring_bg": "#2a2e3a",
    "ring_fg": "#40b4ff",
    "ring_safe": "#50c090",
    "ring_danger": "#f06060",
    "shadow": "rgba(0,0,0,0.20)",
}

# ============================================================================
# Recent reports persistence  (unchanged)
# ============================================================================

RECENT_REPORTS_FILE = "recent_reports.json"


def _load_recent_reports(data_dir: Path) -> list[str]:
    path = data_dir / RECENT_REPORTS_FILE
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [p for p in data if isinstance(p, str) and Path(p).exists()]
    except Exception:
        pass
    return []


def _save_recent_reports(data_dir: Path, reports: list[str]) -> None:
    path = data_dir / RECENT_REPORTS_FILE
    path.write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")


# ============================================================================
# ScanTask (QRunnable — runs in QThreadPool)
# ============================================================================

class _ScanTaskSignals(QObject):
    """Signals emitted when a scan task completes."""
    result_ready = Signal(int, object)  # (task_index, FileResult)


class _ScanTask(QRunnable):
    """QRunnable that executes Scanner.scan_file() for a single file."""

    def __init__(self, scanner: Scanner, path: Path, index: int) -> None:
        super().__init__()
        self._scanner = scanner
        self._path = path
        self._index = index
        self.signals = _ScanTaskSignals()

    def run(self) -> None:
        if self._scanner.cancel_event.is_set():
            from etesting_center.engine.models import FileResult
            self.signals.result_ready.emit(
                self._index,
                FileResult(
                    path=str(self._path), size=0, md5="", sha256="",
                    file_type="unknown", risk="safe", score=0,
                    findings=[], error="扫描已取消",
                ),
            )
            return
        result = self._scanner.scan_file(self._path)
        self.signals.result_ready.emit(self._index, result)


# ============================================================================
# ScanWorker (QObject — orchestrates scan in a QThread)
# ============================================================================

class ScanWorker(QObject):
    progress = Signal(int, int, str)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, target: Path | list[Path] | str, data_dir: Path,
                 quick_mode: bool = False, total_files: int = 0) -> None:
        super().__init__()
        self.target = target
        self.data_dir = data_dir
        self.quick_mode = quick_mode
        self.total_files = total_files
        self._scanner: Scanner | None = None
        # Async completion state (populated in run(), consumed by _on_result)
        self._results: list = []
        self._summary: ScanSummary | None = None
        self._done: int = 0
        self._submitted: int = 0
        self._total: int = 0
        self._started: datetime | None = None
        self._target_str: str = ""

    def cancel(self) -> None:
        if self._scanner:
            self._scanner.cancel()

    def run(self) -> None:
        """Submit all scan tasks and return immediately.

        Completion is driven asynchronously by the QThread event loop:
        each QRunnable emits result_ready → _on_result is invoked →
        when all tasks complete, _emit_report() fires self.finished.
        """
        try:
            self._scanner = Scanner(self.data_dir, quick_mode=self.quick_mode)
            scanner = self._scanner

            # ---- 收集目标文件路径 ----
            if self.target == "FULL_SCAN":
                self.progress.emit(0, 0, "正在收集全盘扫描目标...")
                paths = Scanner.full_scan_targets()
                target_str = "FULL_SCAN"
            elif isinstance(self.target, list):
                paths = list(Scanner.iter_targets(self.target))
                target_str = ", ".join(str(t) for t in self.target)
            else:
                paths = list(Scanner.iter_targets(self.target))
                target_str = str(self.target)

            if scanner.cancel_event.is_set():
                return
            total = len(paths)
            if total == 0:
                self.failed.emit("未找到任何可扫描的文件。")
                return

            # ---- 初始化异步完成状态 ----
            self._results = [None] * total
            self._summary = ScanSummary()
            self._done = 0
            self._submitted = 0
            self._total = total
            self._started = datetime.now(timezone.utc)
            self._target_str = target_str

            # ---- QThreadPool 并行调度（非阻塞，立即返回）----
            pool = QThreadPool.globalInstance()
            pool.setMaxThreadCount(scanner.max_workers)

            for i, path in enumerate(paths):
                if scanner.cancel_event.is_set():
                    break
                task = _ScanTask(scanner, path, i)
                task.signals.result_ready.connect(self._on_result)
                pool.start(task)
                self._submitted += 1

            # 若全部任务在提交前已取消
            if self._submitted == 0:
                self._emit_report()
        except Exception as exc:
            self.failed.emit(str(exc))

    def _on_result(self, index: int, result) -> None:
        """Slot invoked by QThreadPool worker threads via queued signal."""
        self._results[index] = result
        Scanner._update_summary(self._summary, result)
        self._done += 1
        # 节流：每 20 个文件或全部完成时才发射 progress
        if self._done % 20 == 0 or self._done >= self._submitted:
            self.progress.emit(self._done, self._total, str(result.path))
        if self._done >= self._submitted:
            self._emit_report()

    def _emit_report(self) -> None:
        """Build and emit the final ScanReport."""
        scanner = self._scanner
        cancelled = scanner.cancel_event.is_set()
        valid_results = [r for r in self._results if r is not None]
        valid_results.sort(
            key=lambda item: (risk_sort_key(item.risk), -item.score, item.path)
        )
        finished_time = datetime.now(timezone.utc)

        report = ScanReport(
            target=self._target_str,
            started_at=self._started.isoformat(),
            finished_at=finished_time.isoformat(),
            yara_enabled=scanner.yara.enabled and scanner.yara.error is None,
            summary=self._summary,
            results=valid_results,
            cancelled=cancelled,
        )
        self.finished.emit(report)


# ============================================================================
# ToastNotification  (unchanged)
# ============================================================================

class ToastNotification(QFrame):
    TOAST_WIDTH = 380
    TOAST_HEIGHT = 95
    MARGIN = 18
    GAP = 10
    _instances: list[ToastNotification] = []

    def __init__(self, filename: str, score: int, engines: str, dark: bool = False) -> None:
        super().__init__(None)
        self.setObjectName("ToastNotification")
        self.setFixedSize(self.TOAST_WIDTH, self.TOAST_HEIGHT)
        self.setWindowFlags(
            Qt.WindowType.ToolTip
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(5)

        header = QHBoxLayout()
        header.setSpacing(8)
        icon_label = QLabel("!")
        icon_label.setObjectName("ToastIcon")
        icon_label.setFixedSize(22, 22)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_label = QLabel(filename)
        name_label.setObjectName("ToastFileName")
        name_label.setWordWrap(True)
        header.addWidget(icon_label)
        header.addWidget(name_label, 1)
        layout.addLayout(header)

        info = QHBoxLayout()
        info.setSpacing(16)
        score_lbl = QLabel(f"威胁评分: {score}")
        score_lbl.setObjectName("ToastScore")
        engine_lbl = QLabel(f"命中引擎: {engines}")
        engine_lbl.setObjectName("ToastEngines")
        engine_lbl.setWordWrap(True)
        info.addWidget(score_lbl)
        info.addWidget(engine_lbl, 1)
        layout.addLayout(info)

        self._fade_in()

    def _fade_in(self) -> None:
        self._fade_anim = QPropertyAnimation(self, b"windowOpacity")
        self._fade_anim.setDuration(250)
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)
        self._fade_anim.start()

    @classmethod
    def show_summary(cls, count: int, max_score: int, main_engine: str, dark: bool = False) -> None:
        """Show a summary toast when threats are found."""
        cls._instances = [t for t in cls._instances if t.isVisible()]
        while len(cls._instances) >= 3:
            oldest = cls._instances.pop(0)
            oldest.close()

        toast = cls._create_summary(count, max_score, main_engine, dark)
        toast._position(len(cls._instances))
        toast.show()
        cls._instances.append(toast)
        QTimer.singleShot(4000, toast._fade_out)

    @classmethod
    def show_toast(cls, filename: str, score: int, engines: str, dark: bool = False) -> None:
        """Show an individual threat toast."""
        cls._instances = [t for t in cls._instances if t.isVisible()]
        while len(cls._instances) >= 3:
            oldest = cls._instances.pop(0)
            oldest.close()

        toast = cls(filename, score, engines, dark)
        toast._position(len(cls._instances))
        toast.show()
        cls._instances.append(toast)
        QTimer.singleShot(4000, toast._fade_out)

    @classmethod
    def _create_summary(cls, count: int, max_score: int, main_engine: str, dark: bool) -> ToastNotification:
        """Create a summary-style toast without using __init__."""
        toast = cls.__new__(cls)
        QFrame.__init__(toast)
        toast.setObjectName("ToastNotification")
        toast.setFixedSize(cls.TOAST_WIDTH, cls.TOAST_HEIGHT)
        toast.setWindowFlags(
            Qt.WindowType.ToolTip
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        toast.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        toast.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(toast)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(5)

        header = QHBoxLayout()
        header.setSpacing(8)
        icon_label = QLabel("!")
        icon_label.setObjectName("ToastIcon")
        icon_label.setFixedSize(22, 22)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_label = QLabel(f"扫描发现 {count} 个威胁")
        name_label.setObjectName("ToastFileName")
        name_label.setWordWrap(True)
        header.addWidget(icon_label)
        header.addWidget(name_label, 1)
        layout.addLayout(header)

        info = QHBoxLayout()
        info.setSpacing(16)
        score_lbl = QLabel(f"最高评分: {max_score}")
        score_lbl.setObjectName("ToastScore")
        engine_lbl = QLabel(f"主要引擎: {main_engine}")
        engine_lbl.setObjectName("ToastEngines")
        engine_lbl.setWordWrap(True)
        info.addWidget(score_lbl)
        info.addWidget(engine_lbl, 1)
        layout.addLayout(info)

        toast._fade_in()
        return toast

    def _position(self, index: int) -> None:
        screen = QApplication.primaryScreen()
        if screen is None:
            return
        geo = screen.availableGeometry()
        x = geo.right() - self.TOAST_WIDTH - self.MARGIN
        y = geo.bottom() - (self.TOAST_HEIGHT + self.GAP) * (index + 1) - self.MARGIN
        self.move(x, y)

    def _fade_out(self) -> None:
        self._fade_anim = QPropertyAnimation(self, b"windowOpacity")
        self._fade_anim.setDuration(300)
        self._fade_anim.setStartValue(1.0)
        self._fade_anim.setEndValue(0.0)
        self._fade_anim.finished.connect(self.close)
        self._fade_anim.start()


# ============================================================================
# RingProgressWidget
# ============================================================================

class RingProgressWidget(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(200, 200)
        self._percentage: float = 100.0
        self._status: str = "safe"
        self._label: str = "设备安全"
        self._theme: dict = LIGHT

    def set_theme(self, theme: dict) -> None:
        self._theme = theme
        self.update()

    def update_status(self, safe_count: int, total: int, has_threats: bool) -> None:
        if total == 0:
            self._percentage = 100.0
            self._status = "safe"
            self._label = "设备安全"
        elif has_threats:
            self._percentage = max(0, min(100, int((total - safe_count) / total * 100)))
            self._status = "danger"
            self._label = "存在风险"
        else:
            self._percentage = 100.0
            self._status = "safe"
            self._label = "设备安全"
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        side = min(w, h)
        pen_width = 10

        rect = QRectF(
            (w - side) / 2 + pen_width / 2,
            (h - side) / 2 + pen_width / 2,
            side - pen_width,
            side - pen_width,
        )

        painter.setPen(QPen(QColor(self._theme["ring_bg"]), pen_width, Qt.PenStyle.SolidLine))
        painter.drawArc(rect, 90 * 16, 360 * 16)

        if self._status == "danger":
            color = QColor(self._theme["ring_danger"])
        elif self._percentage >= 100:
            color = QColor(self._theme["ring_safe"])
        else:
            color = QColor(self._theme["ring_fg"])

        painter.setPen(QPen(color, pen_width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        span = int(360 * self._percentage / 100 * 16)
        painter.drawArc(rect, 90 * 16, -span)

        painter.setPen(QColor(self._theme["text"]))
        font = QFont("Microsoft YaHei", 15, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self._label)


# ============================================================================
# MiniCard
# ============================================================================

class MiniCard(QFrame):
    def __init__(self, icon: str, title: str, subtitle: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("MiniCard")
        self.setFixedHeight(72)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        icon_label = QLabel(icon)
        icon_label.setObjectName("MiniCardIcon")
        icon_label.setFixedSize(36, 36)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("MiniCardTitle")

        self.sub_label = QLabel(subtitle)
        self.sub_label.setObjectName("MiniCardSub")

        text_col.addWidget(self.title_label)
        text_col.addWidget(self.sub_label)
        layout.addWidget(icon_label)
        layout.addLayout(text_col, 1)


# ============================================================================
# Sidebar
# ============================================================================

class Sidebar(QFrame):
    nav_changed = Signal(int)

    ITEMS = [
        ("首页总览", "H"),
        ("权限审计", "P"),
        ("文件隔离区", "Q"),
        ("实时防护状态", "R"),
        ("自定义设置", "C"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(160)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 24, 0, 16)
        layout.setSpacing(0)

        logo = QLabel("ETestingCenter")
        logo.setObjectName("SidebarLogo")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo)
        layout.addSpacing(28)

        self._nav_buttons: list[QPushButton] = []
        self._active_index: int = 0

        for idx, (text, _) in enumerate(self.ITEMS):
            btn = QPushButton(text)
            btn.setObjectName("SidebarBtn")
            btn.setFixedHeight(42)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, i=idx: self._on_nav(i))
            layout.addWidget(btn)
            self._nav_buttons.append(btn)

        layout.addStretch(1)

        toggle_row = QHBoxLayout()
        toggle_row.setContentsMargins(16, 0, 16, 0)
        toggle_label = QLabel("深色模式")
        toggle_label.setObjectName("SidebarToggleLabel")
        self.dark_toggle = QCheckBox()
        self.dark_toggle.setObjectName("DarkToggle")
        toggle_row.addWidget(toggle_label)
        toggle_row.addStretch()
        toggle_row.addWidget(self.dark_toggle)
        layout.addLayout(toggle_row)

        self._update_selection(0)

    def _on_nav(self, index: int) -> None:
        self._update_selection(index)
        self.nav_changed.emit(index)

    def _update_selection(self, index: int) -> None:
        self._active_index = index
        for i, btn in enumerate(self._nav_buttons):
            btn.setProperty("active", i == index)
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def set_theme(self, dark: bool) -> None:
        self.dark_toggle.blockSignals(True)
        self.dark_toggle.setChecked(dark)
        self.dark_toggle.blockSignals(False)


# ============================================================================
# HomePage
# ============================================================================

class HomePage(QWidget):
    scan_full_requested = Signal()
    scan_custom_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Page")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(60, 36, 60, 28)
        layout.setSpacing(0)

        ring_container = QHBoxLayout()
        ring_container.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ring = RingProgressWidget()
        ring_container.addWidget(self.ring)
        layout.addLayout(ring_container)
        layout.addSpacing(16)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(14)
        btn_row.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.full_scan_btn = QPushButton("一键全盘扫描")
        self.full_scan_btn.setObjectName("HomePrimaryBtn")
        self.full_scan_btn.setFixedSize(180, 46)
        self.full_scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.full_scan_btn.clicked.connect(self.scan_full_requested.emit)

        self.custom_scan_btn = QPushButton("自定义快速扫描")
        self.custom_scan_btn.setObjectName("HomeOutlineBtn")
        self.custom_scan_btn.setFixedSize(180, 46)
        self.custom_scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.custom_scan_btn.clicked.connect(self.scan_custom_requested.emit)

        btn_row.addWidget(self.full_scan_btn)
        btn_row.addWidget(self.custom_scan_btn)
        layout.addLayout(btn_row)
        layout.addSpacing(30)

        cards_row = QHBoxLayout()
        cards_row.setSpacing(14)

        self.card_protection = MiniCard("D", "威胁检测", "就绪")
        self.card_history = MiniCard("H", "扫描记录", "0 次扫描")
        self.card_permission = MiniCard("A", "权限监控", "正常")

        cards_row.addWidget(self.card_protection, 1)
        cards_row.addWidget(self.card_history, 1)
        cards_row.addWidget(self.card_permission, 1)
        layout.addLayout(cards_row)
        layout.addStretch(1)

        bottom = QHBoxLayout()
        privacy = QLabel("ETestingCenter 尊重您的隐私，所有扫描均在本地完成，数据不上传云端。  © Haodong Sun")
        privacy.setObjectName("PrivacyLabel")
        privacy.setWordWrap(True)
        self.memory_label = QLabel("内存: --")
        self.memory_label.setObjectName("MemoryLabel")
        bottom.addWidget(privacy, 1)
        bottom.addWidget(self.memory_label)
        layout.addLayout(bottom)

    def update_memory(self, mb: float) -> None:
        self.memory_label.setText(f"内存: {mb:.0f} MB")

    def set_theme(self, theme: dict) -> None:
        self.ring.set_theme(theme)
        self.ring.update()


# ============================================================================
# WarningDialog – first-launch red-themed modal
# ============================================================================

class WarningDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("WarningDialog")
        self.setWindowTitle("警告")
        self.setFixedSize(460, 260)
        self.setWindowFlags(
            Qt.WindowType.Dialog | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 20)
        layout.setSpacing(16)

        header = QHBoxLayout()
        header.setSpacing(10)
        icon = QLabel("▲")
        icon.setObjectName("WarnIcon")
        icon.setFixedSize(36, 36)
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title = QLabel("警告")
        title.setObjectName("WarnTitle")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #c0392b;")
        header.addWidget(icon)
        header.addWidget(title)
        header.addStretch()
        layout.addLayout(header)

        content = QLabel(
            "我强烈建议新手参考使用，而非当作专业杀毒软件。\n"
            "技术开发者可以当中权衡参考或工具使用，自行删除病毒文件。"
        )
        content.setObjectName("WarnContent")
        content.setWordWrap(True)
        content.setStyleSheet("font-size: 14px; color: #8b0000; line-height: 1.6;")
        layout.addWidget(content)
        layout.addStretch()

        bottom = QHBoxLayout()
        bottom.setSpacing(10)
        self.dont_show_cb = QCheckBox("不再提示")
        self.dont_show_cb.setObjectName("WarnDontShow")

        ok_btn = QPushButton("我知道了")
        ok_btn.setObjectName("WarnOkBtn")
        ok_btn.setFixedSize(110, 36)
        ok_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        ok_btn.clicked.connect(self._on_ok)

        bottom.addWidget(self.dont_show_cb)
        bottom.addStretch()
        bottom.addWidget(ok_btn)
        layout.addLayout(bottom)

        self.setStyleSheet("""
            #WarningDialog {
                background: #fff5f5;
                border: 2px solid #e74c3c;
                border-radius: 10px;
            }
            #WarnIcon {
                font-size: 28px;
                color: #e74c3c;
                background: #fdecea;
                border-radius: 18px;
            }
            #WarnDontShow {
                font-size: 13px;
                color: #666;
            }
            #WarnOkBtn {
                background: #e74c3c;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 600;
            }
            #WarnOkBtn:hover {
                background: #c0392b;
            }
        """)

    def _on_ok(self) -> None:
        if self.dont_show_cb.isChecked():
            QSettings("ETestingCenter", "ETestingCenterCN").setValue("skip_warning", True)
        self.accept()


# ============================================================================
# CompletionDialog
# ============================================================================

class CompletionDialog(QDialog):
    def __init__(self, safe: bool, scanned: int, threats: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(340, 180)
        self.setModal(True)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        card = QFrame()
        card.setObjectName("CompletionDialog")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(32, 28, 32, 24)
        card_layout.setSpacing(12)

        icon_text = "OK" if safe else "!"
        status_text = "扫描完成，设备安全" if safe else f"发现 {threats} 项威胁"
        accent = "#4caf84" if safe else "#e8a040"

        icon_lbl = QLabel(icon_text)
        icon_lbl.setObjectName("CompletionIcon")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setStyleSheet(f"color: {accent};")

        status_lbl = QLabel(status_text)
        status_lbl.setObjectName("CompletionStatus")
        status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        detail_lbl = QLabel(f"共扫描 {scanned} 个文件")
        detail_lbl.setObjectName("CompletionDetail")
        detail_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        close_btn = QPushButton("关闭")
        close_btn.setObjectName("HomeOutlineBtn")
        close_btn.setFixedWidth(120)
        close_btn.clicked.connect(self.accept)

        btn_row = QHBoxLayout()
        btn_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn_row.addWidget(close_btn)

        card_layout.addWidget(icon_lbl)
        card_layout.addWidget(status_lbl)
        card_layout.addWidget(detail_lbl)
        card_layout.addLayout(btn_row)

        outer.addWidget(card)

        self._anim = QPropertyAnimation(self, b"windowOpacity")
        self._anim.setDuration(200)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.start()


# ============================================================================
# ScanPage
# ============================================================================

class ScanPage(QWidget):
    quick_scan_requested = Signal()
    full_scan_requested = Signal()
    custom_file_requested = Signal()
    custom_folder_requested = Signal()
    cancel_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Page")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 32, 48, 24)
        layout.setSpacing(18)

        # 1. Tab row — pure text, no frame, blue underline for active
        tab_row = QHBoxLayout()
        tab_row.setSpacing(0)
        tab_row.setAlignment(Qt.AlignmentFlag.AlignLeft)

        self._scan_tabs: list[QPushButton] = []
        self._current_tab: int = 0

        for idx, text in enumerate(["快速扫描", "全盘扫描", "自定义扫描"]):
            btn = QPushButton(text)
            btn.setObjectName("ScanTab")
            btn.setFixedHeight(36)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, i=idx: self._on_tab(i))
            tab_row.addWidget(btn)
            self._scan_tabs.append(btn)

        layout.addLayout(tab_row)
        self._update_tab_selection(0)

        # 2. Progress bar + current file label (visible only during scan)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFixedHeight(6)
        self.progress.setTextVisible(False)
        self.progress.setObjectName("ScanProgress")
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.progress_label = QLabel("")
        self.progress_label.setObjectName("ScanProgressLabel")
        self.progress_label.setVisible(False)
        layout.addWidget(self.progress_label)

        # 3. Four scan buttons — all outline, 2 rows × 2 cols, generous spacing
        btn_grid = QVBoxLayout()
        btn_grid.setSpacing(16)

        row1 = QHBoxLayout()
        row1.setSpacing(28)

        self.quick_button = QPushButton("快速扫描")
        self.quick_button.setObjectName("ScanOutlineBtn")
        self.quick_button.setFixedSize(200, 52)
        self.quick_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.quick_button.clicked.connect(self.quick_scan_requested.emit)

        self.full_button = QPushButton("全盘扫描")
        self.full_button.setObjectName("ScanOutlineBtn")
        self.full_button.setFixedSize(200, 52)
        self.full_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.full_button.clicked.connect(self.full_scan_requested.emit)

        row1.addWidget(self.quick_button)
        row1.addWidget(self.full_button)
        row1.addStretch(1)

        row2 = QHBoxLayout()
        row2.setSpacing(28)

        self.file_button = QPushButton("选择文件")
        self.file_button.setObjectName("ScanOutlineBtn")
        self.file_button.setFixedSize(200, 52)
        self.file_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.file_button.clicked.connect(self.custom_file_requested.emit)

        self.folder_button = QPushButton("选择文件夹")
        self.folder_button.setObjectName("ScanOutlineBtn")
        self.folder_button.setFixedSize(200, 52)
        self.folder_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.folder_button.clicked.connect(self.custom_folder_requested.emit)

        row2.addWidget(self.file_button)
        row2.addWidget(self.folder_button)
        row2.addStretch(1)

        # Pause / Cancel row — only visible during scan
        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(16)

        self.pause_button = QPushButton("暂停")
        self.pause_button.setObjectName("ScanOutlineBtn")
        self.pause_button.setFixedWidth(100)
        self.pause_button.setVisible(False)

        self.cancel_button = QPushButton("终止")
        self.cancel_button.setObjectName("DangerOutlineBtn")
        self.cancel_button.setFixedWidth(100)
        self.cancel_button.setVisible(False)
        self.cancel_button.clicked.connect(self.cancel_requested.emit)

        ctrl_row.addWidget(self.pause_button)
        ctrl_row.addWidget(self.cancel_button)
        ctrl_row.addStretch(1)

        btn_grid.addLayout(row1)
        btn_grid.addLayout(row2)
        btn_grid.addLayout(ctrl_row)
        layout.addLayout(btn_grid)

        # 4. Result list — no border, transparent background
        self.result_list = QListWidget()
        self.result_list.setObjectName("ResultList")
        self.result_list.setFrameShape(QFrame.Shape.NoFrame)
        self.result_list.setAlternatingRowColors(False)
        self.result_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self.result_list.setMinimumHeight(80)
        self.result_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(self.result_list, 4)

        # 5. Detail text area — no border, transparent background
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setObjectName("DetailText")
        self.detail_text.setFrameShape(QFrame.Shape.NoFrame)
        self.detail_text.setPlaceholderText("")
        layout.addWidget(self.detail_text, 2)

        # 6. Bottom hint — 14px gray text, no frame
        self.bottom_hint = QLabel("点击上方扫描结果查看检测依据")
        self.bottom_hint.setObjectName("ScanBottomHint")
        self.bottom_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.bottom_hint)

        self._paused = False
        self.pause_button.clicked.connect(self._toggle_pause)

    def _toggle_pause(self) -> None:
        self._paused = not self._paused
        self.pause_button.setText("继续" if self._paused else "暂停")

    def _on_tab(self, index: int) -> None:
        self._current_tab = index
        self._update_tab_selection(index)

    def _update_tab_selection(self, index: int) -> None:
        for i, btn in enumerate(self._scan_tabs):
            btn.setProperty("active", i == index)
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def enter_scanning_state(self) -> None:
        self.quick_button.setVisible(False)
        self.full_button.setVisible(False)
        self.file_button.setVisible(False)
        self.folder_button.setVisible(False)
        self.progress.setVisible(True)
        self.progress_label.setVisible(True)
        self.pause_button.setVisible(True)
        self.cancel_button.setVisible(True)
        self.cancel_button.setEnabled(True)
        self.pause_button.setText("暂停")
        self._paused = False

    def enter_idle_state(self) -> None:
        self.quick_button.setVisible(True)
        self.full_button.setVisible(True)
        self.file_button.setVisible(True)
        self.folder_button.setVisible(True)
        self.progress.setVisible(False)
        self.progress_label.setVisible(False)
        self.pause_button.setVisible(False)
        self.cancel_button.setVisible(False)


# ============================================================================
# PermissionAuditPage
# ============================================================================

class PermissionAuditPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Page")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 24, 40, 24)
        layout.setSpacing(16)

        title = QLabel("权限审计")
        title.setObjectName("PageTitle")
        layout.addWidget(title)
        layout.addStretch(1)


# ============================================================================
# QuarantinePage
# ============================================================================

class QuarantinePage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Page")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 24, 40, 24)
        layout.setSpacing(16)

        title = QLabel("文件隔离区")
        title.setObjectName("PageTitle")
        layout.addWidget(title)
        layout.addStretch(1)


# ============================================================================
# ProtectionPage
# ============================================================================

class ProtectionPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Page")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 24, 40, 24)
        layout.setSpacing(16)

        title = QLabel("实时防护状态")
        title.setObjectName("PageTitle")
        layout.addWidget(title)
        layout.addStretch(1)


# ============================================================================
# SettingsPage
# ============================================================================

class SettingsPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Page")

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setObjectName("SettingsScroll")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(40, 24, 40, 24)
        layout.setSpacing(20)

        title = QLabel("自定义设置")
        title.setObjectName("PageTitle")
        layout.addWidget(title)

        cards = [
            ("扫描设置", [
                ("扫描压缩包内文件", False),
                ("显示扫描动画", True),
                ("显示通知弹窗", True),
            ]),
            ("外观设置", [
                ("启动时最小化到托盘", False),
            ]),
            ("存储设置", [
                ("报告保存路径", "桌面"),
                ("自动清理 30 天前报告", True),
            ]),
            ("关于软件", [
                ("版本", APP_VERSION),
                ("定位", "本地威胁检测工具，非杀毒软件"),
                ("引擎", "YARA + 多引擎启发式"),
                ("隐私", "所有数据均在本地处理，不上传云端"),
                ("制作者", "Haodong Sun"),
            ]),
        ]

        for section_title, items in cards:
            card = QFrame()
            card.setObjectName("SettingsCard")
            cl = QVBoxLayout(card)
            cl.setContentsMargins(24, 20, 24, 20)
            cl.setSpacing(12)

            sec_title = QLabel(section_title)
            sec_title.setObjectName("SettingsSectionTitle")
            cl.addWidget(sec_title)

            for item_text, item_value in items:
                row = QHBoxLayout()
                row.setSpacing(10)
                lbl = QLabel(item_text)
                lbl.setObjectName("SettingsItemLabel")

                if isinstance(item_value, bool):
                    toggle = QCheckBox()
                    toggle.setObjectName("SettingsToggle")
                    toggle.setChecked(item_value)
                    row.addWidget(lbl)
                    row.addStretch()
                    row.addWidget(toggle)
                else:
                    val_lbl = QLabel(item_value)
                    val_lbl.setObjectName("SettingsItemValue")
                    row.addWidget(lbl)
                    row.addStretch()
                    row.addWidget(val_lbl)
                cl.addLayout(row)
            layout.addWidget(card)

        layout.addStretch(1)
        scroll.setWidget(container)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)


# ============================================================================
# Helper functions
# ============================================================================

def risk_label(risk: str) -> str:
    return {"safe": "安全", "suspicious": "可疑", "malicious": "恶意"}.get(risk, risk)


def risk_color(risk: str) -> QColor:
    return {
        "safe": QColor("#4caf84"),
        "suspicious": QColor("#e8a040"),
        "malicious": QColor("#e05555"),
    }.get(risk, QColor("#222222"))


# ============================================================================
# Stylesheets
# ============================================================================

def _build_light_stylesheet() -> str:
    return """
    QMainWindow { background: #f7f8fa; }
    QMenuBar { background: #f7f8fa; color: #555; font-size: 13px; padding: 3px 0; }
    QMenuBar::item:selected { background: #e8f4fd; border-radius: 6px; }

    #Sidebar {
        background: #ffffff;
        border-right: 1px solid #e4e7ed;
    }
    #SidebarLogo {
        color: #52a5f0;
        font-size: 15px;
        font-weight: 700;
        letter-spacing: 1px;
    }
    #SidebarBtn {
        background: transparent;
        border: none;
        border-left: 3px solid transparent;
        border-radius: 0;
        color: #555;
        font-size: 13px;
        text-align: left;
        padding-left: 22px;
    }
    #SidebarBtn:hover { background: #f0f2f5; color: #222; }
    #SidebarBtn[active="true"] {
        background: #e8f4fd;
        color: #52a5f0;
        border-left: 3px solid #52a5f0;
        font-weight: 600;
    }
    #SidebarToggleLabel { color: #999; font-size: 12px; }

    #Page { background: transparent; }
    #PageTitle { font-size: 24px; font-weight: 700; color: #222; }

    #HomePrimaryBtn {
        background: #52a5f0; color: #ffffff; border: none;
        border-radius: 12px; font-size: 14px; font-weight: 600;
    }
    #HomePrimaryBtn:hover { background: #3d93e0; }
    #HomeOutlineBtn {
        background: transparent; color: #52a5f0;
        border: 1.5px solid #52a5f0; border-radius: 12px;
        font-size: 14px; font-weight: 500;
    }
    #HomeOutlineBtn:hover { background: #e8f4fd; }
    #DangerOutlineBtn {
        background: transparent; color: #e05555;
        border: 1.5px solid #e05555; border-radius: 12px;
        font-size: 14px; font-weight: 500;
    }
    #DangerOutlineBtn:hover { background: #fef0f0; }
    #MiniCard {
        background: #ffffff; border: 1px solid #e4e7ed; border-radius: 12px;
    }
    #MiniCardIcon {
        background: #f0f7ff; color: #52a5f0; border-radius: 10px;
        font-size: 16px; font-weight: 700;
    }
    #MiniCardTitle { color: #222; font-size: 13px; font-weight: 600; }
    #MiniCardSub { color: #777; font-size: 11px; }
    #PrivacyLabel { color: #aaa; font-size: 11px; }
    #MemoryLabel { color: #aaa; font-size: 11px; }

    #ScanTab {
        background: transparent; border: none; border-bottom: 2px solid transparent;
        color: #777; font-size: 14px; font-weight: 500;
        padding: 0 20px; border-radius: 0;
    }
    #ScanTab:hover { color: #222; }
    #ScanTab[active="true"] {
        color: #52a5f0; border-bottom: 2px solid #52a5f0; font-weight: 600;
    }
    #ScanProgress {
        border: none; border-radius: 3px; background: #e4e7ed;
    }
    #ScanProgress::chunk { background: #52a5f0; border-radius: 3px; }
    #ScanProgressLabel { color: #999; font-size: 12px; }
    #ScanOutlineBtn {
        background: transparent; color: #52a5f0;
        border: 1.5px solid #52a5f0; border-radius: 12px;
        font-size: 15px; font-weight: 500;
    }
    #ScanOutlineBtn:hover { background: #e8f4fd; }
    #ResultList {
        background: transparent; border: none; border-radius: 0px; outline: none;
        font-size: 13px;
    }
    #ResultList::item { padding: 8px 12px; }
    #ResultList::item:selected { background: #e8f4fd; color: #222; }
    #DetailText {
        background: transparent; border: none; border-radius: 0px; outline: none;
        padding: 12px; color: #333; font-family: "Microsoft YaHei", sans-serif;
        font-size: 15px;
    }
    #ScanBottomHint { color: #aaa; font-size: 14px; }

    #FilterChip {
        background: #ffffff; border: 1px solid #d0d5dd; border-radius: 15px;
        color: #555; font-size: 12px; padding: 0 16px;
    }
    #FilterChip:hover { border-color: #52a5f0; color: #52a5f0; }
    #FilterChip[active="true"] {
        background: #52a5f0; color: #ffffff; border-color: #52a5f0;
    }

    #AppTable {
        background: #ffffff; border: 1px solid #e4e7ed; border-radius: 12px;
        gridline-color: #f0f2f5; font-size: 13px;
    }
    #AppTable QHeaderView::section {
        background: #f7f8fa; border: none; border-bottom: 1px solid #e4e7ed;
        padding: 10px 14px; font-size: 12px; font-weight: 600; color: #555;
    }
    #AppTable::item { padding: 8px 14px; }
    #AppTable::item:alternate { background: #fafbfc; }
    #TableActionBtn {
        background: transparent; border: 1px solid #52a5f0; border-radius: 8px;
        color: #52a5f0; font-size: 11px;
    }
    #TableActionBtn:hover { background: #e8f4fd; }
    #TableDangerBtn {
        background: transparent; border: 1px solid #e05555; border-radius: 8px;
        color: #e05555; font-size: 11px;
    }
    #TableDangerBtn:hover { background: #fef0f0; }

    #SearchInput {
        background: #ffffff; border: 1px solid #d0d5dd; border-radius: 12px;
        padding: 0 16px; font-size: 13px; color: #222;
    }
    #SearchInput:focus { border-color: #52a5f0; }

    #ProtectionCard {
        background: #ffffff; border: 1px solid #e4e7ed; border-radius: 12px;
    }
    #StatusDot {
        background: #4caf84; border-radius: 7px; border: none;
    }
    #StatusTitle { font-size: 18px; font-weight: 700; color: #222; }
    #ProtectionDesc { color: #777; font-size: 13px; }
    #ProtectionToggle { font-size: 14px; color: #222; }
    #StatCard {
        background: #ffffff; border: 1px solid #e4e7ed; border-radius: 12px;
    }
    #StatValue { font-size: 22px; font-weight: 700; color: #222; }
    #StatLabel { font-size: 12px; color: #777; }

    #SettingsScroll { background: transparent; }
    #SettingsCard {
        background: #ffffff; border: 1px solid #e4e7ed; border-radius: 12px;
    }
    #SettingsSectionTitle { font-size: 16px; font-weight: 700; color: #222; }
    #SettingsItemLabel { font-size: 13px; color: #444; }
    #SettingsItemValue { font-size: 13px; color: #777; }

    #CompletionDialog {
        background: #ffffff; border: 1px solid #e4e7ed; border-radius: 16px;
    }
    #CompletionStatus { font-size: 16px; font-weight: 700; color: #222; }
    #CompletionDetail { font-size: 12px; color: #777; }

    #ToastNotification {
        background: #ffffff; border: 1px solid #e4e7ed;
        border-left: 4px solid #e05555; border-radius: 10px;
    }
    #ToastIcon {
        background: #e05555; color: #ffffff; border-radius: 11px;
        font-size: 14px; font-weight: 700;
    }
    #ToastFileName { color: #222; font-size: 13px; font-weight: 600; }
    #ToastScore { color: #e05555; font-size: 12px; font-weight: 600; }
    #ToastEngines { color: #777; font-size: 11px; }

    QScrollBar:vertical {
        background: transparent; width: 6px; margin: 0;
    }
    QScrollBar::handle:vertical {
        background: #d0d5dd; border-radius: 3px; min-height: 20px;
    }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

    #DarkToggle::indicator {
        width: 40px; height: 22px; border-radius: 11px;
        background: #d0d5dd; border: none;
    }
    #DarkToggle::indicator:checked { background: #52a5f0; }

    #CompletionIcon { font-size: 32px; font-weight: 800; }

    #SettingsToggle { color: #222; }

    QCheckBox { color: #333; spacing: 8px; }
    QCheckBox::indicator {
        width: 18px; height: 18px; border-radius: 4px;
        border: 1.5px solid #d0d5dd; background: #ffffff;
    }
    QCheckBox::indicator:checked {
        background: #52a5f0; border-color: #52a5f0;
    }
    QGroupBox {
        border: 1px solid #e4e7ed; border-radius: 12px;
        margin-top: 14px; padding-top: 14px; color: #222;
    }
    QGroupBox::title {
        subcontrol-origin: margin; left: 16px; padding: 0 6px;
    }
    QScrollArea { background: transparent; border: none; }

    /* 自定义标题栏 - 浅色 */
    #TitleBar {
        background: #ffffff; border-bottom: 1px solid #e5e7eb;
    }
    #TitleLabel { font-size: 13px; font-weight: 600; color: #222222; }
    #TitleBtn {
        background: transparent; border: 1px solid #d0d5dd; border-radius: 6px;
        color: #4b5563; font-size: 14px;
    }
    #TitleBtn:hover { background: #f0f0f0; border-color: #9ca3af; }
    #TitleBtnClose {
        background: transparent; border: 1px solid #d0d5dd; border-radius: 6px;
        color: #4b5563; font-size: 14px;
    }
    #TitleBtnClose:hover { background: #e53e3e; color: #ffffff; border-color: #e53e3e; }
    """


def _build_dark_stylesheet() -> str:
    return """
    QMainWindow { background: #161a23; }
    QMenuBar { background: #161a23; color: #9098a7; font-size: 13px; padding: 3px 0; }
    QMenuBar::item:selected { background: #222834; border-radius: 6px; }

    #Sidebar {
        background: #1a1e28;
        border-right: 1px solid #2a2e3a;
    }
    #SidebarLogo {
        color: #40b4ff;
        font-size: 15px;
        font-weight: 700;
        letter-spacing: 1px;
    }
    #SidebarBtn {
        background: transparent;
        border: none;
        border-left: 3px solid transparent;
        border-radius: 0;
        color: #9098a7;
        font-size: 13px;
        text-align: left;
        padding-left: 22px;
    }
    #SidebarBtn:hover { background: #222834; color: #ddd; }
    #SidebarBtn[active="true"] {
        background: #1a2d40;
        color: #40b4ff;
        border-left: 3px solid #40b4ff;
        font-weight: 600;
    }
    #SidebarToggleLabel { color: #9098a7; font-size: 12px; }

    #Page { background: transparent; }
    #PageTitle { font-size: 24px; font-weight: 700; color: #ffffff; }

    #HomePrimaryBtn {
        background: #40b4ff; color: #ffffff; border: none;
        border-radius: 12px; font-size: 14px; font-weight: 600;
    }
    #HomePrimaryBtn:hover { background: #3399e6; }
    #HomeOutlineBtn {
        background: transparent; color: #40b4ff;
        border: 1.5px solid #40b4ff; border-radius: 12px;
        font-size: 14px; font-weight: 500;
    }
    #HomeOutlineBtn:hover { background: rgba(64,180,255,0.10); }
    #DangerOutlineBtn {
        background: transparent; color: #f06060;
        border: 1.5px solid #f06060; border-radius: 12px;
        font-size: 14px; font-weight: 500;
    }
    #DangerOutlineBtn:hover { background: rgba(240,96,96,0.10); }
    #MiniCard {
        background: #1e2230; border: 1px solid #2a2e3a; border-radius: 12px;
    }
    #MiniCardIcon {
        background: rgba(64,180,255,0.12); color: #40b4ff; border-radius: 10px;
        font-size: 16px; font-weight: 700;
    }
    #MiniCardTitle { color: #ffffff; font-size: 13px; font-weight: 600; }
    #MiniCardSub { color: #9098a7; font-size: 11px; }
    #PrivacyLabel { color: #666; font-size: 11px; }
    #MemoryLabel { color: #666; font-size: 11px; }

    #ScanTab {
        background: transparent; border: none; border-bottom: 2px solid transparent;
        color: #9098a7; font-size: 14px; font-weight: 500;
        padding: 0 20px; border-radius: 0;
    }
    #ScanTab:hover { color: #ddd; }
    #ScanTab[active="true"] {
        color: #40b4ff; border-bottom: 2px solid #40b4ff; font-weight: 600;
    }
    #ScanProgress {
        border: none; border-radius: 3px; background: #2a2e3a;
    }
    #ScanProgress::chunk { background: #40b4ff; border-radius: 3px; }
    #ScanProgressLabel { color: #666; font-size: 12px; }
    #ScanOutlineBtn {
        background: transparent; color: #40b4ff;
        border: 1.5px solid #40b4ff; border-radius: 12px;
        font-size: 15px; font-weight: 500;
    }
    #ScanOutlineBtn:hover { background: rgba(64,180,255,0.10); }
    #ResultList {
        background: transparent; border: none; border-radius: 0px; outline: none;
        font-size: 13px; color: #ddd;
    }
    #ResultList::item { padding: 8px 12px; }
    #ResultList::item:selected { background: #1a2d40; color: #fff; }
    #DetailText {
        background: transparent; border: none; border-radius: 0px; outline: none;
        padding: 12px; color: #ddd; font-family: "Microsoft YaHei", sans-serif;
        font-size: 15px;
    }
    #ScanBottomHint { color: #666; font-size: 14px; }

    #FilterChip {
        background: #1e2230; border: 1px solid #363b48; border-radius: 15px;
        color: #9098a7; font-size: 12px; padding: 0 16px;
    }
    #FilterChip:hover { border-color: #40b4ff; color: #40b4ff; }
    #FilterChip[active="true"] {
        background: #40b4ff; color: #ffffff; border-color: #40b4ff;
    }

    #AppTable {
        background: #1e2230; border: 1px solid #2a2e3a; border-radius: 12px;
        gridline-color: #2a2e3a; font-size: 13px; color: #ddd;
    }
    #AppTable QHeaderView::section {
        background: #1a1e28; border: none; border-bottom: 1px solid #2a2e3a;
        padding: 10px 14px; font-size: 12px; font-weight: 600; color: #9098a7;
    }
    #AppTable::item { padding: 8px 14px; }
    #AppTable::item:alternate { background: #1a1e28; }
    #TableActionBtn {
        background: transparent; border: 1px solid #40b4ff; border-radius: 8px;
        color: #40b4ff; font-size: 11px;
    }
    #TableActionBtn:hover { background: rgba(64,180,255,0.10); }
    #TableDangerBtn {
        background: transparent; border: 1px solid #f06060; border-radius: 8px;
        color: #f06060; font-size: 11px;
    }
    #TableDangerBtn:hover { background: rgba(240,96,96,0.10); }

    #SearchInput {
        background: #1e2230; border: 1px solid #363b48; border-radius: 12px;
        padding: 0 16px; font-size: 13px; color: #ddd;
    }
    #SearchInput:focus { border-color: #40b4ff; }

    #ProtectionCard {
        background: #1e2230; border: 1px solid #2a2e3a; border-radius: 12px;
    }
    #StatusDot {
        background: #50c090; border-radius: 7px; border: none;
    }
    #StatusTitle { font-size: 18px; font-weight: 700; color: #ffffff; }
    #ProtectionDesc { color: #9098a7; font-size: 13px; }
    #ProtectionToggle { font-size: 14px; color: #ddd; }
    #StatCard {
        background: #1e2230; border: 1px solid #2a2e3a; border-radius: 12px;
    }
    #StatValue { font-size: 22px; font-weight: 700; color: #ffffff; }
    #StatLabel { font-size: 12px; color: #9098a7; }

    #SettingsScroll { background: transparent; }
    #SettingsCard {
        background: #1e2230; border: 1px solid #2a2e3a; border-radius: 12px;
    }
    #SettingsSectionTitle { font-size: 16px; font-weight: 700; color: #ffffff; }
    #SettingsItemLabel { font-size: 13px; color: #ddd; }
    #SettingsItemValue { font-size: 13px; color: #9098a7; }

    #CompletionDialog {
        background: #1e2230; border: 1px solid #2a2e3a; border-radius: 16px;
    }
    #CompletionStatus { font-size: 16px; font-weight: 700; color: #ffffff; }
    #CompletionDetail { font-size: 12px; color: #9098a7; }

    #ToastNotification {
        background: #1e2230; border: 1px solid #2a2e3a;
        border-left: 4px solid #f06060; border-radius: 10px;
    }
    #ToastIcon {
        background: #f06060; color: #ffffff; border-radius: 11px;
        font-size: 14px; font-weight: 700;
    }
    #ToastFileName { color: #ffffff; font-size: 13px; font-weight: 600; }
    #ToastScore { color: #f06060; font-size: 12px; font-weight: 600; }
    #ToastEngines { color: #9098a7; font-size: 11px; }

    QScrollBar:vertical {
        background: transparent; width: 6px; margin: 0;
    }
    QScrollBar::handle:vertical {
        background: #363b48; border-radius: 3px; min-height: 20px;
    }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

    #DarkToggle::indicator {
        width: 40px; height: 22px; border-radius: 11px;
        background: #363b48; border: none;
    }
    #DarkToggle::indicator:checked { background: #40b4ff; }

    #CompletionIcon { font-size: 32px; font-weight: 800; }

    #SettingsToggle { color: #ddd; }

    QCheckBox { color: #ddd; spacing: 8px; }
    QCheckBox::indicator {
        width: 18px; height: 18px; border-radius: 4px;
        border: 1.5px solid #363b48; background: #1e2230;
    }
    QCheckBox::indicator:checked {
        background: #40b4ff; border-color: #40b4ff;
    }
    QGroupBox {
        border: 1px solid #2a2e3a; border-radius: 12px;
        margin-top: 14px; padding-top: 14px; color: #ffffff;
    }
    QGroupBox::title {
        subcontrol-origin: margin; left: 16px; padding: 0 6px;
    }
    QScrollArea { background: transparent; border: none; }

    /* 自定义标题栏 - 深色 */
    #TitleBar {
        background: #161a23; border-bottom: 1px solid #2a2f3a;
    }
    #TitleLabel { font-size: 13px; font-weight: 600; color: #ffffff; }
    #TitleBtn {
        background: transparent; border: 1px solid #363b48; border-radius: 6px;
        color: #9098a7; font-size: 14px;
    }
    #TitleBtn:hover { background: #2a2f3a; border-color: #9098a7; }
    #TitleBtnClose {
        background: transparent; border: 1px solid #363b48; border-radius: 6px;
        color: #9098a7; font-size: 14px;
    }
    #TitleBtnClose:hover { background: #e53e3e; color: #ffffff; border-color: #e53e3e; }
    """


# ============================================================================
# MainWindow
# ============================================================================

class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ETestingCenter - Haodong Sun")
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setFixedSize(1060, 680)
        self.setMouseTracking(True)

        self.data_dir = Path(__file__).resolve().parent / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.current_report: ScanReport | None = None
        self.scan_thread: QThread | None = None
        self.scan_worker: ScanWorker | None = None
        self._recent_reports: list[str] = _load_recent_reports(self.data_dir)
        self._scanning: bool = False
        self._dark_mode: bool = False
        self._theme: dict = LIGHT
        self._drag_pos: QPoint | None = None

        self._build_ui()
        self._connect_signals()

        self._mem_timer = QTimer()
        self._mem_timer.timeout.connect(self._refresh_memory)
        self._mem_timer.start(3000)
        self._refresh_memory()

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)

        # 外层垂直布局：自定义标题栏 + 原有内容
        outer_layout = QVBoxLayout(root)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # ---- 自定义标题栏 ----
        self.title_bar = QWidget()
        self.title_bar.setObjectName("TitleBar")
        self.title_bar.setFixedHeight(40)
        self.title_bar.setCursor(Qt.CursorShape.ArrowCursor)

        title_layout = QHBoxLayout(self.title_bar)
        title_layout.setContentsMargins(16, 0, 8, 0)
        title_layout.setSpacing(0)

        self.title_label = QLabel("ETTestingCenter")
        self.title_label.setObjectName("TitleLabel")
        title_layout.addWidget(self.title_label)
        title_layout.addStretch()

        # 最小化按钮
        self.btn_minimize = QPushButton("─")
        self.btn_minimize.setObjectName("TitleBtn")
        self.btn_minimize.setFixedSize(32, 28)
        self.btn_minimize.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_minimize.clicked.connect(self.showMinimized)
        title_layout.addWidget(self.btn_minimize)
        title_layout.addSpacing(4)

        # 关闭按钮
        self.btn_close = QPushButton("✕")
        self.btn_close.setObjectName("TitleBtnClose")
        self.btn_close.setFixedSize(32, 28)
        self.btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_close.clicked.connect(self.close)
        title_layout.addWidget(self.btn_close)

        outer_layout.addWidget(self.title_bar)

        # ---- 原有内容区域 ----
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.sidebar = Sidebar()
        main_layout.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        self.stack.setObjectName("Page")

        self.home_page = HomePage()
        self.scan_page = ScanPage()
        self.permission_page = PermissionAuditPage()
        self.quarantine_page = QuarantinePage()
        self.protection_page = ProtectionPage()
        self.settings_page = SettingsPage()

        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.scan_page)
        self.stack.addWidget(self.permission_page)
        self.stack.addWidget(self.quarantine_page)
        self.stack.addWidget(self.protection_page)
        self.stack.addWidget(self.settings_page)

        main_layout.addWidget(self.stack, 1)
        outer_layout.addLayout(main_layout, 1)

        self.scan_page.result_list.itemClicked.connect(self._on_result_clicked)

    def _connect_signals(self) -> None:
        self.sidebar.nav_changed.connect(self._on_sidebar_nav)
        self.sidebar.dark_toggle.toggled.connect(self._toggle_dark_mode)
        self.home_page.scan_full_requested.connect(self._home_full_scan)
        self.home_page.scan_custom_requested.connect(self._home_custom_scan)
        self.scan_page.quick_scan_requested.connect(self.quick_scan)
        self.scan_page.full_scan_requested.connect(self.full_scan)
        self.scan_page.custom_file_requested.connect(self.choose_file)
        self.scan_page.custom_folder_requested.connect(self.choose_folder)
        self.scan_page.cancel_requested.connect(self.cancel_scan)

    # ---- 无边框窗口拖动支持 ----

    def mousePressEvent(self, event) -> None:
        if hasattr(self, "title_bar") and self.title_bar.geometry().contains(event.pos()):
            self._drag_pos = event.globalPosition().toPoint()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if self._drag_pos is not None:
            delta = event.globalPosition().toPoint() - self._drag_pos
            self.move(self.pos() + delta)
            self._drag_pos = event.globalPosition().toPoint()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        self._drag_pos = None
        super().mouseReleaseEvent(event)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        path = QPainterPath()
        path.addRoundedRect(QRectF(self.rect()), 12, 12)
        self.setMask(path.toFillPolygon().toPolygon())

    # ---- 主题切换 ----

    def _toggle_dark_mode(self, enabled: bool) -> None:
        self._dark_mode = enabled
        self._theme = DARK if enabled else LIGHT
        self.home_page.set_theme(self._theme)
        if enabled:
            QApplication.instance().setStyleSheet(_build_dark_stylesheet())
        else:
            QApplication.instance().setStyleSheet(_build_light_stylesheet())

    def _refresh_memory(self) -> None:
        try:
            import psutil
            proc = psutil.Process()
            mem_mb = proc.memory_info().rss / (1024 * 1024)
            self.home_page.update_memory(mem_mb)
        except Exception:
            self.home_page.update_memory(0)

    def _on_sidebar_nav(self, sidebar_index: int) -> None:
        # 侧边栏 5 项映射到 stack 索引：
        # 0=首页总览→0, 1=权限审计→2, 2=文件隔离区→3, 3=实时防护→4, 4=设置→5
        # 扫描页(stack 1)仅由首页按钮进入，不在侧边栏中
        stack_map = {0: 0, 1: 2, 2: 3, 3: 4, 4: 5}
        self.stack.setCurrentIndex(stack_map.get(sidebar_index, 0))

    def _home_full_scan(self) -> None:
        self.stack.setCurrentIndex(1)
        self.full_scan()

    def _home_custom_scan(self) -> None:
        self.stack.setCurrentIndex(1)
        self.quick_scan()

    # ---- Scan actions ----

    def quick_scan(self) -> None:
        self.stack.setCurrentIndex(1)
        home = Path.home()
        targets: list[Path] = []

        temp_dir = os.environ.get("TEMP", "")
        if temp_dir:
            temp_path = Path(temp_dir)
            if temp_path.exists():
                targets.append(temp_path)

        downloads = home / "Downloads"
        if downloads.exists():
            targets.append(downloads)

        if not targets:
            self.start_scan(home, quick_mode=True)
            return

        # Show scanning UI immediately — processEvents forces paint before scan starts
        self.scan_page.progress_label.setText("正在准备快速扫描...")
        self.scan_page.enter_scanning_state()
        QApplication.processEvents()

        # Start scan without pre-counting to avoid blocking the UI thread.
        # The scanner handles total=0 gracefully (shows file count in label).
        self.start_scan(targets, quick_mode=True, total_files=0)

    @staticmethod
    def _count_quick_scan_files(targets: list[Path]) -> int:
        """Count .exe/.dll/.sys files in quick scan targets for progress bar."""
        from .engine.scanner import QUICK_SCAN_EXTENSIONS
        count = 0
        seen: set[Path] = set()
        for target in targets:
            if target.is_file():
                resolved = target.resolve()
                if resolved not in seen and target.suffix.lower() in QUICK_SCAN_EXTENSIONS:
                    count += 1
                    seen.add(resolved)
            elif target.is_dir():
                for entry in target.rglob("*"):
                    if entry.is_file() and entry.suffix.lower() in QUICK_SCAN_EXTENSIONS:
                        resolved = entry.resolve()
                        if resolved not in seen:
                            count += 1
                            seen.add(resolved)
        return count

    def full_scan(self) -> None:
        self.start_scan("FULL_SCAN")

    def choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择要扫描的文件")
        if path:
            self.start_scan(Path(path))

    def choose_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "选择要扫描的文件夹")
        if path:
            self.start_scan(Path(path))

    def cancel_scan(self) -> None:
        if self.scan_worker:
            self.scan_worker.cancel()
        self.scan_page.progress_label.setText("正在取消扫描...")
        self.scan_page.cancel_button.setEnabled(False)

    def start_scan(self, target: Path | list[Path] | str,
                   quick_mode: bool = False, total_files: int = 0) -> None:
        if self._scanning:
            return
        self.scan_page.result_list.clear()
        self.scan_page.detail_text.clear()
        self.current_report = None
        self.scan_page.progress.setValue(0)

        if isinstance(target, str) and target == "FULL_SCAN":
            self.scan_page.progress_label.setText("正在收集全盘扫描目标...")
        elif isinstance(target, list):
            display = " + ".join(t.name for t in target[:4])
            if len(target) > 4:
                display += f" 等 {len(target)} 个位置"
            self.scan_page.progress_label.setText(f"正在快速扫描: {display}")
        else:
            self.scan_page.progress_label.setText(f"正在扫描 {target}")

        self.scan_page.enter_scanning_state()
        self._scanning = True

        self.scan_thread = QThread()
        self.scan_worker = ScanWorker(target, self.data_dir, quick_mode=quick_mode,
                                       total_files=total_files)
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.progress.connect(self.on_progress)
        self.scan_worker.finished.connect(self.on_finished)
        self.scan_worker.failed.connect(self.on_failed)
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.failed.connect(self.scan_thread.quit)
        # Null reference after thread finishes so subsequent scans can start
        self.scan_thread.finished.connect(lambda: setattr(self, 'scan_thread', None))
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.start()

    def on_progress(self, done: int, total: int, path: str) -> None:
        if total:
            percent = int((done / total) * 100)
            self.scan_page.progress.setValue(percent)
            self.scan_page.progress_label.setText(f"扫描中 {done}/{total}: {path}")
        else:
            self.scan_page.progress.setValue(0)
            self.scan_page.progress_label.setText(f"已扫描 {done} 个文件: {path}")

    def on_finished(self, report: ScanReport) -> None:
        self.current_report = report
        self.scan_page.progress.setValue(100)
        if report.cancelled:
            self.scan_page.progress_label.setText("扫描已取消")
        else:
            self.scan_page.progress_label.setText(f"扫描完成。YARA 已启用: {report.yara_enabled}")
        self.scan_page.enter_idle_state()
        self._scanning = False
        self.scan_thread = None
        self.scan_worker = None
        self.populate_report(report)
        self._fire_threat_toasts(report)

        safe = report.summary.safe
        total = report.summary.scanned
        has_threats = report.summary.malicious > 0 or report.summary.suspicious > 0
        self.home_page.ring.update_status(safe, total, has_threats)

        dlg = CompletionDialog(
            safe=not has_threats,
            scanned=total,
            threats=report.summary.malicious + report.summary.suspicious,
            parent=self,
        )
        dlg.exec()

    def on_failed(self, message: str) -> None:
        self.scan_page.progress_label.setText("扫描失败")
        self.scan_page.enter_idle_state()
        self._scanning = False
        self.scan_thread = None
        self.scan_worker = None
        import PySide6.QtWidgets as W
        W.QMessageBox.warning(self, APP_NAME, message)

    def _fire_threat_toasts(self, report: ScanReport) -> None:
        threats = [r for r in report.results if r.risk in ("malicious", "suspicious")]
        if not threats:
            return

        # Summary toast
        max_score = max(t.score for t in threats)
        all_engines: list[str] = []
        for t in threats:
            for f in t.findings:
                if f.engine not in all_engines:
                    all_engines.append(f.engine)
        main_engine = all_engines[0] if all_engines else "无"
        ToastNotification.show_summary(len(threats), max_score, main_engine, self._dark_mode)

        # Individual toasts
        for t in threats:
            engines = ", ".join(f.engine for f in t.findings) or "无"
            filename = Path(t.path).name
            ToastNotification.show_toast(filename, t.score, engines, self._dark_mode)

    def populate_report(self, report: ScanReport) -> None:
        self.scan_page.result_list.clear()

        # Only show suspicious/malicious files — not safe ones
        threats = [r for r in report.results if r.risk in ("malicious", "suspicious")]

        if not threats:
            msg = f"扫描了 {report.summary.scanned} 个文件，未发现威胁"
            item = QListWidgetItem(msg)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            item.setForeground(QColor("#4caf84"))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            font = item.font()
            font.setPointSize(16)
            font.setBold(True)
            item.setFont(font)
            item.setSizeHint(item.sizeHint().expandedTo(item.sizeHint() + QSize(0, 32)))
            self.scan_page.result_list.addItem(item)
            return

        for result in threats:
            engines = ", ".join(f.engine for f in result.findings) or "—"
            label = risk_label(result.risk)
            display = f"[{label}]  评分:{result.score}  |  {engines}  |  {result.path}"
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, result)
            item.setForeground(risk_color(result.risk))
            font = item.font()
            font.setPointSize(11)
            item.setFont(font)
            self.scan_page.result_list.addItem(item)

    def _on_result_clicked(self, item: QListWidgetItem) -> None:
        result = item.data(Qt.ItemDataRole.UserRole)
        if result is None:
            return
        lines = [
            f"路径: {result.path}",
            f"风险: {risk_label(result.risk)}",
            f"评分: {result.score}",
            f"类型: {result.file_type}",
            f"大小: {result.size}",
            f"MD5: {result.md5}",
            f"SHA-256: {result.sha256}",
        ]
        if result.error:
            lines.append(f"错误: {result.error}")
        lines.append("")
        lines.append("── 检测依据 ──")
        if not result.findings:
            lines.append("未命中本地指标。")
        for finding in result.findings:
            lines.append(f"引擎: {finding.engine}:{finding.rule}")
            lines.append(f"  严重性: {risk_label(finding.severity)}")
            lines.append(f"  置信度: {finding.confidence}")
            lines.append(f"  依据: {finding.description}")
            if finding.details:
                lines.append(f"  细节: {finding.details}")
            lines.append("")
        self.scan_page.detail_text.setPlainText("\n".join(lines))

    def _export_report(self, fmt: str) -> None:
        if not self.current_report:
            import PySide6.QtWidgets as W
            W.QMessageBox.information(self, APP_NAME, "请先完成一次扫描，再导出报告。")
            return
        suffix = fmt.lower()
        path, _ = QFileDialog.getSaveFileName(
            self, f"导出 {suffix.upper()} 报告", f"etesting-report.{suffix}"
        )
        if not path:
            return
        write_report(self.current_report, Path(path), suffix)
        import PySide6.QtWidgets as W
        W.QMessageBox.information(self, APP_NAME, f"报告已导出:\n{path}")

    def _add_recent_report(self, report_path: str) -> None:
        if report_path in self._recent_reports:
            self._recent_reports.remove(report_path)
        self._recent_reports.insert(0, report_path)
        self._recent_reports = self._recent_reports[:10]
        _save_recent_reports(self.data_dir, self._recent_reports)

    @staticmethod
    def _safe_timestamp() -> str:
        from datetime import datetime
        now = datetime.now()
        return f"{now.year}{now.month:02d}{now.day:02d}_{now.hour:02d}{now.minute:02d}{now.second:02d}"


def apply_style(app: QApplication) -> None:
    app.setStyleSheet(_build_light_stylesheet())
    font = QFont("Microsoft YaHei", 10)
    app.setFont(font)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    apply_style(app)

    # First-launch warning dialog
    settings = QSettings("ETestingCenter", "ETestingCenterCN")
    if not settings.value("skip_warning", False, type=bool):
        dlg = WarningDialog()
        dlg.exec()

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
