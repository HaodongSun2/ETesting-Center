from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from PySide6.QtCore import (
    QObject,
    QPoint,
    QThread,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import QAction, QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from etesting_center import APP_NAME, APP_TAGLINE, APP_VERSION
from etesting_center.engine.models import ScanReport
from etesting_center.engine.scanner import Scanner
from etesting_center.reports.writers import write_report


# ------------------------------------------------------------------
# Recent reports persistence
# ------------------------------------------------------------------

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


# ------------------------------------------------------------------
# Threat popup — real-time bottom-right notification
# ------------------------------------------------------------------

POPUP_WIDTH = 320
POPUP_HEIGHT = 72
POPUP_MARGIN = 12
POPUP_GAP = 4


class ThreatPopup(QFrame):
    """单个威胁弹窗：文件名 + 评分 + 主要引擎，3 秒自动消失。"""

    closed = Signal(object)

    def __init__(self, file_path: str, score: int, engines: list[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ThreatPopup")
        self.setFixedSize(POPUP_WIDTH, POPUP_HEIGHT)
        self.setWindowFlags(Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self._build(file_path, score, engines)
        QTimer.singleShot(3000, self._close)

    def _build(self, file_path: str, score: int, engines: list[str]) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(10)

        # 左侧：威胁图标
        icon_label = QLabel("!")
        icon_label.setObjectName("PopupIcon")
        icon_label.setFixedSize(36, 36)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)

        # 中间：文本
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)

        name = Path(file_path).name
        name_label = QLabel(name if len(name) <= 40 else name[:37] + "...")
        name_label.setObjectName("PopupName")

        if engines:
            engine_text = ", ".join(engines[:3])
            if len(engines) > 3:
                engine_text += " ..."
        else:
            engine_text = "启发式检测"
        info_label = QLabel(f"评分 {score}  ·  {engine_text}")
        info_label.setObjectName("PopupInfo")

        text_layout.addWidget(name_label)
        text_layout.addWidget(info_label)
        layout.addLayout(text_layout, 1)

    def _close(self) -> None:
        self.closed.emit(self)
        self.close()
        self.deleteLater()


class ThreatPopupManager(QObject):
    """管理弹窗生命周期，最多同时 3 个，自动堆叠。"""

    def __init__(self) -> None:
        super().__init__()
        self._popups: list[ThreatPopup] = []

    def show(self, file_path: str, score: int, engines: list[str]) -> None:
        # 超过上限时关闭最旧的
        while len(self._popups) >= 3:
            old = self._popups.pop(0)
            old.closed.disconnect()
            old.close()
            old.deleteLater()

        popup = ThreatPopup(file_path, score, engines)
        popup.closed.connect(lambda p: self._on_closed(p))
        self._popups.append(popup)
        self._reposition()
        popup.show()

    def _on_closed(self, popup: ThreatPopup) -> None:
        if popup in self._popups:
            self._popups.remove(popup)
        self._reposition()

    def _reposition(self) -> None:
        screen = QApplication.primaryScreen()
        if not screen:
            return
        geom = screen.availableGeometry()
        base_x = geom.right() - POPUP_WIDTH - POPUP_MARGIN
        base_y = geom.bottom() - POPUP_MARGIN

        for i, popup in enumerate(self._popups):
            y = base_y - (POPUP_HEIGHT + POPUP_GAP) * (i + 1)
            popup.move(base_x, y)

    def clear(self) -> None:
        for popup in list(self._popups):
            popup.closed.disconnect()
            popup.close()
            popup.deleteLater()
        self._popups.clear()


# ------------------------------------------------------------------
# Worker thread
# ------------------------------------------------------------------

class ScanWorker(QObject):
    progress = Signal(int, int, str)
    threat_found = Signal(str, int, list)  # file_path, score, engines
    finished = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        target: Path | list[Path] | str,
        data_dir: Path,
    ) -> None:
        super().__init__()
        self.target = target
        self.data_dir = data_dir
        self._scanner: Scanner | None = None

    def cancel(self) -> None:
        if self._scanner:
            self._scanner.cancel()

    def run(self) -> None:
        try:
            self._scanner = Scanner(self.data_dir)

            def threat_callback(result):
                engines = [f.engine for f in result.findings] if result.findings else []
                self.threat_found.emit(result.path, result.score, engines)

            if self.target == "FULL_SCAN":
                self.progress.emit(0, 0, "正在收集全盘扫描目标...")
                targets = Scanner.full_scan_targets()
                if self._scanner.cancel_event.is_set():
                    return
                if not targets:
                    self.failed.emit("全盘扫描未找到任何可扫描的文件。")
                    return
                report = self._scanner.scan(
                    targets,
                    progress=lambda done, total, path: self.progress.emit(done, total, path),
                    threat_callback=threat_callback,
                )
            else:
                report = self._scanner.scan(
                    self.target,
                    progress=lambda done, total, path: self.progress.emit(done, total, path),
                    threat_callback=threat_callback,
                )
            self.finished.emit(report)
        except Exception as exc:
            self.failed.emit(str(exc))


# ------------------------------------------------------------------
# Result list item widget
# ------------------------------------------------------------------

class ResultItemWidget(QWidget):
    """简洁的扫描结果行：风险标记 + 文件名 + 评分 + 命中引擎。"""

    def __init__(self, parent: QListWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(12)

        self.risk_badge = QLabel()
        self.risk_badge.setObjectName("RiskBadge")
        self.risk_badge.setFixedWidth(44)
        self.risk_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.name_label = QLabel()
        self.name_label.setObjectName("ResultName")

        self.score_label = QLabel()
        self.score_label.setObjectName("ResultScore")

        self.engine_label = QLabel()
        self.engine_label.setObjectName("ResultEngine")

        layout.addWidget(self.risk_badge)
        layout.addWidget(self.name_label, 1)
        layout.addWidget(self.score_label)
        layout.addWidget(self.engine_label)

    def populate(self, risk: str, name: str, score: int, engines: str) -> None:
        risk_map = {
            "safe": ("安全", "#167348", "#e6f4ea"),
            "suspicious": ("可疑", "#9a6700", "#fff8e5"),
            "malicious": ("恶意", "#b42318", "#fce4e4"),
        }
        label, fg, bg = risk_map.get(risk, (risk, "#1d1d1f", "#f0f0f0"))
        self.risk_badge.setText(label)
        self.risk_badge.setStyleSheet(f"color:{fg};background:{bg};border-radius:4px;font-size:12px;font-weight:600;padding:1px 0;")

        self.name_label.setText(name)

        if score > 0:
            self.score_label.setText(f"{score}分")
            severity = "high" if score >= 80 else "medium" if score >= 35 else "low"
            sc = {"high": "#b42318", "medium": "#9a6700", "low": "#62666d"}.get(severity, "#62666d")
            self.score_label.setStyleSheet(f"color:{sc};font-weight:600;font-size:13px;")
        else:
            self.score_label.setText("")
            self.score_label.setStyleSheet("")

        self.engine_label.setText(engines if engines else "")


# ------------------------------------------------------------------
# Main window
# ------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME}")
        self.setFixedSize(900, 650)

        self.data_dir = Path(__file__).resolve().parent / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.current_report: ScanReport | None = None
        self.scan_thread: QThread | None = None
        self.scan_worker: ScanWorker | None = None
        self._recent_reports: list[str] = _load_recent_reports(self.data_dir)
        self._scanning: bool = False
        self._popup_manager = ThreatPopupManager()

        self._setup_ui()
        self._setup_menu()
        self._refresh_recent_reports_list()

    # ------------------------------------------------------------------
    # 菜单栏
    # ------------------------------------------------------------------
    def _setup_menu(self) -> None:
        export_json = QAction("导出 JSON", self)
        export_json.triggered.connect(lambda: self.export_report("json"))
        export_html = QAction("导出 HTML", self)
        export_html.triggered.connect(lambda: self.export_report("html"))
        export_txt = QAction("导出 TXT", self)
        export_txt.triggered.connect(lambda: self.export_report("txt"))
        export_docx = QAction("导出 Word", self)
        export_docx.triggered.connect(lambda: self.export_report("docx"))
        file_menu = self.menuBar().addMenu("文件")
        file_menu.addAction(export_html)
        file_menu.addAction(export_json)
        file_menu.addAction(export_txt)
        file_menu.addAction(export_docx)

    # ------------------------------------------------------------------
    # UI 搭建
    # ------------------------------------------------------------------
    def _setup_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ---- 顶部标题栏 ----
        header = QFrame()
        header.setObjectName("Header")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(36, 24, 36, 18)
        header_layout.setSpacing(4)

        title = QLabel(APP_NAME)
        title.setObjectName("Title")
        subtitle = QLabel(APP_TAGLINE)
        subtitle.setObjectName("Subtitle")
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        outer.addWidget(header)

        # ---- 只读声明 ----
        notice_bar = QFrame()
        notice_bar.setObjectName("NoticeBar")
        notice_layout = QHBoxLayout(notice_bar)
        notice_layout.setContentsMargins(36, 0, 36, 0)
        self.notice = QLabel("只读检测：扫描过程不会隔离、删除、修复或修改任何文件。")
        self.notice.setObjectName("Notice")
        notice_layout.addWidget(self.notice)
        outer.addWidget(notice_bar)

        # ---- 标签页控件 ----
        self.tab_widget = QTabWidget()
        self.tab_widget.setObjectName("MainTabs")
        self.tab_widget.currentChanged.connect(self._on_tab_changed)

        self.tab_scan = self._build_scan_tab()
        self.tab_report = self._build_report_tab()
        self.tab_more = self._build_more_tab()

        self.tab_widget.addTab(self.tab_scan, "扫描病毒")
        self.tab_widget.addTab(self.tab_report, "生成报告")
        self.tab_widget.addTab(self.tab_more, "更多功能")
        self.tab_widget.setCurrentIndex(0)

        outer.addWidget(self.tab_widget, 1)

    # ------------------------------------------------------------------
    # 标签页：扫描病毒
    # ------------------------------------------------------------------
    def _build_scan_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 18, 36, 18)
        layout.setSpacing(14)

        # -- 按钮行 --
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        self.quick_button = QPushButton("快速扫描")
        self.quick_button.setObjectName("PrimaryButton")
        self.quick_button.setToolTip("扫描 TEMP / Downloads / Desktop / Documents / 启动项 / AppData")
        self.quick_button.clicked.connect(self.quick_scan)

        self.full_button = QPushButton("全盘扫描")
        self.full_button.setObjectName("PrimaryButton")
        self.full_button.setToolTip("遍历所有磁盘分区的可执行文件和脚本，耗时较长")
        self.full_button.clicked.connect(self.full_scan)

        self.file_button = QPushButton("单文件")
        self.file_button.clicked.connect(self.choose_file)

        self.folder_button = QPushButton("自定义路径")
        self.folder_button.clicked.connect(self.choose_folder)

        self.cancel_button = QPushButton("取消")
        self.cancel_button.setObjectName("CancelButton")
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.cancel_button.setVisible(False)

        btn_row.addWidget(self.quick_button)
        btn_row.addWidget(self.full_button)
        btn_row.addWidget(self.file_button)
        btn_row.addWidget(self.folder_button)
        btn_row.addWidget(self.cancel_button)
        btn_row.addStretch(1)
        layout.addLayout(btn_row)

        # -- 进度条 + 状态 --
        progress_row = QHBoxLayout()
        progress_row.setSpacing(10)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFixedHeight(6)
        self.progress.setTextVisible(False)
        self.status_label = QLabel("就绪")
        self.status_label.setObjectName("Status")
        progress_row.addWidget(self.progress, 1)
        progress_row.addWidget(self.status_label)
        layout.addLayout(progress_row)

        # -- 指标卡片 --
        metrics = QHBoxLayout()
        metrics.setSpacing(8)
        self.metric_scanned = self._make_metric("已扫描")
        self.metric_safe = self._make_metric("安全")
        self.metric_suspicious = self._make_metric("可疑")
        self.metric_malicious = self._make_metric("恶意")
        self.metric_errors = self._make_metric("错误")
        for m in [self.metric_scanned, self.metric_safe, self.metric_suspicious, self.metric_malicious, self.metric_errors]:
            metrics.addWidget(m)
        layout.addLayout(metrics)

        # -- 结果区域（ScrollArea 包裹） --
        results_container = QFrame()
        results_container.setObjectName("ResultsContainer")
        results_layout = QHBoxLayout(results_container)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.setSpacing(10)

        # 左侧：结果列表
        self.result_list = QListWidget()
        self.result_list.setObjectName("ResultList")
        self.result_list.setVerticalScrollMode(QListWidget.ScrollMode.ScrollPerPixel)
        self.result_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.result_list.currentRowChanged.connect(self.show_selected_details)
        self.result_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # 右侧：详情面板
        detail_panel = QFrame()
        detail_panel.setObjectName("DetailPanel")
        detail_panel.setFixedWidth(280)
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(12, 10, 12, 10)
        detail_layout.setSpacing(6)

        detail_title = QLabel("检测详情")
        detail_title.setObjectName("PanelTitle")
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("选择一条结果查看检测依据")
        self.details.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        detail_layout.addWidget(detail_title)
        detail_layout.addWidget(self.details, 1)

        results_layout.addWidget(self.result_list, 1)
        results_layout.addWidget(detail_panel)

        layout.addWidget(results_container, 1)
        return page

    def _make_metric(self, title: str) -> QFrame:
        card = QFrame()
        card.setObjectName("MetricCard")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(10, 8, 10, 8)
        cl.setSpacing(2)
        value_label = QLabel("—")
        value_label.setObjectName("MetricValue")
        title_label = QLabel(title)
        title_label.setObjectName("MetricTitle")
        cl.addWidget(value_label)
        cl.addWidget(title_label)
        card._value_label = value_label
        return card

    # ------------------------------------------------------------------
    # 标签页：生成报告
    # ------------------------------------------------------------------
    def _build_report_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 24, 36, 24)
        layout.setSpacing(16)

        # 生成报告按钮
        self.report_button = QPushButton("生成 Word 报告")
        self.report_button.setObjectName("ReportButton")
        self.report_button.clicked.connect(self.generate_report)
        self.report_button.setVisible(False)
        self.report_button.setToolTip("扫描完成后生成企业级 Word 报告，保存到桌面")
        self.report_button.setFixedWidth(200)

        self.report_hint = QLabel("请先完成一次扫描，再生成报告。")
        self.report_hint.setObjectName("ReportHint")

        layout.addWidget(self.report_button)
        layout.addWidget(self.report_hint)

        # 分隔线
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setObjectName("Separator")
        layout.addWidget(sep)

        # 最近报告
        recent_label = QLabel("最近报告")
        recent_label.setObjectName("SectionTitle")
        self.recent_list = QListWidget()
        self.recent_list.setObjectName("RecentList")
        self.recent_list.setMaximumHeight(120)
        self.recent_list.itemDoubleClicked.connect(self._open_recent_report)

        layout.addWidget(recent_label)
        layout.addWidget(self.recent_list)
        layout.addStretch(1)
        return page

    # ------------------------------------------------------------------
    # 标签页：更多功能
    # ------------------------------------------------------------------
    def _build_more_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 24, 36, 24)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame()
        card.setObjectName("MoreCard")
        card.setFixedSize(360, 160)
        card_layout = QVBoxLayout(card)
        card_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.setSpacing(8)

        placeholder = QLabel("更多功能正在开发中")
        placeholder.setObjectName("MoreTitle")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)

        hint = QLabel("敬请期待")
        hint.setObjectName("MoreHint")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card_layout.addWidget(placeholder)
        card_layout.addWidget(hint)
        layout.addWidget(card)
        return page

    # ------------------------------------------------------------------
    # 标签页切换 — 扫描中禁止切换
    # ------------------------------------------------------------------
    def _on_tab_changed(self, index: int) -> None:
        if self._scanning and index != 0:
            self.tab_widget.setCurrentIndex(0)

    # ------------------------------------------------------------------
    # 扫描动作
    # ------------------------------------------------------------------
    def quick_scan(self) -> None:
        home = Path.home()
        targets: list[Path] = []

        temp_dir = os.environ.get("TEMP", "")
        if temp_dir:
            temp_path = Path(temp_dir)
            if temp_path.exists():
                targets.append(temp_path)

        for sub in ["Downloads", "Desktop", "Documents"]:
            p = home / sub
            if p.exists():
                targets.append(p)

        startup = home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if startup.exists():
            targets.append(startup)

        public_startup = Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup")
        if public_startup.exists():
            targets.append(public_startup)

        appdata_local = home / "AppData" / "Local"
        if appdata_local.exists():
            targets.append(appdata_local)

        if not targets:
            self.start_scan(home)
            return
        self.start_scan(targets)

    def full_scan(self) -> None:
        reply = QMessageBox.question(
            self,
            "全盘扫描",
            "全盘扫描将遍历所有磁盘分区的可执行文件和脚本文件，可能需要较长时间。\n\n是否继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
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
        self.status_label.setText("正在取消...")
        self.cancel_button.setEnabled(False)

    # ------------------------------------------------------------------
    # 扫描线程管理
    # ------------------------------------------------------------------
    def start_scan(self, target: Path | list[Path] | str) -> None:
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.information(self, APP_NAME, "当前已有扫描任务正在运行。")
            return
        self.result_list.clear()
        self.details.clear()
        self.current_report = None
        self.progress.setValue(0)
        self._reset_metrics()

        if isinstance(target, str) and target == "FULL_SCAN":
            self.status_label.setText("正在收集目标...")
        elif isinstance(target, list):
            self.status_label.setText("正在快速扫描...")
        else:
            self.status_label.setText(f"扫描中: {Path(target).name}")

        self._enter_scanning_state()

        self.scan_thread = QThread()
        self.scan_worker = ScanWorker(target, self.data_dir)
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.progress.connect(self.on_progress)
        self.scan_worker.threat_found.connect(self._popup_manager.show)
        self.scan_worker.finished.connect(self.on_finished)
        self.scan_worker.failed.connect(self.on_failed)
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.failed.connect(self.scan_thread.quit)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.start()

    def _enter_scanning_state(self) -> None:
        self._scanning = True
        self.file_button.setVisible(False)
        self.folder_button.setVisible(False)
        self.quick_button.setVisible(False)
        self.full_button.setVisible(False)
        self.report_button.setVisible(False)
        self.report_hint.setText("扫描进行中...")
        self.cancel_button.setVisible(True)
        self.cancel_button.setEnabled(True)

    def _enter_idle_state(self) -> None:
        self._scanning = False
        self.file_button.setVisible(True)
        self.folder_button.setVisible(True)
        self.quick_button.setVisible(True)
        self.full_button.setVisible(True)
        self.cancel_button.setVisible(False)

    # ------------------------------------------------------------------
    # 扫描回调
    # ------------------------------------------------------------------
    def on_progress(self, done: int, total: int, path: str) -> None:
        if total:
            percent = int((done / total) * 100)
            self.progress.setValue(percent)
            self.status_label.setText(f"{done}/{total}")
        else:
            self.progress.setValue(0)
            self.status_label.setText(f"已扫描 {done}")

    def on_finished(self, report: ScanReport) -> None:
        self.current_report = report
        self.progress.setValue(100)
        if report.cancelled:
            self.status_label.setText("扫描已取消")
        else:
            self.status_label.setText(f"扫描完成，共 {report.summary.scanned} 个文件")
        self._enter_idle_state()
        self.report_button.setVisible(True)
        self.report_hint.setText("扫描已完成，可生成 Word 报告。")
        self._popup_manager.clear()
        self.populate_report(report)

    def on_failed(self, message: str) -> None:
        self.status_label.setText("扫描失败")
        self._enter_idle_state()
        self.report_button.setVisible(False)
        self.report_hint.setText("扫描失败，无法生成报告。")
        self._popup_manager.clear()
        QMessageBox.warning(self, APP_NAME, message)

    # ------------------------------------------------------------------
    # 结果展示 — 简洁列表
    # ------------------------------------------------------------------
    def _reset_metrics(self) -> None:
        for card in [self.metric_scanned, self.metric_safe, self.metric_suspicious, self.metric_malicious, self.metric_errors]:
            card._value_label.setText("—")

    def populate_report(self, report: ScanReport) -> None:
        self.metric_scanned._value_label.setText(str(report.summary.scanned))
        self.metric_safe._value_label.setText(str(report.summary.safe))
        self.metric_suspicious._value_label.setText(str(report.summary.suspicious))
        self.metric_malicious._value_label.setText(str(report.summary.malicious))
        self.metric_errors._value_label.setText(str(report.summary.errors))

        self.result_list.clear()
        for result in report.results:
            info = ResultItemData(result)
            if result.score > 0:
                engine_names = [f.engine for f in result.findings]
                engines_str = ", ".join(engine_names[:3]) if engine_names else ""
            else:
                engines_str = ""

            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, info)

            widget = ResultItemWidget()
            widget.populate(
                risk=result.risk,
                name=Path(result.path).name,
                score=result.score,
                engines=engines_str,
            )
            item.setSizeHint(widget.sizeHint())
            self.result_list.addItem(item)
            self.result_list.setItemWidget(item, widget)

        if report.results:
            self.result_list.setCurrentRow(0)

    def show_selected_details(self, row: int) -> None:
        if row < 0 or not self.current_report:
            return
        item = self.result_list.item(row)
        if not item:
            return
        info: ResultItemData = item.data(Qt.ItemDataRole.UserRole)
        if not info:
            return
        result = info.result
        lines = [
            f"路径: {result.path}",
            f"风险: {risk_label(result.risk)}",
            f"评分: {result.score}",
            f"类型: {result.file_type}",
            f"大小: {result.size:,} bytes" if result.size else "大小: —",
            f"MD5: {result.md5}",
            f"SHA-256: {result.sha256}",
        ]
        if result.error:
            lines.append(f"错误: {result.error}")
        lines.append("")
        lines.append("检测依据:")
        if not result.findings:
            lines.append("  未命中本地指标。")
        for f in result.findings:
            lines.append(f"  [{f.engine}] {f.rule}")
            lines.append(f"    严重性: {risk_label(f.severity)}  置信度: {f.confidence}")
            lines.append(f"    说明: {f.description}")
            if f.details:
                lines.append(f"    细节: {f.details}")
        self.details.setPlainText("\n".join(lines))

    # ------------------------------------------------------------------
    # 报告导出
    # ------------------------------------------------------------------
    def export_report(self, fmt: str) -> None:
        if not self.current_report:
            QMessageBox.information(self, APP_NAME, "请先完成一次扫描，再导出报告。")
            return
        suffix = fmt.lower()
        path, _ = QFileDialog.getSaveFileName(self, f"导出 {suffix.upper()} 报告", f"etesting-report.{suffix}")
        if not path:
            return
        write_report(self.current_report, Path(path), suffix)
        QMessageBox.information(self, APP_NAME, f"报告已导出:\n{path}")

    def generate_report(self) -> None:
        if not self.current_report:
            QMessageBox.information(self, APP_NAME, "请先完成一次扫描，再生成报告。")
            return
        desktop = Path.home() / "Desktop"
        filename = f"ETestingCenter_扫描报告_{self._safe_timestamp()}.docx"
        default_path = desktop / filename
        path, _ = QFileDialog.getSaveFileName(
            self, "生成 Word 报告", str(default_path), "Word 文档 (*.docx)",
        )
        if not path:
            return
        try:
            from etesting_center.reports.writers import write_docx
            write_docx(self.current_report, Path(path))
            self._add_recent_report(str(path))
            QMessageBox.information(self, APP_NAME, f"Word 报告已生成:\n{path}")
        except ImportError:
            QMessageBox.critical(self, APP_NAME, "缺少 python-docx 库。\n请在命令行执行: pip install python-docx")
        except Exception as exc:
            QMessageBox.critical(self, APP_NAME, f"生成报告失败:\n{exc}")

    # ------------------------------------------------------------------
    # 最近报告
    # ------------------------------------------------------------------
    def _add_recent_report(self, report_path: str) -> None:
        if report_path in self._recent_reports:
            self._recent_reports.remove(report_path)
        self._recent_reports.insert(0, report_path)
        self._recent_reports = self._recent_reports[:10]
        _save_recent_reports(self.data_dir, self._recent_reports)
        self._refresh_recent_reports_list()

    def _refresh_recent_reports_list(self) -> None:
        self.recent_list.clear()
        for rp in self._recent_reports:
            item = QListWidgetItem(Path(rp).name)
            item.setToolTip(rp)
            item.setData(Qt.ItemDataRole.UserRole, rp)
            self.recent_list.addItem(item)

    def _open_recent_report(self, item: QListWidgetItem) -> None:
        path = item.data(Qt.ItemDataRole.UserRole)
        if path and Path(path).exists():
            os.startfile(path)
        else:
            QMessageBox.information(self, APP_NAME, "文件不存在，可能已被移动或删除。")

    @staticmethod
    def _safe_timestamp() -> str:
        from datetime import datetime
        now = datetime.now()
        return f"{now.year}{now.month:02d}{now.day:02d}_{now.hour:02d}{now.minute:02d}{now.second:02d}"

    def closeEvent(self, event) -> None:
        self._popup_manager.clear()
        super().closeEvent(event)


# ------------------------------------------------------------------
# 辅助
# ------------------------------------------------------------------

class ResultItemData:
    """存储在 QListWidgetItem UserRole 中的数据结构。"""
    __slots__ = ("result",)

    def __init__(self, result) -> None:
        self.result = result


def risk_label(risk: str) -> str:
    return {"safe": "安全", "suspicious": "可疑", "malicious": "恶意"}.get(risk, risk)


def risk_color(risk: str) -> QColor:
    return {"safe": QColor("#167348"), "suspicious": QColor("#9a6700"), "malicious": QColor("#b42318")}.get(risk, QColor("#1d1d1f"))


# ------------------------------------------------------------------
# QSS 样式 — 简洁学术风格
# ------------------------------------------------------------------

def apply_style(app: QApplication) -> None:
    app.setStyleSheet("""
        QMainWindow {
            background: #f7f8fa;
        }
        QMenuBar {
            background: #f7f8fa;
            color: #1d1d1f;
            border-bottom: 1px solid #e5e7eb;
            padding: 2px 0;
        }
        QMenuBar::item {
            padding: 4px 12px;
        }
        QMenuBar::item:selected {
            background: #e8edf4;
            border-radius: 4px;
        }

        /* ---- 顶部标题 ---- */
        #Header {
            background: #ffffff;
            border-bottom: 1px solid #e5e7eb;
        }
        #Title {
            font-size: 18px;
            font-weight: 700;
            color: #111827;
        }
        #Subtitle {
            font-size: 13px;
            color: #9ca3af;
        }
        #NoticeBar {
            background: #fafbfc;
            border-bottom: 1px solid #edf0f3;
        }
        #Notice {
            font-size: 12px;
            color: #9ca3af;
            padding: 6px 0;
        }

        /* ---- 标签页 ---- */
        #MainTabs {
            background: transparent;
        }
        #MainTabs::pane {
            background: #f7f8fa;
            border: none;
            padding: 0;
        }
        QTabBar::tab {
            background: transparent;
            color: #6b7280;
            border: none;
            border-bottom: 2px solid transparent;
            padding: 12px 28px;
            margin-right: 0;
            min-height: 40px;
            font-size: 14px;
            font-weight: 500;
        }
        QTabBar::tab:hover {
            color: #374151;
            background: rgba(0,0,0,0.03);
        }
        QTabBar::tab:selected {
            color: #1a56db;
            border-bottom: 2px solid #1a56db;
            font-weight: 600;
        }

        /* ---- 按钮 ---- */
        QPushButton {
            background: #ffffff;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            padding: 7px 16px;
            color: #374151;
            font-size: 13px;
            font-weight: 500;
        }
        QPushButton:hover {
            background: #f9fafb;
            border-color: #9ca3af;
        }
        QPushButton:pressed {
            background: #f3f4f6;
        }
        QPushButton:disabled {
            color: #d1d5db;
            background: #f9fafb;
        }
        #PrimaryButton {
            background: #1a56db;
            color: #ffffff;
            border-color: #1a56db;
        }
        #PrimaryButton:hover {
            background: #1e40af;
        }
        #CancelButton {
            background: #ffffff;
            color: #b42318;
            border-color: #fca5a5;
        }
        #CancelButton:hover {
            background: #fef2f2;
        }
        #ReportButton {
            background: #1a56db;
            color: #ffffff;
            border-color: #1a56db;
            font-size: 14px;
            padding: 8px 20px;
        }
        #ReportButton:hover {
            background: #1e40af;
        }

        /* ---- 进度条 ---- */
        QProgressBar {
            border: none;
            border-radius: 3px;
            background: #e5e7eb;
        }
        QProgressBar::chunk {
            background: #1a56db;
            border-radius: 3px;
        }

        /* ---- 状态 ---- */
        #Status {
            font-size: 12px;
            color: #9ca3af;
        }

        /* ---- 指标卡片 ---- */
        #MetricCard {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
        }
        #MetricValue {
            font-size: 22px;
            font-weight: 700;
            color: #111827;
        }
        #MetricTitle {
            font-size: 11px;
            color: #9ca3af;
        }

        /* ---- 结果容器 ---- */
        #ResultsContainer {
            background: transparent;
            border: none;
        }

        /* ---- 结果列表 ---- */
        #ResultList {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            outline: none;
        }
        #ResultList::item {
            border-bottom: 1px solid #f3f4f6;
            padding: 0;
        }
        #ResultList::item:selected {
            background: #eff6ff;
            border-bottom: 1px solid #bfdbfe;
        }
        #ResultList::item:hover {
            background: #f9fafb;
        }

        /* ---- 详情面板 ---- */
        #DetailPanel {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
        }
        #PanelTitle {
            font-size: 13px;
            font-weight: 600;
            color: #374151;
        }
        QTextEdit {
            background: #fafbfc;
            border: 1px solid #edf0f3;
            border-radius: 4px;
            padding: 8px;
            font-size: 12px;
            color: #374151;
            font-family: "Consolas", "Cascadia Mono", monospace;
        }

        /* ---- 结果行 ---- */
        #ResultName {
            font-size: 13px;
            color: #111827;
        }
        #ResultScore {
            font-size: 13px;
        }
        #ResultEngine {
            font-size: 12px;
            color: #9ca3af;
        }

        /* ---- 报告页 ---- */
        #ReportHint {
            font-size: 13px;
            color: #9ca3af;
        }
        #SectionTitle {
            font-size: 13px;
            font-weight: 600;
            color: #374151;
        }
        #Separator {
            color: #e5e7eb;
        }
        #RecentList {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            font-size: 13px;
            outline: none;
        }
        #RecentList::item {
            padding: 6px 12px;
            border-bottom: 1px solid #f3f4f6;
        }
        #RecentList::item:hover {
            background: #f9fafb;
        }

        /* ---- 更多功能 ---- */
        #MoreCard {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
        }
        #MoreTitle {
            font-size: 16px;
            font-weight: 600;
            color: #6b7280;
        }
        #MoreHint {
            font-size: 13px;
            color: #c4c9d1;
        }

        /* ---- 威胁弹窗 ---- */
        #ThreatPopup {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            border-left: 4px solid #dc2626;
        }
        #PopupIcon {
            background: #fef2f2;
            color: #dc2626;
            border-radius: 18px;
            font-size: 18px;
            font-weight: 800;
        }
        #PopupName {
            font-size: 13px;
            font-weight: 600;
            color: #111827;
        }
        #PopupInfo {
            font-size: 12px;
            color: #6b7280;
        }
    """)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    apply_style(app)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
