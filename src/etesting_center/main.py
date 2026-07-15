from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Qt, Signal
from PySide6.QtGui import QAction, QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from etesting_center import APP_NAME, APP_TAGLINE, APP_VERSION
from etesting_center.engine.models import ScanReport
from etesting_center.engine.scanner import Scanner
from etesting_center.reports.writers import write_report


class ScanWorker(QObject):
    progress = Signal(int, int, str)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, target: Path, data_dir: Path) -> None:
        super().__init__()
        self.target = target
        self.data_dir = data_dir

    def run(self) -> None:
        try:
            scanner = Scanner(self.data_dir)
            report = scanner.scan(self.target, progress=lambda done, total, path: self.progress.emit(done, total, path))
            self.finished.emit(report)
        except Exception as exc:
            self.failed.emit(str(exc))


class Metric(QFrame):
    def __init__(self, title: str, value: str = "0") -> None:
        super().__init__()
        self.setObjectName("Metric")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        self.value_label = QLabel(value)
        self.value_label.setObjectName("MetricValue")
        self.title_label = QLabel(title)
        self.title_label.setObjectName("MetricTitle")
        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)

    def set_value(self, value: int | str) -> None:
        self.value_label.setText(str(value))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(1180, 760)
        self.data_dir = Path(__file__).resolve().parent / "data"
        self.current_report: ScanReport | None = None
        self.scan_thread: QThread | None = None
        self.scan_worker: ScanWorker | None = None
        self._setup_ui()
        self._setup_menu()

    def _setup_menu(self) -> None:
        export_json = QAction("导出 JSON", self)
        export_json.triggered.connect(lambda: self.export_report("json"))
        export_html = QAction("导出 HTML", self)
        export_html.triggered.connect(lambda: self.export_report("html"))
        export_txt = QAction("导出 TXT", self)
        export_txt.triggered.connect(lambda: self.export_report("txt"))
        file_menu = self.menuBar().addMenu("文件")
        file_menu.addAction(export_html)
        file_menu.addAction(export_json)
        file_menu.addAction(export_txt)

    def _setup_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(28, 24, 28, 24)
        outer.setSpacing(18)

        header = QHBoxLayout()
        title_block = QVBoxLayout()
        title = QLabel(APP_NAME)
        title.setObjectName("Title")
        subtitle = QLabel(APP_TAGLINE)
        subtitle.setObjectName("Subtitle")
        title_block.addWidget(title)
        title_block.addWidget(subtitle)
        header.addLayout(title_block)
        header.addStretch(1)

        self.file_button = QPushButton("单文件")
        self.file_button.clicked.connect(self.choose_file)
        self.folder_button = QPushButton("自定义路径")
        self.folder_button.clicked.connect(self.choose_folder)
        self.quick_button = QPushButton("快速扫描")
        self.quick_button.setObjectName("PrimaryButton")
        self.quick_button.clicked.connect(self.quick_scan)
        header.addWidget(self.file_button)
        header.addWidget(self.folder_button)
        header.addWidget(self.quick_button)
        outer.addLayout(header)

        self.notice = QLabel("只读检测：扫描过程不会隔离、删除、修复或修改任何文件。")
        self.notice.setObjectName("Notice")
        outer.addWidget(self.notice)

        metrics = QGridLayout()
        metrics.setHorizontalSpacing(12)
        self.metric_scanned = Metric("已扫描")
        self.metric_safe = Metric("安全")
        self.metric_suspicious = Metric("可疑")
        self.metric_malicious = Metric("恶意")
        self.metric_errors = Metric("错误")
        for column, metric in enumerate(
            [self.metric_scanned, self.metric_safe, self.metric_suspicious, self.metric_malicious, self.metric_errors]
        ):
            metrics.addWidget(metric, 0, column)
        outer.addLayout(metrics)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.status_label = QLabel("就绪")
        self.status_label.setObjectName("Status")
        outer.addWidget(self.progress)
        outer.addWidget(self.status_label)

        content = QHBoxLayout()
        content.setSpacing(14)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["风险", "评分", "类型", "大小", "路径"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self.show_selected_details)
        content.addWidget(self.table, 3)

        detail_panel = QFrame()
        detail_panel.setObjectName("DetailPanel")
        detail_layout = QVBoxLayout(detail_panel)
        detail_title = QLabel("详情")
        detail_title.setObjectName("PanelTitle")
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("选择一条结果查看检测依据。")
        detail_layout.addWidget(detail_title)
        detail_layout.addWidget(self.details)
        content.addWidget(detail_panel, 2)
        outer.addLayout(content, 1)

    def quick_scan(self) -> None:
        home = Path.home()
        candidates = [home / "Downloads", home / "Desktop", home / "Documents"]
        existing = [path for path in candidates if path.exists()]
        if not existing:
            self.start_scan(home)
            return
        self.start_scan(existing[0])

    def choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择要扫描的文件")
        if path:
            self.start_scan(Path(path))

    def choose_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "选择要扫描的文件夹")
        if path:
            self.start_scan(Path(path))

    def start_scan(self, target: Path) -> None:
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.information(self, APP_NAME, "当前已有扫描任务正在运行。")
            return
        self.table.setRowCount(0)
        self.details.clear()
        self.current_report = None
        self.progress.setValue(0)
        self.status_label.setText(f"正在扫描 {target}")
        self._set_buttons_enabled(False)

        self.scan_thread = QThread()
        self.scan_worker = ScanWorker(target, self.data_dir)
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.progress.connect(self.on_progress)
        self.scan_worker.finished.connect(self.on_finished)
        self.scan_worker.failed.connect(self.on_failed)
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.failed.connect(self.scan_thread.quit)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.start()

    def on_progress(self, done: int, total: int, path: str) -> None:
        percent = int((done / total) * 100) if total else 0
        self.progress.setValue(percent)
        self.status_label.setText(f"正在扫描 {done}/{total}: {path}")

    def on_finished(self, report: ScanReport) -> None:
        self.current_report = report
        self.progress.setValue(100)
        self.status_label.setText(f"扫描完成。YARA 已启用: {report.yara_enabled}")
        self._set_buttons_enabled(True)
        self.populate_report(report)

    def on_failed(self, message: str) -> None:
        self.status_label.setText("扫描失败")
        self._set_buttons_enabled(True)
        QMessageBox.warning(self, APP_NAME, message)

    def populate_report(self, report: ScanReport) -> None:
        self.metric_scanned.set_value(report.summary.scanned)
        self.metric_safe.set_value(report.summary.safe)
        self.metric_suspicious.set_value(report.summary.suspicious)
        self.metric_malicious.set_value(report.summary.malicious)
        self.metric_errors.set_value(report.summary.errors)
        self.table.setRowCount(len(report.results))
        for row, result in enumerate(report.results):
            values = [risk_label(result.risk), str(result.score), result.file_type, str(result.size), result.path]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setForeground(risk_color(result.risk))
                    font = QFont()
                    font.setBold(True)
                    item.setFont(font)
                self.table.setItem(row, column, item)
        if report.results:
            self.table.selectRow(0)

    def show_selected_details(self) -> None:
        if not self.current_report:
            return
        selected = self.table.currentRow()
        if selected < 0 or selected >= len(self.current_report.results):
            return
        result = self.current_report.results[selected]
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
        lines.append("检测依据:")
        if not result.findings:
            lines.append("未命中本地指标。")
        for finding in result.findings:
            lines.append(f"- {finding.engine}:{finding.rule}")
            lines.append(f"  严重性: {risk_label(finding.severity)}")
            lines.append(f"  置信度: {finding.confidence}")
            lines.append(f"  依据: {finding.description}")
            if finding.details:
                lines.append(f"  细节: {finding.details}")
        self.details.setPlainText("\n".join(lines))

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

    def _set_buttons_enabled(self, enabled: bool) -> None:
        self.file_button.setEnabled(enabled)
        self.folder_button.setEnabled(enabled)
        self.quick_button.setEnabled(enabled)


def risk_label(risk: str) -> str:
    return {
        "safe": "安全",
        "suspicious": "可疑",
        "malicious": "恶意",
    }.get(risk, risk)


def risk_color(risk: str) -> QColor:
    return {
        "safe": QColor("#167348"),
        "suspicious": QColor("#9a6700"),
        "malicious": QColor("#b42318"),
    }.get(risk, QColor("#1d1d1f"))


def apply_style(app: QApplication) -> None:
    app.setStyleSheet(
        """
        QMainWindow { background: #f5f6f8; }
        QMenuBar { background: #f5f6f8; color: #1d1d1f; }
        QLabel { color: #1d1d1f; }
        #Title { font-size: 30px; font-weight: 680; }
        #Subtitle { color: #62666d; font-size: 13px; }
        #Notice { background: rgba(255,255,255,210); border: 1px solid #e1e4e8; border-radius: 8px; padding: 10px 12px; color: #4b5057; }
        #Status { color: #62666d; }
        QPushButton { background: rgba(255,255,255,225); border: 1px solid #d8dce2; border-radius: 8px; padding: 9px 14px; color: #1d1d1f; }
        QPushButton:hover { background: #ffffff; border-color: #bfc6d0; }
        QPushButton:disabled { color: #a1a6ad; background: #eef0f3; }
        #PrimaryButton { background: #1f6feb; color: white; border-color: #1f6feb; }
        #PrimaryButton:hover { background: #1a5fd0; }
        #Metric, #DetailPanel { background: rgba(255,255,255,225); border: 1px solid #e1e4e8; border-radius: 8px; }
        #MetricValue { font-size: 25px; font-weight: 700; }
        #MetricTitle { color: #62666d; font-size: 12px; }
        #PanelTitle { font-size: 15px; font-weight: 650; }
        QProgressBar { border: 1px solid #d8dce2; border-radius: 7px; height: 12px; background: #eceff3; text-align: center; color: transparent; }
        QProgressBar::chunk { background: #1f6feb; border-radius: 7px; }
        QTableWidget { background: rgba(255,255,255,230); border: 1px solid #e1e4e8; border-radius: 8px; gridline-color: #edf0f2; selection-background-color: #dbeafe; selection-color: #111827; }
        QHeaderView::section { background: #fbfbfc; color: #62666d; border: none; border-bottom: 1px solid #e1e4e8; padding: 8px; font-weight: 650; }
        QTextEdit { background: #fbfbfc; border: 1px solid #e1e4e8; border-radius: 8px; padding: 10px; color: #1d1d1f; font-family: Consolas, 'Cascadia Mono', monospace; font-size: 12px; }
        """
    )


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    apply_style(app)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
