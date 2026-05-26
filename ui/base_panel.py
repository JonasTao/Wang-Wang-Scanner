"""扫描面板基类 — 统一布局、启动与结果展示。"""
from typing import Any, Dict, Type

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QFormLayout,
    QPushButton, QProgressBar, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QLabel, QScrollArea,
)

from core.scanner_base import BaseScanner
from core.worker import ScanWorker


class BaseScanPanel(QWidget):
    scanner_cls: Type[BaseScanner] = None
    panel_title: str = "扫描"
    panel_icon: str = "🔍"

    def __init__(self, dog_callback=None, parent=None):
        super().__init__(parent)
        self._dog_callback = dog_callback
        self._worker: ScanWorker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setSpacing(12)
        outer.setContentsMargins(16, 16, 16, 16)

        header = QLabel(f"{self.panel_icon} {self.panel_title}")
        header.setObjectName("titleLabel")
        outer.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll_w = QWidget()
        scroll_layout = QVBoxLayout(scroll_w)

        self._config_box = QGroupBox("参数配置")
        self._form = QFormLayout()
        self._config_box.setLayout(self._form)
        scroll_layout.addWidget(self._config_box)
        self.build_options(self._form)

        scroll.setWidget(scroll_w)
        outer.addWidget(scroll, stretch=2)

        btn_row = QHBoxLayout()
        self._start_btn = QPushButton("开始扫描")
        self._start_btn.clicked.connect(self.start_scan)
        self._stop_btn = QPushButton("停止")
        self._stop_btn.setObjectName("stopBtn")
        self._stop_btn.clicked.connect(self.stop_scan)
        self._stop_btn.setEnabled(False)
        self._export_btn = QPushButton("导出结果")
        self._export_btn.setObjectName("secondaryBtn")
        self._export_btn.clicked.connect(self._export)
        btn_row.addWidget(self._start_btn)
        btn_row.addWidget(self._stop_btn)
        btn_row.addStretch()
        btn_row.addWidget(self._export_btn)
        outer.addLayout(btn_row)

        self._progress = QProgressBar()
        self._progress.setValue(0)
        self._status = QLabel("就绪")
        self._status.setObjectName("subtitleLabel")
        outer.addWidget(self._progress)
        outer.addWidget(self._status)

        self._table = QTableWidget(0, 0)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet("alternate-background-color: #FFF0F3;")
        outer.addWidget(self._table, stretch=3)

        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setMaximumHeight(120)
        self._log.setPlaceholderText("扫描日志…")
        outer.addWidget(self._log)

        self._last_result = None

    def build_options(self, form: QFormLayout) -> None:
        """子类覆盖：添加配置控件。"""
        pass

    def collect_options(self) -> Dict[str, Any]:
        """子类覆盖：收集配置为 dict。"""
        return {}

    def start_scan(self) -> None:
        if not self.scanner_cls:
            return
        opts = self.collect_options()
        self._log.clear()
        self._table.setRowCount(0)
        self._progress.setValue(0)
        self._status.setText("扫描中…")
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        if self._dog_callback:
            self._dog_callback("scan", f"开始{self.panel_title}啦！")

        self._worker = ScanWorker(self.scanner_cls, opts)
        self._worker.progress.connect(self._on_progress)
        self._worker.log.connect(self._on_log)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def stop_scan(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.cancel_scan()
            self._status.setText("正在停止…")

    def _on_progress(self, percent: int, msg: str) -> None:
        self._progress.setValue(percent)
        if msg:
            self._status.setText(msg)

    def _on_log(self, msg: str) -> None:
        self._log.append(msg)

    def _on_finished(self, result) -> None:
        self._last_result = result
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._progress.setValue(100)
        self._status.setText(result.summary)
        self._fill_table(result.data)
        for line in result.logs:
            if line not in self._log.toPlainText():
                self._log.append(line)
        if self._dog_callback:
            self._dog_callback("done", "扫描完成，汪汪！")

    def _on_error(self, err: str) -> None:
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._log.append(f"[!] 错误: {err}")
        self._status.setText("扫描出错")
        if self._dog_callback:
            self._dog_callback("idle", "出错了，检查一下参数吧…")

    def _fill_table(self, rows: list) -> None:
        if not rows:
            self._table.setRowCount(0)
            self._table.setColumnCount(0)
            return
        cols = list(rows[0].keys())
        self._table.setColumnCount(len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, key in enumerate(cols):
                self._table.setItem(r, c, QTableWidgetItem(str(row.get(key, ""))))

    def _export(self) -> None:
        if not self._last_result:
            self._log.append("[!] 暂无结果可导出")
            return
        from PyQt5.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(self, "导出", "scan_result.txt", "Text (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._last_result.to_text())
            self._log.append(f"[+] 已导出: {path}")
