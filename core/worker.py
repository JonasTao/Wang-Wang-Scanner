"""在后台线程执行扫描，避免阻塞 UI。"""
from typing import Any, Dict, Type

from PyQt5.QtCore import QThread, pyqtSignal

from .scanner_base import BaseScanner, ScanResult


class ScanWorker(QThread):
    progress = pyqtSignal(int, str)
    log = pyqtSignal(str)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, scanner_cls: Type[BaseScanner], options: Dict[str, Any]) -> None:
        super().__init__()
        self._scanner_cls = scanner_cls
        self._options = options
        self._scanner: BaseScanner | None = None

    def run(self) -> None:
        try:
            self._scanner = self._scanner_cls()
            self._scanner.bind_callbacks(
                on_progress=lambda p, m: self.progress.emit(p, m),
                on_log=lambda m: self.log.emit(m),
            )
            result = self._scanner.run(self._options)
            self.finished.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))

    def cancel_scan(self) -> None:
        if self._scanner:
            self._scanner.cancel()
