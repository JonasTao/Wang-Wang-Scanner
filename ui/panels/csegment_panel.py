from PyQt5.QtWidgets import QLineEdit, QCheckBox, QSpinBox, QFormLayout
from scanners.c_segment import CSegmentScanner
from ui.base_panel import BaseScanPanel


class CsegmentPanel(BaseScanPanel):
    scanner_cls = CSegmentScanner
    panel_title = "C 段旁站探测"
    panel_icon = "🗺️"

    def build_options(self, form: QFormLayout) -> None:
        self._target = QLineEdit()
        form.addRow("目标 IP/域名", self._target)
        self._cidr = QLineEdit()
        self._cidr.setPlaceholderText("留空自动 /24")
        form.addRow("自定义 CIDR", self._cidr)
        self._ports = QLineEdit("80,443,8080")
        form.addRow("探测端口", self._ports)
        self._threads = QSpinBox()
        self._threads.setValue(50)
        form.addRow("并发", self._threads)
        self._max = QSpinBox()
        self._max.setValue(254)
        form.addRow("最大主机", self._max)
        self._http = QCheckBox("HTTP 标题抓取")
        self._http.setChecked(True)
        form.addRow(self._http)

    def collect_options(self) -> dict:
        return {
            "target": self._target.text(),
            "cidr": self._cidr.text(),
            "ports": self._ports.text(),
            "threads": self._threads.value(),
            "max_hosts": self._max.value(),
            "check_http": self._http.isChecked(),
        }
