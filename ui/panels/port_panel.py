from PyQt5.QtWidgets import QLineEdit, QComboBox, QCheckBox, QSpinBox, QDoubleSpinBox, QFormLayout

from scanners.port_scanner import PortScanner
from ui.base_panel import BaseScanPanel


class PortPanel(BaseScanPanel):
    scanner_cls = PortScanner
    panel_title = "端口信息收集"
    panel_icon = "🔌"

    def build_options(self, form: QFormLayout) -> None:
        self._target = QLineEdit()
        self._target.setPlaceholderText("IP 或域名")
        form.addRow("目标", self._target)

        self._scan_type = QComboBox()
        self._scan_type.addItems([
            "TCP Connect",
            "UDP (基础)",
            "Nmap SYN",
            "Nmap ACK",
            "Nmap FIN",
            "Nmap 综合",
        ])
        form.addRow("扫描方式", self._scan_type)

        self._preset = QComboBox()
        self._preset.addItems(list(PortScanner.PRESET_PORTS.keys()))
        form.addRow("端口预设", self._preset)

        self._custom = QLineEdit()
        self._custom.setPlaceholderText("自定义: 8080,9000 或 1-1000")
        form.addRow("自定义端口", self._custom)

        self._timeout = QDoubleSpinBox()
        self._timeout.setRange(0.3, 10.0)
        self._timeout.setValue(1.0)
        self._timeout.setSingleStep(0.1)
        form.addRow("超时(秒)", self._timeout)

        self._threads = QSpinBox()
        self._threads.setRange(1, 500)
        self._threads.setValue(100)
        form.addRow("并发线程", self._threads)

        self._banner = QCheckBox("Banner 抓取")
        self._banner.setChecked(True)
        self._service = QCheckBox("服务识别")
        self._service.setChecked(True)
        form.addRow(self._banner)
        form.addRow(self._service)

        self._timing = QComboBox()
        self._timing.addItems(["T1", "T2", "T3", "T4", "T5"])
        self._timing.setCurrentText("T3")
        form.addRow("Nmap 速率", self._timing)

    def collect_options(self) -> dict:
        return {
            "target": self._target.text(),
            "scan_type": self._scan_type.currentText(),
            "port_preset": self._preset.currentText(),
            "custom_ports": self._custom.text(),
            "timeout": self._timeout.value(),
            "threads": self._threads.value(),
            "grab_banner": self._banner.isChecked(),
            "service_detect": self._service.isChecked(),
            "nmap_timing": self._timing.currentText(),
        }
