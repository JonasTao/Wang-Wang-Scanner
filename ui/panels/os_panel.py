from PyQt5.QtWidgets import QLineEdit, QCheckBox, QFormLayout

from scanners.os_detect import OSDetectScanner
from ui.base_panel import BaseScanPanel


class OSPanel(BaseScanPanel):
    scanner_cls = OSDetectScanner
    panel_title = "目标系统检测"
    panel_icon = "💻"

    def build_options(self, form: QFormLayout) -> None:
        self._target = QLineEdit()
        self._target.setPlaceholderText("IP 或域名")
        form.addRow("目标", self._target)

        self._ttl = QCheckBox("TTL 指纹")
        self._ttl.setChecked(True)
        self._banner = QCheckBox("服务 Banner")
        self._banner.setChecked(True)
        self._nmap = QCheckBox("Nmap OS 检测 (需安装 nmap)")
        self._nmap.setChecked(True)
        self._http = QCheckBox("HTTP 头指纹")
        self._http.setChecked(True)
        form.addRow(self._ttl)
        form.addRow(self._banner)
        form.addRow(self._nmap)
        form.addRow(self._http)

        self._ports = QLineEdit("22,80,443,445,3389")
        form.addRow("Banner 端口", self._ports)

    def collect_options(self) -> dict:
        methods = []
        if self._ttl.isChecked():
            methods.append("TTL")
        if self._banner.isChecked():
            methods.append("Banner")
        if self._nmap.isChecked():
            methods.append("Nmap OS")
        if self._http.isChecked():
            methods.append("HTTP头")
        return {
            "target": self._target.text(),
            "methods": methods or ["TTL"],
            "banner_ports": self._ports.text(),
        }
