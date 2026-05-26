from PyQt5.QtWidgets import QLineEdit, QCheckBox, QSpinBox, QFormLayout

from scanners.network_scan import NetworkScanScanner
from ui.base_panel import BaseScanPanel


class NetworkPanel(BaseScanPanel):
    scanner_cls = NetworkScanScanner
    panel_title = "网络信息扫描"
    panel_icon = "🌐"

    def build_options(self, form: QFormLayout) -> None:
        self._target = QLineEdit()
        self._target.setPlaceholderText("域名、IP 或 URL")
        form.addRow("目标", self._target)

        self._dns = QCheckBox("DNS 记录")
        self._dns.setChecked(True)
        self._trace = QCheckBox("Traceroute")
        self._trace.setChecked(True)
        self._ssl = QCheckBox("SSL/TLS 证书")
        self._ssl.setChecked(True)
        self._http = QCheckBox("HTTP 安全头")
        self._http.setChecked(True)
        self._ptr = QCheckBox("反向 DNS")
        form.addRow(self._dns)
        form.addRow(self._trace)
        form.addRow(self._ssl)
        form.addRow(self._http)
        form.addRow(self._ptr)

        self._dns_types = QLineEdit("A,AAAA,MX,NS,TXT,CNAME,SOA")
        form.addRow("DNS 类型", self._dns_types)

        self._hops = QSpinBox()
        self._hops.setRange(5, 64)
        self._hops.setValue(20)
        form.addRow("最大路由跳数", self._hops)

    def collect_options(self) -> dict:
        modules = []
        if self._dns.isChecked():
            modules.append("DNS")
        if self._trace.isChecked():
            modules.append("Traceroute")
        if self._ssl.isChecked():
            modules.append("SSL")
        if self._http.isChecked():
            modules.append("HTTP头")
        if self._ptr.isChecked():
            modules.append("反向解析")
        return {
            "target": self._target.text(),
            "modules": modules or ["DNS"],
            "dns_types": self._dns_types.text(),
            "max_hops": self._hops.value(),
            "security_headers": True,
        }
