from PyQt5.QtWidgets import QLineEdit, QComboBox, QSpinBox, QFormLayout

from scanners.host_discovery import HostDiscoveryScanner
from ui.base_panel import BaseScanPanel


class HostPanel(BaseScanPanel):
    scanner_cls = HostDiscoveryScanner
    panel_title = "存活主机探测"
    panel_icon = "📡"

    def build_options(self, form: QFormLayout) -> None:
        self._target = QLineEdit()
        self._target.setPlaceholderText("192.168.1.0/24")
        form.addRow("目标/IP段", self._target)

        self._ip_range = QLineEdit()
        self._ip_range.setPlaceholderText("留空则使用上方目标")
        form.addRow("扩展 IP 段", self._ip_range)

        self._method = QComboBox()
        self._method.addItems(["ICMP Ping", "TCP Ping", "ARP (同网段)", "组合探测"])
        form.addRow("探测方式", self._method)

        self._tcp_ports = QLineEdit("80,443,22,135,445")
        form.addRow("TCP 探测端口", self._tcp_ports)

        self._ping_ms = QSpinBox()
        self._ping_ms.setRange(200, 5000)
        self._ping_ms.setValue(1000)
        form.addRow("Ping 超时(ms)", self._ping_ms)

        self._threads = QSpinBox()
        self._threads.setRange(1, 300)
        self._threads.setValue(60)
        form.addRow("并发线程", self._threads)

        self._max_hosts = QSpinBox()
        self._max_hosts.setRange(1, 4096)
        self._max_hosts.setValue(512)
        form.addRow("最大主机数", self._max_hosts)

    def collect_options(self) -> dict:
        return {
            "target": self._target.text(),
            "ip_range": self._ip_range.text() or self._target.text(),
            "method": self._method.currentText(),
            "tcp_ports": self._tcp_ports.text(),
            "ping_timeout_ms": self._ping_ms.value(),
            "threads": self._threads.value(),
            "max_hosts": self._max_hosts.value(),
            "timeout": 1.0,
        }
