from PyQt5.QtWidgets import QLineEdit, QComboBox, QCheckBox, QSpinBox, QFormLayout

from scanners.assets import AssetScanner
from ui.base_panel import BaseScanPanel


class AssetPanel(BaseScanPanel):
    scanner_cls = AssetScanner
    panel_title = "网络资产管理"
    panel_icon = "🏢"

    def build_options(self, form: QFormLayout) -> None:
        self._target = QLineEdit()
        self._target.setPlaceholderText("example.com 或 192.168.1.0/24")
        form.addRow("目标", self._target)

        self._mode = QComboBox()
        self._mode.addItems(["综合发现", "子域名枚举", "IP段探测", "服务指纹识别"])
        form.addRow("发现模式", self._mode)

        self._subs = QLineEdit()
        self._subs.setPlaceholderText("额外子域前缀，逗号分隔")
        form.addRow("自定义子域", self._subs)

        self._brute = QCheckBox("子域爆破")
        self._brute.setChecked(True)
        self._ct = QCheckBox("证书透明度 (crt.sh)")
        self._ct.setChecked(True)
        form.addRow(self._brute)
        form.addRow(self._ct)

        self._ip_range = QLineEdit()
        self._ip_range.setPlaceholderText("192.168.1.1-254 或 /24")
        form.addRow("IP 段", self._ip_range)

        self._ports = QLineEdit("80,443,22,3389,8080")
        form.addRow("探测端口", self._ports)

        self._threads = QSpinBox()
        self._threads.setRange(1, 200)
        self._threads.setValue(40)
        form.addRow("并发线程", self._threads)

        self._max_hosts = QSpinBox()
        self._max_hosts.setRange(1, 4096)
        self._max_hosts.setValue(256)
        form.addRow("最大主机数", self._max_hosts)

    def collect_options(self) -> dict:
        return {
            "target": self._target.text(),
            "mode": self._mode.currentText(),
            "custom_subdomains": self._subs.text(),
            "bruteforce": self._brute.isChecked(),
            "cert_search": self._ct.isChecked(),
            "ip_range": self._ip_range.text() or self._target.text(),
            "probe_ports": self._ports.text(),
            "threads": self._threads.value(),
            "max_hosts": self._max_hosts.value(),
            "timeout": 1.0,
        }
