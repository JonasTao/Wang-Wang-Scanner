from PyQt5.QtWidgets import QLineEdit, QComboBox, QSpinBox, QFormLayout
from scanners.snmp_scan import SnmpScanner
from ui.base_panel import BaseScanPanel


class SnmpPanel(BaseScanPanel):
    scanner_cls = SnmpScanner
    panel_title = "SNMP 探测"
    panel_icon = "📶"

    def build_options(self, form: QFormLayout) -> None:
        self._target = QLineEdit()
        form.addRow("目标 IP", self._target)
        self._port = QSpinBox()
        self._port.setValue(161)
        form.addRow("端口", self._port)
        self._communities = QLineEdit("public,private,community,manager")
        form.addRow("团体字列表", self._communities)
        self._version = QComboBox()
        self._version.addItems(["v2c", "v1"])
        form.addRow("SNMP 版本", self._version)

    def collect_options(self) -> dict:
        return {
            "target": self._target.text(),
            "port": self._port.value(),
            "communities": self._communities.text(),
            "version": self._version.currentText(),
        }
