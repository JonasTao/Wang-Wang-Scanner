from PyQt5.QtWidgets import QLineEdit, QCheckBox, QSpinBox, QFormLayout
from scanners.ssl_deep import SslDeepScanner
from ui.base_panel import BaseScanPanel


class SslPanel(BaseScanPanel):
    scanner_cls = SslDeepScanner
    panel_title = "SSL/TLS 检测"
    panel_icon = "🔒"

    def build_options(self, form: QFormLayout) -> None:
        self._target = QLineEdit()
        form.addRow("主机/URL", self._target)
        self._port = QSpinBox()
        self._port.setValue(443)
        form.addRow("端口", self._port)
        self._expiry = QCheckBox("证书过期检查")
        self._expiry.setChecked(True)
        self._versions = QCheckBox("协议版本探测")
        form.addRow(self._expiry)
        form.addRow(self._versions)

    def collect_options(self) -> dict:
        return {
            "target": self._target.text(),
            "port": self._port.value(),
            "check_expiry": self._expiry.isChecked(),
            "test_versions": self._versions.isChecked(),
        }
