from PyQt5.QtWidgets import QLineEdit, QCheckBox, QSpinBox, QFormLayout
from scanners.smb_enum import SmbEnumScanner
from ui.base_panel import BaseScanPanel


class SmbPanel(BaseScanPanel):
    scanner_cls = SmbEnumScanner
    panel_title = "SMB 枚举"
    panel_icon = "📁"

    def build_options(self, form: QFormLayout) -> None:
        self._target = QLineEdit()
        form.addRow("目标", self._target)
        self._port = QSpinBox()
        self._port.setValue(445)
        form.addRow("SMB 端口", self._port)
        self._nbns = QCheckBox("NetBIOS 查询")
        self._nbns.setChecked(True)
        self._banner = QCheckBox("SMB Banner")
        self._banner.setChecked(True)
        self._null = QCheckBox("空会话提示")
        form.addRow(self._nbns)
        form.addRow(self._banner)
        form.addRow(self._null)

    def collect_options(self) -> dict:
        return {
            "target": self._target.text(),
            "port": self._port.value(),
            "nbns": self._nbns.isChecked(),
            "os_hint": self._banner.isChecked(),
            "null_session": self._null.isChecked(),
        }
