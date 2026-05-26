from PyQt5.QtWidgets import QLineEdit, QCheckBox, QSpinBox, QFormLayout
from scanners.sensitive_files import SensitiveFileScanner
from ui.base_panel import BaseScanPanel


class SensitivePanel(BaseScanPanel):
    scanner_cls = SensitiveFileScanner
    panel_title = "敏感文件探测"
    panel_icon = "📂"

    def build_options(self, form: QFormLayout) -> None:
        self._url = QLineEdit()
        form.addRow("目标 URL", self._url)
        self._custom = QLineEdit()
        self._custom.setPlaceholderText("额外路径，逗号分隔")
        form.addRow("自定义路径", self._custom)
        self._max = QSpinBox()
        self._max.setRange(5, 100)
        self._max.setValue(40)
        form.addRow("最大路径数", self._max)
        self._verify = QCheckBox("内容验证")
        self._verify.setChecked(True)
        form.addRow(self._verify)

    def collect_options(self) -> dict:
        return {
            "url": self._url.text(),
            "custom_paths": self._custom.text(),
            "max_paths": self._max.value(),
            "verify_content": self._verify.isChecked(),
        }
