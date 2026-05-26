from PyQt5.QtWidgets import QLineEdit, QCheckBox, QSpinBox, QFormLayout
from scanners.api_discovery import ApiDiscoveryScanner
from ui.base_panel import BaseScanPanel


class ApiPanel(BaseScanPanel):
    scanner_cls = ApiDiscoveryScanner
    panel_title = "API 接口发现"
    panel_icon = "🔗"

    def build_options(self, form: QFormLayout) -> None:
        self._url = QLineEdit()
        form.addRow("目标 URL", self._url)
        self._custom = QLineEdit()
        form.addRow("自定义路径", self._custom)
        self._max = QSpinBox()
        self._max.setValue(25)
        form.addRow("最大路径", self._max)
        self._swagger = QCheckBox("解析 Swagger/OpenAPI")
        self._swagger.setChecked(True)
        self._js = QCheckBox("从 JS 提取 API")
        self._js.setChecked(True)
        form.addRow(self._swagger)
        form.addRow(self._js)

    def collect_options(self) -> dict:
        return {
            "url": self._url.text(),
            "custom_paths": self._custom.text(),
            "max_paths": self._max.value(),
            "parse_swagger": self._swagger.isChecked(),
            "js_extract": self._js.isChecked(),
        }
