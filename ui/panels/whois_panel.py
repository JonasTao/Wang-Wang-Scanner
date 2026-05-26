from PyQt5.QtWidgets import QLineEdit, QFormLayout
from scanners.whois_scan import WhoisScanner
from ui.base_panel import BaseScanPanel


class WhoisPanel(BaseScanPanel):
    scanner_cls = WhoisScanner
    panel_title = "WHOIS 查询"
    panel_icon = "📋"

    def build_options(self, form: QFormLayout) -> None:
        self._domain = QLineEdit()
        self._domain.setPlaceholderText("example.com")
        form.addRow("域名", self._domain)

    def collect_options(self) -> dict:
        return {"domain": self._domain.text(), "fields": "全部"}
