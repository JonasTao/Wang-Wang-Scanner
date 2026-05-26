from PyQt5.QtWidgets import QLineEdit, QCheckBox, QSpinBox, QFormLayout
from scanners.subdomain import SubdomainScanner
from ui.base_panel import BaseScanPanel


class SubdomainPanel(BaseScanPanel):
    scanner_cls = SubdomainScanner
    panel_title = "子域名枚举"
    panel_icon = "🌐"

    def build_options(self, form: QFormLayout) -> None:
        self._domain = QLineEdit()
        form.addRow("主域名", self._domain)
        self._wordlist = QLineEdit()
        self._wordlist.setPlaceholderText("额外子域，逗号分隔")
        form.addRow("自定义字典", self._wordlist)
        self._brute = QCheckBox("字典爆破")
        self._brute.setChecked(True)
        self._ct = QCheckBox("证书透明度")
        self._ct.setChecked(True)
        self._search = QCheckBox("搜索语法提示")
        form.addRow(self._brute)
        form.addRow(self._ct)
        form.addRow(self._search)
        self._threads = QSpinBox()
        self._threads.setRange(1, 200)
        self._threads.setValue(50)
        form.addRow("并发", self._threads)

    def collect_options(self) -> dict:
        methods = []
        if self._brute.isChecked():
            methods.append("字典爆破")
        if self._ct.isChecked():
            methods.append("证书透明度")
        if self._search.isChecked():
            methods.append("搜索引擎")
        return {
            "domain": self._domain.text(),
            "methods": methods or ["字典爆破"],
            "wordlist": self._wordlist.text(),
            "threads": self._threads.value(),
        }
