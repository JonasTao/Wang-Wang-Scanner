from PyQt5.QtWidgets import QLineEdit, QCheckBox, QSpinBox, QFormLayout

from scanners.web_vuln import WebVulnScanner
from ui.base_panel import BaseScanPanel


class WebPanel(BaseScanPanel):
    scanner_cls = WebVulnScanner
    panel_title = "网站漏洞扫描"
    panel_icon = "🛡️"

    def build_options(self, form: QFormLayout) -> None:
        self._url = QLineEdit()
        self._url.setPlaceholderText("https://example.com")
        form.addRow("目标 URL", self._url)

        self._headers = QCheckBox("安全响应头")
        self._headers.setChecked(True)
        self._ssl = QCheckBox("SSL 证书")
        self._ssl.setChecked(True)
        self._dir = QCheckBox("敏感目录探测")
        self._dir.setChecked(True)
        self._sqli = QCheckBox("SQL 注入探测")
        self._sqli.setChecked(True)
        self._xss = QCheckBox("XSS 探测")
        self._xss.setChecked(True)
        self._leak = QCheckBox("信息泄露检测")
        self._leak.setChecked(True)
        self._crawl = QCheckBox("链接爬取")
        form.addRow(self._headers)
        form.addRow(self._ssl)
        form.addRow(self._dir)
        form.addRow(self._sqli)
        form.addRow(self._xss)
        form.addRow(self._leak)
        form.addRow(self._crawl)

        self._paths = QLineEdit()
        self._paths.setPlaceholderText("额外路径，逗号分隔")
        form.addRow("自定义路径", self._paths)

        self._max_paths = QSpinBox()
        self._max_paths.setRange(5, 200)
        self._max_paths.setValue(30)
        form.addRow("最大目录数", self._max_paths)

        self._sqli_depth = QSpinBox()
        self._sqli_depth.setRange(1, 5)
        self._sqli_depth.setValue(2)
        form.addRow("SQLi Payload 数", self._sqli_depth)

    def collect_options(self) -> dict:
        checks = []
        if self._headers.isChecked():
            checks.append("安全响应头")
        if self._ssl.isChecked():
            checks.append("SSL证书")
        if self._dir.isChecked():
            checks.append("敏感目录")
        if self._sqli.isChecked():
            checks.append("SQL注入探测")
        if self._xss.isChecked():
            checks.append("XSS探测")
        if self._leak.isChecked():
            checks.append("信息泄露")
        return {
            "url": self._url.text(),
            "checks": checks,
            "custom_paths": self._paths.text(),
            "max_paths": self._max_paths.value(),
            "sqli": self._sqli.isChecked(),
            "xss": self._xss.isChecked(),
            "sqli_depth": self._sqli_depth.value(),
            "crawl_links": self._crawl.isChecked(),
        }
