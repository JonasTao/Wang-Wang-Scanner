from PyQt5.QtWidgets import QLineEdit, QCheckBox, QFormLayout
from scanners.web_fingerprint import WebFingerprintScanner
from ui.base_panel import BaseScanPanel


class WebFingerprintPanel(BaseScanPanel):
    scanner_cls = WebFingerprintScanner
    panel_title = "Web 指纹识别"
    panel_icon = "🔎"

    def build_options(self, form: QFormLayout) -> None:
        self._url = QLineEdit()
        self._url.setPlaceholderText("https://example.com")
        form.addRow("目标 URL", self._url)
        for attr, label in [
            ("_hdr", "响应头"), ("_waf", "WAF"), ("_cdn", "CDN"),
            ("_cms", "CMS/框架"), ("_cookie", "Cookie"), ("_page", "页面特征"),
        ]:
            cb = QCheckBox(label)
            cb.setChecked(True)
            setattr(self, attr, cb)
            form.addRow(cb)
        self._paths = QCheckBox("技术路径探测")
        self._paths.setChecked(True)
        form.addRow(self._paths)

    def collect_options(self) -> dict:
        checks = []
        if self._hdr.isChecked():
            checks.append("响应头")
        if self._waf.isChecked():
            checks.append("WAF")
        if self._cdn.isChecked():
            checks.append("CDN")
        if self._cms.isChecked():
            checks.append("CMS")
        if self._cookie.isChecked():
            checks.append("Cookie")
        if self._page.isChecked():
            checks.append("页面特征")
        return {
            "url": self._url.text(),
            "checks": checks,
            "probe_paths": self._paths.isChecked(),
            "verify_ssl": False,
        }
