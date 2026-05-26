from PyQt5.QtWidgets import QLineEdit, QCheckBox, QFormLayout
from scanners.dns_security import DnsSecurityScanner
from ui.base_panel import BaseScanPanel


class DnsSecurityPanel(BaseScanPanel):
    scanner_cls = DnsSecurityScanner
    panel_title = "DNS 安全检测"
    panel_icon = "🔐"

    def build_options(self, form: QFormLayout) -> None:
        self._domain = QLineEdit()
        form.addRow("域名", self._domain)
        self._spf = QCheckBox("SPF")
        self._spf.setChecked(True)
        self._dmarc = QCheckBox("DMARC")
        self._dmarc.setChecked(True)
        self._dkim = QCheckBox("DKIM")
        self._dkim.setChecked(True)
        self._dnssec = QCheckBox("DNSSEC")
        self._axfr = QCheckBox("区域传送 AXFR")
        self._axfr.setChecked(True)
        self._caa = QCheckBox("CAA")
        form.addRow(self._spf)
        form.addRow(self._dmarc)
        form.addRow(self._dkim)
        form.addRow(self._dnssec)
        form.addRow(self._axfr)
        form.addRow(self._caa)
        self._dkim_sel = QLineEdit("default,google,domainkey,selector1")
        form.addRow("DKIM 选择器", self._dkim_sel)

    def collect_options(self) -> dict:
        checks = []
        if self._spf.isChecked():
            checks.append("SPF")
        if self._dmarc.isChecked():
            checks.append("DMARC")
        if self._dkim.isChecked():
            checks.append("DKIM")
        if self._dnssec.isChecked():
            checks.append("DNSSEC")
        if self._axfr.isChecked():
            checks.append("区域传送")
        if self._caa.isChecked():
            checks.append("CAA")
        return {
            "domain": self._domain.text(),
            "checks": checks,
            "dkim_selectors": self._dkim_sel.text(),
        }
