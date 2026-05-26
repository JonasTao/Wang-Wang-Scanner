from PyQt5.QtWidgets import QLineEdit, QComboBox, QCheckBox, QFormLayout

from scanners.personnel import PersonnelScanner
from ui.base_panel import BaseScanPanel


class PersonnelPanel(BaseScanPanel):
    scanner_cls = PersonnelScanner
    panel_title = "人员信息搜集"
    panel_icon = "👤"

    def build_options(self, form: QFormLayout) -> None:
        self._domain = QLineEdit()
        self._domain.setPlaceholderText("example.com")
        form.addRow("目标域名", self._domain)

        self._mode = QComboBox()
        self._mode.addItems(["综合", "邮箱探测", "DNS/WHOIS", "仅DNS", "页面信息"])
        form.addRow("搜集模式", self._mode)

        self._chk_email = QCheckBox("邮箱前缀探测")
        self._chk_email.setChecked(True)
        self._chk_dns = QCheckBox("DNS/MX/TXT 记录")
        self._chk_dns.setChecked(True)
        self._chk_page = QCheckBox("页面元信息提取")
        self._chk_page.setChecked(True)
        form.addRow(self._chk_email)
        form.addRow(self._chk_dns)
        form.addRow(self._chk_page)

        self._prefixes = QLineEdit()
        self._prefixes.setPlaceholderText("ceo,cto,dev 逗号分隔")
        form.addRow("自定义邮箱前缀", self._prefixes)

        self._smtp = QCheckBox("SMTP 验证 (较慢)")
        form.addRow(self._smtp)

    def collect_options(self) -> dict:
        return {
            "domain": self._domain.text(),
            "mode": self._mode.currentText(),
            "check_email": self._chk_email.isChecked(),
            "check_whois_dns": self._chk_dns.isChecked(),
            "check_pages": self._chk_page.isChecked(),
            "custom_prefixes": self._prefixes.text(),
            "verify_smtp": self._smtp.isChecked(),
        }
