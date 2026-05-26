from PyQt5.QtWidgets import QLineEdit, QCheckBox, QFormLayout
from scanners.weak_service import WeakServiceScanner
from ui.base_panel import BaseScanPanel


class WeakPanel(BaseScanPanel):
    scanner_cls = WeakServiceScanner
    panel_title = "弱配置检测"
    panel_icon = "⚠️"

    def build_options(self, form: QFormLayout) -> None:
        self._target = QLineEdit()
        form.addRow("目标 IP/域名", self._target)
        self._redis = QCheckBox("Redis 未授权")
        self._redis.setChecked(True)
        self._mongo = QCheckBox("MongoDB")
        self._mongo.setChecked(True)
        self._es = QCheckBox("Elasticsearch")
        self._es.setChecked(True)
        self._docker = QCheckBox("Docker API")
        self._docker.setChecked(True)
        self._ftp = QCheckBox("FTP")
        self._mem = QCheckBox("Memcached")
        form.addRow(self._redis)
        form.addRow(self._mongo)
        form.addRow(self._es)
        form.addRow(self._docker)
        form.addRow(self._ftp)
        form.addRow(self._mem)

    def collect_options(self) -> dict:
        checks = []
        if self._redis.isChecked():
            checks.append("Redis 未授权")
        if self._mongo.isChecked():
            checks.append("MongoDB")
        if self._es.isChecked():
            checks.append("Elasticsearch")
        if self._docker.isChecked():
            checks.append("Docker API")
        if self._ftp.isChecked():
            checks.append("FTP")
        if self._mem.isChecked():
            checks.append("Memcached")
        return {"target": self._target.text(), "checks": checks}
