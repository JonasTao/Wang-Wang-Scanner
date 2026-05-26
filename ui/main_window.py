"""主窗口 — 侧边导航 + 小狗陪伴 + 功能面板。"""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QListWidget, QListWidgetItem, QStackedWidget, QLabel, QMessageBox,
)

from ui.styles import CUTE_STYLE
from ui.dog_companion import DogCompanion
from ui.panels import PANELS


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("🐕🐱 汪汪安全扫描器 — 信息收集工具")
        self.setMinimumSize(1100, 720)
        self.resize(1280, 800)
        self.setStyleSheet(CUTE_STYLE)

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setSpacing(0)
        root.setContentsMargins(12, 12, 12, 12)

        # 左侧栏
        left = QWidget()
        left.setFixedWidth(250)
        left_layout = QVBoxLayout(left)

        brand = QLabel("🐾 汪汪 & 喵喵")
        brand.setObjectName("titleLabel")
        sub = QLabel("网络安全信息收集")
        sub.setObjectName("subtitleLabel")
        left_layout.addWidget(brand)
        left_layout.addWidget(sub)
        left_layout.addSpacing(8)

        self._nav = QListWidget()
        self._nav.setSpacing(4)
        for panel_cls in PANELS:
            item = QListWidgetItem(f"{panel_cls.panel_icon}  {panel_cls.panel_title}")
            self._nav.addItem(item)
        self._nav.currentRowChanged.connect(self._switch_panel)
        left_layout.addWidget(self._nav)

        self._dog = DogCompanion()
        left_layout.addWidget(self._dog, alignment=Qt.AlignCenter)
        left_layout.addStretch()

        warn = QLabel("⚠️ 仅用于授权测试")
        warn.setWordWrap(True)
        warn.setStyleSheet("color: #B8A9C9; font-size: 11px;")
        left_layout.addWidget(warn)

        root.addWidget(left)

        # 右侧内容
        right = QWidget()
        right_layout = QVBoxLayout(right)
        self._stack = QStackedWidget()

        def dog_cb(mood, msg):
            self._dog.set_mood(mood)
            if msg:
                self._dog.say(msg)

        for panel_cls in PANELS:
            self._stack.addWidget(panel_cls(dog_callback=dog_cb))

        right_layout.addWidget(self._stack)
        root.addWidget(right, stretch=1)

        self._nav.setCurrentRow(0)

    def _switch_panel(self, index: int) -> None:
        if 0 <= index < self._stack.count():
            self._stack.setCurrentIndex(index)
            self._dog.set_mood("idle")

    def closeEvent(self, event) -> None:
        reply = QMessageBox.question(
            self, "退出",
            "汪汪喵~ 确定要退出吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()
