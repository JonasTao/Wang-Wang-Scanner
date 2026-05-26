#!/usr/bin/env python3
"""
汪汪安全扫描器 — 网络安全信息收集工具
仅用于已获得书面授权的安全测试。
"""
import os
import sys
import warnings

# ----- 高 DPI：必须在 import PyQt5 之前处理 -----
# 系统/Cursor/旧版 Qt 可能设置了 QT_DEVICE_PIXEL_RATIO，会触发弃用警告
for _key in (
    "QT_DEVICE_PIXEL_RATIO",
    "QT_DEVICE_PIXEL_RATIO_2",  # 部分环境的多屏变体
):
    os.environ.pop(_key, None)

if "QT_AUTO_SCREEN_SCALE_FACTOR" not in os.environ:
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from PyQt5.QtCore import QtMsgType, qInstallMessageHandler
from PyQt5.QtWidgets import QApplication
from ui.main_window import MainWindow


def _qt_message_handler(mode, context, message) -> None:
    """过滤已知的 DPI 弃用提示，其余消息照常输出。"""
    text = message or ""
    if "QT_DEVICE_PIXEL_RATIO" in text and "deprecated" in text.lower():
        return
    if mode == QtMsgType.QtDebugMsg:
        return
    stream = sys.stderr
    if mode in (QtMsgType.QtFatalMsg, QtMsgType.QtCriticalMsg):
        stream.write(f"[Qt] {text}\n")
        if mode == QtMsgType.QtFatalMsg:
            raise RuntimeError(text)
    elif mode in (QtMsgType.QtWarningMsg, QtMsgType.QtInfoMsg):
        stream.write(f"{text}\n")


def main() -> int:
    qInstallMessageHandler(_qt_message_handler)
    app = QApplication(sys.argv)
    app.setApplicationName("汪汪安全扫描器")
    win = MainWindow()
    win.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
