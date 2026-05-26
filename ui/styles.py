"""可爱风格全局样式。"""

CUTE_STYLE = """
QMainWindow, QWidget {
    background-color: #FFF5F8;
    color: #5D4E6D;
    font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
    font-size: 13px;
}
QGroupBox {
    border: 2px dashed #FFB7C5;
    border-radius: 12px;
    margin-top: 14px;
    padding-top: 18px;
    background-color: #FFFFFF;
    font-weight: bold;
    color: #E87A90;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 16px;
    padding: 0 8px;
    background-color: #FFFFFF;
}
QLineEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {
    border: 2px solid #FFD6E0;
    border-radius: 8px;
    padding: 6px 10px;
    background: #FFFBFC;
    selection-background-color: #FFB7C5;
}
QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
    border-color: #FF8FAB;
}
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #FFB7C5, stop:1 #FF8FAB);
    color: white;
    border: none;
    border-radius: 10px;
    padding: 8px 18px;
    font-weight: bold;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #FFC9D4, stop:1 #FF9EB8);
}
QPushButton:pressed {
    background: #E86B8A;
}
QPushButton#stopBtn {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #B8C5E8, stop:1 #8FA8FF);
}
QPushButton#secondaryBtn {
    background: #FFE8EE;
    color: #E87A90;
    border: 2px solid #FFB7C5;
}
QListWidget {
    border: 2px solid #FFD6E0;
    border-radius: 10px;
    background: #FFFBFC;
    outline: none;
}
QListWidget::item {
    padding: 10px 12px;
    border-radius: 8px;
    margin: 2px 6px;
}
QListWidget::item:selected {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #FFB7C5, stop:1 #FFC9A8);
    color: white;
    font-weight: bold;
}
QListWidget::item:hover:!selected {
    background: #FFE8EE;
}
QProgressBar {
    border: 2px solid #FFD6E0;
    border-radius: 8px;
    text-align: center;
    background: #FFFBFC;
    height: 22px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #FFB7C5, stop:1 #A8E6CF);
    border-radius: 6px;
}
QTabWidget::pane {
    border: 2px solid #FFD6E0;
    border-radius: 10px;
    background: #FFFFFF;
}
QTabBar::tab {
    background: #FFE8EE;
    border: 2px solid #FFD6E0;
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    padding: 8px 16px;
    margin-right: 4px;
    color: #E87A90;
}
QTabBar::tab:selected {
    background: #FFFFFF;
    font-weight: bold;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 2px solid #FFB7C5;
    background: white;
}
QCheckBox::indicator:checked {
    background: #FF8FAB;
    border-color: #FF8FAB;
}
QScrollBar:vertical {
    border: none;
    background: #FFF0F3;
    width: 10px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: #FFB7C5;
    border-radius: 5px;
    min-height: 30px;
}
QLabel#titleLabel {
    font-size: 22px;
    font-weight: bold;
    color: #E87A90;
}
QLabel#subtitleLabel {
    color: #B8A9C9;
    font-size: 12px;
}
"""
