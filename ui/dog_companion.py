"""小狗与小猫互动陪伴 — 打闹动画 + 对话气泡。"""
import random
import math
from PyQt5.QtCore import Qt, QTimer, QRectF, pyqtSignal
from PyQt5.QtGui import QPainter, QColor, QPen, QBrush
from PyQt5.QtWidgets import QWidget, QLabel


class DogCompanion(QWidget):
    """小狗 + 小猫互动打闹；扫描时追跑，完成时一起休息。"""

    bark = pyqtSignal(str)

    MESSAGES_IDLE = [
        "汪汪~ 喵喵~ 今天扫哪里？",
        "小猫别挠啦！",
        "主人在做信息收集呢~",
        "只在授权范围扫描哦！",
    ]
    MESSAGES_SCAN = [
        "汪汪！发现目标啦！",
        "喵喵！线索在这里！",
        "追呀追呀~扫描中！",
        "打闹归打闹，扫描很认真！",
    ]
    MESSAGES_DONE = [
        "扫描完成！击掌~ 🐾",
        "汪汪喵~ 报告好啦！",
        "累了，一起晒太阳吧~",
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(220, 250)
        self._frame = 0
        self._dog_blink = False
        self._cat_blink = False
        self._mood = "idle"
        self._phase = 0.0

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._animate)
        self._timer.start(90)

        self._msg_timer = QTimer(self)
        self._msg_timer.timeout.connect(self._random_message)
        self._msg_timer.start(9000)

        self._bubble = QLabel(self)
        self._bubble.setWordWrap(True)
        self._bubble.setAlignment(Qt.AlignCenter)
        self._bubble.setStyleSheet("""
            QLabel {
                background: white;
                border: 2px solid #FFB7C5;
                border-radius: 12px;
                padding: 6px;
                color: #E87A90;
                font-size: 10px;
            }
        """)
        self._bubble.setGeometry(8, 4, 204, 48)
        self._bubble.setText(random.choice(self.MESSAGES_IDLE))

    def set_mood(self, mood: str) -> None:
        self._mood = mood
        pools = {
            "idle": self.MESSAGES_IDLE,
            "scan": self.MESSAGES_SCAN,
            "done": self.MESSAGES_DONE,
        }
        self._bubble.setText(random.choice(pools.get(mood, self.MESSAGES_IDLE)))
        self.update()

    def say(self, text: str) -> None:
        self._bubble.setText(text)
        self.bark.emit(text)

    def _animate(self) -> None:
        self._frame = (self._frame + 1) % 120
        speed = 0.12 if self._mood == "scan" else 0.06
        self._phase = (self._phase + speed) % (2 * math.pi)
        if self._frame % 28 == 0:
            self._dog_blink = True
            self._cat_blink = True
        elif self._frame % 30 == 0:
            self._dog_blink = False
            self._cat_blink = False
        self.update()

    def _random_message(self) -> None:
        pools = {
            "idle": self.MESSAGES_IDLE,
            "scan": self.MESSAGES_SCAN,
            "done": self.MESSAGES_DONE,
        }
        self._bubble.setText(random.choice(pools.get(self._mood, self.MESSAGES_IDLE)))

    def _fight_offset(self) -> tuple:
        """打闹位移：狗左、猫右，周期性靠近挥爪。"""
        t = self._phase
        if self._mood == "done":
            return 0.0, 0.0, 0.0, 0.0
        chase = math.sin(t * 2) * 8
        pounce = max(0, math.sin(t * 3)) * 12
        dog_x = -chase - pounce * 0.5
        cat_x = chase + pounce * 0.5
        dog_paw = max(0, math.sin(t * 4)) * 15 if self._mood == "scan" else max(0, math.sin(t * 2.5)) * 8
        cat_paw = max(0, math.sin(t * 4 + 1.5)) * 15 if self._mood == "scan" else max(0, math.sin(t * 2.5 + 1)) * 8
        return dog_x, cat_x, dog_paw, cat_paw

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        dog_dx, cat_dx, dog_paw, cat_paw = self._fight_offset()

        # 草地
        p.setBrush(QBrush(QColor(200, 240, 210, 120)))
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(QRectF(10, 200, 200, 42), 10, 10)

        self._draw_dog(p, 72 + dog_dx, 175, dog_paw)
        self._draw_cat(p, 148 + cat_dx, 172, cat_paw)

        # 打闹特效：抓痕 / 爱心
        if self._mood != "done" and (dog_paw > 5 or cat_paw > 5):
            p.setPen(QPen(QColor(255, 180, 100, 180), 2))
            cx = 110 + (dog_dx + cat_dx) / 2
            p.drawLine(int(cx - 8), 130, int(cx + 8), 125)
            p.drawLine(int(cx), 128, int(cx + 5), 118)
        if self._mood == "done":
            p.setPen(QPen(QColor("#FF8FAB"), 2))
            p.drawText(int(100), 125, "♥")

        p.end()

    def _draw_dog(self, p: QPainter, cx: float, cy: float, paw: float) -> None:
        wag = math.sin(self._frame * 0.4) * 12
        bounce = abs(math.sin(self._phase * 2)) * 4 if self._mood == "scan" else 0
        cy -= bounce

        p.setBrush(QColor(255, 200, 210, 60))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QRectF(cx - 28, cy + 18, 56, 12))

        p.setPen(QPen(QColor("#D4A574"), 3, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(int(cx + 22 + wag), int(cy - 8), 22, 28, 30 * 16, 100 * 16)

        p.setBrush(QBrush(QColor("#F5C87A")))
        p.setPen(QPen(QColor("#E8B86A"), 2))
        p.drawEllipse(QRectF(cx - 26, cy - 12, 52, 38))
        p.setBrush(QBrush(QColor("#FFE8B8")))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QRectF(cx - 14, cy, 28, 22))

        p.setBrush(QBrush(QColor("#F5C87A")))
        p.setPen(QPen(QColor("#E8B86A"), 2))
        p.drawEllipse(QRectF(cx - 22, cy - 38, 44, 36))
        p.setBrush(QBrush(QColor("#E8A85A")))
        p.drawEllipse(QRectF(cx - 26, cy - 42, 14, 18))
        p.drawEllipse(QRectF(cx + 12, cy - 42, 14, 18))

        if self._dog_blink:
            p.setPen(QPen(QColor("#5D4E6D"), 2))
            p.drawLine(int(cx - 10), int(cy - 26), int(cx - 4), int(cy - 26))
            p.drawLine(int(cx + 4), int(cy - 26), int(cx + 10), int(cy - 26))
        else:
            p.setBrush(QBrush(QColor("#5D4E6D")))
            p.setPen(Qt.NoPen)
            p.drawEllipse(QRectF(cx - 11, int(cy - 28), 7, 9))
            p.drawEllipse(QRectF(cx + 4, int(cy - 28), 7, 9))

        p.setBrush(QBrush(QColor("#5D4E6D")))
        p.drawEllipse(QRectF(cx - 4, cy - 18, 8, 6))
        p.setPen(QPen(QColor("#E87A90"), 2))
        p.setBrush(Qt.NoBrush)
        p.drawArc(int(cx - 6), int(cy - 14), 12, 8, 200 * 16, 140 * 16)

        # 挥爪
        if paw > 2:
            p.setPen(QPen(QColor("#F5C87A"), 3))
            p.drawLine(int(cx + 24), int(cy - 5), int(cx + 24 + paw), int(cy - 20 - paw * 0.3))

    def _draw_cat(self, p: QPainter, cx: float, cy: float, paw: float) -> None:
        arch = math.sin(self._phase * 2.5) * 6 if self._mood != "done" else 0
        bounce = abs(math.sin(self._phase * 2 + 1)) * 4 if self._mood == "scan" else 0
        cy -= bounce - arch

        p.setBrush(QColor(200, 210, 255, 60))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QRectF(cx - 24, cy + 18, 48, 11))

        # 尾巴（竖起）
        tail_wag = math.sin(self._frame * 0.5) * 10
        p.setPen(QPen(QColor("#B8A9C9"), 3, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(int(cx + 18 + tail_wag), int(cy - 25), 20, 35, 0, 90 * 16)

        p.setBrush(QBrush(QColor("#C9B8E8")))
        p.setPen(QPen(QColor("#A898D8"), 2))
        p.drawEllipse(QRectF(cx - 22, cy - 10, 44, 34))

        p.drawEllipse(QRectF(cx - 20, cy - 36, 40, 32))

        # 尖耳朵
        p.setBrush(QBrush(QColor("#B8A8E0")))
        from PyQt5.QtGui import QPolygonF
        from PyQt5.QtCore import QPointF
        left_ear = QPolygonF([QPointF(cx - 18, cy - 34), QPointF(cx - 8, cy - 52), QPointF(cx - 2, cy - 32)])
        right_ear = QPolygonF([QPointF(cx + 2, cy - 32), QPointF(cx + 8, cy - 52), QPointF(cx + 18, cy - 34)])
        p.drawPolygon(left_ear)
        p.drawPolygon(right_ear)

        if self._cat_blink:
            p.setPen(QPen(QColor("#5D4E6D"), 2))
            p.drawLine(int(cx - 9), int(cy - 24), int(cx - 3), int(cy - 24))
            p.drawLine(int(cx + 3), int(cy - 24), int(cx + 9), int(cy - 24))
        else:
            p.setBrush(QBrush(QColor("#5D4E6D")))
            p.setPen(Qt.NoPen)
            p.drawEllipse(QRectF(cx - 10, int(cy - 26), 6, 8))
            p.drawEllipse(QRectF(cx + 4, int(cy - 26), 6, 8))
            # 猫眼竖瞳
            p.setBrush(QBrush(QColor("#A8E6CF")))
            p.drawEllipse(QRectF(cx - 8, int(cy - 25), 2, 5))
            p.drawEllipse(QRectF(cx + 6, int(cy - 25), 2, 5))

        p.setBrush(QBrush(QColor("#E8A0C0")))
        p.drawEllipse(QRectF(cx - 3, cy - 16, 6, 5))
        p.setPen(QPen(QColor("#E87A90"), 2))
        p.drawLine(int(cx - 8), int(cy - 14), int(cx - 16), int(cy - 16))
        p.drawLine(int(cx + 8), int(cy - 14), int(cx + 16), int(cy - 16))

        # 挥爪
        if paw > 2:
            p.setPen(QPen(QColor("#C9B8E8"), 3))
            p.drawLine(int(cx - 22), int(cy - 5), int(cx - 22 - paw), int(cy - 18 - paw * 0.3))
