"""扫描器抽象基类与统一结果结构。"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class ScanResult:
    success: bool
    title: str
    data: List[Dict[str, Any]] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    summary: str = ""

    def to_text(self) -> str:
        lines = [f"=== {self.title} ===", self.summary, ""]
        for entry in self.logs:
            lines.append(entry)
        for row in self.data:
            lines.append(" | ".join(f"{k}: {v}" for k, v in row.items()))
        return "\n".join(lines)


class BaseScanner(ABC):
    """所有扫描模块的基类，支持进度回调与取消。"""

    name: str = "base"

    def __init__(self) -> None:
        self._cancelled = False
        self._on_progress: Optional[Callable[[int, str], None]] = None
        self._on_log: Optional[Callable[[str], None]] = None

    def bind_callbacks(
        self,
        on_progress: Optional[Callable[[int, str], None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._on_progress = on_progress
        self._on_log = on_log

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def log(self, msg: str) -> None:
        if self._on_log:
            self._on_log(msg)

    def progress(self, percent: int, msg: str = "") -> None:
        if self._on_progress:
            self._on_progress(min(100, max(0, percent)), msg)

    @abstractmethod
    def run(self, options: Dict[str, Any]) -> ScanResult:
        ...
