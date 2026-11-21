"""Background QThread worker utilities for non-blocking forensic operations."""

from __future__ import annotations

from typing import Any, Callable
from PySide6.QtCore import QThread, Signal


class ForensicTaskWorker(QThread):
    """Runs long acquisition, hashing, transfer, or AI tasks off the UI thread."""

    finished_ok = Signal(object)
    failed = Signal(str)
    progress = Signal(int, int, str)

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self) -> None:
        try:
            result = self._fn(*self._args, **self._kwargs)
            self.finished_ok.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))
