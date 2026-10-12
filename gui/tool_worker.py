"""Background runner for explicitly selected external recon tools."""
import threading

from PySide6.QtCore import QThread, Signal
from recon.external_tools import run_tool


class ExternalToolWorker(QThread):
    completed = Signal(dict)
    error = Signal(str)

    def __init__(self, tool: str, target: str, wordlist_path: str | None = None):
        super().__init__()
        self.tool = tool
        self.target = target
        self.wordlist_path = wordlist_path
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        try:
            result = run_tool(
                self.tool, self.target, self.wordlist_path,
                timeout=300, should_stop=self._stop_event.is_set,
            )
            self.completed.emit(result)
        except Exception as exc:
            self.error.emit(f"{type(exc).__name__}: {exc}")
