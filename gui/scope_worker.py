"""Background worker for explicitly selected subdomain verification."""
from __future__ import annotations

import asyncio

from PySide6.QtCore import QThread, Signal

from recon.scope_verifier import verify_subdomains


class ScopeVerifyWorker(QThread):
    log_message = Signal(str)
    completed = Signal(dict)
    failed = Signal(str)

    def __init__(self, target: str, hosts):
        super().__init__()
        self.target = str(target)
        self.hosts = list(hosts or [])

    def run(self):
        try:
            result = asyncio.run(
                verify_subdomains(
                    self.target,
                    self.hosts,
                    should_stop=self.isInterruptionRequested,
                    on_log=self.log_message.emit,
                )
            )
            self.completed.emit(result)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")

    def stop(self):
        self.requestInterruption()
