"""Shared, conservative HTTP 429 policy for Recon-GUI crawl phases.

A valid Retry-After is honored up to a configured ceiling. If the server omits
that header, requests are paused using bounded exponential backoff rather than
immediately retrying. Repeated limits stop the remaining active work.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit, urlunsplit


MAX_RETRY_AFTER_SECONDS = 120
MAX_RATE_LIMIT_PAUSES = 3
DEFAULT_FALLBACK_SECONDS = 15.0
MAX_FALLBACK_SECONDS = 120.0


def parse_retry_after(value) -> float | None:
    """Parse Retry-After as delta seconds or an HTTP date; return None if invalid."""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if raw.isdigit():
        try:
            return float(int(raw))
        except (ValueError, OverflowError):
            return None
    try:
        when = parsedate_to_datetime(raw)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


def header_value(headers, name: str) -> str | None:
    """Read a response header from regular dictionaries or case-insensitive mappings."""
    if not headers:
        return None
    try:
        for key, value in headers.items():
            if str(key).lower() == name.lower():
                return str(value)
    except (AttributeError, TypeError, ValueError):
        return None
    return None


def safe_url(value: str) -> str:
    """Strip query strings, fragments, and userinfo from URLs shown in logs."""
    try:
        parsed = urlsplit(str(value or ""))
        host = parsed.hostname or ""
        if not host:
            return parsed.path or "(invalid URL)"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host
        if parsed.port:
            netloc += f":{parsed.port}"
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))
    except (TypeError, ValueError, UnicodeError):
        return "(invalid URL)"


class RateLimitManager:
    """One scan-wide pause/stop state shared by HTTP-based discovery stages.

    The manager is created and used inside the scan's asyncio event loop.
    Requests already in flight when a 429 arrives may finish; waiting request
    tasks block until the common cooldown ends. No proxy rotation or bypass is
    attempted.
    """

    def __init__(
        self,
        *,
        max_pauses: int = MAX_RATE_LIMIT_PAUSES,
        max_retry_after_seconds: float = MAX_RETRY_AFTER_SECONDS,
        fallback_initial_seconds: float = DEFAULT_FALLBACK_SECONDS,
        fallback_max_seconds: float = MAX_FALLBACK_SECONDS,
    ):
        self.max_pauses = max(1, int(max_pauses))
        self.max_retry_after_seconds = max(0.0, float(max_retry_after_seconds))
        self.fallback_initial_seconds = max(0.0, float(fallback_initial_seconds))
        self.fallback_max_seconds = max(self.fallback_initial_seconds, float(fallback_max_seconds))
        self.pause_count = 0
        self.consecutive_pauses = 0
        self.stopped = False
        self.last_delay_seconds = 0.0
        self.last_reason = ""
        self.events: list[dict] = []
        self._loop = None
        self._lock = None
        self._resume_event = None
        self._waiting = False
        self._paused_until = 0.0

    def _ensure_primitives(self):
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
            self._lock = asyncio.Lock()
            self._resume_event = asyncio.Event()
            self._resume_event.set()
        elif self._loop is not loop:
            raise RuntimeError("RateLimitManager must only be used within one asyncio event loop.")

    def _log(self, callback, message: str):
        if callback:
            try:
                callback(message)
            except Exception:
                pass

    def note_success(self) -> None:
        """Reset a sustained 429 streak after ordinary responses resume."""
        if not self.stopped and not self._waiting:
            self.consecutive_pauses = 0

    async def wait_until_ready(self, should_stop=None) -> bool:
        """Gate a new request until the scan-wide cooldown has ended."""
        self._ensure_primitives()
        stop = should_stop or (lambda: False)
        while not self._resume_event.is_set():
            if stop():
                return False
            try:
                await asyncio.wait_for(self._resume_event.wait(), timeout=0.25)
            except asyncio.TimeoutError:
                continue
        return not self.stopped and not stop()

    async def handle_429(
        self,
        headers,
        url: str,
        *,
        on_log=None,
        should_stop=None,
        phase: str = "HTTP",
    ) -> bool:
        """Pause all waiting stages, then resume; return False if the scan must stop."""
        self._ensure_primitives()
        stop = should_stop or (lambda: False)
        loop = asyncio.get_running_loop()
        already_waiting = False
        delay = 0.0
        reason = ""

        async with self._lock:
            if self.stopped:
                return False
            if stop():
                return False
            if self._waiting:
                already_waiting = True
            else:
                retry_after = parse_retry_after(header_value(headers, "Retry-After"))
                if self.consecutive_pauses >= self.max_pauses:
                    self.stopped = True
                    self._resume_event.set()
                    self._log(
                        on_log,
                        f"[429] Repeated rate limits reached the {self.max_pauses}-cooldown safety limit; "
                        f"stopping new requests in {phase}.",
                    )
                    return False

                if retry_after is not None:
                    if retry_after > self.max_retry_after_seconds:
                        self.stopped = True
                        self._resume_event.set()
                        self._log(
                            on_log,
                            f"[429] {safe_url(url)} requested a {retry_after:.0f}s Retry-After, above "
                            f"the {self.max_retry_after_seconds:.0f}s automatic-wait ceiling; "
                            "stopping rather than retrying early.",
                        )
                        return False
                    delay = retry_after
                    reason = "Retry-After"
                else:
                    # A missing header is not a signal to retry immediately. Use cautious backoff.
                    delay = min(
                        self.fallback_initial_seconds * (2 ** self.consecutive_pauses),
                        self.fallback_max_seconds,
                    )
                    reason = "fallback backoff (no valid Retry-After)"

                self.pause_count += 1
                self.consecutive_pauses += 1
                self.last_delay_seconds = delay
                self.last_reason = reason
                self._paused_until = loop.time() + delay
                self._waiting = True
                self._resume_event.clear()
                self.events.append({
                    "phase": str(phase),
                    "url": safe_url(url),
                    "pause_number": self.pause_count,
                    "consecutive_pause": self.consecutive_pauses,
                    "delay_seconds": round(delay, 3),
                    "reason": reason,
                })

        if already_waiting:
            # Coalesce simultaneous 429s into the cooldown already in progress.
            return await self.wait_until_ready(stop)

        self._log(
            on_log,
            f"[429] {phase}: pausing new HTTP requests for {delay:.1f}s ({reason}; "
            f"consecutive cooldown {self.consecutive_pauses}/{self.max_pauses}; "
            f"total cooldowns {self.pause_count}).",
        )
        deadline = loop.time() + delay
        while loop.time() < deadline:
            if stop():
                async with self._lock:
                    self._waiting = False
                    self._resume_event.set()
                return False
            await asyncio.sleep(min(0.25, max(0.0, deadline - loop.time())))

        async with self._lock:
            self._waiting = False
            if stop():
                self._resume_event.set()
                return False
            self._resume_event.set()
        self._log(on_log, f"[429] {phase}: cooldown complete; resuming queued requests.")
        return not self.stopped and not stop()

    def to_dict(self) -> dict:
        return {
            "stopped": bool(self.stopped),
            "cooldowns_applied": int(self.pause_count),
            "consecutive_cooldowns": int(self.consecutive_pauses),
            "last_delay_seconds": float(self.last_delay_seconds),
            "last_reason": self.last_reason,
            "max_cooldowns": self.max_pauses,
            "fallback_initial_seconds": self.fallback_initial_seconds,
            "max_retry_after_seconds": self.max_retry_after_seconds,
            "events": list(self.events),
        }
