"""Compliant adaptive pacing and explicit unlimited crawl policy.

The controller never attempts to evade HTTP 429/503. It honors Retry-After, applies
exponential backoff when the server omits that header, and stops after repeated
consecutive signals rather than hammering the target.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import math
import random


@dataclass(frozen=True)
class RateLimitDecision:
    wait_seconds: float = 0.0
    should_stop: bool = False
    reason: str = ""


class AdaptiveRateController:
    """Stateful per-origin backoff controller shared by crawler phases."""

    def __init__(
        self,
        *,
        base_delay: float = 0.0,
        max_delay: float = 60.0,
        max_consecutive_limits: int = 5,
        jitter: float = 0.0,
        rng=None,
    ):
        self.base_delay = max(0.0, float(base_delay))
        self.max_delay = max(1.0, float(max_delay))
        self.max_consecutive_limits = max(1, int(max_consecutive_limits))
        self.jitter = max(0.0, min(float(jitter), 0.5))
        self._rng = rng or random.Random()
        self.consecutive_limits = 0
        self.current_delay = self.base_delay
        self._success_streak = 0

    @staticmethod
    def parse_retry_after(value) -> float | None:
        """Parse Retry-After seconds or an HTTP-date; None means missing/invalid."""
        if value is None:
            return None
        value = str(value).strip()
        if not value:
            return None
        if value.isdigit():
            return max(0.0, float(int(value)))
        try:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None

    def on_success(self) -> None:
        """Reset the consecutive-limit counter and gradually restore normal pacing."""
        self.consecutive_limits = 0
        self._success_streak += 1
        if self._success_streak < 5:
            return
        self._success_streak = 0
        self.current_delay = max(self.base_delay, self.current_delay * 0.7)

    def on_rate_limit(self, retry_after=None, *, status: int = 429) -> RateLimitDecision:
        """Choose a wait without capping a server-specified Retry-After.

        When Retry-After exists, keep honoring it even if the server repeats 429s.
        When no usable Retry-After exists, exponential backoff is bounded and the
        affected phase eventually stops instead of retrying indefinitely.
        """
        self._success_streak = 0
        self.consecutive_limits += 1
        server_wait = self.parse_retry_after(retry_after)
        if server_wait is None and self.consecutive_limits > self.max_consecutive_limits:
            return RateLimitDecision(
                should_stop=True,
                reason=f"HTTP {status} rate limit repeated without usable Retry-After",
            )

        fallback = min(
            self.max_delay,
            max(1.0, self.base_delay) * math.pow(2, self.consecutive_limits - 1),
        )
        # Retry-After is a minimum wait, not a cap. A zero/short value combined with
        # repeated 429s still receives backoff to avoid a rapid request loop.
        wait = fallback if server_wait is None else max(server_wait, fallback)
        if server_wait is not None and server_wait > 0:
            # Never reduce the server's requested wait to max_delay.
            wait = max(server_wait, min(self.max_delay, fallback))
        if self.jitter and wait > 0:
            wait += self._rng.uniform(0.0, wait * self.jitter)

        # Pace requests more slowly after a limit while permitting recovery after success.
        self.current_delay = min(
            self.max_delay,
            max(self.base_delay, self.current_delay * 2 if self.current_delay else 1.0),
        )
        return RateLimitDecision(
            wait_seconds=wait,
            reason=f"HTTP {status}; honor Retry-After/backoff and reduce request pressure",
        )


@dataclass(frozen=True)
class CrawlLimits:
    """Explicit limits; a zero page/depth value means unlimited."""

    max_pages: int = 0
    max_depth: int = 0

    @property
    def unlimited_pages(self) -> bool:
        return self.max_pages <= 0

    @property
    def unlimited_depth(self) -> bool:
        return self.max_depth <= 0

    def allows_page(self, crawled_pages: int) -> bool:
        return self.unlimited_pages or int(crawled_pages) < self.max_pages

    def allows_depth(self, depth: int) -> bool:
        return self.unlimited_depth or int(depth) <= self.max_depth
