"""Adaptive request pacing for authorized reconnaissance.

This module deliberately does NOT try to bypass HTTP 429 responses.
It honors Retry-After, backs off when servers signal pressure, and supports
an explicit unlimited-page mode at the crawl-policy level. A page-count limit
is a safety/UX setting, not a rate-limit mechanism.
"""
from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
import math
import random


@dataclass
class RateLimitDecision:
    wait_seconds: float = 0.0
    should_stop: bool = False
    reason: str = ""


class AdaptiveRateController:
    """Coordinate pacing after 429/503 responses without attempting evasion."""

    def __init__(
        self,
        *,
        base_delay: float = 0.0,
        max_delay: float = 120.0,
        max_consecutive_limits: int = 5,
        jitter: float = 0.15,
        rng=None,
    ):
        self.base_delay = max(0.0, float(base_delay))
        self.max_delay = max(0.0, float(max_delay))
        self.max_consecutive_limits = max(1, int(max_consecutive_limits))
        self.jitter = max(0.0, min(float(jitter), 0.5))
        self._rng = rng or random.Random()
        self.consecutive_limits = 0
        self.current_delay = self.base_delay

    @staticmethod
    def parse_retry_after(value) -> float | None:
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
        """Gradually return to the configured normal request rate."""
        self.consecutive_limits = 0
        self.current_delay = self.base_delay

    def on_rate_limit(self, retry_after=None, *, status=429) -> RateLimitDecision:
        """Return a compliant wait/stop decision for a server rate-limit signal."""
        self.consecutive_limits += 1
        if self.consecutive_limits > self.max_consecutive_limits:
            return RateLimitDecision(
                should_stop=True,
                reason=f"HTTP {status} rate limit repeated too many times",
            )

        server_wait = self.parse_retry_after(retry_after)
        # Exponential backoff is only used when the server did not provide a wait.
        # When Retry-After exists, the server's value takes precedence.
        if server_wait is not None:
            wait = server_wait
        else:
            exponent = self.consecutive_limits - 1
            wait = max(self.base_delay, self.base_delay * math.pow(2, exponent))
            if wait <= 0:
                wait = min(self.max_delay, math.pow(2, exponent))

        wait = min(self.max_delay, max(0.0, wait))
        if self.jitter and wait > 0:
            wait = min(self.max_delay, wait + self._rng.uniform(0.0, wait * self.jitter))

        self.current_delay = wait
        return RateLimitDecision(
            wait_seconds=wait,
            reason=f"HTTP {status}; honoring server pacing instead of bypassing the limit",
        )


@dataclass(frozen=True)
class CrawlLimits:
    """Explicit crawl limits. ``max_pages=0`` means unlimited pages."""

    max_pages: int = 0
    max_depth: int = 0

    @property
    def unlimited_pages(self) -> bool:
        return self.max_pages <= 0

    def allows_page(self, crawled_pages: int) -> bool:
        return self.unlimited_pages or crawled_pages < self.max_pages

    def allows_depth(self, depth: int) -> bool:
        return self.max_depth <= 0 or depth <= self.max_depth
