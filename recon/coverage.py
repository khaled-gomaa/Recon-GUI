"""Coverage accounting for full-discovery scans.

The crawler should never claim that a target was completely discovered when a
configured cap, rate limit, parser truncation, or request failure prevented it.
This module is intentionally UI/report agnostic so the same accounting can be
used by the desktop view, TXT/CSV/HTML reports, and future persistence.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class CoverageTracker:
    """Track discovered candidates and why they were or were not processed."""

    discovered: int = 0
    crawled: int = 0
    failed: int = 0
    pending: int = 0
    rate_limited: int = 0
    truncated: int = 0
    source_counts: Counter = field(default_factory=Counter)
    status_counts: Counter = field(default_factory=Counter)
    method_counts: Counter = field(default_factory=Counter)
    limits: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    _seen: set[str] = field(default_factory=set, repr=False)

    def add_candidate(self, value: str, source: str = "unknown") -> bool:
        """Register a candidate once; return True when it is new."""
        key = str(value or "").strip()
        if not key or key in self._seen:
            return False
        self._seen.add(key)
        self.discovered += 1
        self.source_counts[str(source or "unknown")] += 1
        return True

    def add_result(
        self,
        *,
        url: str,
        status: int | None = None,
        method: str | None = None,
        source: str | None = None,
        failed: bool = False,
        rate_limited: bool = False,
        truncated: bool = False,
    ) -> None:
        """Record an observed request/result without retaining sensitive values."""
        self.add_candidate(url, source or "crawl")
        self.crawled += 1
        if failed:
            self.failed += 1
        if rate_limited:
            self.rate_limited += 1
        if truncated:
            self.truncated += 1
        if status is not None:
            self.status_counts[str(int(status))] += 1
        if method:
            self.method_counts[str(method).upper()] += 1

    def mark_pending(self, count: int = 1) -> None:
        self.pending = max(0, self.pending + int(count))

    def mark_limit(self, name: str, value, *, partial: bool = True) -> None:
        self.limits[str(name)] = value
        if partial:
            self.add_note(f"limit:{name}={value}")

    def add_note(self, note: str) -> None:
        note = str(note or "").strip()
        if note and note not in self.notes:
            self.notes.append(note)

    @property
    def partial(self) -> bool:
        """Whether any known condition means coverage is incomplete."""
        return bool(
            self.pending
            or self.failed
            or self.rate_limited
            or self.truncated
            or self.limits
        )

    @property
    def completion_ratio(self) -> float:
        """Return a conservative 0..1 ratio of discovered candidates processed."""
        if self.discovered <= 0:
            return 1.0 if self.crawled == 0 and not self.partial else 0.0
        return max(0.0, min(1.0, self.crawled / self.discovered))

    def merge_sources(self, values: Iterable[tuple[str, str]]) -> None:
        """Bulk-register ``(candidate, source)`` pairs."""
        for value, source in values:
            self.add_candidate(value, source)

    def snapshot(self) -> dict:
        return {
            "discovered": self.discovered,
            "crawled": self.crawled,
            "failed": self.failed,
            "pending": self.pending,
            "rate_limited": self.rate_limited,
            "truncated": self.truncated,
            "partial": self.partial,
            "completion_ratio": round(self.completion_ratio, 4),
            "source_counts": dict(sorted(self.source_counts.items())),
            "status_counts": dict(sorted(self.status_counts.items())),
            "method_counts": dict(sorted(self.method_counts.items())),
            "limits": dict(self.limits),
            "notes": list(self.notes),
        }
