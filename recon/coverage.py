"""Source-aware discovery coverage and HTTP request accounting."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit
from typing import Iterable

_STATUS_BUCKETS = {
    "2xx": lambda code: 200 <= code < 300,
    "3xx": lambda code: 300 <= code < 400,
    "4xx": lambda code: 400 <= code < 500,
    "5xx": lambda code: 500 <= code < 600,
}
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _safe_url(value: str) -> str:
    """Remove credentials, query values and fragments from an HTTP URL."""
    try:
        parts = urlsplit(str(value or "").strip())
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} or not parts.hostname:
            return parts.path or "(unknown URL)"
        host = parts.hostname.encode("idna").decode("ascii").lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parts.port
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            host = f"{host}:{port}"
        return urlunsplit((scheme, host, parts.path or "/", "", ""))
    except (TypeError, ValueError, UnicodeError):
        return "(invalid URL)"


def _get(item, key, default=None):
    return item.get(key, default) if isinstance(item, dict) else getattr(item, key, default)


def _code(item):
    try:
        return int(_get(item, "status", 0) or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def _bucket(status):
    for name, predicate in _STATUS_BUCKETS.items():
        if predicate(status):
            return name
    return "unknown" if not status else "other"


def _source_counts(records) -> dict[str, int]:
    counts = Counter()
    for item in records or []:
        sources = item.get("sources") if isinstance(item, dict) else None
        if not sources:
            sources = [item.get("source", "unknown")] if isinstance(item, dict) else ["unknown"]
        counts.update(set(str(source or "unknown") for source in sources))
    return dict(sorted(counts.items(), key=lambda pair: pair[0].casefold()))


@dataclass
class CoverageTracker:
    """Track sanitized response signatures and explicit reasons for partial coverage."""

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
        raw = str(value or "").strip()
        if not raw:
            return False
        method = ""
        candidate = raw
        if " " in raw:
            prefix, rest = raw.split(" ", 1)
            if prefix.upper() in _METHODS and rest.startswith(("http://", "https://")):
                method, candidate = prefix.upper(), rest
        if candidate.startswith(("http://", "https://")):
            candidate = _safe_url(candidate)
        key = f"{method} {candidate}".strip()
        if not key or key in self._seen:
            return False
        self._seen.add(key)
        self.discovered += 1
        self.source_counts[str(source or "unknown")] += 1
        return True

    def add_result(
        self, *, url: str, status: int | None = None, method: str | None = None,
        source: str | None = None, failed: bool = False,
        rate_limited: bool = False, truncated: bool = False,
    ) -> None:
        method_name = str(method or "").upper()
        signature = f"{method_name} {url}" if method_name in _METHODS else str(url or "")
        self.add_candidate(signature, source or "unknown")
        self.crawled += 1
        self.failed += int(bool(failed))
        self.rate_limited += int(bool(rate_limited))
        self.truncated += int(bool(truncated))
        if status is not None:
            try:
                self.status_counts[str(int(status))] += 1
            except (TypeError, ValueError, OverflowError):
                self.status_counts["unknown"] += 1
        if method_name:
            self.method_counts[method_name] += 1

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
        return bool(self.pending or self.failed or self.rate_limited or self.truncated or self.limits)

    @property
    def completion_ratio(self) -> float:
        if self.discovered <= 0:
            return 1.0 if self.crawled == 0 and not self.partial else 0.0
        return max(0.0, min(1.0, self.crawled / self.discovered))

    def merge_sources(self, values: Iterable[tuple[str, str]]) -> None:
        for value, source in values:
            self.add_candidate(value, source)

    def snapshot(self) -> dict:
        return {
            "discovered": self.discovered, "crawled": self.crawled,
            "failed": self.failed, "pending": self.pending,
            "rate_limited": self.rate_limited, "truncated": self.truncated,
            "partial": self.partial, "completion_ratio": round(self.completion_ratio, 4),
            "source_counts": dict(sorted(self.source_counts.items())),
            "status_counts": dict(sorted(self.status_counts.items())),
            "method_counts": dict(sorted(self.method_counts.items())),
            "limits": dict(self.limits), "notes": list(self.notes),
        }


def build_coverage_report(
    *, page_results=None, endpoint_inventory=None, parameter_inventory=None,
    network_observations=None, asset_inventory=None, wordlist_hits=None,
    wordlist_results=None, asset_probe_results=None, passive_sources=None,
    passive_errors=None, historical_urls=None, imported_seed_urls=None,
    wordlist_stats=None, request_intelligence=None, max_pages=0, max_depth=0,
    target_url="", page_limit_reached=None, depth_limit_reached=False,
    stopped_by_user=False, crawler_rate_limited=False, wordlist_rate_limited=False,
    javascript_rate_limited=False, css_rate_limited=False, rate_limit_stopped=False, asset_probe_partial=False,
    asset_probe_rate_limited=False, transport_error_count=0,
    server_error_response_count=0, restricted_response_count=0,
    js_fetch_errors=None, unattempted_js_files=None, truncated_js_files=None,
    response_bodies_truncated=0, content_limit_reached=False,
    seed_import_limit_reached=False, css_summary=None,
):
    """Build a report of observed coverage, sources, configured limits and known gaps.

    A no-known-gaps assessment is not a guarantee that every possible URL exists in
    the inventory. Dynamic, orphaned, authenticated and state-dependent content may
    remain undiscovered even if the observed phases finish without errors.
    """
    pages = list(page_results or [])
    endpoints = list(endpoint_inventory or [])
    parameters = list(parameter_inventory or [])
    requests = list(network_observations or [])
    assets = list(asset_inventory or [])
    hits = list(wordlist_hits or [])
    wordlist_responses = list(wordlist_results or [])
    probes = list(asset_probe_results or [])
    passive = list(passive_sources or [])
    passive_failures = list(passive_errors or [])
    history = list(historical_urls or [])
    seeds = list(imported_seed_urls or [])
    stats = dict(wordlist_stats or {})
    request_models = list(request_intelligence or [])

    status_buckets, status_codes = Counter(), Counter()
    page_transport_failures = 0
    pages_successful_or_redirect = 0
    tracker = CoverageTracker()
    for page in pages:
        status = _code(page)
        status_buckets[_bucket(status)] += 1
        status_codes[str(status) if status else "unknown"] += 1
        page_transport_failures += int(status <= 0)
        pages_successful_or_redirect += int(200 <= status < 400)
        tracker.add_result(
            url=str(_get(page, "url", "")), method="GET", status=status,
            source="http-crawl", failed=status <= 0, rate_limited=status == 429,
            truncated=bool(_get(page, "body_truncated", False)),
        )
    for item in requests:
        status = _code(item)
        tracker.add_result(
            url=str(item.get("url") or ""), method=item.get("method", "UNKNOWN"),
            status=item.get("status"), source=str(item.get("source") or "browser-network"),
            failed=item.get("status") is not None and status <= 0,
            rate_limited=status == 429,
        )
    for item in wordlist_responses:
        status = _code(item)
        tracker.add_result(
            url=str(item.get("url") or ""), method=item.get("method", "GET"),
            status=item.get("status"), source="content-discovery",
            failed=status <= 0, rate_limited=status == 429,
            truncated=bool(item.get("response_truncated")),
        )
    for item in probes:
        status = _code(item)
        tracker.add_result(
            url=str(item.get("url") or ""), method="HEAD", status=item.get("status"),
            source="asset-head", failed=status <= 0, rate_limited=status == 429,
        )

    page_cap = bool(page_limit_reached) if page_limit_reached is not None else bool(max_pages and len(pages) >= int(max_pages))
    css_summary = dict(css_summary or {})
    wordlist_complete = not any(bool(stats.get(key)) for key in (
        "word_limit_reached", "candidate_limit_reached", "path_limit_reached",
        "recursion_depth_limit_reached",
    ))
    if stats.get("rate_limited") or wordlist_rate_limited:
        wordlist_complete = False

    reasons = []
    def gap(condition, message):
        if condition and message not in reasons:
            reasons.append(message)
    gap(stopped_by_user, "Scan was stopped by the user.")
    gap(page_cap, "The page limit was reached; remaining candidates may not have been crawled.")
    gap(depth_limit_reached, "The configured crawl-depth limit prevented following some discovered links.")
    gap(stats.get("word_limit_reached"), "The configured wordlist word cap was reached.")
    gap(stats.get("candidate_limit_reached") or stats.get("path_limit_reached"), "The generated content-discovery path cap was reached.")
    gap(stats.get("recursion_depth_limit_reached"), "Recursive directory discovery reached its configured depth ceiling.")
    gap(crawler_rate_limited, "The page crawler was rate-limited.")
    gap(wordlist_rate_limited or stats.get("rate_limited"), "Content Discovery was rate-limited.")
    gap(javascript_rate_limited, "JavaScript collection was rate-limited.")
    gap(css_rate_limited, "CSS collection was rate-limited.")
    gap(asset_probe_rate_limited, "Asset HEAD checks were rate-limited.")
    gap(transport_error_count, f"{int(transport_error_count)} transport/request errors were observed.")
    gap(server_error_response_count, f"{int(server_error_response_count)} HTTP 5xx responses were observed.")
    gap(restricted_response_count, f"{int(restricted_response_count)} HTTP 401/403 restricted responses were observed.")
    gap(js_fetch_errors, f"{len(js_fetch_errors or [])} JavaScript fetch failures were reported.")
    gap(unattempted_js_files, f"{len(unattempted_js_files or [])} discovered JavaScript files were not attempted.")
    gap(truncated_js_files, f"{len(truncated_js_files or [])} JavaScript files were truncated.")
    gap(response_bodies_truncated or content_limit_reached, "One or more response bodies or parsed items hit a configured size/content limit.")
    gap(seed_import_limit_reached, "The imported seed source hit its configured candidate limit.")
    gap(css_summary.get("status") in {"partial", "error"} or css_summary.get("css_limit_reached"), "CSS discovery was partial, failed, or hit its configured limit.")
    gap(asset_probe_partial, "Asset HEAD checks were partial or hit their configured limit.")
    gap(any(str(item.get("status", "")).lower() in {"partial", "error", "timeout"} for item in passive if isinstance(item, dict)), "One or more passive discovery providers returned partial results or an error.")
    gap(passive_failures, "One or more passive discovery providers failed; see Passive Source Status.")

    for name, value in (
        ("page_limit", page_cap), ("depth_limit", bool(depth_limit_reached)),
        ("wordlist_cap", not wordlist_complete), ("known_coverage_gap", bool(reasons)),
    ):
        if value:
            tracker.mark_limit(name, value)

    endpoint_sources = _source_counts(endpoints)
    asset_sources = _source_counts(assets)
    network_sources = _source_counts(requests)
    historical_hosts = set()
    for candidate in history + seeds:
        try:
            host = (urlsplit(str(candidate)).hostname or "").lower()
            if host:
                historical_hosts.add(host)
        except ValueError:
            pass

    return {
        "target": _safe_url(target_url),
        "assessment": "partial" if reasons else "no-known-gaps-reported",
        "partial": bool(reasons),
        "partial_reasons": reasons,
        "pages": {
            "discovered_and_attempted": len(pages),
            "successful_or_redirect": pages_successful_or_redirect,
            "transport_failed": page_transport_failures,
            "max_pages": int(max_pages or 0), "max_depth": int(max_depth or 0),
            "page_cap_reached": page_cap, "depth_limit_reached": bool(depth_limit_reached),
        },
        "http": {
            "page_status_buckets": dict(status_buckets),
            "page_status_codes": dict(sorted(status_codes.items())),
            "transport_errors": int(transport_error_count or 0),
            "server_error_responses": int(server_error_response_count or 0),
            "restricted_responses": int(restricted_response_count or 0),
        },
        "discovery": {
            "endpoints": len(endpoints), "parameters": len(parameters),
            "browser_request_records": len(requests),
            "request_intelligence_records": len(request_models),
            "observed_request_methods": sum(1 for item in request_models if item.get("evidence") == "observed"),
            "inferred_request_methods": sum(1 for item in request_models if item.get("evidence") != "observed"),
            "asset_references": len(assets), "wordlist_hits": len(hits),
            "wordlist_responses": len(wordlist_responses),
            "historical_url_candidates": len(history), "imported_seed_candidates": len(seeds),
            "passive_providers": len(passive), "historical_hosts": sorted(historical_hosts),
        },
        "sources": {
            "endpoints": endpoint_sources, "assets": asset_sources,
            "network_requests": network_sources,
            "passive": {
                str(item.get("name") or "unknown"): {
                    "status": item.get("status", "unknown"), "count": int(item.get("count", 0) or 0),
                } for item in passive if isinstance(item, dict)
            },
        },
        "wordlist": {
            "enabled": bool(stats.get("enabled", bool(wordlist_responses or hits))),
            "words_loaded": int(stats.get("words_loaded", 0) or 0),
            "candidates_generated": int(stats.get("candidate_count", 0) or 0),
            "responses_recorded": len(wordlist_responses),
            "word_limit_reached": bool(stats.get("word_limit_reached")),
            "candidate_limit_reached": bool(stats.get("candidate_limit_reached")),
            "path_limit_reached": bool(stats.get("path_limit_reached")),
            "recursion_depth_limit_reached": bool(stats.get("recursion_depth_limit_reached")),
            "rate_limited": bool(stats.get("rate_limited") or wordlist_rate_limited),
            "complete_under_configured_limits": wordlist_complete,
        },
        "javascript": {
            "fetch_failures": len(js_fetch_errors or []),
            "unattempted_files": len(unattempted_js_files or []),
            "truncated_files": len(truncated_js_files or []),
            "rate_limited": bool(javascript_rate_limited),
        },
        "request_accounting": {
            key: value for key, value in tracker.snapshot().items()
            if key != "completion_ratio"
        } | {
            "scope": "Sanitized request signatures and response records from enabled phases; not a denominator for every URL that exists on the site."
        },
        "notes": [
            "Coverage measures discovered and attempted data; a no-known-gaps assessment is not proof that every route exists in the inventory.",
            "Orphaned, authenticated, dynamic, generated, state-dependent, or externally linked content can remain undiscovered.",
        ],
    }
