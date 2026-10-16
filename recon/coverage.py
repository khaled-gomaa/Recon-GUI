"""Coverage accounting for the recon pipeline.

This module does not claim that a web application can be crawled 100%.
Instead it reports what the crawler discovered, attempted, completed, and
skipped, together with the discovery sources that produced each item.
"""
from __future__ import annotations

from collections import Counter
from urllib.parse import urlsplit


_STATUS_BUCKETS = {
    "2xx": lambda status: 200 <= status < 300,
    "3xx": lambda status: 300 <= status < 400,
    "4xx": lambda status: 400 <= status < 500,
    "5xx": lambda status: 500 <= status < 600,
}


def _status_bucket(status):
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "unknown"
    for name, predicate in _STATUS_BUCKETS.items():
        if predicate(code):
            return name
    return "other"


def _host(value: str) -> str:
    try:
        return (urlsplit(str(value or "")).hostname or "").lower()
    except ValueError:
        return ""


def build_coverage_report(
    *,
    page_results=None,
    endpoint_inventory=None,
    parameter_inventory=None,
    network_observations=None,
    asset_inventory=None,
    wordlist_hits=None,
    passive_sources=None,
    historical_urls=None,
    imported_seed_urls=None,
    wordlist_stats=None,
    max_pages=0,
    target_url="",
):
    """Return a stable, UI/export-friendly coverage snapshot.

    Counts are intentionally additive by category rather than pretending that
    pages + endpoints + files represent one universal denominator.
    """
    pages = list(page_results or [])
    endpoints = list(endpoint_inventory or [])
    parameters = list(parameter_inventory or [])
    requests = list(network_observations or [])
    assets = list(asset_inventory or [])
    hits = list(wordlist_hits or [])
    sources = list(passive_sources or [])
    history = list(historical_urls or [])
    seeds = list(imported_seed_urls or [])
    stats = dict(wordlist_stats or {})

    statuses = Counter(_status_bucket(getattr(item, "status", None)) for item in pages)
    status_codes = Counter()
    for item in pages:
        try:
            status_codes[str(int(getattr(item, "status", 0)))] += 1
        except (TypeError, ValueError):
            status_codes["unknown"] += 1

    discovered_hosts = sorted({
        host for value in history + seeds
        for host in [_host(value)] if host
    })

    pages_attempted = len(pages)
    pages_ok = sum(1 for item in pages if 200 <= int(getattr(item, "status", 0) or 0) < 400)
    failed_pages = max(0, pages_attempted - pages_ok)
    cap_reached = bool(max_pages and pages_attempted >= int(max_pages))

    wordlist_complete = not any(bool(stats.get(key)) for key in (
        "word_limit_reached", "candidate_limit_reached", "path_limit_reached"
    ))
    if stats.get("rate_limited"):
        wordlist_complete = False

    return {
        "target": target_url,
        "pages": {
            "discovered_and_attempted": pages_attempted,
            "successful_or_redirect": pages_ok,
            "failed": failed_pages,
            "max_pages": int(max_pages or 0),
            "page_cap_reached": cap_reached,
        },
        "http": {
            "status_buckets": dict(statuses),
            "status_codes": dict(sorted(status_codes.items())),
        },
        "discovery": {
            "endpoints": len(endpoints),
            "parameters": len(parameters),
            "browser_requests": len(requests),
            "assets": len(assets),
            "wordlist_hits": len(hits),
            "historical_urls": len(history),
            "imported_seed_urls": len(seeds),
            "passive_sources": len(sources),
            "historical_hosts": discovered_hosts,
        },
        "wordlist": {
            "words_loaded": int(stats.get("words_loaded", 0) or 0),
            "candidates_generated": int(stats.get("candidate_count", 0) or 0),
            "word_limit_reached": bool(stats.get("word_limit_reached")),
            "candidate_limit_reached": bool(stats.get("candidate_limit_reached")),
            "path_limit_reached": bool(stats.get("path_limit_reached")),
            "rate_limited": bool(stats.get("rate_limited")),
            "complete_under_configured_limits": wordlist_complete,
        },
        "notes": [
            "Coverage is a measurement of discovered/attempted data, not proof that every application route exists in the crawl.",
            "Dynamic, authenticated, orphaned, generated, or state-dependent content can remain undiscovered.",
        ],
    }
