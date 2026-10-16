"""Normalize observed and inferred HTTP request intelligence.

This module keeps a strict distinction between runtime evidence and static
inference. A URL found in JavaScript is not presented as an observed request.
"""
from __future__ import annotations

from collections import defaultdict
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _safe_url(url: str) -> str:
    """Strip fragments and query values while retaining parameter names."""
    parts = urlsplit(str(url or "").strip())
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return ""
    query_names = sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True) if name})
    path = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", "", ""))
    return path


def normalize_observation(
    *,
    url: str,
    method: str | None = None,
    source: str = "unknown",
    observed: bool = False,
    content_type: str = "",
    parameter_names=None,
) -> dict | None:
    """Return a safe, report-ready request record."""
    safe = _safe_url(url)
    if not safe:
        return None
    normalized_method = str(method or "UNKNOWN").upper()
    if normalized_method not in _ALLOWED_METHODS:
        normalized_method = "UNKNOWN"
    params = {str(value).strip() for value in (parameter_names or []) if str(value).strip()}
    raw_query = urlsplit(str(url)).query
    params.update(name for name, _ in parse_qsl(raw_query, keep_blank_values=True) if name)
    return {
        "url": safe,
        "method": normalized_method,
        "source": str(source or "unknown"),
        "evidence": "observed" if observed else "inferred",
        "content_type": str(content_type or ""),
        "parameter_names": sorted(params),
    }


def merge_observations(observations) -> list[dict]:
    """Merge observations for the same endpoint/method without retaining values."""
    merged = defaultdict(lambda: {
        "url": "", "method": "UNKNOWN", "sources": set(), "evidence": set(),
        "content_types": set(), "parameter_names": set(),
    })
    for item in observations or []:
        if not isinstance(item, dict):
            continue
        record = normalize_observation(
            url=item.get("url") or item.get("endpoint"),
            method=item.get("method"),
            source=item.get("source", "unknown"),
            observed=item.get("observed", item.get("evidence") == "observed"),
            content_type=item.get("content_type", ""),
            parameter_names=item.get("parameter_names") or item.get("body_parameters"),
        )
        if not record:
            continue
        key = (record["url"], record["method"])
        target = merged[key]
        target["url"] = record["url"]
        target["method"] = record["method"]
        target["sources"].add(record["source"])
        target["evidence"].add(record["evidence"])
        if record["content_type"]:
            target["content_types"].add(record["content_type"])
        target["parameter_names"].update(record["parameter_names"])

    result = []
    for item in merged.values():
        evidence = "observed" if "observed" in item["evidence"] else "inferred"
        result.append({
            "url": item["url"],
            "method": item["method"],
            "sources": sorted(item["sources"]),
            "evidence": evidence,
            "content_types": sorted(item["content_types"]),
            "parameter_names": sorted(item["parameter_names"]),
        })
    return sorted(result, key=lambda x: (x["url"], x["method"]))
