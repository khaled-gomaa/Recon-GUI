"""Normalize observed and inferred HTTP request intelligence without retaining values."""
from __future__ import annotations

from collections import defaultdict
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _safe_url(url: str) -> str:
    """Strip credentials, query values, and fragments while preserving a stable endpoint."""
    try:
        parts = urlsplit(str(url or "").strip())
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} or not parts.hostname:
            return ""
        host = parts.hostname.encode("idna").decode("ascii").lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parts.port
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            host = f"{host}:{port}"
        return urlunsplit((scheme, host, parts.path or "/", "", ""))
    except (TypeError, ValueError, UnicodeError):
        return ""


def _query_names(url: str) -> set[str]:
    try:
        return {name for name, _ in parse_qsl(urlsplit(str(url or "")).query, keep_blank_values=True) if name}
    except (TypeError, ValueError):
        return set()


def normalize_observation(
    *, url: str, method: str | None = None, source: str = "unknown",
    observed: bool = False, content_type: str = "", parameter_names=None,
    query_parameters=None, body_parameters=None, status=None, page="", resource_type="",
) -> dict | None:
    """Return a safe report record; request and response values are never stored."""
    safe = _safe_url(url)
    if not safe:
        return None
    method_name = str(method or "UNKNOWN").strip().upper()
    if method_name not in _ALLOWED_METHODS:
        method_name = "UNKNOWN"
    names = set()
    for values in (parameter_names or [], query_parameters or [], body_parameters or []):
        names.update(str(value).strip() for value in values if str(value).strip())
    names.update(_query_names(url))
    try:
        status_code = int(status) if status is not None else None
    except (TypeError, ValueError, OverflowError):
        status_code = None
    return {
        "url": safe, "method": method_name, "source": str(source or "unknown"),
        "evidence": "observed" if observed else "inferred",
        "content_type": str(content_type or ""), "parameter_names": sorted(names),
        "status": status_code, "page": _safe_url(page) if page else "",
        "resource_type": str(resource_type or ""),
    }


def merge_observations(observations) -> list[dict]:
    """Merge evidence for each endpoint/method; observed traffic takes precedence."""
    merged = defaultdict(lambda: {
        "url": "", "method": "UNKNOWN", "sources": set(), "evidence_levels": set(),
        "content_types": set(), "parameter_names": set(), "status_codes": set(),
        "initiating_pages": set(), "resource_types": set(),
    })
    for item in observations or []:
        if not isinstance(item, dict):
            continue
        record = normalize_observation(
            url=item.get("url") or item.get("endpoint"), method=item.get("method"),
            source=item.get("source", "unknown"),
            observed=bool(item.get("observed")) or str(item.get("evidence", "")).lower() == "observed",
            content_type=item.get("content_type", ""),
            parameter_names=item.get("parameter_names"),
            query_parameters=item.get("query_parameters"),
            body_parameters=item.get("body_parameters"),
            status=item.get("status"),
            page=item.get("page") or item.get("location") or item.get("initiator_page") or "",
            resource_type=item.get("resource_type", ""),
        )
        if not record:
            continue
        item_key = (record["url"], record["method"])
        target = merged[item_key]
        target["url"] = record["url"]
        target["method"] = record["method"]
        target["sources"].add(record["source"])
        target["evidence_levels"].add(record["evidence"])
        if record["content_type"]:
            target["content_types"].add(record["content_type"])
        target["parameter_names"].update(record["parameter_names"])
        if record["status"] is not None:
            target["status_codes"].add(record["status"])
        if record["page"]:
            target["initiating_pages"].add(record["page"])
        if record["resource_type"]:
            target["resource_types"].add(record["resource_type"])

    result = []
    for item in merged.values():
        levels = sorted(item["evidence_levels"])
        result.append({
            "url": item["url"], "method": item["method"],
            "sources": sorted(item["sources"]),
            "evidence": "observed" if "observed" in levels else "inferred",
            "evidence_levels": levels,
            "content_types": sorted(item["content_types"]),
            "parameter_names": sorted(item["parameter_names"]),
            "status_codes": sorted(item["status_codes"]),
            "initiating_pages": sorted(item["initiating_pages"]),
            "resource_types": sorted(item["resource_types"]),
        })
    return sorted(result, key=lambda record: (record["url"], record["method"]))
