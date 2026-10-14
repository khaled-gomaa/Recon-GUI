"""Build safe, source-aware endpoint and parameter inventories."""
from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import parse_qsl, urlsplit


SENSITIVE_NAME_RE = re.compile(r"(?:pass(?:word)?|secret|token|api[_-]?key|auth|session|csrf|xsrf)", re.I)
REVIEW_NAME_RE = re.compile(r"^(?:id|uid|user|account|file|path|url|uri|redirect|next|return|dest|query|search|filter|role|admin|tenant|org|resource|callback)$", re.I)


def _safe_path(value: str) -> str:
    """Strip query values and fragments before storing a location in the inventory."""
    try:
        parsed = urlsplit(value or "")
        path = parsed.path or "/"
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
        return path
    except ValueError:
        return "/"


def _names_from_url(value: str):
    try:
        return [name for name, _value in parse_qsl(urlsplit(value or "").query, keep_blank_values=True) if name]
    except ValueError:
        return []


def _normalize_endpoint(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        if parsed.scheme and parsed.netloc:
            host = parsed.netloc.lower()
            return f"{parsed.scheme.lower()}://{host}{parsed.path or '/'}"
        return parsed.path or value.split("?", 1)[0]
    except ValueError:
        return value.split("?", 1)[0]


def build_endpoint_inventory(
    observations, discovered_routes=None, page_urls=None, forms=None, request_observations=None
):
    """Merge endpoints and attach observed/declaration methods without retaining query values."""
    grouped = defaultdict(lambda: {
        "sources": set(), "locations": set(), "parameters": set(),
        "methods": set(), "statuses": set(), "resource_types": set(),
    })

    def add_record(raw_url, source, location="", method="", status=None, resource_type=""):
        raw_url = str(raw_url or "")
        endpoint = _normalize_endpoint(raw_url)
        if not endpoint:
            return
        item = grouped[endpoint]
        item["sources"].add(str(source or "unknown"))
        safe_location = _safe_path(str(location or ""))
        if safe_location:
            item["locations"].add(safe_location)
        for name in _names_from_url(raw_url):
            item["parameters"].add(name)
        if method:
            item["methods"].add(str(method).upper())
        if status is not None:
            try:
                item["statuses"].add(int(status))
            except (TypeError, ValueError):
                pass
        if resource_type:
            item["resource_types"].add(str(resource_type))

    for record in observations or []:
        add_record(
            record.get("endpoint", ""), record.get("source") or "unknown",
            record.get("location", ""), record.get("method", ""),
        )
    for route in discovered_routes or []:
        add_record(str(route), "discovered-route")
    for url in page_urls or []:
        if _names_from_url(str(url)):
            add_record(str(url), "crawled-page", str(url), "GET")
    for form in forms or []:
        add_record(
            form.get("action", ""), "html-form-action", form.get("page", ""),
            form.get("method", "GET"),
        )
    for observation in request_observations or []:
        add_record(
            observation.get("url", ""), observation.get("source", "browser-network"),
            observation.get("page_url", ""), observation.get("method", ""),
            observation.get("status"), observation.get("resource_type", ""),
        )
        endpoint = _normalize_endpoint(str(observation.get("url", "")))
        if endpoint:
            grouped[endpoint]["parameters"].update(
                str(name) for name in observation.get("parameter_names", []) if str(name).strip()
            )
    return [
        {
            "endpoint": endpoint,
            "sources": sorted(item["sources"]),
            "source_count": len(item["sources"]),
            "locations": sorted(item["locations"])[:20],
            "location_count": len(item["locations"]),
            "parameters": sorted(item["parameters"], key=str.casefold),
            "parameter_count": len(item["parameters"]),
            "methods": sorted(item["methods"]),
            "statuses": sorted(item["statuses"]),
            "resource_types": sorted(item["resource_types"]),
        }
        for endpoint, item in sorted(grouped.items(), key=lambda pair: pair[0].casefold())
    ]


def build_parameter_inventory(
    page_urls, forms, endpoint_observations, discovered_routes=None, candidate_urls=None,
    request_observations=None, historical_urls=None,
):
    """Group names only; values from query strings and form inputs are never retained."""
    grouped = defaultdict(lambda: {"sources": set(), "locations": set(), "methods": set(), "occurrences": 0})
    
    def add(name, source, location, method=""):
        name = str(name or "").strip()
        if not name:
            return
        item = grouped[name]
        item["sources"].add(source)
        safe_location = _safe_path(str(location or ""))
        if safe_location:
            item["locations"].add(safe_location)
        if method:
            item["methods"].add(str(method).upper())
        item["occurrences"] += 1

    for url in page_urls or []:
        for name in _names_from_url(str(url)):
            add(name, "query", str(url), "GET")

    for form in forms or []:
        location = str(form.get("page") or form.get("action") or "")
        method = str(form.get("method") or "GET").upper()
        for name in _names_from_url(str(form.get("action") or "")):
            add(name, "form-action-query", location, method)
        for field in form.get("fields", []) or []:
            add(field.get("name"), "form-field", location, method)

    for observation in endpoint_observations or []:
        raw = str(observation.get("endpoint") or "")
        location = str(observation.get("location") or "")
        source = str(observation.get("source") or "endpoint-query")
        for name in _names_from_url(raw):
            add(name, source, location)

    for route in discovered_routes or []:
        for name in _names_from_url(str(route)):
            add(name, "discovered-route-query", str(route))

    for candidate in candidate_urls or []:
        for name in _names_from_url(str(candidate)):
            add(name, "discovered-link-query", str(candidate))

    for candidate in historical_urls or []:
        for name in _names_from_url(str(candidate)):
            add(name, "historical-archive-query", str(candidate))

    for observation in request_observations or []:
        location = str(observation.get("page_url") or "")
        method = str(observation.get("method") or "")
        for name in _names_from_url(str(observation.get("url") or "")):
            add(name, "browser-network-query", location, method)
        for name in observation.get("parameter_names", []) or []:
            add(name, "browser-network-body-name", location, method)

    result = []
    for name, item in grouped.items():
        if SENSITIVE_NAME_RE.search(name):
            classification = "sensitive-name"
        elif REVIEW_NAME_RE.fullmatch(name):
            classification = "review"
        else:
            classification = "ordinary"
        result.append({
            "name": name,
            "classification": classification,
            "sources": sorted(item["sources"]),
            "source_count": len(item["sources"]),
            "occurrences": item["occurrences"],
            "locations": sorted(item["locations"])[:25],
            "location_count": len(item["locations"]),
            "methods": sorted(item["methods"]),
        })
    return sorted(result, key=lambda item: (-item["occurrences"], item["name"].casefold()))
