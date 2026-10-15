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


def _method_evidence_kind(source: str) -> str:
    """Describe what supports a method without overstating inferred/static evidence."""
    source = str(source or "").strip().lower()
    if any(token in source for token in (
        "manual-browser", "browser-network", "burp-har", "har-import", "runtime-network",
    )):
        return "runtime-observed"
    if "html-form-declaration" in source:
        return "form-declared"
    if any(token in source for token in (
        "javascript-fetch", "javascript-axios", "javascript-xhr", "javascript-ajax",
        "javascript-static",
    )):
        return "static-js-inference"
    if source in {"crawled-page", "http-crawl"}:
        return "crawler-observed"
    if "wayback" in source or "historical" in source:
        return "historical-url-hint"
    return "source-hint"


def build_endpoint_inventory(observations, discovered_routes=None, page_urls=None):
    """Merge endpoint observations while keeping query values and method evidence separate."""
    grouped = defaultdict(lambda: {
        "sources": set(), "locations": set(), "parameters": set(), "methods": set(),
        "method_evidence": defaultdict(lambda: {"evidence": set(), "sources": set()}),
    })

    def add_method_evidence(item, method, source):
        method = str(method or "").strip().upper()
        if not method:
            return
        item["methods"].add(method)
        evidence = _method_evidence_kind(source)
        item["method_evidence"][method]["evidence"].add(evidence)
        item["method_evidence"][method]["sources"].add(str(source or "unknown"))

    for record in observations or []:
        raw = record.get("endpoint", "")
        endpoint = _normalize_endpoint(raw)
        if not endpoint:
            continue
        item = grouped[endpoint]
        source = str(record.get("source") or "unknown")
        item["sources"].add(source)
        add_method_evidence(item, record.get("method", ""), source)
        location = _safe_path(str(record.get("location") or ""))
        if location:
            item["locations"].add(location)
        for name in _names_from_url(raw):
            item["parameters"].add(name)
        for key in ("query_parameters", "body_parameters", "parameter_names"):
            item["parameters"].update(
                str(name).strip() for name in (record.get(key) or []) if str(name).strip()
            )

    for route in discovered_routes or []:
        endpoint = _normalize_endpoint(str(route))
        if endpoint:
            grouped[endpoint]["sources"].add("discovered-route")
            for name in _names_from_url(str(route)):
                grouped[endpoint]["parameters"].add(name)

    for url in page_urls or []:
        if _names_from_url(str(url)):
            endpoint = _normalize_endpoint(str(url))
            item = grouped[endpoint]
            item["sources"].add("crawled-page")
            item["locations"].add(_safe_path(str(url)))
            item["parameters"].update(_names_from_url(str(url)))
            # These are URLs actually fetched by the crawler, not static method guesses.
            add_method_evidence(item, "GET", "crawled-page")

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
            "method_evidence": [
                {
                    "method": method,
                    "evidence": sorted(details["evidence"]),
                    "sources": sorted(details["sources"]),
                }
                for method, details in sorted(item["method_evidence"].items())
            ],
        }
        for endpoint, item in sorted(grouped.items(), key=lambda pair: pair[0].casefold())
    ]


def build_parameter_inventory(
    page_urls, forms, endpoint_observations, discovered_routes=None, candidate_urls=None,
    network_observations=None,
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
        method = str(observation.get("method") or "").upper()
        for name in _names_from_url(raw):
            add(name, source, location, method)
        for name in observation.get("query_parameters", []) or []:
            add(name, source + "-query", location, method)
        for name in observation.get("body_parameters", []) or []:
            add(name, source + "-body", location, method)

    for route in discovered_routes or []:
        for name in _names_from_url(str(route)):
            add(name, "discovered-route-query", str(route))

    for candidate in candidate_urls or []:
        for name in _names_from_url(str(candidate)):
            add(name, "discovered-link-query", str(candidate))

    for observation in network_observations or []:
        location = str(observation.get("page") or observation.get("url") or "")
        method = str(observation.get("method") or "").upper()
        source = str(observation.get("source") or "browser-network")
        for name in observation.get("query_parameters", []) or []:
            add(name, source + "-query", location, method)
        for name in observation.get("body_parameters", []) or []:
            add(name, source + "-body", location, method)

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
