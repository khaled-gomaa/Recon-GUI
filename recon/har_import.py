"""Safe, read-only import of browser/Burp HTTP Archive (HAR 1.2) metadata.

Request/response bodies and credential values are inspected only in memory to derive
field names; they are never returned or stored. URLs lose query strings and fragments.
Only entries whose hostname matches the operator's current target are imported.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

MAX_HAR_BYTES = 50 * 1024 * 1024
MAX_HAR_ENTRIES = 20000


def _safe_url(raw_url: str):
    """Return a credential-free HTTP(S) URL without query values or fragments, plus host."""
    try:
        parsed = urlsplit(str(raw_url or ""))
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").rstrip(".").lower()
        if scheme not in {"http", "https"} or not hostname:
            return "", ""
        hostname = hostname.encode("idna").decode("ascii")
        port = parsed.port
        if ":" in hostname:  # IPv6 literal
            netloc = f"[{hostname}]"
        else:
            netloc = hostname
        if port is not None and not (
            (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        ):
            netloc += f":{port}"
        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, "", "")), hostname
    except (TypeError, ValueError, UnicodeError):
        return "", ""


def _headers(headers):
    result = {}
    for item in headers or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip().lower()
        if name:
            # Only callers should query allowlisted headers; never serialize this map.
            result[name] = str(item.get("value") or "")
    return result


def _parameter_names_from_json(value, depth=0):
    if depth > 20:
        return set()
    names = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).strip():
                names.add(str(key).strip())
            names.update(_parameter_names_from_json(child, depth + 1))
    elif isinstance(value, list):
        for child in value:
            names.update(_parameter_names_from_json(child, depth + 1))
    return names


def _request_body_names(request):
    post_data = request.get("postData") or {}
    if not isinstance(post_data, dict):
        return []
    names = {
        str(item.get("name") or "").strip()
        for item in post_data.get("params", []) or []
        if isinstance(item, dict) and str(item.get("name") or "").strip()
    }
    text = post_data.get("text")
    mime = str(post_data.get("mimeType") or "").lower()
    if isinstance(text, str) and text:
        try:
            if "json" in mime or text.lstrip().startswith(("{", "[")):
                names.update(_parameter_names_from_json(json.loads(text)))
            elif "x-www-form-urlencoded" in mime or not mime:
                names.update(
                    name for name, _value in parse_qsl(text, keep_blank_values=True) if name
                )
            elif "multipart/form-data" in mime:
                names.update(re.findall(r'name="([^"]+)"', text))
        except (ValueError, TypeError, RecursionError):
            pass
    return sorted(name for name in names if name)


def _cookie_metadata(cookie, url, source):
    if not isinstance(cookie, dict):
        return None
    name = str(cookie.get("name") or "").strip()
    if not name:
        return None
    return {
        "url": url,
        "name": name,
        "domain": str(cookie.get("domain") or ""),
        "path": str(cookie.get("path") or "/"),
        "secure": bool(cookie.get("secure", False)),
        "httponly": bool(cookie.get("httpOnly", cookie.get("httponly", False))),
        "samesite": str(cookie.get("sameSite", cookie.get("samesite", "")) or ""),
        "source": source,
    }


def load_har_file(
    file_path: str,
    target_url: str,
    *,
    max_entries: int = MAX_HAR_ENTRIES,
    max_file_bytes: int = MAX_HAR_BYTES,
) -> dict:
    """Import in-scope HAR metadata without sending network requests or retaining secrets."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"HAR file not found: {path}")
    if path.stat().st_size > max(1, int(max_file_bytes)):
        raise ValueError(
            f"HAR file is larger than the {max_file_bytes}-byte import limit; export a smaller selection."
        )
    safe_target, target_host = _safe_url(target_url)
    if not safe_target or not target_host:
        raise ValueError("The current target must be a valid HTTP(S) URL before importing HAR.")

    try:
        document = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse HAR/JSON file: {type(exc).__name__}") from exc
    log = document.get("log", {}) if isinstance(document, dict) else {}
    entries = log.get("entries", []) if isinstance(log, dict) else []
    if not isinstance(entries, list):
        raise ValueError("Invalid HAR structure: log.entries must be a list.")

    limit = max(1, min(int(max_entries), MAX_HAR_ENTRIES))
    truncated = len(entries) > limit
    page_urls = {}
    for page in log.get("pages", []) or []:
        if not isinstance(page, dict):
            continue
        page_id = str(page.get("id") or "")
        url, host = _safe_url((page.get("pageTimings") or {}).get("url") or page.get("url") or "")
        if page_id and url and host == target_host:
            page_urls[page_id] = url

    observations = {}
    cookie_map = {}
    entries_imported = 0
    skipped_out_of_scope = 0
    skipped_invalid = 0

    for entry in entries[:limit]:
        if not isinstance(entry, dict):
            skipped_invalid += 1
            continue
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        if not isinstance(request, dict) or not isinstance(response, dict):
            skipped_invalid += 1
            continue
        safe_request_url, request_host = _safe_url(request.get("url", ""))
        if not safe_request_url:
            skipped_invalid += 1
            continue
        if request_host != target_host:
            skipped_out_of_scope += 1
            continue

        method = str(request.get("method") or "UNKNOWN").strip().upper() or "UNKNOWN"
        parsed_raw = urlsplit(str(request.get("url") or ""))
        query_names = {
            name for name, _value in parse_qsl(parsed_raw.query, keep_blank_values=True) if name
        }
        query_names.update(
            str(item.get("name") or "").strip()
            for item in request.get("queryString", []) or []
            if isinstance(item, dict) and str(item.get("name") or "").strip()
        )
        body_names = _request_body_names(request)
        req_headers = _headers(request.get("headers"))
        response_headers = _headers(response.get("headers"))
        referer, referer_host = _safe_url(req_headers.get("referer", ""))
        if referer_host != target_host:
            referer = ""
        page_ref = str(entry.get("pageref") or "")
        initiating_page = referer or page_urls.get(page_ref, safe_target)
        resource_type = str(entry.get("_resourceType") or entry.get("resourceType") or "")
        status = response.get("status")
        try:
            status = int(status) if status not in (None, "") else None
        except (TypeError, ValueError):
            status = None
        response_content = response.get("content") or {}
        content_type = str(
            response_content.get("mimeType") or response_headers.get("content-type") or ""
        )
        record = {
            "url": safe_request_url,
            "method": method,
            "status": status,
            "source": "burp-har-import",
            "page": initiating_page,
            "resource_type": resource_type,
            "query_parameters": sorted(query_names),
            "body_parameters": body_names,
            "content_type": content_type,
        }
        key = (record["url"], method, initiating_page, record["source"])
        if key not in observations:
            observations[key] = record
        else:
            current = observations[key]
            current["query_parameters"] = sorted(set(current["query_parameters"]) | query_names)
            current["body_parameters"] = sorted(set(current["body_parameters"]) | set(body_names))
            if status is not None:
                current["status"] = status
            if content_type:
                current["content_type"] = content_type
            if resource_type and not current["resource_type"]:
                current["resource_type"] = resource_type
        entries_imported += 1

        for cookie in request.get("cookies", []) or []:
            item = _cookie_metadata(cookie, safe_request_url, "burp-har-request")
            if item:
                cookie_map[(item["url"], item["name"], item["domain"], item["path"], item["source"])] = item
        for cookie in response.get("cookies", []) or []:
            item = _cookie_metadata(cookie, safe_request_url, "burp-har-response")
            if item:
                cookie_map[(item["url"], item["name"], item["domain"], item["path"], item["source"])] = item

    warnings = []
    if truncated:
        warnings.append(
            f"HAR contained {len(entries)} entries; only the first {limit} were processed."
        )
    if skipped_out_of_scope:
        warnings.append(
            f"Ignored {skipped_out_of_scope} entries whose hostname did not match the current target."
        )
    return {
        "network_observations": sorted(
            observations.values(),
            key=lambda item: (item["url"], item["method"], item["page"], item["source"]),
        ),
        "cookie_map": sorted(
            cookie_map.values(),
            key=lambda item: (item["url"], item["name"], item["source"]),
        ),
        "summary": {
            "file_name": path.name,
            "entry_count": len(entries),
            "entries_considered": min(len(entries), limit),
            "entries_imported": entries_imported,
            "unique_requests": len(observations),
            "cookie_metadata_count": len(cookie_map),
            "skipped_out_of_scope": skipped_out_of_scope,
            "skipped_invalid": skipped_invalid,
            "truncated": truncated,
            "max_entries": limit,
            "warnings": warnings,
        },
    }


def merge_har_into_report(
    report: dict,
    imported_observations,
    imported_cookies,
    import_summaries,
) -> dict:
    """Overlay sanitized HAR metadata onto a fresh scan report without changing scan pages."""
    from copy import deepcopy
    from recon.parameter_intelligence import build_parameter_inventory

    merged = deepcopy(report or {})
    observations = {}
    for record in (merged.get("network_observations", []) or []) + list(imported_observations or []):
        if not isinstance(record, dict):
            continue
        safe_record = {
            "url": str(record.get("url") or ""),
            "method": str(record.get("method") or "UNKNOWN").upper(),
            "status": record.get("status"),
            "source": str(record.get("source") or "unknown"),
            "page": str(record.get("page") or ""),
            "resource_type": str(record.get("resource_type") or ""),
            "query_parameters": sorted(set(str(v) for v in record.get("query_parameters", []) or [] if str(v))),
            "body_parameters": sorted(set(str(v) for v in record.get("body_parameters", []) or [] if str(v))),
            "content_type": str(record.get("content_type") or ""),
        }
        if not safe_record["url"]:
            continue
        key = (
            safe_record["url"], safe_record["method"],
            safe_record["page"], safe_record["source"],
        )
        current = observations.get(key)
        if current is None:
            observations[key] = safe_record
        else:
            current["query_parameters"] = sorted(
                set(current["query_parameters"]) | set(safe_record["query_parameters"])
            )
            current["body_parameters"] = sorted(
                set(current["body_parameters"]) | set(safe_record["body_parameters"])
            )
            if safe_record["status"] is not None:
                current["status"] = safe_record["status"]
            if safe_record["content_type"]:
                current["content_type"] = safe_record["content_type"]
            if safe_record["resource_type"] and not current["resource_type"]:
                current["resource_type"] = safe_record["resource_type"]
    merged_observations = sorted(
        observations.values(),
        key=lambda item: (item["url"], item["method"], item["source"], item["page"]),
    )
    merged["network_observations"] = merged_observations

    cookies = {}
    for item in (merged.get("cookie_map", []) or []) + list(imported_cookies or []):
        if not isinstance(item, dict) or not str(item.get("name") or "").strip():
            continue
        safe_cookie = {
            "url": str(item.get("url") or ""),
            "name": str(item.get("name") or ""),
            "domain": str(item.get("domain") or ""),
            "path": str(item.get("path") or "/"),
            "secure": bool(item.get("secure", False)),
            "httponly": bool(item.get("httponly", False)),
            "samesite": str(item.get("samesite") or ""),
            "source": str(item.get("source") or "unknown"),
        }
        key = (
            safe_cookie["url"], safe_cookie["name"], safe_cookie["domain"],
            safe_cookie["path"], safe_cookie["source"],
        )
        cookies[key] = safe_cookie
    merged["cookie_map"] = sorted(
        cookies.values(),
        key=lambda item: (item["url"], item["name"], item["source"]),
    )

    # Extend existing endpoint rows rather than rebuilding away static, historical, or
    # form observations that may not exist in the runtime network inventory.
    endpoints = {}
    for existing in merged.get("endpoint_inventory", []) or []:
        if not isinstance(existing, dict) or not existing.get("endpoint"):
            continue
        item = deepcopy(existing)
        item["sources"] = set(str(v) for v in item.get("sources", []) or [])
        item["methods"] = set(str(v).upper() for v in item.get("methods", []) or [])
        item["parameters"] = set(str(v) for v in item.get("parameters", []) or [])
        item["locations"] = set(str(v) for v in item.get("locations", []) or [])
        item["statuses"] = set(item.get("statuses", []) or [])
        item["resource_types"] = set(item.get("resource_types", []) or [])
        endpoints[str(item["endpoint"])] = item
    for record in imported_observations or []:
        endpoint = str(record.get("url") or "")
        if not endpoint:
            continue
        item = endpoints.setdefault(endpoint, {
            "endpoint": endpoint, "sources": set(), "source_count": 0,
            "locations": set(), "location_count": 0,
            "parameters": set(), "parameter_count": 0,
            "methods": set(), "statuses": set(), "resource_types": set(),
        })
        for field, values in (
            ("sources", [record.get("source", "burp-har-import")]),
            ("methods", [record.get("method", "UNKNOWN")]),
            ("parameters", list(record.get("query_parameters", []) or []) + list(record.get("body_parameters", []) or [])),
            ("locations", [record.get("page", "")]),
            ("resource_types", [record.get("resource_type", "")]),
        ):
            item[field].update(str(value) for value in values if str(value))
        if record.get("status") is not None:
            try:
                item["statuses"].add(int(record["status"]))
            except (TypeError, ValueError):
                pass
    merged["endpoint_inventory"] = []
    for endpoint, item in sorted(endpoints.items(), key=lambda pair: pair[0].casefold()):
        normalized = dict(item)
        for field in ("sources", "methods", "parameters", "locations", "statuses", "resource_types"):
            normalized[field] = sorted(item.get(field, set()))
        normalized["source_count"] = len(normalized["sources"])
        normalized["location_count"] = len(normalized["locations"])
        normalized["parameter_count"] = len(normalized["parameters"])
        merged["endpoint_inventory"].append(normalized)
    merged["endpoints"] = [item["endpoint"] for item in merged["endpoint_inventory"]]

    imported_parameters = build_parameter_inventory(
        [], [], [], network_observations=list(imported_observations or [])
    )
    parameter_map = {
        str(item.get("name")): deepcopy(item)
        for item in merged.get("parameters", []) or []
        if item.get("name")
    }
    for incoming in imported_parameters:
        name = incoming["name"]
        existing = parameter_map.get(name)
        if existing is None:
            parameter_map[name] = incoming
            continue
        existing["sources"] = sorted(set(existing.get("sources", []) or []) | set(incoming.get("sources", []) or []))
        existing["methods"] = sorted(set(existing.get("methods", []) or []) | set(incoming.get("methods", []) or []))
        existing["locations"] = sorted(set(existing.get("locations", []) or []) | set(incoming.get("locations", []) or []))[:25]
        existing["occurrences"] = int(existing.get("occurrences", 0)) + int(incoming.get("occurrences", 0))
        existing["source_count"] = len(existing["sources"])
        existing["location_count"] = len(existing["locations"])
    merged["parameters"] = sorted(
        parameter_map.values(),
        key=lambda item: (-int(item.get("occurrences", 0)), str(item.get("name", "")).casefold()),
    )
    merged["parameter_count"] = len(merged["parameters"])

    summaries = [dict(item) for item in (import_summaries or [])]
    merged["har_import_summary"] = {
        "imports": summaries,
        "files_imported": len(summaries),
        "entries_seen": sum(int(item.get("entry_count", 0) or 0) for item in summaries),
        "entries_imported": sum(int(item.get("entries_imported", 0) or 0) for item in summaries),
        "unique_requests": sum(
            int(item.get("unique_requests", 0) or 0) for item in summaries
        ),
        "truncated": any(bool(item.get("truncated")) for item in summaries),
        "warnings": [warning for item in summaries for warning in item.get("warnings", []) or []],
    }
    return merged
