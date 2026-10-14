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
