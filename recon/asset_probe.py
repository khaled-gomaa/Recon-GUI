"""Bounded metadata checks for same-origin asset references.

Only HEAD is used. This phase never downloads response bodies or follows redirects,
and refuses external origins so session credentials cannot be sent to a CDN or sibling host.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import aiohttp

MAX_ASSET_PROBES = 5000
MAX_RESPONSE_HEADERS = 100


def _origin(url: str):
    try:
        parsed = urlsplit(url or "")
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
        if scheme not in {"http", "https"} or not host:
            return None
        return scheme, host, port
    except (TypeError, ValueError):
        return None


def _safe_url(url: str) -> str:
    parsed = urlsplit(url or "")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", ""))


def _query_parameter_names(url: str) -> list[str]:
    try:
        return sorted({name for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True) if name})
    except ValueError:
        return []


def _retry_after_seconds(value: str | None):
    if not value:
        return None
    value = str(value).strip()
    if value.isdigit():
        return float(int(value))
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


async def probe_asset_references(
    target_url: str,
    assets,
    *,
    cookie_jar=None,
    request_headers=None,
    should_stop=None,
    on_log=None,
    max_assets: int = 500,
    timeout: int = 8,
    delay_ms: int = 200,
) -> dict:
    """Check status/headers of unique referenced URLs using HEAD requests only.

    Every accepted request must match the target's exact HTTP origin (scheme, hostname,
    and port). Query values are used only in-memory for the HEAD request, while the
    returned record uses a query-free URL and parameter names only.
    """
    stop = should_stop or (lambda: False)
    log = on_log or (lambda _message: None)
    target_origin = _origin(target_url)
    if not target_origin:
        raise ValueError("target_url must be a valid HTTP(S) URL.")

    selected = []
    seen = set()
    skipped_out_of_origin = 0
    for item in assets or []:
        if not isinstance(item, dict):
            continue
        raw_url = str(item.get("request_url") or item.get("url") or "").strip()
        if not raw_url:
            continue
        parsed = urlsplit(raw_url)
        if parsed.username or parsed.password or _origin(raw_url) != target_origin:
            skipped_out_of_origin += 1
            continue
        safe_url = _safe_url(raw_url)
        if safe_url in seen:
            continue
        seen.add(safe_url)
        selected.append({
            "request_url": raw_url,
            "url": safe_url,
            "kind": str(item.get("kind") or "resource"),
            "extension": str(item.get("extension") or ""),
            "query_parameter_names": _query_parameter_names(raw_url),
        })

    max_assets = max(1, min(int(max_assets or 1), MAX_ASSET_PROBES))
    total_candidates = len(selected)
    limit_reached = total_candidates > max_assets
    selected = selected[:max_assets]
    delay_ms = max(0, min(int(delay_ms), 86_400_000))
    timeout = max(1, min(int(timeout), 30))
    safe_headers = {
        str(key): str(value) for key, value in (request_headers or {}).items()
        if str(key).lower() in {"authorization", "accept-language"}
        and "\r" not in str(value) and "\n" not in str(value)
    }
    # Always serialize HEAD checks. This keeps pressure low and makes Retry-After
    # handling deterministic; the phase can be interrupted between any two assets.
    connector = aiohttp.TCPConnector(limit=1, ssl=True)
    client_timeout = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 5))
    results = []
    completed = 0
    rate_limited = False
    rate_limited_stop = False
    pause_count = 0

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=client_timeout,
        headers={
            "User-Agent": "Recon-GUI/3.1 (asset metadata check; authorized use)",
            **safe_headers,
        },
        cookie_jar=cookie_jar,
    ) as session:
        for item in selected:
            if stop() or rate_limited_stop:
                break
            if delay_ms:
                await asyncio.sleep(delay_ms / 1000)
            if stop():
                break
            record = {
                "url": item["url"],
                "method": "HEAD",
                "kind": item["kind"],
                "extension": item["extension"],
                "query_parameter_names": item["query_parameter_names"],
                "status": None,
                "content_type": "",
                "content_length": None,
                "allow": "",
                "server": "",
                "last_modified": "",
                "set_cookie_names": [],
                "result": "not checked",
                "error": "",
            }
            try:
                async with session.head(
                    item["request_url"], allow_redirects=False,
                    headers=None,
                ) as response:
                    record["status"] = int(response.status)
                    record["content_type"] = str(response.headers.get("Content-Type", ""))
                    record["content_length"] = response.headers.get("Content-Length")
                    record["allow"] = str(response.headers.get("Allow", ""))
                    record["server"] = str(response.headers.get("Server", ""))
                    record["last_modified"] = str(response.headers.get("Last-Modified", ""))
                    record["set_cookie_names"] = sorted({
                        str(cookie_name)
                        for cookie_name in response.cookies.keys()
                    })
                    record["result"] = (
                        "HEAD supported"
                        if 200 <= response.status < 400
                        else "HEAD unsupported" if response.status in {405, 501}
                        else "HTTP response"
                    )
                    if response.status == 429:
                        rate_limited = True
                        retry_after = _retry_after_seconds(response.headers.get("Retry-After"))
                        pause_count += 1
                        if (
                            retry_after is None
                            or retry_after > 120
                            or pause_count > 3
                        ):
                            rate_limited_stop = True
                            record["result"] = "rate limited; phase stopped safely"
                            log(
                                f"[Assets] {item['url']} returned HTTP 429 without an acceptable "
                                "Retry-After. Stopping asset checks rather than bypassing the limit."
                            )
                        else:
                            record["result"] = "rate limited; compliant cooldown applied"
                            log(
                                f"[Assets] HTTP 429; pausing for {retry_after:.1f}s as requested "
                                f"(cooldown {pause_count}/3)."
                            )
                            await asyncio.sleep(retry_after)
                    # Do not follow redirects. Redirect destinations are separate scope decisions.
                    response.release()
            except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, ValueError) as exc:
                record["result"] = "request failed"
                record["error"] = type(exc).__name__
            results.append(record)
            completed += 1
            try:
                log(f"[Assets] HEAD [{record['status'] if record['status'] is not None else 'ERR'}] {record['url']}")
            except Exception:
                pass
            if rate_limited_stop:
                break

    interrupted = bool(stop())
    unattempted = max(0, len(selected) - completed)
    partial = bool(limit_reached or rate_limited or rate_limited_stop or interrupted or unattempted)
    return {
        "results": results,
        "summary": {
            "enabled": True,
            "unique_same_origin_candidates": total_candidates,
            "selected_candidates": len(selected),
            "requests_completed": completed,
            "skipped_out_of_origin": skipped_out_of_origin,
            "limit": max_assets,
            "limit_reached": limit_reached,
            "rate_limited": rate_limited,
            "rate_limited_stop": rate_limited_stop,
            "stopped_by_user": interrupted,
            "unattempted": unattempted,
            "partial": partial,
            "method": "HEAD",
        },
    }
