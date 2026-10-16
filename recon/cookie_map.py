"""Aggregate cookie metadata without retaining cookie values or query strings."""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def _safe_url(value: str) -> str:
    """Keep an origin/path sample only; never store URL credentials, query values or fragments."""
    try:
        parsed = urlsplit(str(value or "").strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parsed.port
        if port and not (
            (parsed.scheme.lower() == "http" and port == 80)
            or (parsed.scheme.lower() == "https" and port == 443)
        ):
            host = f"{host}:{port}"
        return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", "", ""))
    except (TypeError, ValueError, UnicodeError):
        return ""


def build_cookie_map(page_results=None, wordlist_results=None, session_cookies=None, target_url=""):
    """Return a compact cookie identity map and exact event count.

    Repeated Set-Cookie events for the same cookie attributes are aggregated. The map
    retains at most five query-free sample URLs per identity, along with the number of
    observations and distinct URLs, rather than creating a row for every response.
    """
    events = []
    default_url = _safe_url(target_url)

    for result in page_results or []:
        url = _safe_url(getattr(result, "url", "") or default_url) or default_url
        for event in getattr(result, "cookie_events", []) or []:
            if not isinstance(event, dict):
                continue
            events.append({**event, "url": event.get("url") or url, "source": "http-response"})

    for result in wordlist_results or []:
        if not isinstance(result, dict):
            continue
        url = _safe_url(result.get("url") or default_url) or default_url
        for event in result.get("set_cookie_names", []) or []:
            if not isinstance(event, dict):
                continue
            events.append({**event, "url": event.get("url") or url, "source": "content-discovery"})

    for event in session_cookies or []:
        if not isinstance(event, dict):
            continue
        events.append({
            **event,
            "url": event.get("url") or default_url,
            "source": event.get("source") or "manual-browser",
        })

    grouped = {}
    for event in events:
        name = str(event.get("name") or "").strip()
        if not name:
            continue
        safe_url = _safe_url(event.get("url") or default_url) or default_url
        try:
            host = urlsplit(safe_url).hostname or ""
        except ValueError:
            host = ""
        domain = str(event.get("domain") or host).strip().lower().lstrip(".")
        path = str(event.get("path") or "/").strip() or "/"
        secure = bool(event.get("secure"))
        httponly = bool(event.get("httponly"))
        samesite = str(event.get("samesite") or "").strip()
        key = (name, domain, path, secure, httponly, samesite.casefold())
        item = grouped.setdefault(key, {
            "name": name,
            "domain": domain,
            "path": path,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
            "_sources": set(),
            "_urls": set(),
            "observation_count": 0,
        })
        item["observation_count"] += 1
        source = str(event.get("source") or "unknown")
        item["_sources"].add(source)
        if safe_url:
            item["_urls"].add(safe_url)

    result = []
    for item in grouped.values():
        urls = sorted(item.pop("_urls"))
        sources = sorted(item.pop("_sources"), key=str.casefold)
        item["sample_urls"] = urls[:5]
        item["url"] = urls[0] if urls else default_url
        item["url_count"] = len(urls)
        item["sources"] = sources
        item["source"] = ", ".join(sources)
        result.append(item)

    result.sort(key=lambda item: (
        str(item.get("domain", "")).casefold(),
        str(item.get("name", "")).casefold(),
        str(item.get("path", "")),
        str(item.get("source", "")).casefold(),
    ))
    return {
        "cookie_map": result,
        "cookie_observation_count": len(events),
        "cookie_identity_count": len(result),
        "cookie_url_count": sum(int(item.get("url_count", 0)) for item in result),
    }
