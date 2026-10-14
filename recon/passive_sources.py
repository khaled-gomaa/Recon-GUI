"""Bounded passive recon sources (Certificate Transparency and Wayback CDX)."""
from __future__ import annotations
from urllib.parse import urlparse
import requests

USER_AGENT = "Recon-GUI/3.0 (passive research; authorized use)"
# crt.sh results are parsed completely. Wayback's request is larger than the old
# 300-URL query; reaching this ceiling is explicitly marked as partial.
MAX_HISTORICAL_URLS = 10000


def collect_passive(target: str, timeout: int = 12, on_log=None) -> dict:
    """Query public passive indexes only; discovered hosts are never probed."""
    parsed = urlparse((target or "").strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be a valid HTTP(S) URL")
    root = parsed.hostname.lower().strip(".")
    log = on_log or (lambda _message: None)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json,text/plain,*/*"})
    subdomains, historical_urls, errors = set(), set(), []
    try:
        response = session.get("https://crt.sh/", params={"q": f"%.{root}", "output": "json"},
                               timeout=max(3, min(int(timeout), 20)))
        if response.status_code == 200:
            try:
                rows = response.json()
            except ValueError:
                rows = []
            for row in rows if isinstance(rows, list) else []:
                for name in str(row.get("name_value") or "").splitlines():
                    name = name.strip().lower().lstrip("*.").rstrip(".")
                    if name == root or name.endswith("." + root):
                        subdomains.add(name)
            log(f"[Passive] Certificate Transparency returned {len(subdomains)} hostnames.")
        else:
            errors.append(f"crt.sh HTTP {response.status_code}")
    except (requests.RequestException, ValueError) as exc:
        errors.append(f"crt.sh: {type(exc).__name__}: {exc}")
    try:
        response = session.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": f"{root}/*", "output": "json", "fl": "original",
                    "filter": "statuscode:200", "collapse": "urlkey", "limit": str(MAX_HISTORICAL_URLS)},
            timeout=max(3, min(int(timeout), 20)))
        if response.status_code == 200:
            try:
                rows = response.json()
            except ValueError:
                rows = []
            for row in rows[1:] if isinstance(rows, list) and rows else []:
                value = row[0] if isinstance(row, list) and row else ""
                host = (urlparse(value).hostname or "").lower()
                if value.startswith(("http://", "https://")) and (host == root or host.endswith("." + root)):
                    historical_urls.add(value)
                if len(historical_urls) >= MAX_HISTORICAL_URLS:
                    break
            if len(historical_urls) >= MAX_HISTORICAL_URLS:
                log(
                    f"[Passive] Wayback reached the {MAX_HISTORICAL_URLS}-URL request ceiling; "
                    "results may be partial."
                )
            else:
                log(f"[Passive] Wayback returned {len(historical_urls)} historical URLs.")
        else:
            errors.append(f"Wayback CDX HTTP {response.status_code}")
    except (requests.RequestException, ValueError) as exc:
        errors.append(f"Wayback CDX: {type(exc).__name__}: {exc}")
    finally:
        session.close()
    return {
        "passive_subdomains": sorted(subdomains), "historical_urls": sorted(historical_urls),
        "passive_sources": [
            {"name": "crt.sh", "status": "partial" if any(e.startswith("crt.sh") for e in errors) else "queried", "count": len(subdomains)},
            {"name": "Wayback CDX", "status": "partial" if any(e.startswith("Wayback") for e in errors) or len(historical_urls) >= MAX_HISTORICAL_URLS else "queried", "count": len(historical_urls)},
        ],
        "passive_errors": errors,
    }
