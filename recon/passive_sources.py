"""Bounded passive recon sources (Certificate Transparency and Wayback CDX)."""
from __future__ import annotations
from urllib.parse import urlparse
import requests

from recon.domain_scope import registrable_domain

USER_AGENT = "Recon-GUI/3.0 (passive research; authorized use)"
# crt.sh results are parsed completely. Wayback's request is larger than the old
# 300-URL query; reaching this ceiling is explicitly marked as partial.
MAX_HISTORICAL_URLS = 10000


def collect_passive(target: str, timeout: int = 12, on_log=None) -> dict:
    """Query passive indexes for the registrable domain; discovered hosts are never probed."""
    parsed = urlparse((target or "").strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be a valid HTTP(S) URL")
    root = registrable_domain(parsed.hostname)
    if not root:
        raise ValueError(
            "Passive subdomain discovery requires a registrable DNS domain; "
            "IP addresses and public suffixes cannot define the root scope."
        )
    log = on_log or (lambda _message: None)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json,text/plain,*/*"})
    subdomains, historical_urls, errors = set(), set(), []
    try:
        response = session.get(
            "https://crt.sh/",
            params={"q": f"%.{root}", "output": "json"},
            timeout=max(3, min(int(timeout), 20)),
        )
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
            log(f"[Passive] Certificate Transparency returned {len(subdomains)} hostnames for {root}.")
        else:
            errors.append(f"crt.sh HTTP {response.status_code}")
    except (requests.RequestException, ValueError) as exc:
        errors.append(f"crt.sh: {type(exc).__name__}: {exc}")

    wayback_truncated = False
    wayback_queries = (f"{root}/*", f"*.{root}/*")
    try:
        for pattern in wayback_queries:
            remaining = MAX_HISTORICAL_URLS - len(historical_urls)
            if remaining <= 0:
                wayback_truncated = True
                break
            try:
                response = session.get(
                    "https://web.archive.org/cdx/search/cdx",
                    params={
                        "url": pattern, "output": "json", "fl": "original",
                        "filter": "statuscode:200", "collapse": "urlkey",
                        "limit": str(remaining),
                    },
                    timeout=max(3, min(int(timeout), 20)),
                )
                if response.status_code != 200:
                    errors.append(f"Wayback CDX {pattern}: HTTP {response.status_code}")
                    continue
                try:
                    rows = response.json()
                except ValueError:
                    rows = []
                records = rows[1:] if isinstance(rows, list) and rows else []
                if len(records) >= remaining:
                    wayback_truncated = True
                for row in records:
                    value = row[0] if isinstance(row, list) and row else ""
                    host = (urlparse(value).hostname or "").lower().rstrip(".")
                    if (
                        value.startswith(("http://", "https://"))
                        and (host == root or host.endswith("." + root))
                    ):
                        historical_urls.add(value)
                    if len(historical_urls) >= MAX_HISTORICAL_URLS:
                        wayback_truncated = True
                        break
                if wayback_truncated:
                    break
            except (requests.RequestException, ValueError) as exc:
                errors.append(f"Wayback CDX {pattern}: {type(exc).__name__}: {exc}")
        if wayback_truncated:
            log(
                f"[Passive] Wayback reached the combined {MAX_HISTORICAL_URLS}-URL ceiling; "
                "historical URL coverage may be partial."
            )
        else:
            log(
                f"[Passive] Wayback returned {len(historical_urls)} historical URLs "
                f"across the root and subdomain queries for {root}."
            )
    finally:
        session.close()

    return {
        "passive_subdomains": sorted(subdomains),
        "historical_urls": sorted(historical_urls),
        "passive_sources": [
            {
                "name": "crt.sh",
                "status": "partial" if any(error.startswith("crt.sh") for error in errors) else "queried",
                "count": len(subdomains),
            },
            {
                "name": "Wayback CDX (root + subdomains)",
                "status": "partial" if wayback_truncated or any(error.startswith("Wayback CDX") for error in errors) else "queried",
                "count": len(historical_urls),
            },
        ],
        "passive_errors": errors,
    }
