"""Explicit, low-rate verification of user-selected discovered subdomains.

Only selected same-registrable-domain hostnames are tested. DNS lookup runs first;
if it resolves, one unauthenticated HTTP HEAD request is attempted over HTTPS, with
HTTP fallback only when HTTPS cannot be contacted. Redirects are never followed.
"""
from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlparse

import aiohttp

from recon.subdomain_finder import SubdomainFinder

MAX_VERIFY_HOSTS = 200
MAX_VERIFY_CONCURRENCY = 5
MAX_TIMEOUT_SECONDS = 8


def normalize_in_scope_hosts(target: str, candidates) -> list[str]:
    """Return unique valid subdomains under the inferred registrable domain.

    The helper deliberately does not infer authorization: callers must invoke it
    only for hostnames the operator explicitly selected for verification.
    """
    parsed = urlparse((target or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be a full HTTP(S) URL")
    root_domain = SubdomainFinder(parsed.hostname).base_domain.encode("idna").decode("ascii").lower()
    normalized = set()
    for raw in candidates or []:
        value = str(raw or "").strip().lower().rstrip(".")
        if not value or "://" in value or "/" in value or ":" in value:
            continue
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            continue
        if len(value) > 253 or value == root_domain or not value.endswith("." + root_domain):
            continue
        labels = value.split(".")
        if any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            or not all(ch.isalnum() or ch == "-" for ch in label)
            for label in labels
        ):
            continue
        normalized.add(value)
    return sorted(normalized)


async def verify_subdomains(
    target: str,
    candidates,
    *,
    timeout: int = 4,
    max_hosts: int = MAX_VERIFY_HOSTS,
    concurrency: int = MAX_VERIFY_CONCURRENCY,
    should_stop=None,
    on_log=None,
) -> dict:
    """DNS-check and make one no-credentials HEAD request per explicitly selected host."""
    stop = should_stop or (lambda: False)
    log = on_log or (lambda _message: None)
    normalized = normalize_in_scope_hosts(target, candidates)
    limit = max(1, min(int(max_hosts), MAX_VERIFY_HOSTS))
    selected = normalized[:limit]
    truncated = len(normalized) > len(selected)
    if truncated:
        log(
            f"[Scope] Selected {len(normalized)} valid hosts; verifying the first {limit}. "
            "Unverified selected hosts remain unchecked."
        )
    if not selected:
        return {
            "results": [], "candidate_count": len(normalized), "verified_count": 0,
            "skipped_count": len(normalized), "truncated": truncated,
        }

    request_timeout = max(1, min(int(timeout), MAX_TIMEOUT_SECONDS))
    semaphore = asyncio.Semaphore(max(1, min(int(concurrency), MAX_VERIFY_CONCURRENCY)))
    connector = aiohttp.TCPConnector(limit=max(1, min(int(concurrency), MAX_VERIFY_CONCURRENCY)), ssl=True)
    client_timeout = aiohttp.ClientTimeout(total=request_timeout, connect=request_timeout)
    results = []
    loop = asyncio.get_running_loop()

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=client_timeout,
        headers={"User-Agent": "Recon-GUI scope verification (operator initiated)", "Accept": "*/*"},
        cookie_jar=aiohttp.DummyCookieJar(),
        trust_env=False,
    ) as session:
        async def check(host: str):
            record = {
                "host": host, "dns_status": "not-checked", "ip_addresses": [],
                "http_status": None, "http_url": "", "http_result": "not-checked",
                "server": "", "error": "",
            }
            if stop():
                record["http_result"] = "stopped"
                return record
            async with semaphore:
                if stop():
                    record["http_result"] = "stopped"
                    return record
                try:
                    infos = await asyncio.wait_for(
                        loop.getaddrinfo(host, None, type=socket.SOCK_STREAM),
                        timeout=request_timeout,
                    )
                    ips = sorted({str(item[4][0]) for item in infos if len(item) > 4 and item[4]})
                    record["ip_addresses"] = ips
                    if not ips:
                        record["dns_status"] = "no-address"
                        record["http_result"] = "not-tested"
                        return record
                    record["dns_status"] = "resolved"
                except (OSError, asyncio.TimeoutError, socket.gaierror) as exc:
                    record["dns_status"] = "failed"
                    record["http_result"] = "not-tested"
                    record["error"] = type(exc).__name__
                    return record

                for scheme in ("https", "http"):
                    if stop():
                        record["http_result"] = "stopped"
                        return record
                    url = f"{scheme}://{host}/"
                    try:
                        async with session.head(url, allow_redirects=False) as response:
                            record["http_url"] = url
                            record["http_status"] = int(response.status)
                            record["server"] = str(response.headers.get("Server", ""))[:120]
                            if response.status in {301, 302, 303, 307, 308}:
                                record["http_result"] = "redirect"
                            else:
                                record["http_result"] = "responded"
                            return record
                    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                        record["error"] = type(exc).__name__
                        # Do not make a second request if HTTPS reached a server but returned
                        # a response. Fallback happens only for a connection/TLS-level error.
                        if scheme == "http":
                            record["http_result"] = "unreachable"
                return record

        tasks = [asyncio.create_task(check(host)) for host in selected]
        for task in asyncio.as_completed(tasks):
            try:
                results.append(await task)
            except Exception as exc:
                log(f"[Scope] Verification worker error: {type(exc).__name__}: {exc}")
        if stop():
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    order = {host: idx for idx, host in enumerate(selected)}
    results.sort(key=lambda item: order.get(item["host"], 999999))
    log(
        f"[Scope] Verification complete: {sum(1 for item in results if item['dns_status'] == 'resolved')} DNS-resolved, "
        f"{sum(1 for item in results if item['http_status'] is not None)} HTTP responses."
    )
    return {
        "results": results,
        "candidate_count": len(normalized),
        "verified_count": len(results),
        "skipped_count": max(0, len(normalized) - len(results)),
        "truncated": truncated,
    }
