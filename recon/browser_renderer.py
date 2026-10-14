"""Optional Playwright rendering; external-origin requests are blocked by default."""
from __future__ import annotations
import asyncio
import json
from yarl import URL
import aiohttp
import re
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlparse, urlsplit

def _origin(url):
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
        return scheme, host, port
    except (TypeError, ValueError):
        return None


MAX_RENDER_PAGES = 30
MAX_RENDER_CONCURRENCY = 2
NAVIGATION_TIMEOUT_MS = 15000


def _parameter_names_from_body(data, content_type=""):
    """Extract only field names; request body values are never saved."""
    if not data:
        return []
    names = set()
    try:
        if "json" in str(content_type).lower() or str(data).lstrip().startswith(("{", "[")):
            parsed = json.loads(data)
            def visit(value):
                if isinstance(value, dict):
                    for key, item in value.items():
                        names.add(str(key))
                        visit(item)
                elif isinstance(value, list):
                    for item in value:
                        visit(item)
            visit(parsed)
        else:
            names.update(name for name, _ in parse_qsl(str(data), keep_blank_values=True) if name)
    except (ValueError, TypeError, RecursionError):
        return []
    return sorted(name for name in names if name)


async def render_pages(
    urls, headers=None, should_stop=None, on_log=None,
    max_pages: int = MAX_RENDER_PAGES, concurrency: int = MAX_RENDER_CONCURRENCY,
    network_observations=None, cookie_observations=None, cookie_jar=None,
):
    """Render same-origin pages in one shared browser context and record safe request metadata."""
    stop = should_stop or (lambda: False)
    log = on_log or (lambda _message: None)
    observations = network_observations if network_observations is not None else []
    cookie_events = cookie_observations if cookie_observations is not None else []
    limited_urls = list(dict.fromkeys(
        str(url) for url in urls if str(url).startswith(("http://", "https://"))
    ))[:max(1, min(int(max_pages), MAX_RENDER_PAGES))]
    if not limited_urls:
        return {}
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Playwright is optional. Install the playwright package and run "
            "playwright install chromium to enable JavaScript rendering."
        ) from exc

    expected_host = (urlparse(limited_urls[0]).hostname or "").lower()
    expected_origin = _origin(limited_urls[0])
    safe_headers = {
        str(k): str(v) for k, v in (headers or {}).items()
        if str(k).lower() in {"authorization", "accept-language"}
        and "\r" not in str(v) and "\n" not in str(v)
    }
    initial_cookies = []
    if cookie_jar is not None:
        try:
            for name, morsel in cookie_jar.filter_cookies(URL(limited_urls[0])).items():
                initial_cookies.append({
                    "name": name, "value": morsel.value, "url": limited_urls[0],
                })
        except Exception as exc:
            log(f"[Browser] Could not seed existing HTTP cookies: {type(exc).__name__}")
    raw_cookie = next(
        (str(value) for key, value in (headers or {}).items() if str(key).lower() == "cookie"),
        "",
    )
    if raw_cookie:
        parsed_cookie = SimpleCookie()
        try:
            parsed_cookie.load(raw_cookie)
            existing = {item["name"] for item in initial_cookies}
            for morsel in parsed_cookie.values():
                if morsel.key not in existing:
                    initial_cookies.append({"name": morsel.key, "value": morsel.value, "url": limited_urls[0]})
        except (TypeError, ValueError):
            log("[Browser] Supplied Cookie header could not be parsed; other headers remain available.")

    semaphore = asyncio.Semaphore(max(1, min(int(concurrency), MAX_RENDER_CONCURRENCY)))
    rendered = {}
    request_to_observation = {}
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = None
        try:
            context = await browser.new_context(extra_http_headers=safe_headers)
            if initial_cookies:
                try:
                    await context.add_cookies(initial_cookies)
                except Exception as exc:
                    log(f"[Browser] Could not transfer HTTP cookies into browser context: {type(exc).__name__}")

            async def render_one(url):
                if stop() or urlparse(url).hostname != expected_host or _origin(url) != expected_origin:
                    return
                async with semaphore:
                    if stop():
                        return
                    page = await context.new_page()
                    async def scope_guard(route):
                        if _origin(route.request.url) != expected_origin:
                            await route.abort()
                        else:
                            await route.continue_()
                    await page.route("**/*", scope_guard)

                    def record_request(request):
                        request_url = request.url
                        if _origin(request_url) != expected_origin:
                            return
                        try:
                            request_headers = request.headers
                        except Exception:
                            request_headers = {}
                        content_type = str(request_headers.get("content-type", ""))
                        body_names = _parameter_names_from_body(request.post_data, content_type)
                        try:
                            query_names = sorted({
                                name for name, _ in parse_qsl(urlsplit(request_url).query, keep_blank_values=True)
                                if name
                            })
                        except ValueError:
                            query_names = []
                        observation = {
                            "url": request_url,
                            "method": str(request.method or "GET").upper(),
                            "resource_type": str(request.resource_type or ""),
                            "page_url": url,
                            "status": None,
                            "source": "browser-network",
                            "parameter_names": body_names,
                            "query_parameter_names": query_names,
                            "has_request_body": bool(request.post_data),
                        }
                        observations.append(observation)
                        key = (request_url, str(request.method or "GET").upper())
                        request_to_observation.setdefault(key, []).append(observation)

                    def record_response(response):
                        key = (response.url, str(response.request.method or "GET").upper())
                        pending = request_to_observation.get(key, [])
                        if pending:
                            observation = pending.pop(0)
                            observation["status"] = int(response.status)
                        else:
                            observation = None

                    page.on("request", record_request)
                    page.on("response", record_response)
                    try:
                        response = await page.goto(url, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
                        if response is not None and response.status == 429:
                            log(f"[Browser] {url} returned HTTP 429; skipping render.")
                            return
                        await page.wait_for_timeout(700)
                        if not stop():
                            rendered[url] = await page.content()
                            log(f"[Browser] Rendered DOM and recorded same-origin network activity: {url}")
                    except Exception as exc:
                        log(f"[Browser] Render failed for {url}: {type(exc).__name__}: {exc}")
                    finally:
                        await page.close()

            tasks = [asyncio.create_task(render_one(url)) for url in limited_urls]
            for task in tasks:
                if stop():
                    break
                try:
                    await task
                except Exception as exc:
                    log(f"[Browser] Render task failed: {type(exc).__name__}: {exc}")
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            if context is not None:
                try:
                    browser_cookies = await context.cookies()
                    host_cookie_set = set()
                    for cookie in browser_cookies:
                        domain = str(cookie.get("domain") or "").lstrip(".").lower()
                        if domain != expected_host:
                            continue
                        key = (cookie.get("name", ""), domain, cookie.get("path", "/"))
                        if key in host_cookie_set:
                            continue
                        host_cookie_set.add(key)
                        cookie_events.append({
                            "name": str(cookie.get("name") or ""),
                            "domain": domain, "path": str(cookie.get("path") or "/"),
                            "secure": bool(cookie.get("secure")),
                            "httponly": bool(cookie.get("httpOnly")),
                            "samesite": str(cookie.get("sameSite") or ""),
                            "source": "browser-context",
                        })
                        if cookie_jar is not None and cookie.get("name"):
                            try:
                                morsels = SimpleCookie()
                                morsels[str(cookie["name"])] = str(cookie.get("value") or "")
                                morsel = morsels[str(cookie["name"])]
                                morsel["domain"] = str(cookie.get("domain") or "")
                                morsel["path"] = str(cookie.get("path") or "/")
                                if cookie.get("secure"):
                                    morsel["secure"] = True
                                if cookie.get("httpOnly"):
                                    morsel["httponly"] = True
                                if cookie.get("sameSite"):
                                    morsel["samesite"] = str(cookie["sameSite"])
                                cookie_jar.update_cookies(morsels, response_url=URL(limited_urls[0]))
                            except Exception as exc:
                                log(f"[Browser] Cookie sync back to HTTP session failed: {type(exc).__name__}")
                except Exception as exc:
                    log(f"[Browser] Could not collect cookie metadata: {type(exc).__name__}")
        finally:
            if context is not None:
                await context.close()
            await browser.close()
    return rendered
