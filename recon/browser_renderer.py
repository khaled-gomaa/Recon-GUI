"""Optional Playwright rendering; external-origin requests are blocked by default."""
from __future__ import annotations
import asyncio
from urllib.parse import urlparse

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


async def render_pages(urls, headers=None, should_stop=None, on_log=None, on_network_event=None,
                       max_pages: int = MAX_RENDER_PAGES, concurrency: int = MAX_RENDER_CONCURRENCY):
    """Render a bounded list of URLs and return their post-JavaScript DOM HTML."""
    stop = should_stop or (lambda: False)
    log = on_log or (lambda _message: None)
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
        if str(k).lower() in {"authorization", "cookie", "accept-language"}
        and "\r" not in str(v) and "\n" not in str(v)
    }
    semaphore = asyncio.Semaphore(max(1, min(int(concurrency), MAX_RENDER_CONCURRENCY)))
    rendered = {}
    emit = on_network_event or (lambda _record: None)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context(extra_http_headers=safe_headers)
        try:
            async def render_one(url):
                if stop() or (urlparse(url).hostname or "").lower() != expected_host or _origin(url) != expected_origin:
                    return
                async with semaphore:
                    if stop():
                        return
                    page = await context.new_page()

                    from urllib.parse import parse_qsl, urlsplit, urlunsplit
                    import json

                    def safe_request_url(value):
                        parsed = urlsplit(value or "")
                        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))

                    def on_request(request):
                        if (urlparse(request.url).hostname or "").lower() != expected_host or _origin(request.url) != expected_origin:
                            return
                        try:
                            query_parameters = sorted({name for name, _ in parse_qsl(urlsplit(request.url).query, keep_blank_values=True) if name})
                        except ValueError:
                            query_parameters = []
                        body_parameters = []
                        post_data = request.post_data or ""
                        try:
                            content_type = str(request.headers.get("content-type", "")).lower()
                            if "json" in content_type:
                                value = json.loads(post_data)
                                if isinstance(value, dict):
                                    body_parameters = sorted(str(name) for name in value)
                            elif "x-www-form-urlencoded" in content_type or (post_data and not content_type):
                                body_parameters = sorted({name for name, _ in parse_qsl(post_data, keep_blank_values=True) if name})
                        except (ValueError, TypeError):
                            body_parameters = []
                        record = {
                            "url": safe_request_url(request.url),
                            "method": str(request.method or "GET").upper(),
                            "source": "rendered-browser",
                            "page": safe_request_url(url),
                            "resource_type": str(request.resource_type or ""),
                            "query_parameters": query_parameters,
                            "body_parameters": body_parameters,
                            "status": None,
                            "content_type": "",
                        }
                        requests_by_id[id(request)] = record
                        try:
                            emit(dict(record))
                        except Exception:
                            pass

                    async def on_response(response):
                        record = requests_by_id.get(id(response.request))
                        if record is None:
                            return
                        record["status"] = int(response.status)
                        try:
                            response_headers = await response.all_headers()
                            record["content_type"] = response_headers.get("content-type", "")
                        except Exception:
                            pass
                        try:
                            emit(dict(record))
                        except Exception:
                            pass

                    requests_by_id = {}
                    page.on("request", on_request)
                    page.on("response", lambda response: asyncio.create_task(on_response(response)))

                    async def scope_guard(route):
                        request_host = (urlparse(route.request.url).hostname or "").lower()
                        if request_host != expected_host or _origin(route.request.url) != expected_origin:
                            await route.abort()
                        else:
                            await route.continue_()
                    await page.route("**/*", scope_guard)
                    try:
                        response = await page.goto(url, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
                        if response is not None and response.status == 429:
                            log(f"[Browser] {url} returned HTTP 429; skipping render.")
                            return
                        await page.wait_for_timeout(700)
                        if not stop():
                            rendered[url] = await page.content()
                            log(f"[Browser] Rendered DOM: {url}")
                    except Exception as exc:
                        log(f"[Browser] Render failed for {url}: {type(exc).__name__}: {exc}")
                    finally:
                        pass
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
        finally:
            await context.close()
            await browser.close()
    return rendered


async def capture_manual_session(
    start_url: str, cookie_jar=None, should_stop=None, on_log=None,
    on_network_event=None, duration_seconds: int = 90,
):
    """Open headed Chromium so an operator can log in/browse while same-origin traffic is recorded.

    This is opt-in. Request/response bodies and cookie values are never emitted to callbacks.
    Session cookies are copied to the shared in-memory aiohttp jar only when their domain
    matches the target hostname, keeping follow-up HTTP phases session-aware.
    """
    from http.cookies import SimpleCookie
    from urllib.parse import parse_qsl, urlsplit, urlunsplit
    from yarl import URL

    stop = should_stop or (lambda: False)
    log = on_log or (lambda _message: None)
    emit = on_network_event or (lambda _record: None)
    parsed_start = urlsplit(start_url)
    expected_host = (parsed_start.hostname or "").lower().rstrip(".")
    expected_origin = _origin(start_url)
    duration = max(15, min(int(duration_seconds), 600))
    observations = {}
    captured_cookies = []

    def safe_url(value):
        parsed = urlsplit(value or "")
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))

    def query_names(value):
        try:
            return sorted({name for name, _ in parse_qsl(urlsplit(value).query, keep_blank_values=True) if name})
        except ValueError:
            return []

    def body_names(request):
        raw = request.post_data or ""
        if not raw:
            return []
        content_type = ""
        try:
            content_type = str(request.headers.get("content-type", "")).lower()
        except Exception:
            pass
        try:
            import json
            if "json" in content_type:
                value = json.loads(raw)
                if isinstance(value, dict):
                    return sorted(str(key) for key in value.keys())
                return []
            if "x-www-form-urlencoded" in content_type or not content_type:
                return sorted({name for name, _ in parse_qsl(raw, keep_blank_values=True) if name})
        except (ValueError, TypeError):
            return []
        # Multipart uploads: record field names only, never values or file content.
        import re
        return sorted(set(re.findall(r'name="([^"]+)"', raw)))

    def is_target_request(request):
        try:
            candidate = urlsplit(request.url)
            return (
                (candidate.hostname or "").lower().rstrip(".") == expected_host
                and _origin(request.url) == expected_origin
                and candidate.scheme.lower() in ("http", "https")
            )
        except ValueError:
            return False

    def notify(record):
        try:
            emit(dict(record))
        except Exception:
            pass

    async def run_capture():
        async with __import__("playwright.async_api", fromlist=["async_playwright"]).async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=False)
            try:
                context = await browser.new_context()
                page = await context.new_page()

                def on_request(request):
                    if not is_target_request(request):
                        return
                    key = id(request)
                    try:
                        referrer = request.headers.get("referer", "")
                    except Exception:
                        referrer = ""
                    record = {
                        "url": safe_url(request.url),
                        "method": str(request.method or "GET").upper(),
                        "source": "manual-browser",
                        "page": safe_url(referrer) if referrer else safe_url(start_url),
                        "resource_type": str(request.resource_type or ""),
                        "query_parameters": query_names(request.url),
                        "body_parameters": body_names(request),
                        "status": None,
                        "content_type": "",
                    }
                    observations[key] = record
                    notify(record)

                async def on_response(response):
                    request = response.request
                    if not is_target_request(request):
                        return
                    key = id(request)
                    record = observations.get(key)
                    if record is None:
                        on_request(request)
                        record = observations.get(key)
                    if record is None:
                        return
                    record["status"] = int(response.status)
                    try:
                        headers = await response.all_headers()
                        record["content_type"] = headers.get("content-type", "")
                    except Exception:
                        pass
                    notify(record)

                page.on("request", on_request)
                page.on("response", lambda response: __import__("asyncio").create_task(on_response(response)))
                try:
                    await page.goto(start_url, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
                except Exception as exc:
                    log(f"[Manual Browser] Initial navigation: {type(exc).__name__}: {exc}")
                log(
                    f"[Manual Browser] Chromium is open for manual login/browsing for up to {duration}s. "
                    "Only same-origin request metadata is recorded; request bodies and cookie values are not logged."
                )
                deadline = __import__("asyncio").get_running_loop().time() + duration
                while not stop() and __import__("asyncio").get_running_loop().time() < deadline:
                    await __import__("asyncio").sleep(0.25)
                if stop():
                    log("[Manual Browser] Capture stopped by user.")
                else:
                    log("[Manual Browser] Capture window finished; collecting cookie names/attributes.")
                try:
                    browser_cookies = await context.cookies()
                except Exception:
                    browser_cookies = []
                for cookie in browser_cookies:
                    domain = str(cookie.get("domain") or "").lower().lstrip(".").rstrip(".")
                    if not (expected_host == domain or expected_host.endswith("." + domain)):
                        continue
                    metadata = {
                        "name": str(cookie.get("name") or ""),
                        "domain": str(cookie.get("domain") or ""),
                        "path": str(cookie.get("path") or "/"),
                        "secure": bool(cookie.get("secure")),
                        "httponly": bool(cookie.get("httpOnly")),
                        "samesite": str(cookie.get("sameSite") or ""),
                        "source": "browser-session",
                    }
                    captured_cookies.append(metadata)
                    if cookie_jar is not None and metadata["name"]:
                        morsel = SimpleCookie()
                        morsel[metadata["name"]] = str(cookie.get("value") or "")
                        item = morsel[metadata["name"]]
                        if metadata["domain"]:
                            item["domain"] = str(cookie.get("domain"))
                        item["path"] = metadata["path"]
                        item["secure"] = metadata["secure"]
                        item["httponly"] = metadata["httponly"]
                        if metadata["samesite"]:
                            item["samesite"] = metadata["samesite"]
                        try:
                            cookie_jar.update_cookies(morsel, response_url=URL(start_url))
                        except Exception as exc:
                            log(f"[Manual Browser] Could not transfer cookie '{metadata['name']}' to HTTP session: {type(exc).__name__}")
                await context.close()
            finally:
                await browser.close()

    try:
        await run_capture()
    except ImportError as exc:
        raise RuntimeError(
            "Manual browser capture needs Playwright. Install requirements-optional.txt and run playwright install chromium."
        ) from exc
    except Exception as exc:
        raise RuntimeError(f"Manual browser capture failed: {type(exc).__name__}: {exc}") from exc

    return {
        "network_observations": list(observations.values()),
        "session_cookies": captured_cookies,
        "manual_browser_seconds": duration,
    }
