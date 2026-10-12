"""Optional Playwright rendering; external-origin requests are blocked by default."""
from __future__ import annotations
import asyncio
from urllib.parse import urlparse

MAX_RENDER_PAGES = 30
MAX_RENDER_CONCURRENCY = 2
NAVIGATION_TIMEOUT_MS = 15000


async def render_pages(urls, headers=None, should_stop=None, on_log=None,
                       max_pages: int = MAX_RENDER_PAGES, concurrency: int = MAX_RENDER_CONCURRENCY):
    """Render a bounded list of URLs and return their post-JavaScript DOM HTML."""
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Playwright is optional. Install the playwright package and run "
            "playwright install chromium to enable JavaScript rendering."
        ) from exc
    stop = should_stop or (lambda: False)
    log = on_log or (lambda _message: None)
    limited_urls = list(dict.fromkeys(
        str(url) for url in urls if str(url).startswith(("http://", "https://"))
    ))[:max(1, min(int(max_pages), MAX_RENDER_PAGES))]
    if not limited_urls:
        return {}
    expected_host = (urlparse(limited_urls[0]).hostname or "").lower()
    safe_headers = {
        str(k): str(v) for k, v in (headers or {}).items()
        if str(k).lower() in {"authorization", "cookie", "accept-language"}
        and "\r" not in str(v) and "\n" not in str(v)
    }
    semaphore = asyncio.Semaphore(max(1, min(int(concurrency), MAX_RENDER_CONCURRENCY)))
    rendered = {}
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            async def render_one(url):
                if stop() or (urlparse(url).hostname or "").lower() != expected_host:
                    return
                async with semaphore:
                    if stop():
                        return
                    context = await browser.new_context(extra_http_headers=safe_headers)
                    page = await context.new_page()
                    async def scope_guard(route):
                        request_host = (urlparse(route.request.url).hostname or "").lower()
                        if request_host != expected_host:
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
                        await context.close()
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
            await browser.close()
    return rendered
