"""Collect same-host JavaScript files and extract endpoint/source-map references."""
import asyncio
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from recon.js_endpoint_extractor import JSEndpointExtractor
from crawler.fetcher import build_headers

SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s*]+)")
JS_URL_RE = re.compile(r"""["']([^"']+\.js(?:\?[^"']*)?)["']""")
MAX_JS_BYTES = 2 * 1024 * 1024
MAX_JS_FILES = 200


class JSCollector:
    def __init__(self, base_url: str, on_log=None, request_headers=None, cookie_jar=None):
        self.base_url = base_url
        self.base_host = (urlparse(base_url).hostname or "").lower()
        self.base_origin = self._origin(base_url)
        self.on_log = on_log or (lambda msg: None)
        self.request_headers = dict(request_headers or {})
        self.cookie_jar = cookie_jar
        self.rate_limit_stopped = False
        self.js_urls: set = set()
        self.js_contents: dict = {}
        self.inline_scripts: list = []
        self.endpoints: set = set()
        self.source_maps: set = set()
        self.route_urls: set = set()
        self._analyzed_js_urls: set = set()

    @staticmethod
    def _origin(url: str):
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            host = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
            return scheme, host, port
        except (TypeError, ValueError):
            return None

    def _in_scope(self, url: str) -> bool:
        host = urlparse(url).hostname
        return bool(host and host.lower() == self.base_host)

    def collect_from_html(self, page_url: str, html: str):
        soup = BeautifulSoup(html or "", "lxml")
        resource_base = page_url
        base_tag = soup.find("base", href=True)
        if base_tag:
            candidate = urljoin(page_url, base_tag["href"].strip())
            parsed_base = urlparse(candidate)
            if parsed_base.scheme.lower() in ("http", "https") and parsed_base.hostname:
                resource_base = candidate

        for tag in soup.find_all("script", src=True):
            absolute = urljoin(resource_base, tag["src"].strip())
            if absolute.startswith(("http://", "https://")) and self._in_scope(absolute):
                self.js_urls.add(absolute)
        for tag in soup.find_all("script", src=False):
            content = tag.string or tag.get_text() or ""
            if content.strip():
                self.inline_scripts.append(content)
                self.endpoints.update(JSEndpointExtractor.extract(content))
                for route in JSEndpointExtractor.extract_routes(content):
                    candidate = urljoin(resource_base, route)
                    if candidate.startswith(("http://", "https://")) and self._in_scope(candidate):
                        self.route_urls.add(candidate)

    async def download_and_analyze(self, concurrency: int = 5, should_stop=None, delay_seconds: float = 0.0):
        stop = should_stop or (lambda: False)
        concurrency = max(1, min(int(concurrency), 10))
        delay_seconds = max(0.0, min(float(delay_seconds), 86400.0))
        if delay_seconds > 0:
            concurrency = 1
        timeout = aiohttp.ClientTimeout(total=15, connect=8)
        connector = aiohttp.TCPConnector(limit=concurrency, ssl=True)
        session_options = {"connector": connector}
        if self.cookie_jar is not None:
            session_options["cookie_jar"] = self.cookie_jar
        async with aiohttp.ClientSession(**session_options) as session:
            while (
                self.js_urls - self._analyzed_js_urls
                and len(self._analyzed_js_urls) < MAX_JS_FILES
                and not stop()
                and not self.rate_limit_stopped
            ):
                batch = sorted(self.js_urls - self._analyzed_js_urls)[
                    :min(concurrency, MAX_JS_FILES - len(self._analyzed_js_urls))
                ]
                await asyncio.gather(
                    *(self._fetch_js(session, url, timeout, stop) for url in batch),
                    return_exceptions=True,
                )
                # Mark attempts once to avoid repeating failing endpoints on a second pass.
                self._analyzed_js_urls.update(batch)
                if delay_seconds > 0 and (self.js_urls - self._analyzed_js_urls) and not stop():
                    await asyncio.sleep(delay_seconds)

        if len(self.js_urls) > MAX_JS_FILES:
            self.on_log(f"[JS] File limit reached ({MAX_JS_FILES}).")

    async def _fetch_js(self, session, url, timeout, stop):
        if stop() or not self._in_scope(url):
            return
        try:
            request_headers = build_headers()
            if self._origin(url) == self.base_origin:
                request_headers.update({
                    str(key): str(value) for key, value in self.request_headers.items()
                    if str(key).lower() in {"authorization", "cookie", "accept-language"}
                    and "\r" not in str(value) and "\n" not in str(value)
                })
            async with session.get(
                url, headers=request_headers, timeout=timeout, allow_redirects=False
            ) as resp:
                # Do not follow redirects: their destinations may be outside scope.
                if resp.status == 429:
                    self.rate_limit_stopped = True
                    self.on_log(f"[429] JavaScript download was rate-limited at {url}; stopping JS collection safely.")
                    return
                if resp.status != 200:
                    return
                data = await resp.content.read(MAX_JS_BYTES + 1)
                if len(data) > MAX_JS_BYTES:
                    data = data[:MAX_JS_BYTES]
                    self.on_log(f"[JS] Truncated oversized file: {url}")
                content = data.decode(resp.charset or "utf-8", errors="replace")
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError) as exc:
            self.on_log(f"[JS] Error {url}: {exc}")
            return

        self.js_contents[url] = content
        self.endpoints.update(JSEndpointExtractor.extract(content))
        for route in JSEndpointExtractor.extract_routes(content):
            candidate = urljoin(url, route)
            if candidate.startswith(("http://", "https://")) and self._in_scope(candidate):
                self.route_urls.add(candidate)

        for match in JS_URL_RE.findall(content):
            candidate = urljoin(url, match)
            if candidate.startswith(("http://", "https://")) and self._in_scope(candidate):
                self.js_urls.add(candidate)

        for match in SOURCEMAP_RE.findall(content):
            candidate = urljoin(url, match)
            if candidate.startswith(("http://", "https://")) and self._in_scope(candidate):
                self.source_maps.add(candidate)

        self.on_log(f"[JS] Analyzed {url} ({len(content)} characters)")

    def to_dict(self) -> dict:
        return {
            "js_files": sorted(self.js_urls),
            "inline_script_count": len(self.inline_scripts),
            "endpoints": sorted(self.endpoints),
            "source_maps": sorted(self.source_maps),
            "discovered_routes": sorted(self.route_urls),
        }
