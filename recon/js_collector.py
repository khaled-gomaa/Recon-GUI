"""Collect same-host JavaScript files and extract endpoint/source-map references."""
import asyncio
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from crawler.parser import PageParser
from recon.js_endpoint_extractor import JSEndpointExtractor
from crawler.fetcher import build_headers

SOURCEMAP_RE = re.compile(r"//[#@]\\s*sourceMappingURL=([^\\s*]+)")
JS_URL_RE = re.compile(r"""["'\x60]([^"'\x60]+\\.js(?:\\?[^"'\x60]*)?)["'\x60]""")
MAX_JS_BYTES = 2 * 1024 * 1024
MAX_JS_FILES = 200


class JSCollector:
    def __init__(self, base_url: str, on_log=None):
        self.base_url = base_url
        self.base_host = (urlparse(base_url).hostname or "").lower()
        self.on_log = on_log or (lambda msg: None)
        self.js_urls: set = set()
        self.js_contents: dict = {}
        self.inline_scripts: list = []
        self.endpoints: set = set()
        self.source_maps: set = set()

    def _in_scope(self, url: str) -> bool:
        host = urlparse(url).hostname
        return bool(host and host.lower() == self.base_host)

    def collect_from_html(self, page_url: str, html: str):
        soup = BeautifulSoup(html or "", "lxml")
        for tag in soup.find_all("script", src=True):
            absolute = urljoin(page_url, tag["src"].strip())
            if absolute.startswith(("http://", "https://")) and self._in_scope(absolute):
                self.js_urls.add(absolute)
        for tag in soup.find_all("script", src=False):
            content = tag.string or tag.get_text() or ""
            if content.strip():
                self.inline_scripts.append(content)
                self.endpoints.update(JSEndpointExtractor.extract(content))

    async def download_and_analyze(self, concurrency: int = 5, should_stop=None):
        stop = should_stop or (lambda: False)
        if not self.js_urls:
            return
        concurrency = max(1, min(int(concurrency), 10))
        timeout = aiohttp.ClientTimeout(total=15, connect=8)
        connector = aiohttp.TCPConnector(limit=concurrency, ssl=True)
        analyzed = set()

        async with aiohttp.ClientSession(connector=connector) as session:
            while self.js_urls - analyzed and len(analyzed) < MAX_JS_FILES and not stop():
                batch = sorted(self.js_urls - analyzed)[:concurrency]
                batch = batch[:MAX_JS_FILES - len(analyzed)]
                await asyncio.gather(
                    *(self._fetch_js(session, url, timeout, stop) for url in batch),
                    return_exceptions=True,
                )
                analyzed.update(batch)

        if len(self.js_urls) > MAX_JS_FILES:
            self.on_log(f"[JS] File limit reached ({MAX_JS_FILES}).")

    async def _fetch_js(self, session, url, timeout, stop):
        if stop() or not self._in_scope(url):
            return
        try:
            async with session.get(
                url, headers=build_headers(), timeout=timeout, allow_redirects=False
            ) as resp:
                # Do not follow redirects; their destination may be outside scope.
                if resp.status != 200:
                    return
                ctype = resp.headers.get("Content-Type", "").lower()
                if ctype and not any(t in ctype for t in ("javascript", "ecmascript", "text/plain", "application/octet-stream")):
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
        }
