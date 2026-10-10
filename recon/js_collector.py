"""Collect and analyze JavaScript files."""
import asyncio
import re
import aiohttp
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from recon.js_endpoint_extractor import JSEndpointExtractor
from crawler.fetcher import build_headers

JS_URL_RE = re.compile(r"""["']([^"']+\.js(?:\?[^"']*)?)["']""")
SOURCEMAP_RE = re.compile(r"""//[#@]\s*sourceMappingURL=([^\s]+)""")


class JSCollector:
    def __init__(self, base_url: str, on_log=None):
        self.base_url = base_url
        self.on_log = on_log or (lambda msg: None)
        self.js_urls: set = set()
        self.js_contents: dict = {}
        self.inline_scripts: list = []
        self.endpoints: set = set()
        self.source_maps: set = set()

    def collect_from_html(self, page_url: str, html: str):
        soup = BeautifulSoup(html, "lxml")
        for tag in soup.find_all("script", src=True):
            absolute = urljoin(page_url, tag["src"].strip())
            if absolute.startswith(("http://", "https://")):
                self.js_urls.add(absolute)
        for tag in soup.find_all("script", src=False):
            content = tag.string or ""
            if content.strip():
                self.inline_scripts.append(content)
                self.endpoints.update(JSEndpointExtractor.extract(content))

    async def download_and_analyze(self, concurrency: int = 20):
        if not self.js_urls:
            return
        semaphore = asyncio.Semaphore(concurrency)
        connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                asyncio.create_task(self._fetch_js(session, url, semaphore))
                for url in list(self.js_urls)
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _fetch_js(self, session, url, semaphore):
        async with semaphore:
            try:
                async with session.get(
                    url, headers=build_headers(),
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status != 200:
                        return
                    content = await resp.text(errors="ignore")
            except Exception as exc:
                self.on_log(f"[JS] Error {url}: {exc}")
                return

            self.js_contents[url] = content
            self.endpoints.update(JSEndpointExtractor.extract(content))

            for match in JS_URL_RE.findall(content):
                absolute = urljoin(url, match)
                if absolute.startswith(("http://", "https://")):
                    self.js_urls.add(absolute)

            for match in SOURCEMAP_RE.findall(content):
                self.source_maps.add(urljoin(url, match))

            self.on_log(f"[JS] Analyzed {url} ({len(content)} bytes)")

    def to_dict(self) -> dict:
        return {
            "js_files": sorted(self.js_urls),
            "inline_script_count": len(self.inline_scripts),
            "endpoints": sorted(self.endpoints),
            "source_maps": sorted(self.source_maps),
        }
