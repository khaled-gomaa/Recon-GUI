"""Collect same-host JavaScript files and extract endpoint/source-map references."""
import asyncio
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup
from recon.rate_limit_policy import AdaptiveRateController

from recon.js_endpoint_extractor import JSEndpointExtractor
from crawler.fetcher import build_headers

SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s*]+)")
JS_URL_RE = re.compile(r"""["']([^"']+\.js(?:\?[^"']*)?)["']""")
MAX_JS_BYTES = 2 * 1024 * 1024
# Zero means process every discovered same-host JS URL. Each file still has a
# clearly logged byte cap, a timeout, and normal scope/rate-limit protections.
MAX_JS_FILES = 0


class JSCollector:
    def __init__(self, base_url: str, on_log=None, request_headers=None, cookie_jar=None):
        self.base_url = base_url
        self.base_host = (urlparse(base_url).hostname or "").lower()
        self.base_origin = self._origin(base_url)
        self.on_log = on_log or (lambda msg: None)
        self.request_headers = dict(request_headers or {})
        self.cookie_jar = cookie_jar
        self.rate_limit_stopped = False
        self.rate_controller = AdaptiveRateController(
            base_delay=0.0, max_delay=60.0, max_consecutive_limits=5, jitter=0.0
        )
        self._resume_event = None
        self._rate_limit_lock = None
        self._request_gate_lock = None
        self._next_request_time = 0.0
        self._retry_urls: set[str] = set()
        # Each failed referenced script is tracked as metadata only; query values and
        # raw exception strings are never recorded.
        self.fetch_errors: list[dict] = []
        self._fetch_error_keys: set[tuple] = set()
        self.js_urls: set = set()
        self.js_contents: dict = {}
        self.truncated_js_files: set = set()
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

    @staticmethod
    def _safe_url(url: str) -> str:
        """Remove credentials, query values, fragments, and invalid ports from diagnostics."""
        from urllib.parse import urlsplit, urlunsplit
        try:
            parsed = urlsplit(str(url or ""))
            scheme = parsed.scheme.lower()
            host = (parsed.hostname or "").lower()
            if not host or scheme not in {"http", "https"}:
                return parsed.path or "(invalid URL)"
            if ":" in host:
                host = f"[{host}]"
            port = parsed.port
            if port and not (
                (scheme == "http" and port == 80)
                or (scheme == "https" and port == 443)
            ):
                host = f"{host}:{port}"
            return urlunsplit((scheme, host, parsed.path or "/", "", ""))
        except (TypeError, ValueError, UnicodeError):
            return "(invalid URL)"

    def _record_fetch_error(self, url: str, status=None, error_type=""):
        safe_url = self._safe_url(url)
        try:
            code = int(status) if status is not None else 0
        except (TypeError, ValueError, OverflowError):
            code = 0
        kind = str(error_type or (f"HTTP {code}" if code else "No HTTP response"))
        key = (safe_url, code, kind)
        if key in self._fetch_error_keys:
            return
        self._fetch_error_keys.add(key)
        self.fetch_errors.append({
            "url": safe_url,
            "status": code,
            "error_type": kind,
            "source": "javascript",
        })

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
        self._resume_event = asyncio.Event()
        self._resume_event.set()
        self._rate_limit_lock = asyncio.Lock()
        self._request_gate_lock = asyncio.Lock()
        self._next_request_time = 0.0
        session_options = {"connector": connector}
        if self.cookie_jar is not None:
            session_options["cookie_jar"] = self.cookie_jar
        async with aiohttp.ClientSession(**session_options) as session:
            while (
                self.js_urls - self._analyzed_js_urls
                and (not MAX_JS_FILES or len(self._analyzed_js_urls) < MAX_JS_FILES)
                and not stop()
                and not self.rate_limit_stopped
            ):
                remaining = sorted(self.js_urls - self._analyzed_js_urls)
                batch_size = min(concurrency, MAX_JS_FILES - len(self._analyzed_js_urls)) if MAX_JS_FILES else concurrency
                batch = remaining[:batch_size]
                await asyncio.gather(
                    *(self._fetch_js(session, url, timeout, stop) for url in batch),
                    return_exceptions=True,
                )
                # A rate-limited URL remains eligible for a retry after the shared cooldown.
                retry_urls = self._retry_urls.intersection(batch)
                self._analyzed_js_urls.update(set(batch) - retry_urls)
                self._retry_urls.difference_update(batch)
                if delay_seconds > 0 and (self.js_urls - self._analyzed_js_urls) and not stop():
                    await asyncio.sleep(delay_seconds)

        if MAX_JS_FILES and len(self.js_urls) > MAX_JS_FILES:
            self.on_log(f"[JS] File limit reached ({MAX_JS_FILES}); unprocessed files remain.")

    async def _request_gate(self, stop):
        """Apply shared adaptive pacing to all concurrent JS fetches."""
        await self._resume_event.wait()
        if stop() or self.rate_limit_stopped:
            return False
        async with self._request_gate_lock:
            loop = asyncio.get_running_loop()
            while not stop() and not self.rate_limit_stopped:
                await self._resume_event.wait()
                wait = self._next_request_time - loop.time()
                if wait <= 0:
                    self._next_request_time = loop.time() + self.rate_controller.current_delay
                    return True
                await asyncio.sleep(min(0.25, wait))
            return False

    async def _handle_rate_limit(self, url, response, stop):
        async with self._rate_limit_lock:
            if stop() or self.rate_limit_stopped:
                return False
            decision = self.rate_controller.on_rate_limit(
                response.headers.get("Retry-After"), status=int(response.status)
            )
            self._record_fetch_error(url, response.status, "HTTP rate limited")
            if decision.should_stop:
                self.rate_limit_stopped = True
                self.on_log(
                    f"[429] JavaScript discovery at {self._safe_url(url)}: {decision.reason}; "
                    "stopping this phase without retrying early."
                )
                self._resume_event.set()
                return False
            self._retry_urls.add(url)
            self._resume_event.clear()
            loop = asyncio.get_running_loop()
            deadline = loop.time() + decision.wait_seconds
            self.on_log(
                f"[Rate limit] JavaScript fetch received HTTP {response.status}; "
                f"waiting {decision.wait_seconds:.1f}s before retrying."
            )
            while loop.time() < deadline:
                if stop():
                    self._resume_event.set()
                    return False
                await asyncio.sleep(min(0.25, max(0.0, deadline - loop.time())))
            self._resume_event.set()
            return True

    async def _fetch_js(self, session, url, timeout, stop):
        if stop() or not self._in_scope(url):
            return
        if not await self._request_gate(stop):
            return
        try:
            request_headers = build_headers()
            request_headers["User-Agent"] = "Recon-GUI/3.2 (+authorized reconnaissance)"
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
                if resp.status in {429, 503}:
                    await self._handle_rate_limit(url, resp, stop)
                    return
                self.rate_controller.on_success()
                if resp.status != 200:
                    self._record_fetch_error(url, resp.status, f"HTTP {resp.status}; response not analyzed")
                    self.on_log(
                        f"[JS] Could not analyze {self._safe_url(url)}: HTTP {resp.status}."
                    )
                    return
                data = await resp.content.read(MAX_JS_BYTES + 1)
                if len(data) > MAX_JS_BYTES:
                    self.truncated_js_files.add(url)
                    data = data[:MAX_JS_BYTES]
                    self.on_log(f"[JS] Truncated oversized file: {url}")
                content = data.decode(resp.charset or "utf-8", errors="replace")
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError) as exc:
            self._record_fetch_error(url, 0, type(exc).__name__)
            self.on_log(f"[JS] Request failed for {self._safe_url(url)}: {type(exc).__name__}")
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
            "truncated_js_files": sorted(self.truncated_js_files),
            "js_fetch_errors": list(self.fetch_errors),
            "js_fetch_error_count": len(self.fetch_errors),
            "inline_script_count": len(self.inline_scripts),
            "endpoints": sorted(self.endpoints),
            "source_maps": sorted(self.source_maps),
            "discovered_routes": sorted(self.route_urls),
        }
