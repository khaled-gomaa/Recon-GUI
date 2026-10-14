"""Async crawl engine with bounded workers, strict hostname scope, and TLS verification."""
import asyncio
import gzip
import hashlib
import io
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse, urljoin, urldefrag

import aiohttp
from crawler.parser import PageParser

MAX_BODY_BYTES = 5 * 1024 * 1024
MAX_DECOMPRESSED_SITEMAP_BYTES = 20 * 1024 * 1024
REDIRECT_CODES = {301, 302, 303, 307, 308}
MAX_RETRY_AFTER_SECONDS = 120
MAX_RATE_LIMIT_PAUSES = 3


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _normalize_http_url(url: str):
    """Canonicalize HTTP(S) URLs for safe, predictable deduplication."""
    if not url:
        return None
    try:
        url, _ = urldefrag(url.strip())
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        # Accessing .port validates malformed ports (for example, ":notaport").
        port = parsed.port
    except (AttributeError, TypeError, ValueError):
        return None

    if scheme not in ("http", "https") or not hostname:
        return None

    hostname = hostname.rstrip(".").lower()
    if not hostname:
        return None
    # DNS names are case-insensitive and Unicode labels have an ASCII wire form.
    if ":" not in hostname:
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return None

    # Keep IPv6 literals bracketed when rebuilding the authority component.
    netloc_host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        netloc_host = f"{netloc_host}:{port}"

    # Preserve explicit user-info when present; only normalize the host/port.
    user_info = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    path = parsed.path or "/"
    return parsed._replace(
        scheme=scheme,
        netloc=user_info + netloc_host,
        path=path,
        fragment="",
    ).geturl()


class CrawlResult:
    def __init__(
        self, url: str, status: int, title: str, html: str,
        redirect_chain=None, final_url=None, word_count: int = 0,
        content_hash: str = "", text_hash: str = "",
        content_length: int = 0, content_type: str = "",
        favicon_hash: str = "",
        links=None, body_truncated: bool = False, asset_references=None,
    ):
        self.url = url
        self.status = status
        self.title = title
        self.html = html
        self.redirect_chain = redirect_chain or []
        self.final_url = final_url or url
        self.word_count = word_count
        self.content_hash = content_hash
        self.text_hash = text_hash
        self.content_length = content_length
        self.content_type = content_type
        self.favicon_hash = favicon_hash
        self.links = list(links or [])
        self.asset_references = list(asset_references or [])
        self.body_truncated = bool(body_truncated)
        # Kept in memory for analysis; deliberately omitted from to_dict().
        self.headers = {}
        self.cookie_events = []
        self.depth = 0
        self.error = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "title": self.title,
            "final_url": self.final_url,
            "redirect_chain": self.redirect_chain,
            "word_count": self.word_count,
            "content_length": self.content_length,
            "body_truncated": self.body_truncated,
            "content_type": self.content_type,
            "content_hash": self.content_hash,
            "text_hash": self.text_hash,
            "favicon_hash": self.favicon_hash,
            "depth": self.depth,
            "error": self.error,
            "cookie_events": list(self.cookie_events),
        }


class CrawlEngine:
    def __init__(
        self,
        start_url: str,
        max_depth: int = 2,
        max_pages: int = 100,
        concurrency: int = 5,
        on_page_crawled=None,
        on_log=None,
        should_stop=None,
        request_headers=None,
        respect_robots=True,
        cookie_jar=None,
    ):
        normalized = _normalize_http_url(start_url)
        if not normalized:
            raise ValueError("start_url must be a full http:// or https:// URL")
        self.start_url = normalized
        self.base_domain = (urlparse(normalized).hostname or "").lower()
        self.max_depth = max(0, int(max_depth))
        self.max_pages = max(1, int(max_pages))
        self.concurrency = max(1, min(int(concurrency), 20))
        self.parser = PageParser(self.start_url)
        self.on_page_crawled = on_page_crawled
        self.on_log = on_log or (lambda msg: None)
        self.should_stop = should_stop or (lambda: False)
        self.request_headers = {
            str(key): str(value) for key, value in (request_headers or {}).items()
            if str(key).lower() in {"authorization", "cookie", "accept-language"}
            and "\r" not in str(value) and "\n" not in str(value)
        }
        self.respect_robots = bool(respect_robots)
        self.cookie_jar = cookie_jar
        self.crawl_delay_seconds = 0.0
        self.robots_url = ""
        self._robots_loaded = False
        self._request_gate_lock = asyncio.Lock()
        self._next_request_time = 0.0
        self.visited: set = set()
        self.results: list = []
        self._schedule_lock = asyncio.Lock()
        self.rate_limit_stopped = False
        self.page_limit_reached = False
        self.depth_limit_reached = False
        self._page_limit_logged = False
        self._depth_limit_logged = False
        self._rate_limit_pauses = 0
        self._resume_event = None
        self._rate_limit_lock = None
        self._rate_limit_cooldown_until = 0.0

    @staticmethod
    def _parse_retry_after(headers: dict):
        value = next(
            (str(v).strip() for k, v in (headers or {}).items()
             if str(k).lower() == "retry-after"),
            None,
        )
        if not value:
            return None
        if value.isdigit():
            return float(int(value))
        try:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None

    async def _handle_429(self, headers: dict, url: str):
        """Honor Retry-After or stop safely; never attempt to evade rate limiting."""
        async with self._rate_limit_lock:
            if self.rate_limit_stopped:
                return False

            loop = asyncio.get_running_loop()
            now = loop.time()
            if self._rate_limit_pauses and now <= self._rate_limit_cooldown_until + 2.0:
                return True

            retry_after = self._parse_retry_after(headers)
            if retry_after is None:
                self.rate_limit_stopped = True
                self._log(
                    f"[429] {url} returned Too Many Requests without a valid Retry-After. "
                    "Stopping new crawl requests instead of bypassing the limit."
                )
                self._resume_event.set()
                return False
            if retry_after > MAX_RETRY_AFTER_SECONDS:
                self.rate_limit_stopped = True
                self._log(
                    f"[429] Server requested a {retry_after:.0f}s wait, above the "
                    f"{MAX_RETRY_AFTER_SECONDS}s automatic wait ceiling. Stopping rather "
                    "than retrying early."
                )
                self._resume_event.set()
                return False
            if self._rate_limit_pauses >= MAX_RATE_LIMIT_PAUSES:
                self.rate_limit_stopped = True
                self._log(
                    f"[429] Rate limit repeated {self._rate_limit_pauses} times. "
                    "Stopping new crawl requests to avoid additional pressure."
                )
                self._resume_event.set()
                return False

            self._rate_limit_pauses += 1
            self._rate_limit_cooldown_until = now + retry_after
            self._resume_event.clear()
            self._log(
                f"[429] Pausing new crawl requests for {retry_after:.1f}s per Retry-After "
                f"(cool-down {self._rate_limit_pauses}/{MAX_RATE_LIMIT_PAUSES})."
            )
            deadline = loop.time() + retry_after
            while loop.time() < deadline:
                if self.should_stop():
                    self._resume_event.set()
                    return False
                await asyncio.sleep(min(0.25, max(0.0, deadline - loop.time())))
            if self.should_stop():
                self._resume_event.set()
                return False
            self._resume_event.set()
            self._log("[429] Cool-down complete; resuming queued crawl requests at the configured rate.")
            return True

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

    def _headers_for_url(self, url: str) -> dict:
        """Never send session credentials to a different scheme/host/port."""
        if self._origin(url) == self._origin(self.start_url):
            return dict(self.request_headers)
        return {}

    def _in_scope(self, url: str) -> bool:
        try:
            host = urlparse(url).hostname
            if not host:
                return False
            host = host.rstrip(".").lower()
            if ":" not in host:
                host = host.encode("idna").decode("ascii")
            return host == self.base_domain
        except (UnicodeError, ValueError):
            return False

    @staticmethod
    def _parse_crawl_delay(robots_text: str) -> float:
        """Read the applicable non-standard Crawl-delay directive."""
        groups = []
        agents, delays, has_directive = [], [], False
        for raw_line in (robots_text or "").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, value = (part.strip() for part in line.split(":", 1))
            if key.lower() == "user-agent":
                if agents and has_directive:
                    groups.append((agents, delays))
                    agents, delays, has_directive = [], [], False
                agents.append(value.lower())
            elif agents:
                has_directive = True
                if key.lower() == "crawl-delay":
                    try:
                        delay = float(value)
                        if 0 <= delay <= 86400:
                            delays.append(delay)
                    except (TypeError, ValueError, OverflowError):
                        pass
        if agents:
            groups.append((agents, delays))
        specific, wildcard = [], []
        for group_agents, group_delays in groups:
            if not group_delays:
                continue
            if any(agent in {"recon-gui", "recon-gui/3.0"} for agent in group_agents):
                specific.extend(group_delays)
            elif "*" in group_agents:
                wildcard.extend(group_delays)
        candidates = specific or wildcard
        return max(candidates) if candidates else 0.0

    async def _load_robots(self, session):
        """Fetch robots.txt once and adopt Crawl-delay when present."""
        self._robots_loaded = True
        parsed = urlparse(self.start_url)
        self.robots_url = parsed._replace(path="/robots.txt", params="", query="", fragment="").geturl()
        try:
            async with session.get(self.robots_url, headers=self._headers_for_url(self.robots_url) or None, allow_redirects=False) as response:
                if response.status == 429:
                    await self._handle_429(dict(response.headers), self.robots_url)
                    return
                if response.status != 200:
                    self._log(f"[robots.txt] HTTP {response.status}; no Crawl-delay directive applied.")
                    return
                data = await response.content.read(1024 * 1024 + 1)
                text = data[:1024 * 1024].decode(response.charset or "utf-8", errors="replace")
                self.crawl_delay_seconds = self._parse_crawl_delay(text)
                if self.crawl_delay_seconds:
                    self._log(f"[robots.txt] Respecting Crawl-delay={self.crawl_delay_seconds:g}s.")
                else:
                    self._log("[robots.txt] No applicable Crawl-delay directive.")
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, ValueError) as exc:
            self._log(f"[robots.txt] Could not read Crawl-delay: {type(exc).__name__}: {exc}")

    async def _request_gate(self) -> bool:
        """Serialize request start times when robots.txt asks for a delay."""
        delay = self.crawl_delay_seconds
        if delay <= 0:
            return not self.should_stop()
        async with self._request_gate_lock:
            loop = asyncio.get_running_loop()
            while not self.should_stop():
                wait = self._next_request_time - loop.time()
                if wait <= 0:
                    self._next_request_time = loop.time() + delay
                    return True
                await asyncio.sleep(min(0.25, wait))
            return False

    def _log(self, message: str):
        """Best-effort logging: a GUI callback must never break crawl workers."""
        try:
            self.on_log(message)
        except Exception:
            # Logging is auxiliary; keep crawling even if a UI/log adapter fails.
            pass

    async def crawl(self, seed_urls=None, seed_depth=0):
        """Crawl the start URL once, or crawl additional same-host seeds with existing limits."""
        timeout = aiohttp.ClientTimeout(total=15, connect=8)
        # Keep certificate verification enabled. Never disable TLS verification for recon.
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=True)
        headers = {
            "User-Agent": "Recon-GUI/3.0 (+authorized security testing)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        queue = asyncio.Queue()
        self._resume_event = asyncio.Event()
        self._resume_event.set()
        self._rate_limit_lock = asyncio.Lock()
        if self.rate_limit_stopped:
            seed_items = []
        elif seed_urls is None:
            seed_items = [(self.start_url, 0)]
        else:
            try:
                depth = max(0, int(seed_depth))
            except (TypeError, ValueError):
                depth = 0
            seed_items = [(url, depth) for url in seed_urls]

        # Reserve seeds before workers start so concurrency cannot exceed max_pages.
        for raw_url, depth in seed_items:
            normalized = _normalize_http_url(raw_url)
            if not normalized or not self._in_scope(normalized):
                continue
            if normalized in self.visited:
                continue
            if len(self.visited) >= self.max_pages:
                self.page_limit_reached = True
                if not self._page_limit_logged:
                    self._log(
                        f"[LIMIT] Max pages ({self.max_pages}) reached while adding seeds; "
                        "some candidate URLs were not crawled."
                    )
                    self._page_limit_logged = True
                continue
            self.visited.add(normalized)
            queue.put_nowait((normalized, depth))

        session_options = {
            "connector": connector, "timeout": timeout, "headers": headers,
            "raise_for_status": False,
        }
        if self.cookie_jar is not None:
            session_options["cookie_jar"] = self.cookie_jar
        async with aiohttp.ClientSession(**session_options) as session:
            if self.respect_robots and not self._robots_loaded:
                await self._load_robots(session)

            async def worker():
                while True:
                    item = await queue.get()
                    try:
                        if item is None:
                            return
                        if self.should_stop():
                            continue
                        url, depth = item
                        await self._resume_event.wait()
                        if self.should_stop() or self.rate_limit_stopped:
                            continue
                        result, links = await self._crawl_one(session, url, depth)
                        if result is None:
                            continue
                        self.results.append(result)
                        self._log(
                            f"[{result.status or 'ERR'}] depth={depth} {url}"
                            + (f" -> {result.final_url}" if result.final_url != url else "")
                            + (f" -- {result.title[:60]}" if result.title else "")
                            + (f" -- {result.error}" if result.error else "")
                        )
                        if self.on_page_crawled:
                            try:
                                self.on_page_crawled(result)
                            except Exception as exc:
                                # UI/reporting callbacks must not prevent discovery from continuing.
                                self._log(f"[CALLBACK ERROR] {type(exc).__name__}: {exc}")

                        if result.status == 429:
                            await self._handle_429(result.headers, url)
                            continue

                        if result.status != 200 or self.should_stop() or self.rate_limit_stopped:
                            continue
                        if depth >= self.max_depth:
                            has_unvisited_in_scope_links = any(
                                (candidate := _normalize_http_url(link))
                                and self._in_scope(candidate)
                                and candidate not in self.visited
                                for link in links
                            )
                            if has_unvisited_in_scope_links:
                                self.depth_limit_reached = True
                                if not self._depth_limit_logged:
                                    self._log(
                                        f"[LIMIT] Max depth ({self.max_depth}) reached with additional "
                                        "same-host links still undiscovered by crawling."
                                    )
                                    self._depth_limit_logged = True
                            continue
                        for link in links:
                            normalized_link = _normalize_http_url(link)
                            if not normalized_link or not self._in_scope(normalized_link):
                                continue
                            async with self._schedule_lock:
                                # visited contains both queued and in-flight URLs, so the cap is reserved atomically.
                                if normalized_link in self.visited:
                                    continue
                                if len(self.visited) >= self.max_pages:
                                    self.page_limit_reached = True
                                    if not self._page_limit_logged:
                                        self._log(
                                            f"[LIMIT] Max pages ({self.max_pages}) reached; further "
                                            "same-host links were discovered but not queued."
                                        )
                                        self._page_limit_logged = True
                                    continue
                                self.visited.add(normalized_link)
                                queue.put_nowait((normalized_link, depth + 1))
                    except Exception as exc:
                        self._log(f"[WORKER ERROR] {type(exc).__name__}: {exc}")
                    finally:
                        queue.task_done()

            workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
            await queue.join()
            for _ in workers:
                queue.put_nowait(None)
            await queue.join()
            await asyncio.gather(*workers, return_exceptions=True)

        if self.rate_limit_stopped:
            self._log("[Crawl] Stopped early because a safe Retry-After resume was not available.")
        self._log(f"Crawl finished: {len(self.results)} page responses recorded.")
        if self.page_limit_reached:
            self._log("[Crawl] Result is partial because the configured page limit was reached.")
        if self.depth_limit_reached:
            self._log("[Crawl] Result is partial because the configured depth limit left same-host links unvisited.")
        return self.results

    async def _crawl_one(self, session, url, depth):
        current_url = url
        redirect_chain = []
        final_status = 0
        content_type = ""
        html = ""
        response_headers = {}
        cookie_events = []
        response_body_truncated = False

        try:
            for _ in range(6):
                if self.should_stop() or not await self._request_gate():
                    return None, []
                async with session.get(current_url, headers=self._headers_for_url(current_url) or None, allow_redirects=False) as response:
                    final_status = response.status
                    content_type = response.headers.get("Content-Type", "")
                    response_headers = dict(response.headers)
                    for cookie_name, morsel in response.cookies.items():
                        cookie_events.append({
                            "name": cookie_name,
                            "domain": morsel.get("domain", ""),
                            "path": morsel.get("path", ""),
                            "secure": bool(morsel.get("secure", "")),
                            "httponly": bool(morsel.get("httponly", "")),
                            "samesite": morsel.get("samesite", ""),
                        })
                    if final_status in REDIRECT_CODES:
                        location = response.headers.get("Location", "")
                        if not location:
                            break
                        candidate = _normalize_http_url(urljoin(current_url, location))
                        if not candidate:
                            break
                        redirect_chain.append({
                            "status": final_status,
                            "from": current_url,
                            "to": candidate,
                        })
                        # Record but never request a redirect destination outside the starting hostname.
                        current_url = candidate
                        if not self._in_scope(candidate):
                            break
                        continue
                    current_path = urlparse(current_url).path.lower()
                    is_html = "text/html" in content_type.lower() or "application/xhtml+xml" in content_type.lower()
                    is_gzipped_sitemap = current_path.endswith(".xml.gz")
                    is_xml = (
                        "xml" in content_type.lower()
                        or current_path.endswith((".xml", ".xml.gz"))
                    )
                    is_robots = current_path == "/robots.txt" or current_path.endswith("/robots.txt")
                    if is_html or is_xml or is_robots:
                        body = await response.content.read(MAX_BODY_BYTES + 1)
                        if len(body) > MAX_BODY_BYTES:
                            response_body_truncated = True
                            body = body[:MAX_BODY_BYTES]
                            self._log(f"[LIMIT] Body truncated at {MAX_BODY_BYTES} bytes: {url}")
                        if is_gzipped_sitemap:
                            if response_body_truncated:
                                self._log(
                                    f"[LIMIT] Compressed sitemap exceeded {MAX_BODY_BYTES} bytes; "
                                    f"it was not partially decompressed: {url}"
                                )
                                body = b""
                            else:
                                try:
                                    with gzip.GzipFile(fileobj=io.BytesIO(body), mode="rb") as compressed:
                                        body = compressed.read(MAX_DECOMPRESSED_SITEMAP_BYTES + 1)
                                    if len(body) > MAX_DECOMPRESSED_SITEMAP_BYTES:
                                        response_body_truncated = True
                                        body = body[:MAX_DECOMPRESSED_SITEMAP_BYTES]
                                        self._log(
                                            f"[LIMIT] Decompressed sitemap capped at "
                                            f"{MAX_DECOMPRESSED_SITEMAP_BYTES} bytes: {url}"
                                        )
                                except (OSError, EOFError, gzip.BadGzipFile) as exc:
                                    response_body_truncated = True
                                    body = b""
                                    self._log(
                                        f"[Sitemap] Could not decompress {url}: {type(exc).__name__}"
                                    )
                        html = body.decode("utf-8" if is_gzipped_sitemap else (response.charset or "utf-8"), errors="replace")
                    break

            parsed = self.parser.parse(html, current_url) if html else {
                "title": "", "text": "", "links": [], "assets": [],
            }
            page_text = parsed["text"]
            result = CrawlResult(
                url=url,
                status=final_status,
                title=parsed["title"],
                html=html,
                redirect_chain=redirect_chain,
                final_url=current_url,
                word_count=len(page_text.split()),
                content_hash=_hash(html) if html else "",
                text_hash=_hash(page_text) if page_text else "",
                content_length=len(html.encode("utf-8")),
                content_type=content_type,
                links=parsed.get("links", []) if html else [],
                asset_references=parsed.get("assets", []) if html else [],
                body_truncated=response_body_truncated,
            )
            result.headers = response_headers
            result.cookie_events = cookie_events
            result.depth = depth
            result.error = ""
            return result, parsed["links"] if html else []
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError) as exc:
            result = CrawlResult(
                url=url, status=final_status, title="", html="",
                redirect_chain=redirect_chain, final_url=current_url,
                content_type=content_type, body_truncated=response_body_truncated,
            )
            result.headers = response_headers
            result.cookie_events = cookie_events
            result.depth = depth
            result.error = f"{type(exc).__name__}: {exc}"
            return result, []
