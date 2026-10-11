"""Async crawl engine with bounded workers, strict hostname scope, and TLS verification."""
import asyncio
import hashlib
from urllib.parse import urlparse, urljoin, urldefrag

import aiohttp
from crawler.parser import PageParser

MAX_BODY_BYTES = 5 * 1024 * 1024
REDIRECT_CODES = {301, 302, 303, 307, 308}


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
        # Kept in memory for analysis; deliberately omitted from to_dict().
        self.headers = {}
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
            "content_type": self.content_type,
            "content_hash": self.content_hash,
            "text_hash": self.text_hash,
            "favicon_hash": self.favicon_hash,
            "depth": self.depth,
            "error": self.error,
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
        self.visited: set = set()
        self.results: list = []
        self._schedule_lock = asyncio.Lock()

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
            "User-Agent": "Recon-GUI/2.1 (+authorized security testing)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        queue = asyncio.Queue()
        if seed_urls is None:
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
            if normalized in self.visited or len(self.visited) >= self.max_pages:
                continue
            self.visited.add(normalized)
            queue.put_nowait((normalized, depth))

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers,
            raise_for_status=False,
        ) as session:
            async def worker():
                while True:
                    item = await queue.get()
                    try:
                        if item is None:
                            return
                        if self.should_stop():
                            continue
                        url, depth = item
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

                        if result.status != 200 or depth >= self.max_depth or self.should_stop():
                            continue
                        for link in links:
                            normalized_link = _normalize_http_url(link)
                            if not normalized_link or not self._in_scope(normalized_link):
                                continue
                            async with self._schedule_lock:
                                # visited contains both queued and in-flight URLs, so the cap is reserved atomically.
                                if normalized_link in self.visited or len(self.visited) >= self.max_pages:
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

        self._log(f"Crawl finished: {len(self.results)} page responses recorded.")
        return self.results

    async def _crawl_one(self, session, url, depth):
        current_url = url
        redirect_chain = []
        final_status = 0
        content_type = ""
        html = ""
        response_headers = {}

        try:
            for _ in range(6):
                if self.should_stop():
                    return None, []
                async with session.get(current_url, allow_redirects=False) as response:
                    final_status = response.status
                    content_type = response.headers.get("Content-Type", "")
                    response_headers = dict(response.headers)
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
                    if "text/html" in content_type.lower() or "application/xhtml+xml" in content_type.lower():
                        body = await response.content.read(MAX_BODY_BYTES + 1)
                        if len(body) > MAX_BODY_BYTES:
                            body = body[:MAX_BODY_BYTES]
                            self._log(f"[LIMIT] Body truncated at {MAX_BODY_BYTES} bytes: {url}")
                        html = body.decode(response.charset or "utf-8", errors="replace")
                    break

            parsed = self.parser.parse(html, current_url) if html else {"title": "", "text": "", "links": []}
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
            )
            result.headers = response_headers
            result.depth = depth
            result.error = ""
            return result, parsed["links"] if html else []
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError) as exc:
            result = CrawlResult(
                url=url, status=final_status, title="", html="",
                redirect_chain=redirect_chain, final_url=current_url,
                content_type=content_type,
            )
            result.headers = response_headers
            result.depth = depth
            result.error = f"{type(exc).__name__}: {exc}"
            return result, []
