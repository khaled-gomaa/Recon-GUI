"""Async crawl engine with high concurrency, UA rotation, and full metadata."""
import asyncio
import hashlib
import aiohttp
from urllib.parse import urlparse, urljoin
from crawler.parser import PageParser
from crawler.fetcher import build_headers


class CrawlResult:
    def __init__(
        self,
        url: str,
        status: int,
        title: str,
        html: str,
        redirect_chain=None,
        final_url=None,
        word_count: int = 0,
        content_hash: str = "",
        text_hash: str = "",
        content_length: int = 0,
        content_type: str = "",
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
        }


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


class CrawlEngine:
    def __init__(
        self,
        start_url: str,
        max_depth: int = 2,
        max_pages: int = 100,
        concurrency: int = 50,
        on_page_crawled=None,
        on_log=None,
    ):
        self.start_url = start_url
        self.base_domain = urlparse(start_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.parser = PageParser(start_url)
        self.on_page_crawled = on_page_crawled
        self.on_log = on_log or (lambda msg: None)
        self.visited: set = set()
        self.results: list = []

    def _log(self, msg: str):
        self.on_log(msg)

    async def crawl(self):
        queue: asyncio.Queue = asyncio.Queue()
        await queue.put((self.start_url, 0))
        self.visited.add(self.start_url)

        semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            while not queue.empty() and len(self.results) < self.max_pages:
                url, depth = await queue.get()
                if depth > self.max_depth:
                    continue
                task = asyncio.create_task(
                    self._crawl_one(session, url, depth, queue, semaphore)
                )
                tasks.append(task)
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def _crawl_one(self, session, url, depth, queue, semaphore):
        async with semaphore:
            if len(self.results) >= self.max_pages:
                return

            current_url = url
            redirect_chain = []
            max_redirects = 5
            html = ""
            final_status = 0
            content_type = ""

            for _ in range(max_redirects + 1):
                try:
                    async with session.get(
                        current_url,
                        headers=build_headers(),
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=False,
                    ) as resp:
                        final_status = resp.status
                        content_type = resp.headers.get("Content-Type", "")

                        if resp.status in (301, 302, 303, 307, 308):
                            location = resp.headers.get("Location", "")
                            if not location:
                                break
                            next_url = urljoin(current_url, location)
                            redirect_chain.append({
                                "status": resp.status,
                                "from": current_url,
                                "to": next_url,
                            })
                            current_url = next_url
                            continue

                        if "text/html" in content_type or resp.status == 200:
                            html = await resp.text(errors="ignore")
                        break
                except Exception as exc:
                    self._log(f"[ERR] {current_url} -- {exc}")
                    return

            if not html:
                result = CrawlResult(
                    url=url, status=final_status, title="", html="",
                    redirect_chain=redirect_chain, final_url=current_url,
                    content_type=content_type,
                )
                self.results.append(result)
                self._log(f"[{final_status}] {url}"
                          + (f" -> {current_url}" if current_url != url else ""))
                if self.on_page_crawled:
                    self.on_page_crawled(result)
                return

            parsed = self.parser.parse(html, current_url)
            text = parsed["text"]
            word_count = len(text.split())

            result = CrawlResult(
                url=url,
                status=final_status,
                title=parsed["title"],
                html=html,
                redirect_chain=redirect_chain,
                final_url=current_url,
                word_count=word_count,
                content_hash=_hash(html),
                text_hash=_hash(text),
                content_length=len(html),
                content_type=content_type,
            )
            self.results.append(result)

            redirect_note = ""
            if redirect_chain:
                chain_str = " -> ".join(str(c["status"]) for c in redirect_chain)
                redirect_note = f" [{chain_str} -> {final_status}]"

            self._log(f"[{final_status}]{redirect_note} {url} -- "
                      f"{word_count} words -- {parsed['title'][:50]}")

            if self.on_page_crawled:
                self.on_page_crawled(result)

            if final_status != 200 or depth >= self.max_depth:
                return

            for link in parsed["links"]:
                if (PageParser.is_same_domain(link, self.start_url)
                        and link not in self.visited):
                    self.visited.add(link)
                    await queue.put((link, depth + 1))
