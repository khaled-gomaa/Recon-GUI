"""Low-rate optional wordlist path checks for authorized targets."""
import asyncio
from pathlib import Path
from urllib.parse import urljoin, urlparse

import aiohttp
from crawler.fetcher import build_headers

DEFAULT_EXTENSIONS = ["", ".html", ".php", ".bak", ".old", ".txt", ".zip"]
MAX_WORDS = 500


class WordlistScanner:
    def __init__(
        self, base_url: str, wordlist_path: str, extensions=None,
        concurrency: int = 5, timeout: int = 8, delay_ms: int = 200,
        on_hit=None, on_log=None, should_stop=None,
    ):
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("base_url must be a valid HTTP(S) URL")
        self.origin = f"{parsed.scheme}://{parsed.netloc}/"
        self.base_host = parsed.hostname.lower()
        self.wordlist_path = Path(wordlist_path)
        self.extensions = extensions if extensions is not None else DEFAULT_EXTENSIONS
        self.concurrency = max(1, min(int(concurrency), 5))
        self.timeout = max(1, int(timeout))
        self.delay_ms = max(0, int(delay_ms))
        self.on_hit = on_hit or (lambda url, status, size: None)
        self.on_log = on_log or (lambda msg: None)
        self.should_stop = should_stop or (lambda: False)
        self.hits = []
        self.bad_status = {400, 404, 410, 429, 500, 502, 503, 504}
        self.baseline_size = None
        self._rate_limited = False

    def _load_wordlist(self):
        if not self.wordlist_path.is_file():
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist_path}")
        entries = []
        for raw in self.wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            word = raw.strip()
            if word and not word.startswith("#"):
                entries.append(word.lstrip("/"))
            if len(entries) >= MAX_WORDS:
                self.on_log(f"[Wordlist] Limited to first {MAX_WORDS} entries.")
                break
        self.on_log(f"[Wordlist] Loaded {len(entries)} entries")
        return entries

    def _build_targets(self, word: str):
        # Only relative path candidates are permitted; absolute URLs in wordlists are ignored.
        if "://" in word or word.startswith("//"):
            return []
        words = [word] if "/" in word or word.startswith(".") else [word + ext for ext in self.extensions]
        result = []
        for candidate in words:
            url = urljoin(self.origin, candidate)
            parsed = urlparse(url)
            if parsed.scheme in ("http", "https") and parsed.hostname and parsed.hostname.lower() == self.base_host:
                result.append(url)
        return result

    async def _fetch_baseline(self, session):
        try:
            async with session.get(
                urljoin(self.origin, "this-path-should-not-exist-recon-baseline-74c31"),
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                allow_redirects=False,
            ) as resp:
                data = await resp.content.read(1024 * 1024 + 1)
                self.baseline_size = len(data[:1024 * 1024])
                self.on_log(f"[Baseline] Reference response: HTTP {resp.status}, {self.baseline_size} bytes")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            self.baseline_size = None

    async def scan(self):
        words = self._load_wordlist()
        targets = list(dict.fromkeys(target for word in words for target in self._build_targets(word)))
        self.on_log(f"[Wordlist] Checking {len(targets)} candidates (concurrency={self.concurrency}, delay={self.delay_ms}ms).")
        queue = asyncio.Queue()
        for target in targets:
            queue.put_nowait(target)
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=min(self.timeout, 5))
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=True)
        headers = build_headers()

        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            await self._fetch_baseline(session)

            async def worker():
                while True:
                    url = await queue.get()
                    try:
                        if url is None:
                            return
                        if self.should_stop() or self._rate_limited:
                            continue
                        try:
                            async with session.get(url, allow_redirects=False) as resp:
                                data = await resp.content.read(1024 * 1024 + 1)
                                size = len(data[:1024 * 1024])
                                if resp.status in self.bad_status:
                                    if resp.status == 429:
                                        self.on_log(f"[Wordlist] Rate limited (429) at {url}; stopping checks.")
                                        self._rate_limited = True
                                    continue
                                if self.baseline_size is not None and abs(size - self.baseline_size) < 50:
                                    continue
                                hit = {
                                    "url": url, "status": resp.status, "size": size,
                                    "content_type": resp.headers.get("Content-Type", ""),
                                }
                                self.hits.append(hit)
                                self.on_hit(url, resp.status, size)
                        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                            self.on_log(f"[Wordlist] Request failed for {url}: {exc}")
                        if self.delay_ms:
                            await asyncio.sleep(self.delay_ms / 1000)
                    finally:
                        queue.task_done()

            workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
            await queue.join()
            for _ in workers:
                queue.put_nowait(None)
            await queue.join()
            await asyncio.gather(*workers, return_exceptions=True)

        self.on_log(f"[Wordlist] Finished: {len(self.hits)} potential hits.")
        return self.hits
