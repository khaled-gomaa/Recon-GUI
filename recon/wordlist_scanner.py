"""Wordlist-based directory/file scanner (like gobuster/dirb)."""
import asyncio
import aiohttp
from pathlib import Path
from urllib.parse import urljoin
from crawler.fetcher import build_headers

DEFAULT_EXTENSIONS = ["", ".html", ".php", ".bak", ".old", ".txt", ".zip"]


class WordlistScanner:
    def __init__(
        self,
        base_url: str,
        wordlist_path: str,
        extensions=None,
        concurrency: int = 50,
        timeout: int = 8,
        on_hit=None,
        on_log=None,
    ):
        self.base_url = base_url.rstrip("/") + "/"
        self.wordlist_path = Path(wordlist_path)
        self.extensions = extensions if extensions is not None else DEFAULT_EXTENSIONS
        self.concurrency = concurrency
        self.timeout = timeout
        self.on_hit = on_hit or (lambda url, status, size: None)
        self.on_log = on_log or (lambda msg: None)
        self.hits: list = []
        self.bad_status = {400, 404, 410, 500, 502, 503}
        self.baseline_size = None

    def _load_wordlist(self) -> list:
        if not self.wordlist_path.exists():
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist_path}")
        entries = []
        for line in self.wordlist_path.read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line)
        self.on_log(f"[Wordlist] Loaded {len(entries)} entries")
        return entries

    def _build_targets(self, word: str) -> list:
        targets = []
        if "/" in word or word.startswith("."):
            targets.append(urljoin(self.base_url, word))
        else:
            for ext in self.extensions:
                targets.append(urljoin(self.base_url, word + ext))
        return targets

    async def _fetch_baseline(self, session):
        try:
            async with session.get(
                urljoin(self.base_url, "this-does-not-exist-9x8y7z"),
                headers=build_headers(),
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                body = await resp.read()
                self.baseline_size = len(body)
                self.on_log(f"[Baseline] 404 size = {self.baseline_size} bytes")
        except Exception:
            self.baseline_size = None

    async def _check_one(self, session, url, semaphore):
        async with semaphore:
            try:
                async with session.get(
                    url,
                    headers=build_headers(),
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=False,
                ) as resp:
                    body = await resp.read()
                    size = len(body)
                    if resp.status in self.bad_status:
                        return
                    if self.baseline_size and abs(size - self.baseline_size) < 50:
                        return
                    hit = {
                        "url": url,
                        "status": resp.status,
                        "size": size,
                        "content_type": resp.headers.get("Content-Type", ""),
                    }
                    self.hits.append(hit)
                    self.on_hit(url, resp.status, size)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

    async def scan(self):
        words = self._load_wordlist()
        semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)

        async with aiohttp.ClientSession(connector=connector) as session:
            await self._fetch_baseline(session)
            tasks = []
            for word in words:
                for target in self._build_targets(word):
                    tasks.append(asyncio.create_task(
                        self._check_one(session, target, semaphore)
                    ))
            await asyncio.gather(*tasks, return_exceptions=True)

        self.on_log(f"[Wordlist] Done. {len(self.hits)} hits.")
        return self.hits
