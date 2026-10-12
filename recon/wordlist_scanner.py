"""Low-rate optional wordlist path checks for authorized targets."""
import asyncio
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import aiohttp
from crawler.fetcher import build_headers

DEFAULT_EXTENSIONS = ["", ".html", ".php", ".bak", ".old", ".txt", ".zip"]
MAX_WORDS = 500
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_RETRY_AFTER_SECONDS = 120
MAX_RATE_LIMIT_PAUSES = 3


class WordlistScanner:
    def __init__(
        self, base_url: str, wordlist_path: str, extensions=None,
        concurrency: int = 5, timeout: int = 8, delay_ms: int = 200,
        on_hit=None, on_log=None, should_stop=None, on_result=None,
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
        self.on_result = on_result or (lambda result: None)
        self.hits = []
        # Complete per-candidate response history, including ordinary 404 responses.
        self.responses = []
        self.bad_status = {400, 404, 410, 429, 500, 502, 503, 504}
        self.baseline_size = None
        self._rate_limited = False  # True means safely stopped, not bypassed.
        self._rate_limit_pauses = 0
        self._resume_event = None
        self._rate_limit_lock = None
        self._rate_limit_cooldown_until = 0.0

    def _log(self, message: str):
        """Logging is best-effort and must not terminate a scan worker."""
        try:
            self.on_log(message)
        except Exception:
            pass

    def _notify_hit(self, url: str, status: int, size: int):
        """Report a hit without letting an external callback stop the scan."""
        try:
            self.on_hit(url, status, size)
        except Exception as exc:
            self._log(f"[Wordlist] Hit callback failed: {type(exc).__name__}: {exc}")

    def _notify_result(self, result: dict):
        """Emit every response for live tables; callback errors are non-fatal."""
        try:
            self.on_result(result)
        except Exception as exc:
            self._log(f"[Wordlist] Result callback failed: {type(exc).__name__}: {exc}")

    @staticmethod
    def _parse_retry_after(value):
        """Return Retry-After as seconds, or None when the header is absent/invalid."""
        if not value:
            return None
        value = str(value).strip()
        if value.isdigit():
            return float(int(value))
        try:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None

    async def _handle_429(self, headers, url):
        """Pause the queue only for a server-specified cool-down; otherwise stop safely."""
        async with self._rate_limit_lock:
            if self._rate_limited:
                return False

            loop = asyncio.get_running_loop()
            now = loop.time()
            # Several already-in-flight responses can return 429 together. One shared
            # wait covers that burst, rather than stacking duplicate sleeps.
            if self._rate_limit_pauses and now <= self._rate_limit_cooldown_until + 2.0:
                return True

            retry_after = self._parse_retry_after(headers.get("Retry-After"))
            if retry_after is None:
                self._rate_limited = True
                self._log(
                    f"[429] {url} returned Too Many Requests without a valid Retry-After. "
                    "Stopping content discovery; the scan will not try to evade the limit."
                )
                return False

            if retry_after > MAX_RETRY_AFTER_SECONDS:
                self._rate_limited = True
                self._log(
                    f"[429] Server requested a {retry_after:.0f}s wait, above the "
                    f"{MAX_RETRY_AFTER_SECONDS}s automatic wait ceiling. Stopping rather "
                    "than retrying early or bypassing the limit."
                )
                return False

            if self._rate_limit_pauses >= MAX_RATE_LIMIT_PAUSES:
                self._rate_limited = True
                self._log(
                    f"[429] Rate limit repeated {self._rate_limit_pauses} times. "
                    "Stopping content discovery to avoid continuing to pressure the target."
                )
                return False

            self._rate_limit_pauses += 1
            self._rate_limit_cooldown_until = now + retry_after
            self._resume_event.clear()
            self._log(
                f"[429] Pausing new requests for {retry_after:.1f}s as requested by "
                f"Retry-After (cool-down {self._rate_limit_pauses}/{MAX_RATE_LIMIT_PAUSES})."
            )
            try:
                await asyncio.sleep(retry_after)
            except asyncio.CancelledError:
                self._rate_limited = True
                raise

            if self.should_stop():
                self._rate_limited = True
                return False

            self._resume_event.set()
            self._log("[429] Cool-down complete; resuming remaining queued checks at the configured rate.")
            return True

    def _load_wordlist(self):
        if not self.wordlist_path.is_file():
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist_path}")
        entries = []
        for raw in self.wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            word = raw.strip()
            if word and not word.startswith("#"):
                entries.append(word.lstrip("/"))
            if len(entries) >= MAX_WORDS:
                self._log(f"[Wordlist] Limited to first {MAX_WORDS} entries.")
                break
        self._log(f"[Wordlist] Loaded {len(entries)} entries")
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
        baseline_url = urljoin(self.origin, "this-path-should-not-exist-recon-baseline-74c31")
        for attempt in range(2):
            if self.should_stop() or self._rate_limited:
                return
            await self._resume_event.wait()
            try:
                async with session.get(
                    baseline_url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=False,
                ) as resp:
                    if resp.status == 429:
                        headers = dict(resp.headers)
                        self._log(f"[Baseline] Received HTTP 429 from {baseline_url}.")
                        if attempt == 0 and await self._handle_429(headers, baseline_url):
                            continue
                        self._rate_limited = True
                        self._log("[Baseline] Rate limit persisted; stopping content discovery.")
                        return
                    data = await resp.content.read(MAX_RESPONSE_BYTES + 1)
                    self.baseline_size = len(data[:MAX_RESPONSE_BYTES])
                    self._log(
                        f"[Baseline] Reference response: HTTP {resp.status}, "
                        f"{self.baseline_size} bytes"
                    )
                    return
            except (aiohttp.ClientError, asyncio.TimeoutError):
                self.baseline_size = None
                return

    async def scan(self):
        words = self._load_wordlist()
        targets = list(dict.fromkeys(target for word in words for target in self._build_targets(word)))
        self._log(
            f"[Wordlist] Checking {len(targets)} candidates "
            f"(concurrency={self.concurrency}, delay={self.delay_ms}ms)."
        )
        self._resume_event = asyncio.Event()
        self._resume_event.set()
        self._rate_limit_lock = asyncio.Lock()
        queue = asyncio.Queue()
        for target in targets:
            queue.put_nowait(target)
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=min(self.timeout, 5))
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=True)
        headers = build_headers()

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers
        ) as session:
            await self._fetch_baseline(session)

            async def worker():
                while True:
                    url = await queue.get()
                    try:
                        if url is None:
                            return
                        await self._resume_event.wait()
                        if self.should_stop() or self._rate_limited:
                            continue
                        try:
                            rate_limit_headers = None
                            async with session.get(url, allow_redirects=False) as resp:
                                data = await resp.content.read(MAX_RESPONSE_BYTES + 1)
                                body = data[:MAX_RESPONSE_BYTES]
                                size = len(body)
                                text = body.decode(resp.charset or "utf-8", errors="replace")
                                word_count = len(text.split())
                                baseline_match = (
                                    self.baseline_size is not None
                                    and abs(size - self.baseline_size) < 50
                                )
                                result = {
                                    "url": url,
                                    "status": resp.status,
                                    "size": size,
                                    "word_count": word_count,
                                    "content_type": resp.headers.get("Content-Type", ""),
                                    "location": resp.headers.get("Location", ""),
                                    "baseline_match": baseline_match,
                                    "potential_hit": (
                                        resp.status not in self.bad_status
                                        and not baseline_match
                                    ),
                                }
                                self.responses.append(result)
                                self._notify_result(result)
                                if resp.status == 429:
                                    rate_limit_headers = dict(resp.headers)
                                elif result["potential_hit"]:
                                    self.hits.append(result)
                                    self._notify_hit(url, resp.status, size)

                            if rate_limit_headers is not None:
                                await self._handle_429(rate_limit_headers, url)
                        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                            self._log(f"[Wordlist] Request failed for {url}: {exc}")
                        except Exception as exc:
                            # A malformed response or optional callback should not kill a worker.
                            self._log(
                                f"[Wordlist] Unexpected error for {url}: "
                                f"{type(exc).__name__}: {exc}"
                            )

                        # Apply delay even for ordinary 404/filtered responses.
                        if self.delay_ms and not self.should_stop():
                            await asyncio.sleep(self.delay_ms / 1000)
                    finally:
                        queue.task_done()

            workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
            await queue.join()
            for _ in workers:
                queue.put_nowait(None)
            await queue.join()
            await asyncio.gather(*workers, return_exceptions=True)

        if self._rate_limited:
            self._log("[Wordlist] Ended early because the target is rate-limiting requests.")
        self._log(f"[Wordlist] Finished: {len(self.hits)} potential hits.")
        return self.hits
