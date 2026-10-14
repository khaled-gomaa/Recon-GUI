"""Low-rate optional wordlist path checks for authorized targets."""
import asyncio
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import aiohttp
from crawler.fetcher import build_headers

# Broad, common web extensions. Keep the extension list configurable in the GUI.
DEFAULT_EXTENSIONS = [
    "", ".html", ".htm", ".xhtml", ".php", ".php3", ".php4", ".php5", ".phtml",
    ".asp", ".aspx", ".jsp", ".jspx", ".cfm", ".cgi", ".pl", ".py", ".rb",
    ".json", ".xml", ".txt", ".js", ".mjs", ".css", ".map", ".yaml", ".yml",
    ".conf", ".config", ".ini", ".env", ".log", ".bak", ".old", ".orig", ".save",
    ".backup", ".swp", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".sql",
    ".db", ".pdf", ".csv",
]
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_RETRY_AFTER_SECONDS = 120
MAX_RATE_LIMIT_PAUSES = 3


class WordlistScanner:
    def __init__(
        self, base_url: str, wordlist_path: str, extensions=None,
        concurrency: int = 5, timeout: int = 8, delay_ms: int = 200,
        on_hit=None, on_log=None, should_stop=None, on_result=None, request_headers=None,
        max_words: int = 0, max_candidates: int = 0, methods=None, cookie_jar=None,
    ):
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("base_url must be a valid HTTP(S) URL")
        self.origin = f"{parsed.scheme}://{parsed.netloc}/"
        self.base_host = parsed.hostname.lower()
        self.wordlist_path = Path(wordlist_path)
        selected_extensions = DEFAULT_EXTENSIONS if extensions is None else list(extensions)
        normalized_extensions = []
        for extension in selected_extensions:
            extension = str(extension or "").strip()
            if extension and not extension.startswith("."):
                extension = "." + extension
            if extension and ("/" in extension or "\\" in extension or "?" in extension or "#" in extension):
                continue
            if extension not in normalized_extensions:
                normalized_extensions.append(extension)
        self.extensions = [""] + [item for item in normalized_extensions if item]
        self.max_words = max(0, int(max_words))  # 0 means every non-comment line in the list.
        self.max_candidates = max(0, int(max_candidates))  # 0 means no artificial candidate cap.
        allowed_methods = {"GET", "HEAD", "OPTIONS"}
        selected_methods = methods if methods is not None else ["GET"]
        self.methods = list(dict.fromkeys(
            str(item).strip().upper() for item in selected_methods
            if str(item).strip().upper() in allowed_methods
        )) or ["GET"]
        self.cookie_jar = cookie_jar
        self.scan_metadata = {}
        self.concurrency = max(1, min(int(concurrency), 5))
        self.timeout = max(1, int(timeout))
        self.delay_ms = max(0, int(delay_ms))
        self.on_hit = on_hit or (lambda url, status, size: None)
        self.on_log = on_log or (lambda msg: None)
        self.should_stop = should_stop or (lambda: False)
        self.on_result = on_result or (lambda result: None)
        self.request_headers = dict(request_headers or {})
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
                self._resume_event.set()
                return False

            if retry_after > MAX_RETRY_AFTER_SECONDS:
                self._rate_limited = True
                self._log(
                    f"[429] Server requested a {retry_after:.0f}s wait, above the "
                    f"{MAX_RETRY_AFTER_SECONDS}s automatic wait ceiling. Stopping rather "
                    "than retrying early or bypassing the limit."
                )
                self._resume_event.set()
                return False

            if self._rate_limit_pauses >= MAX_RATE_LIMIT_PAUSES:
                self._rate_limited = True
                self._log(
                    f"[429] Rate limit repeated {self._rate_limit_pauses} times. "
                    "Stopping content discovery to avoid continuing to pressure the target."
                )
                self._resume_event.set()
                return False

            self._rate_limit_pauses += 1
            self._rate_limit_cooldown_until = now + retry_after
            self._resume_event.clear()
            self._log(
                f"[429] Pausing new requests for {retry_after:.1f}s as requested by "
                f"Retry-After (cool-down {self._rate_limit_pauses}/{MAX_RATE_LIMIT_PAUSES})."
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
            self._log("[429] Cool-down complete; resuming remaining queued checks at the configured rate.")
            return True

    def _load_wordlist(self):
        if not self.wordlist_path.is_file():
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist_path}")
        entries = []
        for raw in self.wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            word = raw.strip()
            if not word or word.startswith("#"):
                continue
            word = word.lstrip("/")
            # Reject absolute URLs and path traversal before building candidates.
            if "://" in word or word.startswith("//") or any(part == ".." for part in word.replace("\\\\", "/").split("/")):
                continue
            entries.append(word)
            if self.max_words and len(entries) >= self.max_words:
                self._log(f"[Wordlist] Word cap reached ({self.max_words}); remaining entries were not loaded.")
                break
        self._log(f"[Wordlist] Loaded {len(entries)} entries" + (" (no word cap)." if not self.max_words else ""))
        return entries

    def _build_targets(self, word: str):
        # Only relative path candidates are permitted; absolute URLs and traversal are ignored.
        word = str(word or "").strip().replace("\\\\", "/").lstrip("/")
        if not word or "://" in word or word.startswith("//") or any(
            part == ".." for part in word.split("/")
        ):
            return []
        basename = word.rstrip("/").rsplit("/", 1)[-1]
        has_extension = bool(re.search(r"\\.[A-Za-z0-9_-]{1,12}$", basename)) or basename.startswith(".")
        if word.endswith("/") or has_extension:
            candidates = [word]
        else:
            candidates = [word + extension for extension in self.extensions]
        result = []
        for candidate in candidates:
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
        targets = []
        seen_targets = set()
        candidates_truncated = False
        for word in words:
            for target in self._build_targets(word):
                if target in seen_targets:
                    continue
                if self.max_candidates and len(targets) >= self.max_candidates:
                    candidates_truncated = True
                    break
                seen_targets.add(target)
                targets.append(target)
            if candidates_truncated:
                break
        if candidates_truncated:
            self._log(
                f"[Wordlist] Candidate cap reached ({self.max_candidates}); "
                "increase the cap or set it to 0 to try every generated path."
            )
        request_candidates = [(method, url) for url in targets for method in self.methods]
        self.scan_metadata = {
            "words_loaded": len(words), "unique_path_candidates": len(targets),
            "methods": list(self.methods), "request_candidates": len(request_candidates),
            "max_words": self.max_words, "max_candidates": self.max_candidates,
            "word_cap_enabled": bool(self.max_words), "candidate_cap_enabled": bool(self.max_candidates),
            "candidates_truncated": candidates_truncated, "requests_completed": 0,
        }
        self._log(
            f"[Wordlist] Checking {len(targets)} paths / {len(request_candidates)} HTTP requests "
            f"using {', '.join(self.methods)} (concurrency={self.concurrency}, delay={self.delay_ms}ms)."
        )
        self._resume_event = asyncio.Event()
        self._resume_event.set()
        self._rate_limit_lock = asyncio.Lock()
        queue = asyncio.Queue()
        for request_candidate in request_candidates:
            queue.put_nowait(request_candidate)
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=min(self.timeout, 5))
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=True)
        headers = build_headers()
        headers.update({
            str(key): str(value) for key, value in self.request_headers.items()
            if str(key).lower() in {"authorization", "cookie", "accept-language"}
            and "\r" not in str(value) and "\n" not in str(value)
        })

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers, cookie_jar=self.cookie_jar
        ) as session:
            await self._fetch_baseline(session)

            async def worker():
                while True:
                    request_item = await queue.get()
                    try:
                        if request_item is None:
                            return
                        method, url = request_item
                        await self._resume_event.wait()
                        if self.should_stop() or self._rate_limited:
                            continue
                        try:
                            rate_limit_headers = None
                            async with session.request(method, url, allow_redirects=False) as resp:
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
                                    "method": method,
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
                                self.scan_metadata["requests_completed"] = len(self.responses)
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
        self.rate_limit_stopped = self._rate_limited and not self.should_stop()
        self.scan_metadata["requests_completed"] = len(self.responses)
        self.scan_metadata["potential_hits"] = len(self.hits)
        self._log(
            f"[Wordlist] Finished: {len(self.responses)}/{len(request_candidates)} requests, "
            f"{len(self.hits)} potential hits."
        )
        return self.hits
