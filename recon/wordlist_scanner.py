"""Low-rate optional wordlist path checks for authorized targets."""
import asyncio
import hashlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import aiohttp
from crawler.fetcher import build_headers

# Common web/application and backup/config extensions. A blank extension probes the
# path exactly as written. Users can override this list from the GUI.
DEFAULT_EXTENSIONS = [
    "", ".php", ".php3", ".php4", ".php5", ".phtml", ".html", ".htm", ".xhtml",
    ".js", ".mjs", ".json", ".xml", ".txt", ".css", ".map", ".yaml", ".yml",
    ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action", ".cfm", ".cgi", ".pl", ".py", ".rb",
    ".env", ".conf", ".config", ".ini", ".log", ".csv", ".sql", ".db", ".sqlite",
    ".bak", ".old", ".orig", ".backup", ".save", ".swp", ".zip", ".tar", ".tar.gz",
    ".tgz", ".gz", ".7z", ".rar", ".pdf", ".md",
]
# Backward-compatible symbol: zero means no implicit word-count cap.
MAX_WORDS = 0
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_RETRY_AFTER_SECONDS = 120
MAX_RATE_LIMIT_PAUSES = 3


class WordlistScanner:
    def __init__(
        self, base_url: str, wordlist_path: str, extensions=None,
        concurrency: int = 5, timeout: int = 8, delay_ms: int = 200,
        on_hit=None, on_log=None, should_stop=None, on_result=None, request_headers=None,
        max_words: int = 0, cookie_jar=None, max_candidates: int = 0,
    ):
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("base_url must be a valid HTTP(S) URL")
        self.origin = f"{parsed.scheme}://{parsed.netloc}/"
        self.base_host = parsed.hostname.lower()
        self.wordlist_path = Path(wordlist_path)
        raw_extensions = extensions if extensions is not None else DEFAULT_EXTENSIONS
        normalized_extensions = []
        for extension in raw_extensions:
            extension = str(extension or "").strip()
            if extension and not extension.startswith("."):
                extension = "." + extension
            if extension not in normalized_extensions:
                normalized_extensions.append(extension)
        self.extensions = normalized_extensions or [""]
        self.max_words = max(0, int(max_words or 0))
        self.max_candidates = max(0, int(max_candidates or 0))
        self.cookie_jar = cookie_jar
        self.words_loaded = 0
        self.candidate_count = 0
        self.word_limit_reached = False
        self.path_limit_reached = False
        self.candidate_limit_reached = False
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

    def _iter_wordlist(self, deduplicate: bool = True):
        """Yield safe path words one at a time; target-level deduplication handles production scans."""
        if not self.wordlist_path.is_file():
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist_path}")
        self.words_loaded = 0
        self.word_limit_reached = False
        self.candidate_limit_reached = False
        seen = set() if deduplicate else None
        skipped_query_lines = 0
        with self.wordlist_path.open("r", encoding="utf-8", errors="ignore") as stream:
            for raw in stream:
                if self.should_stop() or self._rate_limited:
                    break
                word = raw.strip().lstrip("/")
                if not word or word.startswith("#") or (seen is not None and word in seen):
                    continue
                # This is path discovery (GET only); parameter names are mined separately.
                if "?" in word or "#" in word or "://" in word or word.startswith("//"):
                    skipped_query_lines += 1
                    continue
                if self.max_words and self.words_loaded >= self.max_words:
                    self.word_limit_reached = True
                    self._log(
                        f"[Wordlist] Explicit word limit reached ({self.max_words}); "
                        "remaining entries were not loaded or checked. Raise the limit or set it to 0 for all words."
                    )
                    break
                if any(part == ".." for part in word.replace("\\", "/").split("/")):
                    continue
                if seen is not None:
                    seen.add(word)
                self.words_loaded += 1
                yield word
        cap_note = f" (explicit cap: {self.max_words})" if self.max_words else " (no implicit word-count cap)"
        word_label = "unique entries" if deduplicate else "valid entries"
        self._log(f"[Wordlist] Streamed {self.words_loaded} {word_label}{cap_note}")
        if skipped_query_lines:
            self._log(
                f"[Wordlist] Skipped {skipped_query_lines} entry lines with query strings/fragments or absolute URLs; "
                "parameter names are collected separately."
            )

    def _load_wordlist(self):
        """Compatibility helper for tests/callers; production scans stream this iterator."""
        entries = list(self._iter_wordlist())
        self.candidate_limit_reached = self.word_limit_reached
        return entries

    def _build_targets(self, word: str):
        # Wordlists describe relative paths only; never allow a line to set another origin.
        word = str(word or "").strip().lstrip("/")
        if not word or "://" in word or word.startswith("//") or "\r" in word or "\n" in word:
            return []
        leaf = word.rsplit("/", 1)[-1]
        # Keep explicit filenames and dotfiles exact rather than appending nonsensical
        # variants such as robots.txt.php or .env.html.
        if leaf.startswith(".") or ("." in leaf and not leaf.endswith(".")):
            candidates = [word]
        else:
            candidates = [word + ext for ext in self.extensions]
        result = []
        for candidate in candidates:
            url = urljoin(self.origin, candidate)
            parsed = urlparse(url)
            if parsed.scheme in ("http", "https") and parsed.hostname and parsed.hostname.lower() == self.base_host:
                result.append(url)
        return list(dict.fromkeys(result))

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
        self.candidate_count = 0
        self.responses = []
        self.hits = []
        self.path_limit_reached = False
        self.word_limit_reached = False
        self.candidate_limit_reached = False
        self._log(
            f"[Wordlist] Streaming path discovery (concurrency={self.concurrency}, "
            f"delay={self.delay_ms}ms, extensions={len(self.extensions)}; "
            f"word cap={self.max_words or 'all'}, candidate cap={self.max_candidates or 'all'})."
        )
        self._resume_event = asyncio.Event()
        self._resume_event.set()
        self._rate_limit_lock = asyncio.Lock()
        queue = asyncio.Queue(maxsize=max(8, self.concurrency * 4))
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=min(self.timeout, 5))
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=True)
        headers = build_headers()
        headers.update({
            str(key): str(value) for key, value in self.request_headers.items()
            if str(key).lower() in {"authorization", "cookie", "accept-language"}
            and "\\r" not in str(value) and "\\n" not in str(value)
        })

        session_options = {
            "connector": connector, "timeout": timeout, "headers": headers,
        }
        if self.cookie_jar is not None:
            session_options["cookie_jar"] = self.cookie_jar
        async with aiohttp.ClientSession(**session_options) as session:
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
                                set_cookie_names = []
                                for cookie_name, morsel in resp.cookies.items():
                                    set_cookie_names.append({
                                        "name": cookie_name,
                                        "domain": morsel.get("domain", ""),
                                        "path": morsel.get("path", ""),
                                        "secure": bool(morsel.get("secure", "")),
                                        "httponly": bool(morsel.get("httponly", "")),
                                        "samesite": morsel.get("samesite", ""),
                                    })
                                result = {
                                    "url": url,
                                    "final_url": str(resp.url),
                                    "method": "GET",
                                    "source": "wordlist",
                                    "status": resp.status,
                                    "size": size,
                                    "word_count": word_count,
                                    "content_type": resp.headers.get("Content-Type", ""),
                                    "location": resp.headers.get("Location", ""),
                                    "server": resp.headers.get("Server", ""),
                                    "last_modified": resp.headers.get("Last-Modified", ""),
                                    "allow": resp.headers.get("Allow", ""),
                                    "www_authenticate": resp.headers.get("WWW-Authenticate", ""),
                                    "content_hash": hashlib.sha256(body).hexdigest()[:16],
                                    "response_truncated": len(data) > MAX_RESPONSE_BYTES,
                                    "set_cookie_names": set_cookie_names,
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
            seen_targets = set()
            try:
                for word in self._iter_wordlist(deduplicate=False):
                    if self.should_stop() or self._rate_limited:
                        break
                    for target in self._build_targets(word):
                        if target in seen_targets:
                            continue
                        if self.max_candidates and self.candidate_count >= self.max_candidates:
                            self.path_limit_reached = True
                            self._log(
                                f"[Wordlist] Explicit candidate limit reached ({self.max_candidates}); "
                                "remaining generated paths were not checked. Set it to 0 for all candidates."
                            )
                            break
                        seen_targets.add(target)
                        self.candidate_count += 1
                        await queue.put(target)
                        if self.should_stop() or self._rate_limited:
                            break
                    if self.path_limit_reached or self.should_stop() or self._rate_limited:
                        break
            finally:
                # Bounded queue + live workers prevents huge wordlists from building an
                # unbounded queue in memory, even when scans are stopped or rate-limited.
                for _ in workers:
                    await queue.put(None)
            await queue.join()
            await asyncio.gather(*workers, return_exceptions=True)

        self.candidate_limit_reached = self.word_limit_reached or self.path_limit_reached
        if self._rate_limited:
            self._log("[Wordlist] Ended early because the target is rate-limiting requests.")
        self.rate_limit_stopped = self._rate_limited and not self.should_stop()
        self._log(
            f"[Wordlist] Finished: {len(self.responses)} responses recorded, "
            f"{len(self.hits)} potential hits, {self.candidate_count} candidates generated; "
            f"word limit reached={self.word_limit_reached}, candidate limit reached={self.path_limit_reached}."
        )
        return self.hits
