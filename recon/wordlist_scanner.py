"""Low-rate optional wordlist path checks for authorized targets."""
import asyncio
import hashlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import aiohttp
from crawler.fetcher import build_headers
from recon.rate_limit_policy import AdaptiveRateController

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
MAX_RETRY_AFTER_SECONDS = 120  # compatibility constant; server Retry-After is not capped
MAX_RATE_LIMIT_PAUSES = 5


class WordlistScanner:
    def __init__(
        self, base_url: str, wordlist_path: str, extensions=None,
        concurrency: int = 5, timeout: int = 8, delay_ms: int = 200,
        on_hit=None, on_log=None, should_stop=None, on_result=None, request_headers=None,
        max_words: int = 0, cookie_jar=None, max_candidates: int = 0,
        recursive: bool = False, recursion_depth: int = 1,
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
        self.recursive = bool(recursive)
        self.recursion_depth = max(1, min(int(recursion_depth), 5))
        self.recursive_dirs_found = 0
        self.recursion_rounds = 0
        self.recursion_depth_limit_reached = False
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
        self._request_gate_lock = None
        self._next_request_time = 0.0
        self.rate_controller = AdaptiveRateController(
            base_delay=0.0, max_delay=60.0, max_consecutive_limits=MAX_RATE_LIMIT_PAUSES, jitter=0.0
        )
        self._rate_limit_cooldown_until = 0.0

    @staticmethod
    def _safe_result_url(value: str) -> str:
        """Keep diagnostics query-free; parameter values may contain secrets."""
        from urllib.parse import urlsplit, urlunsplit
        try:
            parsed = urlsplit(str(value or ""))
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
        except ValueError:
            return "(invalid URL)"

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
        return AdaptiveRateController.parse_retry_after(value)

    async def _request_gate(self):
        """Apply one shared per-origin pacing gate across wordlist workers."""
        if self._resume_event is None or self._request_gate_lock is None:
            return not self.should_stop() and not self._rate_limited
        await self._resume_event.wait()
        if self.should_stop() or self._rate_limited:
            return False
        async with self._request_gate_lock:
            loop = asyncio.get_running_loop()
            while not self.should_stop() and not self._rate_limited:
                await self._resume_event.wait()
                delay = max(self.delay_ms / 1000.0, self.rate_controller.current_delay)
                wait = self._next_request_time - loop.time()
                if wait <= 0:
                    self._next_request_time = loop.time() + delay
                    return True
                await asyncio.sleep(min(0.25, wait))
            return False

    async def _handle_429(self, headers, url, status=429):
        """Honor Retry-After or exponential backoff, then resume within a safe retry budget."""
        async with self._rate_limit_lock:
            if self._rate_limited or self.should_stop():
                return False
            retry_after = next(
                (str(value).strip() for key, value in (headers or {}).items()
                 if str(key).lower() == "retry-after"),
                None,
            )
            decision = self.rate_controller.on_rate_limit(retry_after, status=int(status))
            self._rate_limit_pauses = self.rate_controller.consecutive_limits
            if decision.should_stop:
                self._rate_limited = True
                self._log(
                    f"[Rate limit] HTTP {status} at {self._safe_result_url(url)}: {decision.reason}. "
                    "Stopping this discovery phase rather than retrying early."
                )
                self._resume_event.set()
                return False

            loop = asyncio.get_running_loop()
            self._rate_limit_cooldown_until = loop.time() + decision.wait_seconds
            self._resume_event.clear()
            self._log(
                f"[429] Pausing new content-discovery requests for {decision.wait_seconds:.1f}s; "
                f"adaptive pacing is now {self.rate_controller.current_delay:.2f}s."
            )
            deadline = loop.time() + decision.wait_seconds
            while loop.time() < deadline:
                if self.should_stop():
                    self._resume_event.set()
                    return False
                await asyncio.sleep(min(0.25, max(0.0, deadline - loop.time())))
            if self.should_stop():
                self._resume_event.set()
                return False
            self._resume_event.set()
            self._log("[429] Cool-down complete; resuming remaining queued checks at reduced pacing.")
            return True

    def _iter_wordlist(self, deduplicate: bool = True, *, track_stats: bool = True):
        """Stream safe relative paths; recursive passes re-read the list without changing base counts."""
        if not self.wordlist_path.is_file():
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist_path}")
        if track_stats:
            self.words_loaded = 0
            self.word_limit_reached = False
            self.candidate_limit_reached = False
        seen = set() if deduplicate else None
        skipped_query_lines = 0
        local_words = 0
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
                if self.max_words and local_words >= self.max_words:
                    if track_stats:
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
                local_words += 1
                if track_stats:
                    self.words_loaded += 1
                yield word
        if track_stats:
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

    def _build_targets(self, word: str, prefix: str = ""):
        # Wordlists describe relative paths only; never allow a line to set another origin.
        word = str(word or "").strip().lstrip("/")
        prefix = str(prefix or "").strip("/")
        if (
            not word or "://" in word or word.startswith("//")
            or "\r" in word or "\n" in word
            or any(part == ".." for part in word.replace("\\", "/").split("/"))
            or any(part == ".." for part in prefix.replace("\\", "/").split("/"))
        ):
            return []
        relative = f"{prefix}/{word}" if prefix else word
        leaf = relative.rsplit("/", 1)[-1]
        # Keep explicit filenames and dotfiles exact rather than appending nonsensical
        # variants such as robots.txt.php or .env.html.
        if relative.endswith("/") or leaf.startswith(".") or ("." in leaf and not leaf.endswith(".")):
            candidates = [relative]
        else:
            candidates = [relative + ext for ext in self.extensions]
        result = []
        for candidate in candidates:
            url = urljoin(self.origin, candidate)
            parsed = urlparse(url)
            if parsed.scheme in ("http", "https") and parsed.hostname and parsed.hostname.lower() == self.base_host:
                result.append(url)
        return list(dict.fromkeys(result))

    def _recursive_directory_prefix(self, result: dict) -> str:
        """Return a directory path only when an in-scope candidate looks directory-like."""
        if not self.recursive or not result.get("potential_hit"):
            return ""
        base = urlparse(self.origin)
        requested = urlparse(str(result.get("url") or ""))
        requested_port = requested.port or (443 if requested.scheme.lower() == "https" else 80)
        base_port = base.port or (443 if base.scheme.lower() == "https" else 80)
        if (
            requested.scheme.lower() != base.scheme.lower()
            or (requested.hostname or "").lower() != self.base_host
            or requested_port != base_port
        ):
            return ""

        location = str(result.get("location") or "").strip()
        if location:
            redirected = urlparse(urljoin(str(result.get("url") or ""), location))
            redirected_port = redirected.port or (443 if redirected.scheme.lower() == "https" else 80)
            if (
                redirected.scheme.lower() == base.scheme.lower()
                and (redirected.hostname or "").lower() == self.base_host
                and redirected_port == base_port
                and redirected.path.endswith("/")
                and redirected.path.strip("/")
            ):
                return redirected.path.strip("/") + "/"

        final_url = str(result.get("final_url") or result.get("url") or "")
        final = urlparse(final_url)
        final_port = final.port or (443 if final.scheme.lower() == "https" else 80)
        if final.scheme.lower() != base.scheme.lower() or (final.hostname or "").lower() != self.base_host or final_port != base_port:
            return ""
        path = final.path or "/"
        if path.endswith("/") and path.strip("/"):
            return path.strip("/") + "/"

        # Heuristic for applications that serve directory routes without a trailing slash.
        # Recursion is opt-in and the configured depth/path caps remain global.
        leaf = path.rsplit("/", 1)[-1]
        content_type = str(result.get("content_type") or "").lower()
        status = int(result.get("status") or 0)
        if path.strip("/") and status in {200, 401, 403} and "html" in content_type and "." not in leaf:
            return path.strip("/") + "/"
        return ""

    async def _fetch_baseline(self, session):
        """Keep the wildcard baseline usable by waiting and retrying rate-limited responses."""
        baseline_url = urljoin(self.origin, "this-path-should-not-exist-recon-baseline-74c31")
        while not self.should_stop() and not self._rate_limited:
            if not await self._request_gate():
                return
            try:
                async with session.get(
                    baseline_url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in {429, 503}:
                        self._log(
                            f"[Baseline] Received HTTP {resp.status} from "
                            f"{self._safe_result_url(baseline_url)}."
                        )
                        if await self._handle_429(dict(resp.headers), baseline_url, status=resp.status):
                            continue
                        self._resume_event.set()
                        return
                    self.rate_controller.on_success()
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
        self.recursive_dirs_found = 0
        self.recursion_rounds = 0
        self.recursion_depth_limit_reached = False
        self._log(
            f"[Wordlist] Streaming path discovery (concurrency={self.concurrency}, "
            f"delay={self.delay_ms}ms, extensions={len(self.extensions)}; "
            f"word cap={self.max_words or 'all'}, candidate cap={self.max_candidates or 'all'}; "
            f"recursion={'on/depth ' + str(self.recursion_depth) if self.recursive else 'off'})."
        )
        self._resume_event = asyncio.Event()
        self._resume_event.set()
        self._rate_limit_lock = asyncio.Lock()
        self._request_gate_lock = asyncio.Lock()
        self._next_request_time = 0.0
        queue = asyncio.Queue(maxsize=max(8, self.concurrency * 4))
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=min(self.timeout, 5))
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=True)
        headers = build_headers()
        # Use a consistent, truthful identity; never rotate or spoof headers to evade 429.
        headers["User-Agent"] = "Recon-GUI/3.2 (+authorized reconnaissance)"
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
                        if not await self._request_gate():
                            continue
                        try:
                            rate_limit_headers = None
                            rate_limit_status = 429
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
                                if resp.status in {429, 503}:
                                    rate_limit_headers = dict(resp.headers)
                                    rate_limit_status = int(resp.status)
                                else:
                                    self.rate_controller.on_success()
                                if result["potential_hit"] and resp.status != 429:
                                    self.hits.append(result)
                                    self._notify_hit(url, resp.status, size)

                            if rate_limit_headers is not None:
                                await self._handle_429(rate_limit_headers, url, status=rate_limit_status)
                        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                            failure = {
                                "url": self._safe_result_url(url),
                                "final_url": self._safe_result_url(url),
                                "method": "GET",
                                "source": "wordlist",
                                "status": 0,
                                "size": 0,
                                "word_count": 0,
                                "content_type": "",
                                "location": "",
                                "server": "",
                                "last_modified": "",
                                "allow": "",
                                "www_authenticate": "",
                                "content_hash": "",
                                "response_truncated": False,
                                "set_cookie_names": [],
                                "baseline_match": False,
                                "potential_hit": False,
                                "error": type(exc).__name__,
                            }
                            self.responses.append(failure)
                            self._notify_result(failure)
                            self._log(
                                f"[Wordlist] Request failed for {self._safe_result_url(url)}: "
                                f"{type(exc).__name__}"
                            )
                        except Exception as exc:
                            # A malformed response or optional callback should not kill a worker.
                            failure = {
                                "url": self._safe_result_url(url),
                                "final_url": self._safe_result_url(url),
                                "method": "GET",
                                "source": "wordlist",
                                "status": 0,
                                "size": 0,
                                "word_count": 0,
                                "content_type": "",
                                "location": "",
                                "server": "",
                                "last_modified": "",
                                "allow": "",
                                "www_authenticate": "",
                                "content_hash": "",
                                "response_truncated": False,
                                "set_cookie_names": [],
                                "baseline_match": False,
                                "potential_hit": False,
                                "error": type(exc).__name__,
                            }
                            self.responses.append(failure)
                            self._notify_result(failure)
                            self._log(
                                f"[Wordlist] Unexpected error for {self._safe_result_url(url)}: "
                                f"{type(exc).__name__}"
                            )

                        # Apply delay even for ordinary 404/filtered responses.
                        if self.delay_ms and not self.should_stop():
                            await asyncio.sleep(self.delay_ms / 1000)
                    finally:
                        queue.task_done()

            workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
            seen_targets = set()

            async def enqueue_wordlist(prefix: str = "", track_stats: bool = False):
                for word in self._iter_wordlist(deduplicate=False, track_stats=track_stats):
                    if self.should_stop() or self._rate_limited:
                        break
                    for target in self._build_targets(word, prefix=prefix):
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

            try:
                # First pass enumerates the supplied list from the selected origin.
                await enqueue_wordlist(track_stats=True)
                await queue.join()

                # Optional dirsearch-style recursion: only directory-like potential hits
                # discovered in the previous pass seed the next bounded depth round.
                explored_directories = set()
                new_directories = {
                    prefix for response in self.responses
                    if (prefix := self._recursive_directory_prefix(response))
                }
                self.recursive_dirs_found = len(new_directories)
                for depth in range(1, self.recursion_depth + 1):
                    if (
                        not self.recursive or not new_directories
                        or self.should_stop() or self._rate_limited or self.path_limit_reached
                    ):
                        break
                    current_directories = sorted(new_directories - explored_directories)
                    if not current_directories:
                        break
                    self.recursion_rounds = depth
                    self._log(
                        f"[Wordlist] Recursive pass {depth}/{self.recursion_depth}: "
                        f"{len(current_directories)} directory candidate(s)."
                    )
                    explored_directories.update(current_directories)
                    response_start = len(self.responses)
                    for prefix in current_directories:
                        await enqueue_wordlist(prefix=prefix, track_stats=False)
                        if self.path_limit_reached or self.should_stop() or self._rate_limited:
                            break
                    await queue.join()
                    new_directories = {
                        prefix for response in self.responses[response_start:]
                        if (prefix := self._recursive_directory_prefix(response))
                    } - explored_directories
                    self.recursive_dirs_found = len(explored_directories | new_directories)

                if (
                    self.recursive and new_directories
                    and self.recursion_rounds >= self.recursion_depth
                    and not self.should_stop() and not self._rate_limited
                    and not self.path_limit_reached
                ):
                    self.recursion_depth_limit_reached = True
                    self._log(
                        f"[Wordlist] Recursion depth cap reached ({self.recursion_depth}); "
                        "new directory-like paths remain for a deeper pass."
                    )
            finally:
                # Keep the queue bounded and workers alive until every recursive pass is done.
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
            f"word limit reached={self.word_limit_reached}, candidate limit reached={self.path_limit_reached}; "
            f"recursive rounds={self.recursion_rounds}, directory candidates={self.recursive_dirs_found}, "
            f"recursion depth cap reached={self.recursion_depth_limit_reached}."
        )
        return self.hits
