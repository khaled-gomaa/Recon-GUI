"""QThread worker for the desktop crawler, with cooperative cancellation."""
import asyncio
import threading

import aiohttp
from PySide6.QtCore import QThread, Signal

from crawler.engine import CrawlEngine
from recon.analyzer import ReconAnalyzer
from recon.matchers import MatcherFilter
from recon.favicon_hasher import get_favicon_hash
from recon.similarity_detector import SimilarityDetector


class CrawlWorker(QThread):
    log_message = Signal(str)
    page_crawled = Signal(object)
    discovery_result = Signal(dict)
    finished = Signal(dict)
    error = Signal(str)

    def __init__(
        self, url, max_depth, max_pages, concurrency=10,
        wordlist_path=None, matcher: MatcherFilter = None,
    ):
        super().__init__()
        self.url = url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = max(1, min(int(concurrency), 20))
        self.wordlist_path = wordlist_path
        self.matcher = matcher or MatcherFilter()
        self._stop_event = threading.Event()

    def stop(self):
        """Request a graceful stop; in-flight requests are allowed to finish."""
        self._stop_event.set()

    def _stopping(self):
        return self._stop_event.is_set()

    def run(self):
        loop = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            analyzer = ReconAnalyzer(self.url)
            engine = CrawlEngine(
                start_url=self.url,
                max_depth=self.max_depth,
                max_pages=self.max_pages,
                concurrency=self.concurrency,
                on_log=lambda msg: self.log_message.emit(msg),
                on_page_crawled=lambda result: self.page_crawled.emit(result),
                should_stop=self._stopping,
            )
            loop.run_until_complete(engine.crawl())

            analyzed_urls = set()

            def _analyze_new_results():
                # Follow-up discovery passes append new results to the same engine.
                for result in engine.results:
                    if result.url in analyzed_urls:
                        continue
                    analyzer.analyze_page(result.url, result.html, headers=result.headers)
                    analyzed_urls.add(result.url)

            # Analyze response metadata as well as HTML.
            _analyze_new_results()

            if not self._stopping():
                self.log_message.emit("[Favicon] Computing favicon hash...")
                try:
                    async def _hash_favicon():
                        connector = aiohttp.TCPConnector(ssl=True)
                        async with aiohttp.ClientSession(connector=connector) as session:
                            return await get_favicon_hash(session, self.url)
                    analyzer.favicon_hash = loop.run_until_complete(_hash_favicon())
                    self.log_message.emit(
                        f"[Favicon] Hash = {analyzer.favicon_hash}"
                        if analyzer.favicon_hash else "[Favicon] Not found."
                    )
                except Exception as exc:
                    self.log_message.emit(f"[Favicon] Error: {exc}")

            if not self._stopping():
                # Two bounded passes let routes found in external JS enter the page table,
                # while page limits and exact-host scope remain enforced by CrawlEngine.
                for discovery_round in range(2):
                    self.log_message.emit(
                        f"[JS] Downloading/analyzing same-host JavaScript "
                        f"(route pass {discovery_round + 1}/2)..."
                    )
                    analyzer.finalize_js(loop, should_stop=self._stopping)
                    if self._stopping() or not analyzer.js_collector.route_urls:
                        break

                    before_count = len(engine.results)
                    route_seeds = sorted(analyzer.js_collector.route_urls)
                    self.log_message.emit(
                        f"[DISCOVERY] Crawling {len(route_seeds)} route candidates extracted from JavaScript."
                    )
                    loop.run_until_complete(
                        engine.crawl(seed_urls=route_seeds, seed_depth=1)
                    )
                    _analyze_new_results()
                    if len(engine.results) == before_count:
                        break

                # Analyze any JS assets discovered on the final extra batch without
                # adding an unbounded third route crawl.
                if not self._stopping():
                    analyzer.finalize_js(loop, should_stop=self._stopping)

            wordlist_results = []
            if self.wordlist_path and not self._stopping():
                from recon.wordlist_scanner import WordlistScanner
                self.log_message.emit(f"[Wordlist] Checking authorized paths: {self.wordlist_path}")
                scanner = WordlistScanner(
                    base_url=self.url,
                    wordlist_path=self.wordlist_path,
                    concurrency=self.concurrency,
                    on_hit=lambda url, status, size: self.log_message.emit(
                        f"[HIT {status}] {url} ({size} bytes)"
                    ),
                    on_log=lambda message: self.log_message.emit(message),
                    should_stop=self._stopping,
                    on_result=lambda result: self.discovery_result.emit(result),
                )
                analyzer.wordlist_hits = loop.run_until_complete(scanner.scan())
                wordlist_results = scanner.responses
                if scanner.rate_limit_stopped:
                    self.log_message.emit("[Content Discovery] Stopped safely because rate limiting did not permit a compliant resume.")

            all_results = engine.results
            if not self.matcher.is_empty():
                self.log_message.emit(f"[Matcher] Applying: {self.matcher.describe()}")
                filtered = [result for result in all_results if self.matcher.matches(result)]
                self.log_message.emit(f"[Matcher] Kept {len(filtered)}/{len(all_results)} pages.")
            else:
                filtered = all_results

            report = analyzer.to_dict()
            report["target"] = self.url
            report["pages"] = [result.to_dict() for result in all_results]
            report["wordlist_results"] = wordlist_results
            report["wordlist_rate_limited_stop"] = bool(
                self.wordlist_path and 'scanner' in locals()
                and getattr(scanner, "rate_limit_stopped", False)
            )
            report["filtered_pages"] = [result.to_dict() for result in filtered]
            report["similarity"] = SimilarityDetector().analyze(filtered)
            report["matcher_description"] = self.matcher.describe()
            report["matcher_applied"] = not self.matcher.is_empty()
            report["stopped_by_user"] = self._stopping()
            self.finished.emit(report)

        except Exception as exc:
            self.error.emit(f"{type(exc).__name__}: {exc}")
        finally:
            if loop is not None:
                try:
                    loop.close()
                except Exception:
                    pass
