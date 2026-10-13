"""QThread worker for the desktop crawler, with cooperative cancellation."""
import asyncio
import hashlib
import threading
from datetime import datetime, timezone

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
        render_javascript=False, passive_discovery=False, request_headers=None,
        crawl_historical_urls=False,
    ):
        super().__init__()
        self.url = url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = max(1, min(int(concurrency), 20))
        self.wordlist_path = wordlist_path
        self.matcher = matcher or MatcherFilter()
        self.render_javascript = bool(render_javascript)
        self.passive_discovery = bool(passive_discovery)
        self.crawl_historical_urls = bool(crawl_historical_urls)
        self.request_headers = {
            str(key): str(value) for key, value in (request_headers or {}).items()
            if str(key).lower() in {"authorization", "cookie", "accept-language"}
            and "\r" not in str(value) and "\n" not in str(value)
        }
        self._stop_event = threading.Event()

    def stop(self):
        """Request a graceful stop; in-flight requests are allowed to finish."""
        self._stop_event.set()

    def _stopping(self):
        return self._stop_event.is_set()

    def run(self):
        loop = None
        started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            analyzer = ReconAnalyzer(self.url, request_headers=self.request_headers, on_log=self.log_message.emit)
            engine = CrawlEngine(
                start_url=self.url,
                max_depth=self.max_depth,
                max_pages=self.max_pages,
                concurrency=self.concurrency,
                on_log=lambda msg: self.log_message.emit(msg),
                on_page_crawled=lambda result: self.page_crawled.emit(result),
                should_stop=self._stopping,
                request_headers=self.request_headers,
                respect_robots=True,
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

            if self.crawl_historical_urls and not self._stopping() and not engine.rate_limit_stopped:
                from urllib.parse import urlparse
                target_host = (urlparse(self.url).hostname or "").lower()
                history_seeds = sorted({
                    url for url in passive_results.get("historical_urls", [])
                    if (urlparse(url).hostname or "").lower() == target_host
                    and urlparse(url).scheme.lower() in ("http", "https")
                })[:min(50, self.max_pages)]
                if history_seeds:
                    self.log_message.emit(
                        f"[History] Crawling {len(history_seeds)} same-host historical URL candidates "
                        "(explicit option; normal page and scope limits still apply)."
                    )
                    loop.run_until_complete(engine.crawl(seed_urls=history_seeds, seed_depth=1))
                    _analyze_new_results()
                elif self.passive_discovery:
                    self.log_message.emit("[History] No same-host historical URL candidates to crawl.")

            rendered_pages = 0
            if self.render_javascript and not self._stopping() and not engine.rate_limit_stopped:
                from recon.browser_renderer import render_pages
                candidates = [
                    item.url for item in engine.results
                    if item.status == 200 and item.html
                    and ("html" in (item.content_type or "").lower() or not item.content_type)
                ][:30]
                self.log_message.emit(
                    f"[Browser] Optional JavaScript rendering enabled for {len(candidates)} pages."
                )
                try:
                    rendered = loop.run_until_complete(render_pages(
                        candidates, headers=self.request_headers,
                        should_stop=self._stopping, on_log=self.log_message.emit,
                    ))
                except RuntimeError as exc:
                    rendered = {}
                    self.log_message.emit(f"[Browser] {exc}")
                by_url = {item.url: item for item in engine.results}
                route_seeds = set()
                for url, html in rendered.items():
                    result = by_url.get(url)
                    if result is None or self._stopping():
                        continue
                    parsed = engine.parser.parse(html, url)
                    result.html = html
                    result.title = parsed.get("title", result.title)
                    result.word_count = len((parsed.get("text") or "").split())
                    result.content_hash = hashlib.sha256(
                        html.encode("utf-8", errors="ignore")
                    ).hexdigest()[:16]
                    result.text_hash = hashlib.sha256(
                        (parsed.get("text") or "").encode("utf-8", errors="ignore")
                    ).hexdigest()[:16]
                    result.content_length = len(html.encode("utf-8", errors="ignore"))
                    analyzer.report.header_audits = [
                        audit for audit in analyzer.report.header_audits if audit.url != url
                    ]
                    analyzed_urls.discard(url)
                    route_seeds.update(parsed.get("links", []))
                    rendered_pages += 1
                _analyze_new_results()
                if route_seeds and not self._stopping():
                    self.log_message.emit(
                        f"[Browser] Following {len(route_seeds)} same-host routes from rendered DOM."
                    )
                    loop.run_until_complete(engine.crawl(seed_urls=sorted(route_seeds), seed_depth=1))
                    _analyze_new_results()

            if not self._stopping() and not engine.rate_limit_stopped:
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

            if not self._stopping() and not engine.rate_limit_stopped:
                # Two bounded passes let routes found in external JS enter the page table,
                # while page limits and exact-host scope remain enforced by CrawlEngine.
                for discovery_round in range(2):
                    self.log_message.emit(
                        f"[JS] Downloading/analyzing same-host JavaScript "
                        f"(route pass {discovery_round + 1}/2)..."
                    )
                    analyzer.finalize_js(loop, should_stop=self._stopping, delay_seconds=engine.crawl_delay_seconds)
                    if self._stopping() or analyzer.js_collector.rate_limit_stopped or not analyzer.js_collector.route_urls:
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

            passive_results = {
                "passive_subdomains": [], "historical_urls": [],
                "passive_sources": [], "passive_errors": [],
            }
            if self.passive_discovery and not self._stopping():
                self.log_message.emit(
                    "[Passive] Querying Certificate Transparency and Wayback (no target probing)."
                )
                try:
                    from recon.passive_sources import collect_passive
                    passive_results = collect_passive(self.url, on_log=self.log_message.emit)
                    analyzer.report.subdomains.update(passive_results.get("passive_subdomains", []))
                except Exception as exc:
                    self.log_message.emit(f"[Passive] {type(exc).__name__}: {exc}")
                    passive_results["passive_errors"].append(f"{type(exc).__name__}: {exc}")

            wordlist_results = []
            wordlist_rate_limited_stop = False
            if self.wordlist_path and not self._stopping() and not engine.rate_limit_stopped:
                from recon.wordlist_scanner import WordlistScanner
                self.log_message.emit(f"[Wordlist] Checking authorized paths: {self.wordlist_path}")
                scanner = WordlistScanner(
                    base_url=self.url,
                    wordlist_path=self.wordlist_path,
                    concurrency=1 if engine.crawl_delay_seconds > 0 else self.concurrency,
                    on_hit=lambda url, status, size: self.log_message.emit(
                        f"[HIT {status}] {url} ({size} bytes)"
                    ),
                    on_log=lambda message: self.log_message.emit(message),
                    should_stop=self._stopping,
                    on_result=lambda result: self.discovery_result.emit(result),
                    request_headers=self.request_headers,
                    delay_ms=max(200, int(engine.crawl_delay_seconds * 1000)),
                )
                analyzer.wordlist_hits = loop.run_until_complete(scanner.scan())
                wordlist_results = scanner.responses
                wordlist_rate_limited_stop = scanner.rate_limit_stopped
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
            report.update(passive_results)
            report["started_at"] = started_at
            report["rendering_enabled"] = self.render_javascript
            report["historical_urls_crawled"] = self.crawl_historical_urls
            report["rendered_pages"] = rendered_pages
            report["robots_url"] = engine.robots_url
            report["crawl_delay_seconds"] = engine.crawl_delay_seconds
            report["auth_configured"] = bool(self.request_headers)
            report["auth_types"] = [
                label for label, key in (
                    ("Authorization header", "authorization"),
                    ("Cookie header", "cookie"),
                    ("Accept-Language", "accept-language"),
                ) if any(header.lower() == key for header in self.request_headers)
            ]
            report["target"] = self.url
            report["pages"] = [result.to_dict() for result in all_results]
            report["wordlist_results"] = wordlist_results
            report["wordlist_rate_limited_stop"] = wordlist_rate_limited_stop
            report["crawler_rate_limited_stop"] = engine.rate_limit_stopped
            report["filtered_pages"] = [result.to_dict() for result in filtered]
            report["similarity"] = SimilarityDetector().analyze(filtered)
            report["matcher_description"] = self.matcher.describe()
            report["matcher_applied"] = not self.matcher.is_empty()
            report["stopped_by_user"] = self._stopping()
            try:
                from recon.history_store import HistoryStore
                report = HistoryStore().save_report(report)
                self.log_message.emit(
                    f"[History] Saved scan #{report['scan_id']}: "
                    f"{report['history_diff']['added_count']} new, "
                    f"{report['history_diff']['removed_count']} removed, "
                    f"{report['history_diff']['changed_count']} changed URLs."
                )
            except Exception as exc:
                report["history_error"] = f"{type(exc).__name__}: {exc}"
                self.log_message.emit(
                    f"[History] Could not save local history: {type(exc).__name__}: {exc}"
                )
            self.finished.emit(report)

        except Exception as exc:
            self.error.emit(f"{type(exc).__name__}: {exc}")
        finally:
            if loop is not None:
                try:
                    loop.close()
                except Exception:
                    pass
