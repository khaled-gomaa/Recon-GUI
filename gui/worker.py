"""QThread worker running the crawl engine with matchers, filters, favicon hash."""
import asyncio
import aiohttp
from PySide6.QtCore import QThread, Signal
from crawler.engine import CrawlEngine
from recon.analyzer import ReconAnalyzer
from recon.matchers import MatcherFilter
from recon.favicon_hasher import get_favicon_hash


class CrawlWorker(QThread):
    log_message = Signal(str)
    page_crawled = Signal(object)
    finished = Signal(dict)
    error = Signal(str)

    def __init__(
        self,
        url,
        max_depth,
        max_pages,
        concurrency=50,
        wordlist_path=None,
        matcher: MatcherFilter = None,
    ):
        super().__init__()
        self.url = url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.wordlist_path = wordlist_path
        self.matcher = matcher or MatcherFilter()

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
                on_page_crawled=lambda r: self.page_crawled.emit(r),
            )

            loop.run_until_complete(engine.crawl())

            for result in engine.results:
                analyzer.analyze_page(result.url, result.html)

            # --- Favicon hash ---
            self.log_message.emit("[Favicon] Computing favicon hash...")
            try:
                async def _hash():
                    connector = aiohttp.TCPConnector(ssl=False)
                    async with aiohttp.ClientSession(connector=connector) as s:
                        return await get_favicon_hash(s, self.url)
                analyzer.favicon_hash = loop.run_until_complete(_hash())
                if analyzer.favicon_hash:
                    self.log_message.emit(
                        f"[Favicon] Hash = {analyzer.favicon_hash}"
                    )
                else:
                    self.log_message.emit("[Favicon] Not found.")
            except Exception as exc:
                self.log_message.emit(f"[Favicon] Error: {exc}")

            # --- JS collection ---
            self.log_message.emit("[JS] Downloading and analyzing JavaScript files...")
            analyzer.finalize_js(loop)

            # --- Wordlist scan ---
            if self.wordlist_path:
                from recon.wordlist_scanner import WordlistScanner
                self.log_message.emit(f"[Wordlist] Scanning: {self.wordlist_path}")
                scanner = WordlistScanner(
                    base_url=self.url,
                    wordlist_path=self.wordlist_path,
                    concurrency=self.concurrency,
                    on_hit=lambda u, s, sz: self.log_message.emit(
                        f"[HIT {s}] {u} ({sz} bytes)"
                    ),
                    on_log=lambda m: self.log_message.emit(m),
                )
                analyzer.wordlist_hits = loop.run_until_complete(scanner.scan())

            # --- Apply matchers/filters ---
            all_results = engine.results
            if not self.matcher.is_empty():
                self.log_message.emit(
                    f"[Matcher] Applying: {self.matcher.describe()}"
                )
                filtered = [r for r in all_results if self.matcher.matches(r)]
                self.log_message.emit(
                    f"[Matcher] Kept {len(filtered)}/{len(all_results)} pages."
                )
            else:
                filtered = all_results

            # --- Similarity on filtered set ---
            from recon.similarity_detector import SimilarityDetector
            similarity = SimilarityDetector().analyze(filtered)

            report = analyzer.to_dict()
            report["pages"] = [r.to_dict() for r in all_results]
            report["filtered_pages"] = [r.to_dict() for r in filtered]
            report["similarity"] = similarity
            report["matcher_description"] = self.matcher.describe()
            report["matcher_applied"] = not self.matcher.is_empty()

            self.finished.emit(report)
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            if loop:
                loop.close()
