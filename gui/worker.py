"""QThread worker for the desktop crawler, with cooperative cancellation."""
import asyncio
import hashlib
import threading
from datetime import datetime, timezone
from http.cookies import SimpleCookie

from yarl import URL

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
        crawl_historical_urls=False, wordlist_extensions=None,
        use_subfinder=True, manual_browser_session=False, manual_browser_duration=180,
        wordlist_max_words=0, wordlist_max_candidates=0,
        recursive_content_discovery=False, content_recursion_depth=2,
        imported_seed_urls=None, seed_import_summary=None,
        probe_assets=False, asset_probe_max=500,
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
        self.wordlist_extensions = list(wordlist_extensions) if wordlist_extensions is not None else None
        self.use_subfinder = bool(use_subfinder)
        self.manual_browser_session = bool(manual_browser_session)
        self.manual_browser_duration = max(30, min(int(manual_browser_duration), 600))
        self.wordlist_max_words = max(0, int(wordlist_max_words or 0))
        self.wordlist_max_candidates = max(0, int(wordlist_max_candidates or 0))
        self.recursive_content_discovery = bool(recursive_content_discovery)
        self.content_recursion_depth = max(1, min(int(content_recursion_depth), 5))
        # Imported seeds are validated by the importer and rechecked by CrawlEngine.
        self.imported_seed_urls = list(dict.fromkeys(
            str(value).strip() for value in (imported_seed_urls or [])
            if str(value).strip()
        ))[:100_000]
        self.seed_import_summary = dict(seed_import_summary or {})
        self.probe_assets = bool(probe_assets)
        self.asset_probe_max = max(1, min(int(asset_probe_max or 500), 5000))
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
        from urllib.parse import urlparse

        loop = None
        started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # One cookie jar is reused between the crawl, JS download, and Content Discovery
            # sessions. The user-supplied Cookie header is imported into the jar once so
            # cookie Domain/Path/Secure rules can be handled by the HTTP client.
            session_cookie_jar = aiohttp.CookieJar(unsafe=True)
            phase_headers = dict(self.request_headers)
            raw_cookie_header = ""
            for header_name in list(phase_headers):
                if header_name.lower() == "cookie":
                    raw_cookie_header = phase_headers.pop(header_name)
                    break
            if raw_cookie_header:
                parsed_cookies = SimpleCookie()
                try:
                    parsed_cookies.load(raw_cookie_header)
                    if parsed_cookies:
                        session_cookie_jar.update_cookies(parsed_cookies, response_url=URL(self.url))
                        self.log_message.emit("[Session] Imported supplied cookie names into the in-memory session jar.")
                except Exception as exc:
                    self.log_message.emit(f"[Session] Supplied Cookie header could not be parsed: {type(exc).__name__}.")
            analyzer = ReconAnalyzer(
                self.url, request_headers=phase_headers, on_log=self.log_message.emit,
                cookie_jar=session_cookie_jar,
            )
            engine = CrawlEngine(
                start_url=self.url,
                max_depth=self.max_depth,
                max_pages=self.max_pages,
                concurrency=self.concurrency,
                on_log=lambda msg: self.log_message.emit(msg),
                on_page_crawled=lambda result: self.page_crawled.emit(result),
                should_stop=self._stopping,
                request_headers=phase_headers,
                respect_robots=True,
                cookie_jar=session_cookie_jar,
            )
            passive_results = {
                "passive_subdomains": [], "historical_urls": [],
                "passive_sources": [], "passive_errors": [],
                "subfinder_subdomains": [], "subfinder_status": "not-run", "subfinder_error": "",
            }
            manual_browser_results = {
                "network_observations": [], "session_cookies": [], "manual_browser_seconds": 0,
            }
            if self.manual_browser_session and not self._stopping():
                self.log_message.emit("[Manual Browser] Starting an interactive session before crawling.")
                try:
                    from recon.browser_renderer import capture_manual_session
                    manual_browser_results = loop.run_until_complete(capture_manual_session(
                        self.url, cookie_jar=session_cookie_jar,
                        should_stop=self._stopping, on_log=self.log_message.emit,
                        on_network_event=analyzer.record_network_observation,
                        duration_seconds=self.manual_browser_duration,
                    ))
                    self.log_message.emit(
                        f"[Manual Browser] Captured {len(manual_browser_results.get('network_observations', []))} request records "
                        f"and {len(manual_browser_results.get('session_cookies', []))} cookie metadata records."
                    )
                except RuntimeError as exc:
                    self.log_message.emit(f"[Manual Browser] {exc} Continuing with HTTP-only session.")
            if self.passive_discovery and not self._stopping():
                self.log_message.emit(
                    "[Passive] Querying Certificate Transparency and Wayback (no target probing)."
                )
                try:
                    from recon.passive_sources import collect_passive
                    passive_results = collect_passive(self.url, on_log=self.log_message.emit)
                    analyzer.report.subdomains.update(passive_results.get("passive_subdomains", []))
                    # ParamSpider-style passive parameter mining: learn endpoint/query names
                    # from archived same-host URLs without sending new requests to them.
                    target_host = (urlparse(self.url).hostname or "").lower()
                    archived_query_urls = 0
                    for archived_url in passive_results.get("historical_urls", []):
                        archived = urlparse(archived_url)
                        if (
                            archived.scheme.lower() in ("http", "https")
                            and (archived.hostname or "").lower() == target_host
                        ):
                            analyzer._record_endpoint(
                                archived_url, "wayback-archive", self.url, method="GET"
                            )
                            if archived.query:
                                archived_query_urls += 1
                    self.log_message.emit(
                        f"[Wayback] Indexed {archived_query_urls} same-host historical URLs with query strings "
                        "for parameter inventory; no archived URLs were actively fetched in this step."
                    )
                except Exception as exc:
                    self.log_message.emit(f"[Passive] {type(exc).__name__}: {exc}")
                    passive_results["passive_errors"].append(f"{type(exc).__name__}: {exc}")

            if self.use_subfinder and not self._stopping():
                self.log_message.emit("[Subfinder] Starting optional passive hostname discovery.")
                try:
                    from recon.subfinder import discover_subdomains
                    result = discover_subdomains(
                        self.url, should_stop=self._stopping, on_log=self.log_message.emit,
                    )
                    passive_results["subfinder_subdomains"] = result.get("subfinder_subdomains", [])
                    passive_results["subfinder_status"] = result.get("subfinder_status", "unknown")
                    passive_results["subfinder_error"] = result.get("subfinder_error", "")
                    merged_hosts = set(passive_results.get("passive_subdomains", []))
                    merged_hosts.update(passive_results["subfinder_subdomains"])
                    passive_results["passive_subdomains"] = sorted(merged_hosts)
                    passive_results["passive_sources"].append({
                        "name": "Subfinder",
                        "status": passive_results["subfinder_status"],
                        "count": len(passive_results["subfinder_subdomains"]),
                    })
                    if passive_results["subfinder_error"]:
                        passive_results["passive_errors"].append(
                            "Subfinder: " + passive_results["subfinder_error"]
                        )
                    analyzer.report.subdomains.update(passive_results["subfinder_subdomains"])
                except Exception as exc:
                    passive_results["subfinder_status"] = "error"
                    passive_results["subfinder_error"] = f"{type(exc).__name__}: {exc}"
                    passive_results["passive_errors"].append(
                        "Subfinder: " + passive_results["subfinder_error"]
                    )
                    self.log_message.emit(f"[Subfinder] {type(exc).__name__}: {exc}")

            historical_seeds = []
            if self.crawl_historical_urls and not self._stopping():
                target_host = (urlparse(self.url).hostname or "").lower()
                historical_seeds = sorted({
                    candidate for candidate in passive_results.get("historical_urls", [])
                    if (urlparse(candidate).hostname or "").lower() == target_host
                    and urlparse(candidate).scheme.lower() in ("http", "https")
                })[:min(50, max(0, self.max_pages - 1))]
                if historical_seeds:
                    self.log_message.emit(
                        f"[History] Added {len(historical_seeds)} same-host historical URL candidates "
                        "to the initial bounded crawl."
                    )
                else:
                    self.log_message.emit("[History] No same-host historical URLs available to crawl.")

            scan_seeds = list(dict.fromkeys([self.url, *historical_seeds, *self.imported_seed_urls]))
            if self.imported_seed_urls:
                self.log_message.emit(
                    f"[Seeds] Added {len(self.imported_seed_urls)} imported same-host URL candidates "
                    "as depth-0 seeds. Engine scope/page/rate limits still apply."
                )
            loop.run_until_complete(engine.crawl(seed_urls=scan_seeds, seed_depth=0))

            analyzed_urls = set()

            def _analyze_new_results():
                # Follow-up discovery passes append new results to the same engine.
                for result in engine.results:
                    if result.url in analyzed_urls:
                        continue
                    analyzer.analyze_page(
                        result.url, result.html, headers=result.headers,
                        discovered_links=getattr(result, "links", []),
                        discovered_assets=getattr(result, "asset_references", []),
                    )
                    analyzed_urls.add(result.url)

            # Analyze response metadata as well as HTML.
            _analyze_new_results()

            rendered_pages = 0
            if self.render_javascript and not self._stopping() and not engine.rate_limit_stopped:
                from recon.browser_renderer import render_pages
                candidates = [
                    item.url for item in engine.results
                    if item.status == 200 and item.html
                    and ("html" in (item.content_type or "").lower() or not item.content_type)
                ]
                self.log_message.emit(
                    f"[Browser] Optional JavaScript rendering enabled for {len(candidates)} pages."
                )
                try:
                    rendered = loop.run_until_complete(render_pages(
                        candidates, headers=self.request_headers,
                        should_stop=self._stopping, on_log=self.log_message.emit,
                        on_network_event=analyzer.record_network_observation,
                        max_pages=self.max_pages,
                        storage_state=manual_browser_results.get("_storage_state"),
                        cookie_jar=session_cookie_jar,
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
                    result.links = parsed.get("links", [])
                    merged_assets = {
                        (item.get("url", ""), item.get("kind", "")): item
                        for item in list(getattr(result, "asset_references", [])) + list(parsed.get("assets", []))
                    }
                    result.asset_references = list(merged_assets.values())
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
                # Iterate until the JS queue and route queue stop producing new crawl pages.
                # The crawler's configured page cap, stop event, exact-host scope and 429
                # gate remain the hard boundaries; no fixed two-round truncation.
                discovery_round = 0
                while (
                    not self._stopping()
                    and not engine.rate_limit_stopped
                    and not analyzer.js_collector.rate_limit_stopped
                ):
                    discovery_round += 1
                    self.log_message.emit(
                        f"[JS] Downloading/analyzing same-host JavaScript (discovery round {discovery_round})..."
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

            # Parse same-origin stylesheet files and recursively discover CSS @import/url()
            # references before the optional HEAD check. External CSS references are recorded,
            # never fetched; the shared session cookie jar remains in-memory only.
            css_collector = None
            css_discovery_data = {
                "css_files_discovered": 0, "css_files_attempted": 0, "css_files_fetched": 0,
                "css_files_truncated": [], "css_file_errors": [],
                "css_limit_reached": False, "css_rate_limited_stop": False, "css_assets": [],
            }
            css_rate_limited_stop = False
            if not self._stopping() and not engine.rate_limit_stopped and not analyzer.js_collector.rate_limit_stopped:
                from recon.css_collector import CSSCollector
                css_collector = CSSCollector(
                    self.url, cookie_jar=session_cookie_jar,
                    request_headers=phase_headers, on_log=self.log_message.emit,
                )
                stylesheet_seeds = list(analyzer.asset_observations.values())
                for observation in analyzer.network_observations.values():
                    if (
                        str(observation.get("resource_type") or "").lower() == "stylesheet"
                        or str(observation.get("url") or "").split("?", 1)[0].lower().endswith(".css")
                    ):
                        stylesheet_seeds.append({
                            "url": observation.get("url", ""),
                            "kind": "stylesheet",
                        })
                try:
                    css_discovery_data = loop.run_until_complete(
                        css_collector.collect(
                            stylesheet_seeds, should_stop=self._stopping,
                            delay_ms=max(200, int(engine.crawl_delay_seconds * 1000)),
                        )
                    )
                    css_rate_limited_stop = css_collector.rate_limit_stopped
                    analyzer.css_files_fetched = {
                        __import__("recon.parameter_intelligence", fromlist=["_normalize_endpoint"])._normalize_endpoint(url)
                        for url in css_collector.fetched_contents
                    }
                    analyzer.css_files_truncated = {
                        __import__("recon.parameter_intelligence", fromlist=["_normalize_endpoint"])._normalize_endpoint(url)
                        for url in css_collector.truncated_files
                    }
                    for item in css_collector.assets.values():
                        analyzer._record_asset_reference(
                            item.get("referrer") or self.url,
                            {
                                "url": item.get("request_url") or item.get("url", ""),
                                "kind": item.get("kind", "css-resource"),
                                "extension": item.get("extension", ""),
                            },
                        )
                    if css_collector.css_urls:
                        self.log_message.emit(
                            f"[CSS] Discovered {len(css_collector.css_urls)} same-origin stylesheet URL(s); "
                            f"fetched {len(css_collector.fetched_contents)} and extracted "
                            f"{len(css_collector.assets)} nested asset references."
                        )
                except Exception as exc:
                    css_discovery_data["css_file_errors"].append(
                        {"url": "", "error": type(exc).__name__}
                    )
                    self.log_message.emit(f"[CSS] Discovery phase failed: {type(exc).__name__}: {exc}")
                css_discovery_data["css_rate_limited_stop"] = css_rate_limited_stop

            wordlist_results = []
            wordlist_rate_limited_stop = False
            if (
                self.wordlist_path and not self._stopping()
                and not engine.rate_limit_stopped and not analyzer.js_collector.rate_limit_stopped
                and not css_rate_limited_stop
            ):
                from recon.wordlist_scanner import WordlistScanner
                self.log_message.emit(f"[Wordlist] Checking authorized paths: {self.wordlist_path}")
                scanner = WordlistScanner(
                    base_url=self.url,
                    wordlist_path=self.wordlist_path,
                    extensions=self.wordlist_extensions,
                    max_words=self.wordlist_max_words,
                    max_candidates=self.wordlist_max_candidates,
                    recursive=self.recursive_content_discovery,
                    recursion_depth=self.content_recursion_depth,
                    concurrency=1 if engine.crawl_delay_seconds > 0 else self.concurrency,
                    on_hit=lambda url, status, size: self.log_message.emit(
                        f"[HIT {status}] {url} ({size} bytes)"
                    ),
                    on_log=lambda message: self.log_message.emit(message),
                    should_stop=self._stopping,
                    on_result=lambda result: self.discovery_result.emit(result),
                    request_headers=phase_headers,
                    cookie_jar=session_cookie_jar,
                    delay_ms=max(200, int(engine.crawl_delay_seconds * 1000)),
                )
                analyzer.wordlist_hits = loop.run_until_complete(scanner.scan())
                wordlist_results = scanner.responses
                wordlist_rate_limited_stop = scanner.rate_limit_stopped
                if scanner.rate_limit_stopped:
                    self.log_message.emit("[Content Discovery] Stopped safely because rate limiting did not permit a compliant resume.")

            asset_probe_data = {
                "results": [],
                "summary": {
                    "enabled": self.probe_assets, "unique_same_origin_candidates": 0,
                    "selected_candidates": 0, "requests_completed": 0,
                    "skipped_out_of_origin": 0, "limit": self.asset_probe_max,
                    "limit_reached": False, "rate_limited": False,
                    "rate_limited_stop": False, "stopped_by_user": False,
                    "unattempted": 0, "partial": False, "method": "HEAD",
                },
            }
            # Optional, same-origin-only HEAD checks validate referenced files without
            # downloading bodies. Do not start another request phase after an HTTP 429.
            if (
                self.probe_assets and not self._stopping()
                and not engine.rate_limit_stopped and not analyzer.js_collector.rate_limit_stopped
                and not css_rate_limited_stop and not wordlist_rate_limited_stop
            ):
                from recon.asset_probe import probe_asset_references
                candidates = [
                    {
                        "url": item.get("url", ""),
                        "request_url": item.get("request_url") or item.get("url", ""),
                        "kind": item.get("kind", "resource"),
                        "extension": item.get("extension", ""),
                    }
                    for item in analyzer.asset_observations.values()
                ]
                self.log_message.emit(
                    f"[Assets] HEAD-checking referenced resources (limit={self.asset_probe_max}); "
                    "same-origin only, no response bodies, no redirects."
                )
                try:
                    asset_probe_data = loop.run_until_complete(probe_asset_references(
                        self.url, candidates, cookie_jar=session_cookie_jar,
                        request_headers=self.request_headers, should_stop=self._stopping,
                        on_log=self.log_message.emit, max_assets=self.asset_probe_max,
                        delay_ms=max(200, int(engine.crawl_delay_seconds * 1000)),
                    ))
                except Exception as exc:
                    self.log_message.emit(f"[Assets] Probe phase failed: {type(exc).__name__}")
                    asset_probe_data["summary"].update({
                        "enabled": True, "partial": True,
                        "error": type(exc).__name__,
                    })
            elif self.probe_assets:
                self.log_message.emit(
                    "[Assets] HEAD phase skipped because the scan stopped or an earlier phase was rate-limited."
                )
                asset_probe_data["summary"].update({
                    "enabled": True, "partial": True,
                    "skipped_due_to_previous_stop_or_rate_limit": True,
                })

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
            report["css_discovery_summary"] = css_discovery_data
            report["css_rate_limited_stop"] = css_rate_limited_stop
            report["asset_probe_summary"] = asset_probe_data.get("summary", {})
            report["asset_probe_results"] = asset_probe_data.get("results", [])
            probes_by_url = {
                str(item.get("url") or ""): item
                for item in report["asset_probe_results"] if item.get("url")
            }
            for asset in report.get("asset_inventory", []) or []:
                probe = probes_by_url.get(str(asset.get("url") or ""))
                asset["probe_checked"] = bool(probe)
                asset["probe_method"] = "HEAD" if probe else ""
                asset["probe_status"] = probe.get("status") if probe else None
                asset["probe_result"] = probe.get("result", "") if probe else ""
                asset["probe_content_type"] = probe.get("content_type", "") if probe else ""
                asset["probe_content_length"] = probe.get("content_length") if probe else None
                asset["probe_error"] = probe.get("error", "") if probe else ""
            report["seed_import_summary"] = {
                key: self.seed_import_summary.get(key)
                for key in (
                    "source_file", "source_type", "input_candidates", "accepted_count",
                    "rejected_or_out_of_scope", "limit", "limit_reached",
                )
                if key in self.seed_import_summary
            }
            imported_seed_set = set(self.imported_seed_urls)
            report["imported_seed_urls_crawled"] = len(
                {result.url for result in all_results} & imported_seed_set
            )
            report["manual_browser_session_enabled"] = self.manual_browser_session
            report["manual_browser_seconds"] = manual_browser_results.get("manual_browser_seconds", 0)
            report["manual_browser_window_seconds"] = manual_browser_results.get(
                "manual_browser_window_seconds", self.manual_browser_duration if self.manual_browser_session else 0
            )
            report["pages"] = [result.to_dict() for result in all_results]
            report["wordlist_results"] = wordlist_results
            report["wordlist_candidates"] = (
                scanner.candidate_count if self.wordlist_path and "scanner" in locals() else 0
            )
            report["wordlist_words_loaded"] = (
                scanner.words_loaded if self.wordlist_path and "scanner" in locals() else 0
            )
            report["wordlist_word_limit_reached"] = (
                scanner.word_limit_reached if self.wordlist_path and "scanner" in locals() else False
            )
            report["wordlist_path_limit_reached"] = (
                scanner.path_limit_reached if self.wordlist_path and "scanner" in locals() else False
            )
            report["wordlist_candidate_limit_reached"] = (
                scanner.candidate_limit_reached if self.wordlist_path and "scanner" in locals() else False
            )
            report["wordlist_max_words"] = (
                scanner.max_words if self.wordlist_path and "scanner" in locals() else self.wordlist_max_words
            )
            report["wordlist_max_candidates"] = (
                scanner.max_candidates if self.wordlist_path and "scanner" in locals() else self.wordlist_max_candidates
            )
            report["wordlist_recursive_enabled"] = (
                scanner.recursive if self.wordlist_path and "scanner" in locals() else self.recursive_content_discovery
            )
            report["wordlist_recursion_depth"] = (
                scanner.recursion_depth if self.wordlist_path and "scanner" in locals() else self.content_recursion_depth
            )
            report["wordlist_recursive_dirs_found"] = (
                scanner.recursive_dirs_found if self.wordlist_path and "scanner" in locals() else 0
            )
            report["wordlist_recursion_rounds"] = (
                scanner.recursion_rounds if self.wordlist_path and "scanner" in locals() else 0
            )
            report["wordlist_recursion_depth_limit_reached"] = (
                scanner.recursion_depth_limit_reached if self.wordlist_path and "scanner" in locals() else False
            )
            report["wordlist_limit_summary"] = {
                "words_loaded": report["wordlist_words_loaded"],
                "unique_candidates_generated": report["wordlist_candidates"],
                "max_words": report["wordlist_max_words"],
                "max_candidates": report["wordlist_max_candidates"],
                "word_limit_reached": report["wordlist_word_limit_reached"],
                "path_limit_reached": report["wordlist_path_limit_reached"],
            }
            # The cookie map stores names and attributes only, never cookie values.
            cookie_map = []
            for result in all_results:
                for event in getattr(result, "cookie_events", []) or []:
                    cookie_map.append({"url": result.url, "source": "http-response", **event})
            for result in wordlist_results:
                for event in result.get("set_cookie_names", []) or []:
                    cookie_map.append({"url": result.get("url", ""), "source": "content-discovery", **event})
            cookie_map.extend(manual_browser_results.get("session_cookies", []) or [])
            unique_cookie_map = {}
            for event in cookie_map:
                key = (
                    event.get("url", ""), event.get("name", ""), event.get("domain", ""),
                    event.get("path", ""), event.get("source", ""),
                )
                unique_cookie_map[key] = event
            report["cookie_map"] = sorted(
                unique_cookie_map.values(),
                key=lambda item: (item.get("url", ""), item.get("name", ""), item.get("source", "")),
            )
            report["wordlist_rate_limited_stop"] = wordlist_rate_limited_stop
            report["crawler_rate_limited_stop"] = engine.rate_limit_stopped
            report["page_limit_reached"] = engine.page_limit_reached
            report["depth_limit_reached"] = engine.depth_limit_reached
            report["filtered_pages"] = [result.to_dict() for result in filtered]
            report["similarity"] = SimilarityDetector().analyze(filtered)
            report["matcher_description"] = self.matcher.describe()
            report["matcher_applied"] = not self.matcher.is_empty()
            report["stopped_by_user"] = self._stopping()

            # Make inspection caps visible instead of presenting truncated evidence as complete.
            body_truncated_pages = [
                page.get("url", "") for page in report.get("pages", []) if page.get("body_truncated")
            ]
            truncated_js_files = report.get("truncated_js_files", []) or []
            truncated_css_urls = css_discovery_data.get("css_files_truncated", []) or []
            truncated_wordlist_urls = [
                item.get("url", "") for item in wordlist_results if item.get("response_truncated")
            ]
            content_limit_notes = []
            if body_truncated_pages:
                content_limit_notes.append(
                    f"{len(body_truncated_pages)} HTML/XML/robots response body/bodies truncated at the crawler body cap."
                )
            if truncated_js_files:
                content_limit_notes.append(
                    f"{len(truncated_js_files)} JavaScript file(s) truncated at the per-file JS byte cap."
                )
            if truncated_wordlist_urls:
                content_limit_notes.append(
                    f"{len(truncated_wordlist_urls)} Content Discovery response(s) truncated at the response byte cap."
                )
            if truncated_css_urls:
                content_limit_notes.append(
                    f"{len(truncated_css_urls)} CSS file(s) truncated at the per-file stylesheet byte cap."
                )
            report["body_truncated_pages"] = body_truncated_pages
            report["truncated_js_files"] = truncated_js_files
            report["truncated_css_files"] = truncated_css_urls
            report["truncated_wordlist_urls"] = truncated_wordlist_urls
            report["content_limit_reached"] = bool(
                body_truncated_pages or truncated_js_files or truncated_wordlist_urls or truncated_css_urls
            )
            report["content_limit_notes"] = content_limit_notes
            report["coverage_summary"] = {
                "pages_crawled": len(all_results),
                "page_cap": self.max_pages,
                "max_depth": self.max_depth,
                "page_limit_reached": engine.page_limit_reached,
                "depth_limit_reached": engine.depth_limit_reached,
                "wordlist_words_loaded": report.get("wordlist_words_loaded", 0),
                "wordlist_candidates": report.get("wordlist_candidates", 0),
                "wordlist_max_words": report.get("wordlist_max_words", 0),
                "wordlist_max_candidates": report.get("wordlist_max_candidates", 0),
                "wordlist_recursive_enabled": report.get("wordlist_recursive_enabled", False),
                "wordlist_recursion_depth": report.get("wordlist_recursion_depth", 1),
                "wordlist_recursive_dirs_found": report.get("wordlist_recursive_dirs_found", 0),
                "wordlist_recursion_rounds": report.get("wordlist_recursion_rounds", 0),
                "wordlist_recursion_depth_limit_reached": report.get("wordlist_recursion_depth_limit_reached", False),
                "wordlist_word_limit_reached": report.get("wordlist_word_limit_reached", False),
                "wordlist_path_limit_reached": report.get("wordlist_path_limit_reached", False),
                "wordlist_limit_reached": report.get("wordlist_candidate_limit_reached", False),
                "javascript_files_discovered": len(analyzer.js_collector.js_urls),
                "javascript_files_attempted": len(analyzer.js_collector._analyzed_js_urls),
                "javascript_files_truncated": len(truncated_js_files),
                "css_files_discovered": css_discovery_data.get("css_files_discovered", 0),
                "css_files_attempted": css_discovery_data.get("css_files_attempted", 0),
                "css_files_fetched": css_discovery_data.get("css_files_fetched", 0),
                "css_files_truncated": len(truncated_css_urls),
                "css_file_errors": len(css_discovery_data.get("css_file_errors", [])),
                "css_limit_reached": bool(css_discovery_data.get("css_limit_reached")),
                "css_rate_limited_stop": css_rate_limited_stop,
                "asset_references": len(report.get("asset_inventory", [])),
                "external_asset_references": sum(
                    1 for item in report.get("asset_inventory", []) if not item.get("in_scope", False)
                ),
                "asset_references_without_page_or_js_fetch": sum(
                    1 for item in report.get("asset_inventory", [])
                    if not item.get("fetched_by_page_crawler")
                    and not item.get("fetched_by_js_collector")
                    and not item.get("fetched_by_css_collector")
                ),
                "response_bodies_truncated": len(body_truncated_pages) + len(truncated_wordlist_urls),
                "content_limit_reached": report["content_limit_reached"],
                "imported_seed_candidates": len(self.imported_seed_urls),
                "imported_seed_urls_crawled": report.get("imported_seed_urls_crawled", 0),
                "imported_seed_limit_reached": bool(self.seed_import_summary.get("limit_reached")),
                "asset_probe_candidates": asset_probe_data.get("summary", {}).get("unique_same_origin_candidates", 0),
                "asset_probe_selected": asset_probe_data.get("summary", {}).get("selected_candidates", 0),
                "asset_probe_requests_completed": asset_probe_data.get("summary", {}).get("requests_completed", 0),
                "asset_probe_limit_reached": asset_probe_data.get("summary", {}).get("limit_reached", False),
                "asset_probe_rate_limited": asset_probe_data.get("summary", {}).get("rate_limited", False),
                "asset_probe_rate_limited_stop": asset_probe_data.get("summary", {}).get("rate_limited_stop", False),
                "asset_probe_partial": asset_probe_data.get("summary", {}).get("partial", False),
            }
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
                from recon.finding_correlator import correlate_findings
                report["related_findings"] = correlate_findings(report)
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
