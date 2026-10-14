"""Aggregate observations from crawled pages and build linked inventories."""
from urllib.parse import parse_qsl, urljoin, urlparse, urlsplit
from dataclasses import dataclass, field

from recon.advanced_analysis import analyze_html
from recon.email_extractor import EmailExtractor
from recon.subdomain_finder import SubdomainFinder
from recon.js_endpoint_extractor import JSEndpointExtractor
from recon.header_auditor import HeaderAuditor
from recon.js_collector import JSCollector
from recon.parameter_intelligence import (
    build_endpoint_inventory, build_parameter_inventory, _normalize_endpoint,
)


@dataclass
class ReconReport:
    emails: set = field(default_factory=set)
    subdomains: set = field(default_factory=set)
    endpoints: set = field(default_factory=set)
    header_audits: list = field(default_factory=list)


class ReconAnalyzer:
    def __init__(self, base_domain: str, request_headers: dict | None = None, on_log=None, cookie_jar=None):
        parsed_host = urlparse(base_domain).hostname
        host = (parsed_host or base_domain).lower()
        self.base_host = host
        self.base_url = base_domain if "://" in base_domain else "https://" + base_domain
        self.subdomain_finder = SubdomainFinder(host)
        self.report = ReconReport()
        self.js_collector = JSCollector(
            base_domain, on_log=on_log, request_headers=request_headers, cookie_jar=cookie_jar
        )
        self.request_headers = dict(request_headers or {})
        self.cookie_jar = cookie_jar
        self.wordlist_hits: list = []
        self.favicon_hash: str = ""
        self.matcher_applied: bool = False
        self.forms: dict[tuple, dict] = {}
        self.json_ld: dict[tuple, dict] = {}
        self.sensitive_findings: dict[tuple, dict] = {}
        self.page_urls: set[str] = set()
        self.discovered_links: set[str] = set()
        # Raw endpoint candidates exist only in memory so parameter names can be extracted.
        # Reported endpoint paths remove query strings and their potentially sensitive values.
        self.endpoint_observations: list[dict] = []
        self._observation_keys: set[tuple] = set()
        self.network_observations: dict[tuple, dict] = {}
        self.asset_observations: dict[tuple, dict] = {}
        self._asset_observation_keys: set[tuple] = set()

    def _record_endpoint(
        self, endpoint: str, source: str, location: str, method=None,
        query_parameters=None, body_parameters=None,
    ):
        endpoint = str(endpoint or "").strip()
        if not endpoint:
            return
        parsed = urlparse(endpoint)
        if not (parsed.scheme and parsed.netloc):
            endpoint = urljoin(location or self.base_url, endpoint)
            parsed = urlparse(endpoint)
        # External references are not app endpoints. The crawler's in-scope HTML links
        # and route candidates should all resolve to the target hostname.
        if parsed.scheme.lower() not in ("http", "https") or (parsed.hostname or "").lower() != self.base_host:
            return
        method = str(method or "").strip().upper()
        key = (endpoint, source, location, method)
        if key in self._observation_keys:
            return
        self._observation_keys.add(key)
        self.endpoint_observations.append({
            "endpoint": endpoint, "source": source, "location": location,
            "method": method,
            "query_parameters": sorted({str(name) for name in (query_parameters or []) if str(name)}),
            "body_parameters": sorted({str(name) for name in (body_parameters or []) if str(name)}),
        })
        safe_endpoint = _normalize_endpoint(endpoint)
        if safe_endpoint:
            self.report.endpoints.add(safe_endpoint)

    def record_network_observation(self, record: dict):
        """Store request metadata only; URLs are already sanitized and bodies are never retained."""
        raw_url = str(record.get("url") or "").strip()
        if not raw_url:
            return
        parsed = urlparse(raw_url)
        if parsed.scheme.lower() not in ("http", "https") or (parsed.hostname or "").lower() != self.base_host:
            return
        method = str(record.get("method") or "GET").upper()
        source = str(record.get("source") or "browser-network")
        location = str(record.get("page") or "")
        query_names = sorted({str(name) for name in (record.get("query_parameters") or []) if str(name)})
        body_names = sorted({str(name) for name in (record.get("body_parameters") or []) if str(name)})
        key = (raw_url, method, location, source)
        current = self.network_observations.get(key)
        safe_record = {
            "url": _normalize_endpoint(raw_url),
            "method": method,
            "source": source,
            "page": _normalize_endpoint(location) if location else "",
            "resource_type": str(record.get("resource_type") or ""),
            "query_parameters": query_names,
            "body_parameters": body_names,
            "status": record.get("status"),
            "content_type": str(record.get("content_type") or ""),
        }
        if current:
            if safe_record["status"] is not None:
                current["status"] = safe_record["status"]
            if safe_record["content_type"]:
                current["content_type"] = safe_record["content_type"]
            current["query_parameters"] = sorted(set(current["query_parameters"]) | set(query_names))
            current["body_parameters"] = sorted(set(current["body_parameters"]) | set(body_names))
        else:
            self.network_observations[key] = safe_record
        self._record_endpoint(
            raw_url, source, location or self.base_url, method,
            query_parameters=query_names, body_parameters=body_names,
        )

    def _record_asset_reference(self, page_url: str, asset: dict):
        raw_url = str((asset or {}).get("url") or "").strip()
        if not raw_url:
            return
        parsed = urlparse(raw_url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return
        try:
            host = parsed.hostname.rstrip(".").lower().encode("idna").decode("ascii")
        except UnicodeError:
            return
        safe_url = _normalize_endpoint(raw_url)
        if not safe_url:
            return
        page_path = _normalize_endpoint(page_url)
        kind = str((asset or {}).get("kind") or "resource")
        extension = str((asset or {}).get("extension") or "")
        key = (safe_url, kind, page_path)
        if key in self._asset_observation_keys:
            return
        self._asset_observation_keys.add(key)
        item_key = (safe_url, kind)
        item = self.asset_observations.setdefault(item_key, {
            "url": safe_url, "request_url": raw_url, "kind": kind, "extension": extension,
            "referrers": set(), "query_parameter_names": set(),
            "in_scope": host == self.base_host,
        })
        if page_path:
            item["referrers"].add(page_path)
        try:
            item["query_parameter_names"].update(
                name for name, _value in parse_qsl(urlsplit(raw_url).query, keep_blank_values=True)
                if name
            )
        except ValueError:
            pass

    def analyze_page(
        self, url: str, html: str, headers: dict = None, discovered_links=None,
        discovered_assets=None,
    ):
        html = html or ""
        self.page_urls.add(url)
        for asset in discovered_assets or []:
            self._record_asset_reference(url, asset)
        for link in discovered_links or []:
            if not isinstance(link, str) or not link.startswith(("http://", "https://")):
                continue
            parsed_link = urlparse(link)
            if (parsed_link.hostname or "").lower() != self.base_host:
                continue
            self.discovered_links.add(link)
            self._record_endpoint(
                link,
                "discovered-link-query" if parsed_link.query else "html-link",
                url,
            )
        self.report.emails.update(EmailExtractor.extract(html))
        self.report.subdomains.update(self.subdomain_finder.find(html))
        for endpoint in JSEndpointExtractor.extract(html):
            self._record_endpoint(endpoint, "html-or-inline-js", url)
        for request in JSEndpointExtractor.extract_request_observations(html):
            self._record_endpoint(
                request.get("endpoint", ""), request.get("source", "javascript-static"), url,
                method=request.get("method"),
                body_parameters=request.get("body_parameters", []),
            )
        self.js_collector.collect_from_html(url, html)

        for route in JSEndpointExtractor.extract_routes(html):
            resolved = urljoin(url, route)
            if urlparse(resolved).scheme.lower() in ("http", "https"):
                self._record_endpoint(resolved, "inline-route", url)

        advanced = analyze_html(url, html)
        for form in advanced["forms"]:
            key = (form.get("page"), form.get("method"), form.get("action"))
            self.forms[key] = form
            action = str(form.get("action") or "").strip()
            method = str(form.get("method") or "GET").upper()
            field_names = sorted({
                str(field.get("name") or "").strip()
                for field in (form.get("fields") or [])
                if str(field.get("name") or "").strip()
            })
            if action:
                self._record_endpoint(
                    action, "html-form-declaration", url, method=method,
                    query_parameters=field_names if method == "GET" else [],
                    body_parameters=field_names if method not in {"GET", "HEAD"} else [],
                )
        for item in advanced["json_ld"]:
            key = (item.get("page"), item.get("type"), item.get("name", ""))
            self.json_ld[key] = item
        for item in advanced["sensitive_findings"]:
            key = (item.get("page"), item.get("type"), item.get("source"), item.get("key_name", ""))
            self.sensitive_findings[key] = item

        if headers:
            # Refresh by URL because rendered DOM may replace a static page result.
            self.report.header_audits = [
                audit for audit in self.report.header_audits if audit.url != url
            ]
            self.report.header_audits.append(HeaderAuditor.audit(url, headers))

    def finalize_js(self, loop, should_stop=None, delay_seconds: float = 0.0):
        loop.run_until_complete(
            self.js_collector.download_and_analyze(
                should_stop=should_stop, delay_seconds=delay_seconds
            )
        )
        for js_url, js_content in self.js_collector.js_contents.items():
            for endpoint in JSEndpointExtractor.extract(js_content):
                self._record_endpoint(endpoint, "javascript", js_url)
            for request in JSEndpointExtractor.extract_request_observations(js_content):
                self._record_endpoint(
                    request.get("endpoint", ""), request.get("source", "javascript-static"), js_url,
                    method=request.get("method"),
                    body_parameters=request.get("body_parameters", []),
                )
            for route in JSEndpointExtractor.extract_routes(js_content):
                self._record_endpoint(urljoin(js_url, route), "javascript-route", js_url)
            self.report.emails.update(EmailExtractor.extract(js_content))
            self.report.subdomains.update(self.subdomain_finder.find(js_content))
            js_analysis = analyze_html(js_url, js_content)
            for item in js_analysis["sensitive_findings"]:
                key = (item.get("page"), item.get("type"), item.get("source"), item.get("key_name", ""))
                self.sensitive_findings[key] = item

    def to_dict(self) -> dict:
        forms = sorted(self.forms.values(), key=lambda item: (item["page"], item["action"]))
        endpoint_inventory = build_endpoint_inventory(
            self.endpoint_observations,
            discovered_routes=self.js_collector.route_urls,
            page_urls=self.page_urls,
        )
        parameters = build_parameter_inventory(
            self.page_urls, forms, self.endpoint_observations,
            discovered_routes=self.js_collector.route_urls,
            candidate_urls=self.discovered_links,
            network_observations=list(self.network_observations.values()),
        )
        # Never expose parameter values extracted from endpoint/query strings.
        safe_routes = sorted({_normalize_endpoint(route) for route in self.js_collector.route_urls if _normalize_endpoint(route)})
        safe_endpoints = sorted({item["endpoint"] for item in endpoint_inventory})
        return {
            "favicon_hash": self.favicon_hash,
            "emails": sorted(self.report.emails),
            "subdomains": sorted(self.report.subdomains),
            "endpoints": safe_endpoints,
            "endpoint_inventory": endpoint_inventory,
            "endpoint_observations_count": len(self.endpoint_observations),
            "network_observations": sorted(
                self.network_observations.values(),
                key=lambda item: (item.get("url", ""), item.get("method", ""), item.get("source", "")),
            ),
            "asset_inventory": [
                {
                    "url": item["url"], "kind": item["kind"], "extension": item["extension"],
                    "referrers": sorted(item["referrers"]),
                    "reference_count": len(item["referrers"]),
                    "query_parameter_names": sorted(item["query_parameter_names"]),
                    "in_scope": item["in_scope"],
                    "fetched_by_page_crawler": item["url"] in {
                        _normalize_endpoint(page_url) for page_url in self.page_urls
                    },
                    "fetched_by_js_collector": item["url"] in {
                        _normalize_endpoint(js_url) for js_url in self.js_collector.js_contents
                    },
                }
                for _key, item in sorted(
                    self.asset_observations.items(), key=lambda pair: (pair[0][0].casefold(), pair[0][1])
                )
            ],
            "discovered_link_count": len(self.discovered_links),
            "parameters": parameters,
            "parameter_count": len(parameters),
            "header_audits": [
                {"url": audit.url, "present": audit.present, "missing": audit.missing}
                for audit in self.report.header_audits
            ],
            "js_files": sorted(self.js_collector.js_urls),
            "truncated_js_files": sorted({
                _normalize_endpoint(url) for url in self.js_collector.truncated_js_files
                if _normalize_endpoint(url)
            }),
            "source_maps": sorted(self.js_collector.source_maps),
            "discovered_routes": safe_routes,
            "inline_script_count": len(self.js_collector.inline_scripts),
            "js_rate_limited_stop": self.js_collector.rate_limit_stopped,
            "wordlist_hits": self.wordlist_hits,
            "forms": forms,
            "json_ld": sorted(self.json_ld.values(), key=lambda item: (item["page"], item["type"])),
            "sensitive_findings": sorted(
                self.sensitive_findings.values(),
                key=lambda item: (item["page"], item["type"], item.get("source", "")),
            ),
        }
