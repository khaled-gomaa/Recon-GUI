"""Aggregate observations from crawled pages and build linked inventories."""
from urllib.parse import urljoin, urlparse
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
    def __init__(self, base_domain: str, request_headers: dict | None = None, on_log=None):
        parsed_host = urlparse(base_domain).hostname
        host = (parsed_host or base_domain).lower()
        self.subdomain_finder = SubdomainFinder(host)
        self.report = ReconReport()
        self.js_collector = JSCollector(base_domain, on_log=on_log, request_headers=request_headers)
        self.request_headers = dict(request_headers or {})
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

    def _record_endpoint(self, endpoint: str, source: str, location: str):
        endpoint = str(endpoint or "").strip()
        if not endpoint:
            return
        key = (endpoint, source, location)
        if key in self._observation_keys:
            return
        self._observation_keys.add(key)
        self.endpoint_observations.append({
            "endpoint": endpoint, "source": source, "location": location,
        })
        safe_endpoint = _normalize_endpoint(endpoint)
        if safe_endpoint:
            self.report.endpoints.add(safe_endpoint)

    def analyze_page(self, url: str, html: str, headers: dict = None, discovered_links=None):
        html = html or ""
        self.page_urls.add(url)
        for link in discovered_links or []:
            if not isinstance(link, str) or not link.startswith(("http://", "https://")):
                continue
            self.discovered_links.add(link)
            if urlparse(link).query:
                self._record_endpoint(link, "discovered-link-query", url)
        self.report.emails.update(EmailExtractor.extract(html))
        self.report.subdomains.update(self.subdomain_finder.find(html))
        for endpoint in JSEndpointExtractor.extract(html):
            self._record_endpoint(endpoint, "html-or-inline-js", url)
        self.js_collector.collect_from_html(url, html)

        for route in JSEndpointExtractor.extract_routes(html):
            resolved = urljoin(url, route)
            if urlparse(resolved).scheme.lower() in ("http", "https"):
                self._record_endpoint(resolved, "inline-route", url)

        advanced = analyze_html(url, html)
        for form in advanced["forms"]:
            key = (form.get("page"), form.get("method"), form.get("action"))
            self.forms[key] = form
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
            "discovered_link_count": len(self.discovered_links),
            "parameters": parameters,
            "parameter_count": len(parameters),
            "header_audits": [
                {"url": audit.url, "present": audit.present, "missing": audit.missing}
                for audit in self.report.header_audits
            ],
            "js_files": sorted(self.js_collector.js_urls),
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
