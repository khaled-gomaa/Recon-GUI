"""Aggregate observations from crawled pages, JavaScript, and HTML analysis."""
from urllib.parse import urlparse
from dataclasses import dataclass, field

from recon.advanced_analysis import analyze_html
from recon.email_extractor import EmailExtractor
from recon.subdomain_finder import SubdomainFinder
from recon.js_endpoint_extractor import JSEndpointExtractor
from recon.header_auditor import HeaderAuditor
from recon.js_collector import JSCollector


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

    def analyze_page(self, url: str, html: str, headers: dict = None):
        html = html or ""
        self.report.emails.update(EmailExtractor.extract(html))
        self.report.subdomains.update(self.subdomain_finder.find(html))
        self.report.endpoints.update(JSEndpointExtractor.extract(html))
        self.js_collector.collect_from_html(url, html)

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
            self.report.header_audits.append(HeaderAuditor.audit(url, headers))

    def finalize_js(self, loop, should_stop=None):
        loop.run_until_complete(
            self.js_collector.download_and_analyze(should_stop=should_stop)
        )
        self.report.endpoints.update(self.js_collector.endpoints)

    def to_dict(self) -> dict:
        return {
            "favicon_hash": self.favicon_hash,
            "emails": sorted(self.report.emails),
            "subdomains": sorted(self.report.subdomains),
            "endpoints": sorted(self.report.endpoints),
            "header_audits": [
                {"url": audit.url, "present": audit.present, "missing": audit.missing}
                for audit in self.report.header_audits
            ],
            "js_files": sorted(self.js_collector.js_urls),
            "source_maps": sorted(self.js_collector.source_maps),
            "discovered_routes": sorted(self.js_collector.route_urls),
            "inline_script_count": len(self.js_collector.inline_scripts),
            "wordlist_hits": self.wordlist_hits,
            "forms": sorted(self.forms.values(), key=lambda item: (item["page"], item["action"])),
            "json_ld": sorted(self.json_ld.values(), key=lambda item: (item["page"], item["type"])),
            "sensitive_findings": sorted(
                self.sensitive_findings.values(),
                key=lambda item: (item["page"], item["type"], item.get("source", "")),
            ),
        }
