"""Aggregate all reconnaissance results."""
from dataclasses import dataclass, field
from recon.email_extractor import EmailExtractor
from recon.subdomain_finder import SubdomainFinder
from recon.js_endpoint_extractor import JSEndpointExtractor
from recon.header_auditor import HeaderAuditor, HeaderAuditResult
from recon.js_collector import JSCollector


@dataclass
class ReconReport:
    emails: set = field(default_factory=set)
    subdomains: set = field(default_factory=set)
    endpoints: set = field(default_factory=set)
    header_audits: list = field(default_factory=list)


class ReconAnalyzer:
    def __init__(self, base_domain: str):
        self.subdomain_finder = SubdomainFinder(base_domain)
        self.report = ReconReport()
        self.js_collector = JSCollector(base_domain)
        self.wordlist_hits: list = []
        self.favicon_hash: str = ""
        self.matcher_applied: bool = False

    def analyze_page(self, url: str, html: str, headers: dict = None):
        self.report.emails.update(EmailExtractor.extract(html))
        self.report.subdomains.update(self.subdomain_finder.find(html))
        self.report.endpoints.update(JSEndpointExtractor.extract(html))
        self.js_collector.collect_from_html(url, html)
        if headers:
            self.report.header_audits.append(HeaderAuditor.audit(url, headers))

    def finalize_js(self, loop):
        loop.run_until_complete(self.js_collector.download_and_analyze())

    def to_dict(self) -> dict:
        return {
            "favicon_hash": self.favicon_hash,
            "emails": sorted(self.report.emails),
            "subdomains": sorted(self.report.subdomains),
            "endpoints": sorted(self.report.endpoints),
            "header_audits": [
                {"url": a.url, "present": a.present, "missing": a.missing}
                for a in self.report.header_audits
            ],
            "js_files": sorted(self.js_collector.js_urls),
            "source_maps": sorted(self.js_collector.source_maps),
            "inline_script_count": len(self.js_collector.inline_scripts),
            "wordlist_hits": self.wordlist_hits,
        }
