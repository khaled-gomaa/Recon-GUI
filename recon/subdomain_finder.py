"""Discover nested subdomains mentioned in crawled content."""
import re
from urllib.parse import urlparse

# Common multi-label public suffixes where the registrable domain has three labels.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au",
    "co.nz", "org.nz", "co.jp",
    "com.br", "com.cn", "com.sg", "com.tr", "com.mx",
    "co.in", "firm.in", "net.in", "org.in",
    "co.za",
}


class SubdomainFinder:
    def __init__(self, base_domain: str):
        parsed_host = urlparse(base_domain).hostname
        host = (parsed_host or base_domain).lower().strip(".")
        labels = host.split(".")
        if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
            root = ".".join(labels[-3:])
        elif len(labels) >= 2:
            root = ".".join(labels[-2:])
        else:
            root = host
        self.base_domain = root
        self.pattern = re.compile(
            r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+)"
            + re.escape(self.base_domain) + r")\b",
            re.IGNORECASE,
        )

    def find(self, text: str) -> set:
        found = {match.group(1).lower().rstrip(".") for match in self.pattern.finditer(text or "")}
        return {host for host in found if host != self.base_domain}
