"""Discover nested subdomains mentioned in crawled content."""
import re
from urllib.parse import urlparse

from recon.domain_scope import registrable_domain


class SubdomainFinder:
    def __init__(self, base_domain: str):
        parsed_host = urlparse(base_domain).hostname
        host = (parsed_host or base_domain).lower().strip(".")
        # Use the local Public Suffix List (including private hosting suffixes) so
        # e.g. tenant.blogspot.com is not grouped with unrelated Blogspot tenants.
        self.base_domain = registrable_domain(host) or host
        root = self.base_domain
        self.pattern = re.compile(
            r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            + re.escape(self.base_domain) + r")\b",
            re.IGNORECASE,
        )

    def find(self, text: str) -> set:
        found = {match.group(1).lower().rstrip(".") for match in self.pattern.finditer(text or "")}
        return {host for host in found if host != self.base_domain}
