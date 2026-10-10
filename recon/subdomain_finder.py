"""Discover subdomains mentioned in page content."""
import re


class SubdomainFinder:
    def __init__(self, base_domain: str):
        self.base_domain = base_domain
        self.pattern = re.compile(
            r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
            r"\." + re.escape(base_domain) + r"\b"
        )

    def find(self, text: str) -> set:
        matches = self.pattern.findall(text)
        subs = set()
        for sub in matches:
            full = f"{sub}.{self.base_domain}"
            if full != self.base_domain:
                subs.add(full)
        return subs
