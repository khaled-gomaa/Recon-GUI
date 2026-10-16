"""Discover nested subdomains mentioned in crawled content."""
import re
from urllib.parse import urlparse

from recon.domain_scope import registrable_domain


class SubdomainFinder:
    def __init__(self, base_domain: str, on_log=None):
        parsed_host = urlparse(base_domain).hostname
        host = (parsed_host or base_domain).lower().strip(".")
        self.on_log = on_log or (lambda _message: None)
        self.enabled = True
        # Public suffix support is required to group sibling hosts reliably.
        # A missing dependency should not abort a full crawl for this passive
        # text-extraction feature. Active subdomain verification still calls
        # registrable_domain() directly and remains fail-closed.
        try:
            self.base_domain = registrable_domain(host) or host
        except (RuntimeError, OSError) as exc:
            # Frozen PyInstaller builds can occasionally miss tldextract's hidden
            # .tld_set_snapshot resource. This is optional text discovery; do not
            # abort the entire crawl. Active scope verification remains fail-closed.
            self.enabled = False
            self.base_domain = host
            self.on_log(
                "[Subdomains] Text-based subdomain extraction is disabled because "
                f"public-suffix support is unavailable ({exc}). Install dependencies "
                "with 'py -m pip install -r requirements.txt' or run run_windows.bat."
            )
        self.pattern = re.compile(
            r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            + re.escape(self.base_domain) + r")\b",
            re.IGNORECASE,
        )

    def find(self, text: str) -> set:
        if not self.enabled:
            return set()
        found = {match.group(1).lower().rstrip(".") for match in self.pattern.finditer(text or "")}
        return {host for host in found if host != self.base_domain}
