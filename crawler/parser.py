"""Parse HTML, extract links, and gather raw content for recon."""
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag


class PageParser:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def parse(self, html: str, current_url: str) -> dict:
        soup = BeautifulSoup(html, "lxml")
        document_base = self._document_base(soup, current_url)
        return {
            "title": self._get_title(soup),
            "links": self._extract_links(soup, document_base),
            "raw_html": html,
            "text": soup.get_text(separator=" ", strip=True),
            "scripts": self._extract_script_srcs(soup, document_base),
        }

    @staticmethod
    def _document_base(soup: BeautifulSoup, current_url: str) -> str:
        """Resolve relative resources against a valid HTML <base href>, if present."""
        tag = soup.find("base", href=True)
        if not tag:
            return current_url
        candidate = urljoin(current_url, tag["href"].strip())
        parsed = urlparse(candidate)
        if parsed.scheme.lower() in ("http", "https") and parsed.hostname:
            return candidate
        return current_url

    @staticmethod
    def _get_title(soup: BeautifulSoup) -> str:
        tag = soup.find("title")
        return tag.get_text(strip=True) if tag else ""

    def _extract_links(self, soup: BeautifulSoup, current_url: str) -> list:
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            absolute = urljoin(current_url, href)
            absolute, _ = urldefrag(absolute)
            if absolute.startswith(("http://", "https://")):
                links.add(absolute)
        return list(links)

    def _extract_script_srcs(self, soup: BeautifulSoup, current_url: str) -> list:
        scripts = set()
        for tag in soup.find_all("script", src=True):
            src = tag["src"].strip()
            if src:
                absolute = urljoin(current_url, src)
                if absolute.startswith(("http://", "https://")):
                    scripts.add(absolute)
        return list(scripts)

    @staticmethod
    def is_same_domain(url: str, base: str) -> bool:
        return urlparse(url).netloc == urlparse(base).netloc
