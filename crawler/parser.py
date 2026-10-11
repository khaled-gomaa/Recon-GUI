"""Parse HTML and discover ordinary, hidden, and client-side routes."""
import re
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, urldefrag

from recon.js_endpoint_extractor import JSEndpointExtractor

META_REFRESH_RE = re.compile(r"""(?:^|;)\s*url\s*=\s*['"]?([^;'"]+)""", re.IGNORECASE)
DATA_URL_ATTRIBUTES = ("data-href", "data-url", "data-link", "data-endpoint", "data-action", "data-target")
STATIC_SUFFIXES = (
    ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
)


class PageParser:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def parse(self, html: str, current_url: str) -> dict:
        soup = BeautifulSoup(html or "", "lxml")
        document_base = self._document_base(soup, current_url)
        inline_routes = set()
        for script in soup.find_all("script", src=False):
            inline_routes.update(JSEndpointExtractor.extract_routes(script.string or script.get_text() or ""))
        for comment in soup.find_all(string=lambda value: isinstance(value, Comment)):
            inline_routes.update(JSEndpointExtractor.extract_routes(str(comment)))

        return {
            "title": self._get_title(soup),
            "links": self._extract_links(soup, document_base, inline_routes),
            "raw_html": html or "",
            "text": soup.get_text(separator=" ", strip=True),
            "scripts": self._extract_script_srcs(soup, document_base),
            "hidden_routes": sorted(self._resolve_candidates(inline_routes, document_base)),
        }

    @staticmethod
    def _document_base(soup: BeautifulSoup, current_url: str) -> str:
        """Resolve relative resources against a valid HTML <base href>, if present."""
        tag = soup.find("base", href=True)
        if not tag:
            return current_url
        try:
            candidate = urljoin(current_url, tag["href"].strip())
            parsed = urlparse(candidate)
            if parsed.scheme.lower() in ("http", "https") and parsed.hostname:
                return candidate
        except (TypeError, ValueError, UnicodeError):
            pass
        return current_url

    @staticmethod
    def _get_title(soup: BeautifulSoup) -> str:
        tag = soup.find("title")
        return tag.get_text(strip=True) if tag else ""

    @staticmethod
    def _candidate_url(value: str, current_url: str):
        value = (value or "").strip()
        if not value or value.lower().startswith(
            ("#", "mailto:", "tel:", "javascript:", "data:", "blob:")
        ):
            return None
        try:
            absolute = urljoin(current_url, value)
            absolute, _ = urldefrag(absolute)
            parsed = urlparse(absolute)
            if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
                return None
            # Invalid URL authorities (such as malformed IPv6 literals) are ignored.
            _ = parsed.port
        except (TypeError, ValueError, UnicodeError):
            return None
        if parsed.path.lower().endswith(STATIC_SUFFIXES):
            return None
        return absolute

    @classmethod
    def _resolve_candidates(cls, candidates, current_url: str) -> set:
        return {
            resolved for item in candidates
            if (resolved := cls._candidate_url(item, current_url))
        }

    def _extract_links(self, soup: BeautifulSoup, current_url: str, inline_routes=None) -> list:
        links = set()
        tag_attributes = (
            ("a", "href"), ("area", "href"), ("form", "action"),
            ("button", "formaction"), ("input", "formaction"),
            ("iframe", "src"), ("frame", "src"), ("object", "data"),
        )
        for tag_name, attribute in tag_attributes:
            for tag in soup.find_all(tag_name, attrs={attribute: True}):
                candidate = self._candidate_url(tag.get(attribute, ""), current_url)
                if candidate:
                    links.add(candidate)

        # Canonical/alternate links can reveal public routes; ignore stylesheet links.
        for tag in soup.find_all("link", href=True):
            rel = {str(value).lower() for value in (tag.get("rel") or [])}
            if rel.intersection({"canonical", "alternate"}):
                candidate = self._candidate_url(tag["href"], current_url)
                if candidate:
                    links.add(candidate)

        # Data attributes and onclick handlers frequently hide SPA navigation targets.
        for tag in soup.find_all(True):
            for attribute in DATA_URL_ATTRIBUTES:
                if tag.has_attr(attribute):
                    candidate = self._candidate_url(tag.get(attribute, ""), current_url)
                    if candidate:
                        links.add(candidate)
            onclick = tag.get("onclick", "")
            if onclick:
                for route in JSEndpointExtractor.extract_routes(onclick):
                    candidate = self._candidate_url(route, current_url)
                    if candidate:
                        links.add(candidate)

        # HTML meta refresh is a navigation just like an anchor.
        for tag in soup.find_all("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)}):
            match = META_REFRESH_RE.search(tag.get("content", ""))
            if match:
                candidate = self._candidate_url(match.group(1), current_url)
                if candidate:
                    links.add(candidate)

        for route in inline_routes or ():
            candidate = self._candidate_url(route, current_url)
            if candidate:
                links.add(candidate)
        return sorted(links)

    def _extract_script_srcs(self, soup: BeautifulSoup, current_url: str) -> list:
        scripts = set()
        for tag in soup.find_all("script", src=True):
            src = tag["src"].strip()
            if not src:
                continue
            try:
                absolute = urljoin(current_url, src)
                parsed = urlparse(absolute)
                if parsed.scheme.lower() in ("http", "https") and parsed.hostname:
                    _ = parsed.port
                    scripts.add(absolute)
            except (TypeError, ValueError, UnicodeError):
                continue
        return sorted(scripts)

    @staticmethod
    def is_same_domain(url: str, base: str) -> bool:
        return (urlparse(url).hostname or "").lower() == (urlparse(base).hostname or "").lower()
