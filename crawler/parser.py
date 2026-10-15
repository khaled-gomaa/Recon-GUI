"""Parse HTML and discover ordinary, hidden, and client-side routes."""
import json
import re
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, urldefrag

from recon.js_endpoint_extractor import JSEndpointExtractor

META_REFRESH_RE = re.compile(r"""(?:^|;)\s*url\s*=\s*['"]?([^;'"]+)""", re.IGNORECASE)
ROBOTS_RULE_RE = re.compile(r"^\s*(?:allow|disallow):\s*(/[^\s#]*)", re.IGNORECASE | re.MULTILINE)
ROBOTS_SITEMAP_RE = re.compile(r"^\s*sitemap:\s*(https?://\S+)", re.IGNORECASE | re.MULTILINE)
DATA_URL_ATTRIBUTES = ("data-href", "data-url", "data-link", "data-endpoint", "data-action", "data-target")
STATIC_SUFFIXES = (
    ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
)
DOWNLOAD_SUFFIXES = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".zip",
    ".7z", ".rar", ".tar", ".gz", ".tgz", ".sql", ".db", ".sqlite", ".bak",
    ".old", ".orig", ".backup", ".conf", ".config", ".env", ".log", ".wasm",
)
SRCSET_RE = re.compile(r"""(?:^|,)\s*([^,\s]+)""")
CSS_URL_RE = re.compile(r"""url\(\s*['"]?([^'")\s]+)""", re.IGNORECASE)
JSONLD_URL_KEYS = {
    "@id", "url", "mainentityofpage", "ispartof", "haspart", "relatedlink",
    "significantlink", "sameas", "contenturl", "embedurl", "subjectof",
}
MAX_JSONLD_SCRIPTS = 100
MAX_JSONLD_SCRIPT_CHARS = 1_000_000
MAX_JSONLD_URLS_PER_PAGE = 500


class PageParser:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def parse(self, html: str, current_url: str) -> dict:
        raw_content = html or ""
        source_path = urlparse(current_url).path.lower()
        looks_like_sitemap = (
            source_path.endswith((".xml", ".xml.gz"))
            or re.search(r"<(?:[a-z0-9_-]+:)?(?:urlset|sitemapindex)\b", raw_content[:1000], re.IGNORECASE)
        )
        # Use an XML-aware parser for sitemap documents rather than silently treating them as HTML.
        soup = BeautifulSoup(raw_content, "xml" if looks_like_sitemap else "lxml")
        document_base = self._document_base(soup, current_url)
        inline_routes = set()
        for script in soup.find_all("script", src=False):
            inline_routes.update(JSEndpointExtractor.extract_routes(script.string or script.get_text() or ""))
        for comment in soup.find_all(string=lambda value: isinstance(value, Comment)):
            inline_routes.update(JSEndpointExtractor.extract_routes(str(comment)))

        return {
            "title": self._get_title(soup),
            "links": self._extract_links(
                soup, document_base, inline_routes,
                raw_content=html or "", source_url=current_url,
            ),
            "raw_html": html or "",
            "text": soup.get_text(separator=" ", strip=True),
            "scripts": self._extract_script_srcs(soup, document_base),
            "assets": self._extract_asset_references(soup, document_base),
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

    def _extract_links(
        self, soup: BeautifulSoup, current_url: str, inline_routes=None,
        raw_content: str = "", source_url: str = "",
    ) -> list:
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

        # Social/meta canonical hints may survive even when a body has no ordinary links.
        for tag in soup.find_all("meta", attrs={"content": True}):
            key = str(tag.get("property") or tag.get("name") or tag.get("itemprop") or "").strip().lower()
            if key not in {"og:url", "twitter:url", "url"}:
                continue
            candidate = self._candidate_url(tag.get("content", ""), current_url)
            if candidate:
                links.add(candidate)

        # Structured data can expose pages that are not linked in visible navigation.
        # Only URL-like fields are considered, with strict per-page parsing limits.
        jsonld_count = 0
        for script in soup.find_all("script", attrs={"type": re.compile(r"application/ld\\+json", re.I)})[:MAX_JSONLD_SCRIPTS]:
            text = script.string or script.get_text() or ""
            if not text.strip() or len(text) > MAX_JSONLD_SCRIPT_CHARS:
                continue
            try:
                data = json.loads(text)
            except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
                continue
            for value in self._jsonld_url_candidates(data):
                candidate = self._candidate_url(value, current_url)
                if candidate:
                    links.add(candidate)
                    jsonld_count += 1
                    if jsonld_count >= MAX_JSONLD_URLS_PER_PAGE:
                        break
            if jsonld_count >= MAX_JSONLD_URLS_PER_PAGE:
                break

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

        # Sitemap XML <loc> elements are high-confidence page URLs.
        source_path = urlparse(source_url or current_url).path.lower()
        is_sitemap = (
            source_path.endswith((".xml", ".xml.gz"))
            or soup.find("urlset") is not None
            or soup.find("sitemapindex") is not None
        )
        if is_sitemap:
            for tag in soup.find_all("loc"):
                candidate = self._candidate_url(tag.get_text(strip=True), current_url)
                if candidate:
                    links.add(candidate)

        # robots.txt often discloses paths and sitemap locations unavailable from links.
        if source_path == "/robots.txt" or source_path.endswith("/robots.txt"):
            for match in ROBOTS_RULE_RE.finditer(raw_content or ""):
                path = match.group(1).strip()
                # Wildcard rules are patterns, not concrete paths to request.
                if not path or "*" in path or "$" in path:
                    continue
                candidate = self._candidate_url(path, current_url)
                if candidate:
                    links.add(candidate)
            for match in ROBOTS_SITEMAP_RE.finditer(raw_content or ""):
                candidate = self._candidate_url(match.group(1).strip(), current_url)
                if candidate:
                    links.add(candidate)

        return sorted(links)

    @staticmethod
    def _jsonld_url_candidates(document):
        """Yield URL-like fields from JSON-LD without treating labels/images as pages."""
        found = set()
        visited = 0

        def visit(value, depth=0):
            nonlocal visited
            if depth > 20 or visited >= MAX_JSONLD_URLS_PER_PAGE * 20:
                return
            visited += 1
            if isinstance(value, dict):
                for key, child in value.items():
                    normalized_key = str(key).strip().lower()
                    if normalized_key in JSONLD_URL_KEYS:
                        if isinstance(child, str) and child.strip():
                            found.add(child.strip())
                        elif isinstance(child, list):
                            for item in child:
                                if isinstance(item, str) and item.strip():
                                    found.add(item.strip())
                                elif isinstance(item, (dict, list)):
                                    visit(item, depth + 1)
                        elif isinstance(child, dict):
                            visit(child, depth + 1)
                    if isinstance(child, (dict, list)):
                        visit(child, depth + 1)
                    if len(found) >= MAX_JSONLD_URLS_PER_PAGE:
                        return
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, (dict, list)):
                        visit(child, depth + 1)
                    if len(found) >= MAX_JSONLD_URLS_PER_PAGE:
                        return

        visit(document)
        return sorted(found)[:MAX_JSONLD_URLS_PER_PAGE]

    @staticmethod
    def _resource_candidate_url(value: str, current_url: str):
        """Resolve an HTTP resource URL without dropping static-file extensions."""
        value = (value or "").strip()
        if not value or value.lower().startswith(
            ("#", "mailto:", "tel:", "javascript:", "data:", "blob:")
        ):
            return None
        try:
            absolute, _ = urldefrag(urljoin(current_url, value))
            parsed = urlparse(absolute)
            if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
                return None
            _ = parsed.port
            if parsed.username or parsed.password:
                return None
            return absolute
        except (TypeError, ValueError, UnicodeError):
            return None

    def _extract_asset_references(self, soup: BeautifulSoup, current_url: str) -> list:
        """Inventory static resources without queuing them as crawl pages."""
        assets = {}

        def add(value, hinted_kind="resource"):
            url = self._resource_candidate_url(value, current_url)
            if not url:
                return
            parsed = urlparse(url)
            path = parsed.path.lower()
            # Avoid platform-specific path rules and ignore query strings.
            leaf = path.rsplit("/", 1)[-1]
            extension = "." + leaf.rsplit(".", 1)[-1] if "." in leaf else ""
            kind = hinted_kind
            if extension in {".js", ".mjs"}:
                kind = "javascript"
            elif extension == ".css":
                kind = "stylesheet"
            elif extension in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp"}:
                kind = "image"
            elif extension in {".woff", ".woff2", ".ttf", ".otf", ".eot"}:
                kind = "font"
            elif extension in {".mp4", ".webm", ".mov", ".mp3", ".wav", ".ogg", ".m4a"}:
                kind = "media"
            elif extension in DOWNLOAD_SUFFIXES:
                kind = "download"
            key = (url, kind)
            assets[key] = {"url": url, "kind": kind, "extension": extension}

        attributes = (
            ("img", "src", "image"), ("img", "data-src", "image"),
            ("input", "src", "image"), ("video", "src", "media"),
            ("video", "poster", "image"), ("audio", "src", "media"),
            ("source", "src", "media"), ("track", "src", "media"),
            ("script", "src", "javascript"), ("object", "data", "download"),
            ("embed", "src", "download"), ("image", "href", "image"),
            ("image", "xlink:href", "image"),
        )
        for tag_name, attribute, kind in attributes:
            for tag in soup.find_all(tag_name, attrs={attribute: True}):
                add(tag.get(attribute, ""), kind)

        for tag_name in ("img", "source"):
            for tag in soup.find_all(tag_name, attrs={"srcset": True}):
                for match in SRCSET_RE.finditer(tag.get("srcset", "")):
                    add(match.group(1), "image" if tag_name == "img" else "media")
            for tag in soup.find_all(tag_name, attrs={"data-srcset": True}):
                for match in SRCSET_RE.finditer(tag.get("data-srcset", "")):
                    add(match.group(1), "image" if tag_name == "img" else "media")

        for tag in soup.find_all("link", href=True):
            rel = {str(value).lower() for value in (tag.get("rel") or [])}
            as_type = str(tag.get("as") or "").lower()
            if rel.intersection({
                "stylesheet", "icon", "apple-touch-icon", "manifest", "preload",
                "prefetch", "modulepreload", "mask-icon",
            }) or urlparse(tag.get("href", "")).path.lower().endswith(STATIC_SUFFIXES + DOWNLOAD_SUFFIXES):
                hint = {
                    "style": "stylesheet", "script": "javascript", "image": "image",
                    "font": "font", "video": "media", "audio": "media", "document": "download",
                }.get(as_type, "stylesheet" if "stylesheet" in rel else "resource")
                add(tag["href"], hint)

        # Expose direct download anchors as assets even when their URLs are also crawl seeds.
        for tag_name in ("a", "area"):
            for tag in soup.find_all(tag_name, href=True):
                path = urlparse(tag["href"].strip()).path.lower()
                if path.endswith(DOWNLOAD_SUFFIXES):
                    add(tag["href"], "download")

        for tag in soup.find_all(True):
            style = tag.get("style", "")
            for match in CSS_URL_RE.finditer(style):
                add(match.group(1), "css-resource")
        for style_tag in soup.find_all("style"):
            for match in CSS_URL_RE.finditer(style_tag.get_text() or ""):
                add(match.group(1), "css-resource")

        return sorted(assets.values(), key=lambda item: (item["url"].casefold(), item["kind"]))

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
