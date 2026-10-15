"""Extract API endpoints and likely client-side routes from JavaScript."""
import re
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit, urldefrag

ENDPOINT_PATTERNS = [
    re.compile(r"""["'](/api/[a-zA-Z0-9_\-/{}.:]+)["']"""),
    re.compile(r"""["'](/v[0-9]/[a-zA-Z0-9_\-/{}.:]+)["']"""),
    re.compile(r"""["'](/rest/[a-zA-Z0-9_\-/{}.:]+)["']"""),
    re.compile(r"""["'](/graphql)["']"""),
    re.compile(r"""fetch\(["']([^"']+)["']\)"""),
    re.compile(r"""axios\.\w+\(["']([^"']+)["']\)"""),
    re.compile(r"""url:\s*["']([^"']+)["']"""),
]

# Discover root-relative strings commonly used as routes in SPA routers and fetch calls.
ROUTE_LITERAL_RE = re.compile(
    r"""["'](/[A-Za-z0-9_~!$&()*+,;=:@%{}./?%-]{1,220})["']"""
)
STATIC_SUFFIXES = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
)
JS_ASSET_SUFFIXES = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".avif", ".bmp", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4",
    ".webm", ".mov", ".mp3", ".wav", ".ogg", ".m4a", ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".json", ".xml", ".txt", ".yaml",
    ".yml", ".webmanifest", ".wasm", ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz",
    ".sql", ".db", ".sqlite", ".bak", ".old", ".orig", ".backup", ".conf", ".config",
    ".ini", ".env", ".log",
)
QUOTED_LITERAL_RE = re.compile(r"""(?P<quote>['"])(?P<value>[^'"\r\n]{1,700})(?P=quote)""")
SOURCE_MAP_RE = re.compile(r"""sourceMappingURL\s*=\s*['"]?([^\s*'"<>]+)""", re.I)


class JSEndpointExtractor:
    @staticmethod
    def extract_asset_references(content: str, base_url: str, source: str = "javascript-static-reference") -> list:
        """Find quoted static asset/file URLs in HTML or JavaScript without fetching them.

        Query values stay in memory for the HTTP request phase only; the analyzer strips them
        from stored asset URLs and persists only parameter names.
        """
        text = str(content or "")
        candidates = [match.group("value").strip() for match in QUOTED_LITERAL_RE.finditer(text)]
        candidates.extend(match.group(1).strip() for match in SOURCE_MAP_RE.finditer(text))
        found = {}
        for value in candidates:
            if not value or value.lower().startswith(("javascript:", "data:", "blob:", "mailto:", "tel:", "#")):
                continue
            try:
                absolute = urljoin(base_url, value)
                absolute, _fragment = urldefrag(absolute)
                parsed = urlparse(absolute)
                if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                    continue
                if parsed.username or parsed.password:
                    continue
                _ = parsed.port
                if not parsed.path.lower().endswith(JS_ASSET_SUFFIXES):
                    continue
                extension = next(
                    (suffix for suffix in sorted(JS_ASSET_SUFFIXES, key=len, reverse=True)
                     if parsed.path.lower().endswith(suffix)),
                    "",
                )
                if extension in {".js", ".mjs"}:
                    kind = "javascript"
                elif extension == ".css":
                    kind = "stylesheet"
                elif extension == ".map":
                    kind = "source-map"
                elif extension in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp"}:
                    kind = "image"
                elif extension in {".woff", ".woff2", ".ttf", ".otf", ".eot"}:
                    kind = "font"
                elif extension in {".mp4", ".webm", ".mov", ".mp3", ".wav", ".ogg", ".m4a"}:
                    kind = "media"
                elif extension in {".json", ".xml", ".txt", ".yaml", ".yml", ".webmanifest", ".wasm", ".csv"}:
                    kind = "data"
                else:
                    kind = "download"
                safe_url = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", ""))
                key = (safe_url, kind)
                found.setdefault(key, {
                    "url": absolute, "kind": kind, "extension": extension,
                    "source": str(source or "javascript-static-reference"),
                })
            except (TypeError, ValueError, UnicodeError):
                continue
        return [found[key] for key in sorted(found, key=lambda value: (value[0].casefold(), value[1]))]

    @staticmethod
    def extract(js_content: str) -> set:
        endpoints = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.findall(js_content or ""):
                endpoints.add(match)
        return endpoints

    @staticmethod
    def extract_request_observations(js_content: str) -> list:
        """Infer only explicit client request method hints from static JavaScript.

        This is evidence from source text, not proof that a request was executed.
        Body field names may be emitted; values are never retained.
        """
        text = js_content or ""
        observations = {}

        def add(url, method="GET", source="javascript-static", body_text=""):
            url = str(url or "").strip()
            if not url or url.startswith(("javascript:", "data:", "#")):
                return
            method = str(method or "GET").upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                method = "UNKNOWN"
            body_parameters = set()
            for match in re.finditer(r"""(?:^|[,\s{])([A-Za-z_$][\w$.-]*)\s*:""", body_text or ""):
                body_parameters.add(match.group(1))
            for match in re.finditer(r"""["']([^"'\n]{1,100})["']\s*:""", body_text or ""):
                body_parameters.add(match.group(1))
            key = (url, method, source)
            record = observations.setdefault(key, {
                "endpoint": url, "method": method, "source": source,
                "body_parameters": [],
            })
            record["body_parameters"] = sorted(set(record["body_parameters"]) | body_parameters)

        # fetch(url, { method: "POST", body: JSON.stringify({id: x}) })
        fetch_pattern = re.compile(
            r"""fetch\s*\(\s*(['"])([^'"]+)\1\s*(?:,\s*\{([\s\S]{0,900}?)\}\s*)?\)""",
            re.I,
        )
        for match in fetch_pattern.finditer(text):
            config = match.group(3) or ""
            method_match = re.search(r"""\bmethod\s*:\s*(['"])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1""", config, re.I)
            has_body = bool(re.search(r"""\bbody\s*:""", config, re.I))
            method = method_match.group(2) if method_match else ("POST" if has_body else "GET")
            body_match = re.search(
                r"""\bbody\s*:\s*(?:JSON\.stringify\s*\()?\s*(\{[\s\S]{0,600})""",
                config, re.I,
            )
            add(match.group(2), method, "javascript-fetch", body_match.group(1) if body_match else "")

        # axios.get/post/put/patch/delete/head/options("url", ...)
        for match in re.finditer(
            r"""axios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*(['"])([^'"]+)\2\s*(?:,\s*(\{[\s\S]{0,600}?\}))?\s*\)""",
            text, re.I,
        ):
            add(match.group(3), match.group(1), "javascript-axios", match.group(4) or "")

        # XMLHttpRequest.open("POST", "url", ...)
        for match in re.finditer(
            r"""\.open\s*\(\s*(['"])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1\s*,\s*(['"])([^'"]+)\3""",
            text, re.I,
        ):
            add(match.group(4), match.group(2), "javascript-xhr")

        # jQuery $.ajax({ url: "/path", method/type: "POST", data: {...} })
        for match in re.finditer(r"""\$\.ajax\s*\(\s*\{([\s\S]{0,1200})\}\s*\)""", text, re.I):
            config = match.group(1)
            url_match = re.search(r"""\burl\s*:\s*(['"])([^'"]+)\1""", config, re.I)
            if not url_match:
                continue
            method_match = re.search(r"""\b(?:method|type)\s*:\s*(['"])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1""", config, re.I)
            data_match = re.search(r"""\bdata\s*:\s*(\{[\s\S]{0,600})""", config, re.I)
            add(
                url_match.group(2), method_match.group(2) if method_match else "GET",
                "javascript-ajax", data_match.group(1) if data_match else "",
            )
        return list(observations.values())

    @staticmethod
    def extract_routes(js_content: str) -> set:
        """Return likely first-party route paths, excluding obvious static assets."""
        routes = set()
        for candidate in ROUTE_LITERAL_RE.findall(js_content or ""):
            if candidate.startswith("//"):
                continue
            path = urlparse(candidate).path.lower()
            if path in ("", "/") or path.endswith(STATIC_SUFFIXES):
                continue
            routes.add(candidate)
        return routes
