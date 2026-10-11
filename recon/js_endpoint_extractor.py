"""Extract API endpoints and likely client-side routes from JavaScript."""
import re
from urllib.parse import urlparse

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


class JSEndpointExtractor:
    @staticmethod
    def extract(js_content: str) -> set:
        endpoints = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.findall(js_content or ""):
                endpoints.add(match)
        return endpoints

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
