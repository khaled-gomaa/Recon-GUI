"""Extract API endpoints and paths from JavaScript."""
import re

ENDPOINT_PATTERNS = [
    re.compile(r"""["'](/api/[a-zA-Z0-9_\-/{}.:]+)["']"""),
    re.compile(r"""["'](/v[0-9]/[a-zA-Z0-9_\-/{}.:]+)["']"""),
    re.compile(r"""["'](/rest/[a-zA-Z0-9_\-/{}.:]+)["']"""),
    re.compile(r"""["'](/graphql)["']"""),
    re.compile(r"""fetch\(["']([^"']+)["']\)"""),
    re.compile(r"""axios\.\w+\(["']([^"']+)["']\)"""),
    re.compile(r"""url:\s*["']([^"']+)["']"""),
]


class JSEndpointExtractor:
    @staticmethod
    def extract(js_content: str) -> set:
        endpoints = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.findall(js_content):
                endpoints.add(match)
        return endpoints
