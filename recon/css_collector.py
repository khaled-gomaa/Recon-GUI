"""Discover assets and nested stylesheet imports referenced by same-origin CSS.

CSS is fetched only from the selected target's exact origin. External URLs referenced by CSS
are recorded as references but never fetched. Response bodies and query values are not persisted.
"""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import aiohttp
from recon.rate_limit_policy import AdaptiveRateController

MAX_CSS_BYTES = 2 * 1024 * 1024
MAX_CSS_FILES = 0  # 0 means process every discovered same-origin stylesheet.
MAX_RETRY_AFTER_SECONDS = 120  # compatibility constant; explicit Retry-After is not capped
MAX_RATE_LIMIT_PAUSES = 5

CSS_URL_RE = re.compile(r"""url\(\s*(?P<quote>['"]?)(?P<url>[^)'"]+?)(?P=quote)\s*\)""", re.I)
CSS_IMPORT_RE = re.compile(
    r"""@import\s+(?:url\(\s*)?['"]?([^'")\s;]+)['"]?\s*\)?""", re.I
)
SOURCE_MAP_RE = re.compile(r"""sourceMappingURL\s*=\s*['"]?([^\s*'"<>]+)""", re.I)
COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/")


def _origin(url: str):
    try:
        parsed = urlsplit(url or "")
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
        if scheme not in {"http", "https"} or not host:
            return None
        return scheme, host, port
    except (TypeError, ValueError):
        return None


def _safe_url(url: str) -> str:
    parsed = urlsplit(url or "")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", ""))


def _query_parameter_names(url: str) -> list[str]:
    try:
        return sorted({name for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True) if name})
    except ValueError:
        return []


def _extension(url: str) -> str:
    leaf = urlsplit(url).path.rsplit("/", 1)[-1].lower()
    return "." + leaf.rsplit(".", 1)[-1] if "." in leaf and not leaf.endswith(".") else ""


def _kind(url: str, imported: bool = False, source_map: bool = False) -> str:
    ext = _extension(url)
    if source_map or ext == ".map":
        return "source-map"
    if imported or ext == ".css":
        return "stylesheet"
    if ext in {".js", ".mjs"}:
        return "javascript"
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp"}:
        return "image"
    if ext in {".woff", ".woff2", ".ttf", ".otf", ".eot"}:
        return "font"
    if ext in {".mp4", ".webm", ".mov", ".mp3", ".wav", ".ogg", ".m4a"}:
        return "media"
    if ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip",
               ".7z", ".rar", ".tar", ".gz", ".tgz", ".sql", ".db", ".sqlite",
               ".bak", ".old", ".orig", ".backup", ".conf", ".config", ".env", ".log"}:
        return "download"
    return "css-resource"


def _retry_after_seconds(value: str | None):
    if not value:
        return None
    value = str(value).strip()
    if value.isdigit():
        return float(int(value))
    try:
        moment = parsedate_to_datetime(value)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return max(0.0, (moment - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


class CSSCollector:
    """Sequential, same-origin CSS collector with recursive @import discovery."""

    def __init__(self, target_url: str, *, cookie_jar=None, request_headers=None, on_log=None):
        self.target_url = target_url
        self.target_origin = _origin(target_url)
        if not self.target_origin:
            raise ValueError("target_url must be a valid HTTP(S) URL")
        self.cookie_jar = cookie_jar
        self.request_headers = dict(request_headers or {})
        self.on_log = on_log or (lambda _message: None)
        self.css_urls: set[str] = set()
        self.attempted_urls: set[str] = set()
        self.fetched_contents: dict[str, str] = {}
        self.truncated_files: set[str] = set()
        self.errors: list[dict] = []
        self.assets: dict[tuple[str, str], dict] = {}
        self.rate_limit_stopped = False
        self.retry_after_pauses = 0
        self.rate_controller = AdaptiveRateController(
            base_delay=0.0, max_delay=60.0, max_consecutive_limits=MAX_RATE_LIMIT_PAUSES, jitter=0.0
        )
        self.limit_reached = False

    def _log(self, message: str):
        try:
            self.on_log(message)
        except Exception:
            pass

    def _in_origin(self, url: str) -> bool:
        return _origin(url) == self.target_origin

    def _record_asset(self, raw_url: str, referrer: str, *, imported=False, source_map=False):
        value = str(raw_url or "").strip().strip("\"'")
        if not value or value.startswith(("#", "data:", "blob:", "javascript:", "mailto:")):
            return None
        try:
            absolute = urljoin(referrer, value)
            parsed = urlsplit(absolute)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                return None
            _ = parsed.port
            if parsed.username or parsed.password:
                return None
        except (ValueError, UnicodeError):
            return None
        safe = _safe_url(absolute)
        kind = _kind(absolute, imported=imported, source_map=source_map)
        record = {
            "url": safe,
            "request_url": absolute,
            "kind": kind,
            "extension": _extension(absolute),
            "referrer": _safe_url(referrer),
            "source": "css-import" if imported else "css-source-map" if source_map else "css-url",
            "query_parameter_names": _query_parameter_names(absolute),
            "in_scope": _origin(absolute) == self.target_origin,
        }
        self.assets[(safe, kind)] = record
        if imported and record["in_scope"]:
            self.css_urls.add(absolute)
        return record

    def seed_from_references(self, asset_references):
        """Queue only same-origin stylesheet references already seen in page markup/network."""
        for item in asset_references or []:
            if not isinstance(item, dict):
                continue
            raw_url = str(item.get("request_url") or item.get("url") or "").strip()
            kind = str(item.get("kind") or "").lower()
            if raw_url and (kind == "stylesheet" or _extension(raw_url) == ".css"):
                if self._in_origin(raw_url):
                    self.css_urls.add(raw_url)

    @staticmethod
    def _parse_css(css_text: str, css_url: str):
        """Return syntactically referenced CSS assets; caller decides which may be fetched."""
        text = css_text or ""
        source_maps = set(SOURCE_MAP_RE.findall(text))
        # Remove comments before ordinary url()/@import scans so examples in comments
        # do not become false discoveries; retain source map references collected above.
        clean = COMMENT_RE.sub("", text)
        references = {}
        for match in CSS_URL_RE.finditer(clean):
            value = match.group("url").strip().strip("\"'")
            if value:
                references[(value, False, False)] = value
        for match in CSS_IMPORT_RE.finditer(clean):
            value = match.group(1).strip().strip("\"'")
            if value:
                references[(value, True, False)] = value
        for value in source_maps:
            if value:
                references[(value.strip(), False, True)] = value.strip()
        records = []
        for (value, imported, source_map), _ in references.items():
            value = str(value).strip()
            if not value or value.lower().startswith(("data:", "blob:", "javascript:", "#")):
                continue
            try:
                absolute = urljoin(css_url, value)
                parsed = urlsplit(absolute)
                if (
                    parsed.scheme.lower() not in {"http", "https"}
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                ):
                    continue
                _ = parsed.port
            except (TypeError, ValueError, UnicodeError):
                continue
            kind = _kind(absolute, imported=imported, source_map=source_map)
            records.append({
                "url": _safe_url(absolute),
                "request_url": absolute,
                "kind": kind,
                "extension": _extension(absolute),
                "referrer": _safe_url(css_url),
                "source": "css-import" if imported else "css-source-map" if source_map else "css-url",
                "query_parameter_names": _query_parameter_names(absolute),
                "in_scope": _origin(absolute) == _origin(css_url),
            })
        return records

    async def collect(self, asset_references, *, should_stop=None, delay_ms=200):
        """Fetch and analyze the discovered same-origin CSS queue; recurse through @import."""
        stop = should_stop or (lambda: False)
        self.seed_from_references(asset_references)
        delay_ms = max(0, min(int(delay_ms), 86_400_000))
        timeout = aiohttp.ClientTimeout(total=15, connect=8)
        safe_headers = {
            str(key): str(value) for key, value in self.request_headers.items()
            if str(key).lower() in {"authorization", "accept-language"}
            and "\r" not in str(value) and "\n" not in str(value)
        }
        connector = aiohttp.TCPConnector(limit=1, ssl=True)
        session_options = {
            "connector": connector,
            "timeout": timeout,
            "headers": {
                "User-Agent": "Recon-GUI/3.1 (stylesheet discovery; authorized use)",
                "Accept": "text/css,*/*;q=0.1",
                **safe_headers,
            },
            "trust_env": False,
        }
        if self.cookie_jar is not None:
            session_options["cookie_jar"] = self.cookie_jar

        async with aiohttp.ClientSession(**session_options) as session:
            while True:
                if stop() or self.rate_limit_stopped:
                    break
                pending = sorted(self.css_urls - self.attempted_urls)
                if not pending:
                    break
                if MAX_CSS_FILES and len(self.attempted_urls) >= MAX_CSS_FILES:
                    self.limit_reached = True
                    self._log(f"[CSS] Stylesheet ceiling reached ({MAX_CSS_FILES}); undiscovered remaining files are not fetched.")
                    break
                url = pending[0]
                self.attempted_urls.add(url)
                if not self._in_origin(url):
                    continue
                if delay_ms:
                    await asyncio.sleep(delay_ms / 1000)
                if stop():
                    break
                try:
                    async with session.get(url, allow_redirects=False) as response:
                        if response.status == 429 or (
                            response.status == 503 and response.headers.get("Retry-After")
                        ):
                            decision = self.rate_controller.on_rate_limit(
                                response.headers.get("Retry-After"), status=int(response.status)
                            )
                            self.retry_after_pauses = self.rate_controller.consecutive_limits
                            if decision.should_stop:
                                self.rate_limit_stopped = True
                                self.errors.append({"url": _safe_url(url), "error": "rate-limited-stop"})
                                self._log(
                                    f"[CSS] {_safe_url(url)}: {decision.reason}. "
                                    "Stopping stylesheet discovery instead of retrying early."
                                )
                                break
                            self.attempted_urls.discard(url)
                            self._log(
                                f"[CSS] HTTP {response.status}; pausing for {decision.wait_seconds:.1f}s "
                                "before retrying the stylesheet."
                            )
                            deadline = asyncio.get_running_loop().time() + decision.wait_seconds
                            while asyncio.get_running_loop().time() < deadline:
                                if stop():
                                    break
                                await asyncio.sleep(min(0.25, max(0.0, deadline - asyncio.get_running_loop().time())))
                            if stop():
                                break
                            continue
                        self.rate_controller.on_success()
                        if response.status != 200:
                            self.errors.append({"url": _safe_url(url), "status": int(response.status), "error": "http-error"})
                            continue
                        content_type = str(response.headers.get("Content-Type", "")).lower()
                        if "css" not in content_type and _extension(url) != ".css":
                            self.errors.append({"url": _safe_url(url), "status": int(response.status), "error": "not-css-content"})
                            continue
                        body_buffer = bytearray()
                        # Stream until EOF or one byte beyond the cap. A single read(n)
                        # may return an arbitrary short chunk before EOF.
                        while len(body_buffer) <= MAX_CSS_BYTES:
                            remaining = MAX_CSS_BYTES + 1 - len(body_buffer)
                            chunk = await response.content.read(min(64 * 1024, remaining))
                            if not chunk:
                                break
                            body_buffer.extend(chunk)
                        if len(body_buffer) > MAX_CSS_BYTES:
                            self.truncated_files.add(url)
                            del body_buffer[MAX_CSS_BYTES:]
                            self._log(f"[CSS] Truncated oversized stylesheet ({MAX_CSS_BYTES} bytes): {_safe_url(url)}")
                        css = bytes(body_buffer).decode(response.charset or "utf-8", errors="replace")
                except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, ValueError) as exc:
                    self.errors.append({"url": _safe_url(url), "error": type(exc).__name__})
                    self._log(f"[CSS] Could not read {_safe_url(url)}: {type(exc).__name__}")
                    continue

                self.fetched_contents[url] = css
                discovered = self._parse_css(css, url)
                for item in discovered:
                    self.assets[(item["url"], item["kind"])] = item
                    if item["kind"] == "stylesheet" and item["in_scope"]:
                        self.css_urls.add(item["request_url"])
                self._log(f"[CSS] Analyzed {_safe_url(url)}; found {len(discovered)} references.")

        return self.to_dict()

    def to_dict(self):
        return {
            "css_files_discovered": len(self.css_urls),
            "css_files_attempted": len(self.attempted_urls),
            "css_files_fetched": len(self.fetched_contents),
            "css_files_truncated": sorted(_safe_url(url) for url in self.truncated_files),
            "css_file_errors": list(self.errors),
            "css_limit_reached": self.limit_reached,
            "css_rate_limited_stop": self.rate_limit_stopped,
            "css_assets": [
                {key: value for key, value in item.items() if key != "request_url"}
                for item in sorted(self.assets.values(), key=lambda row: (row["url"].casefold(), row["kind"]))
            ],
        }
