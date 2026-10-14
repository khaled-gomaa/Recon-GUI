"""Import extra crawl seeds from sitemaps, URL lists, CSV exports, and access logs.

Imported URLs are seeds only: the normal crawler scope, depth/page limits, robots
crawl-delay, session credential boundaries, and HTTP 429 handling still apply.
"""
from __future__ import annotations

import csv
import gzip
import html
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_IMPORT_BYTES = 50 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_IMPORTED_SEEDS = 100_000
URL_RE = re.compile(r"https?://[^\s<>\\"'\x60,;]+", re.I)
REQUEST_TARGET_RE = re.compile(
    r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+((?:https?://)?/[^\s\\"']*)",
    re.I,
)
TRAILING_URL_PUNCTUATION = ".,);]}>'\\""


def _read_source(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"URL seed file not found: {path}")
    size = path.stat().st_size
    if size > MAX_IMPORT_BYTES:
        raise ValueError(f"Input is larger than the {MAX_IMPORT_BYTES // (1024 * 1024)} MiB import limit.")
    if path.suffix.lower() == ".gz" or path.name.lower().endswith(".xml.gz"):
        pieces = []
        total = 0
        with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk.encode("utf-8", errors="replace"))
                if total > MAX_DECOMPRESSED_BYTES:
                    raise ValueError(
                        f"Decompressed input is larger than the {MAX_DECOMPRESSED_BYTES // (1024 * 1024)} MiB safety limit."
                    )
                pieces.append(chunk)
        return "".join(pieces)
    return path.read_text(encoding="utf-8-sig", errors="replace")


def _canonical_http_url(value: str, target_url: str, target_host: str) -> str | None:
    value = html.unescape(str(value or "").strip()).strip(TRAILING_URL_PUNCTUATION)
    if not value or any(ord(char) < 32 for char in value):
        return None
    if value.startswith("//"):
        # Protocol-relative URLs are only accepted when they remain on the target host.
        value = urlsplit(target_url).scheme + ":" + value
    elif value.startswith("/"):
        value = urljoin(target_url, value)
    elif not value.lower().startswith(("http://", "https://")):
        return None

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").rstrip(".").lower()
        if scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
            return None
        host = host.encode("idna").decode("ascii")
        # Align with CrawlEngine's exact-host boundary: sibling subdomains are not
        # silently promoted into the active crawl just because they are in a file.
        if host != target_host:
            return None
        port = parsed.port
        if port and not (1 <= port <= 65535):
            return None
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None
        netloc = f"[{host}]" if ":" in host else host
        if port:
            netloc += f":{port}"
        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, parsed.query, ""))
    except (ValueError, UnicodeError):
        return None


def _candidate_strings(text: str, suffix: str) -> list[str]:
    """Extract absolute URLs plus relative request paths from common exports/logs."""
    found = []
    for match in URL_RE.findall(text):
        found.append(match.strip(TRAILING_URL_PUNCTUATION))

    # Apache/Nginx/proxy logs often store only the request target, e.g. GET /api?q=1 HTTP/1.1.
    for match in REQUEST_TARGET_RE.finditer(text):
        found.append(match.group(1).strip(TRAILING_URL_PUNCTUATION))

    # A plain text list can contain one root-relative URL per line.
    if suffix not in {".csv", ".json", ".xml", ".har"}:
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("/") and not line.startswith("//") and not any(ch.isspace() for ch in line):
                found.append(line.strip(TRAILING_URL_PUNCTUATION))
    return found


def _xml_candidates(text: str) -> list[str]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Could not parse XML sitemap/export: {exc}") from exc
    found = []
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1].lower() if isinstance(element.tag, str) else ""
        if local_name in {"loc", "url", "href"}:
            value = (element.text or "").strip()
            if value:
                found.append(value)
        for key, value in element.attrib.items():
            if key.rsplit("}", 1)[-1].lower() in {"href", "url", "loc"} and value:
                found.append(str(value).strip())
    return found


def _json_candidates(text: str) -> list[str]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []

    found = []
    url_keys = {"url", "uri", "href", "loc", "page", "requesturl", "request_url", "canonical"}

    def visit(value, key=""):
        if isinstance(value, dict):
            for child_key, child in value.items():
                visit(child, str(child_key).replace("-", "_").lower())
        elif isinstance(value, list):
            for child in value:
                visit(child, key)
        elif isinstance(value, str) and key.replace("_", "") in {item.replace("_", "") for item in url_keys}:
            found.append(value.strip())

    visit(payload)
    return found


def load_seed_urls(path: str | Path, target_url: str, max_seeds: int = MAX_IMPORTED_SEEDS) -> dict:
    """Return deduplicated same-host seed URLs from a local file, plus coverage notes.

    Supported inputs: TXT/CSV URL exports, XML sitemaps, gzip-compressed XML,
    JSON URL collections, and common access-log request lines. Requests and crawls
    are performed elsewhere after this function validates the hostname boundary.
    """
    target = urlsplit(str(target_url or "").strip())
    if target.scheme.lower() not in {"http", "https"} or not target.hostname:
        raise ValueError("target_url must be a full HTTP(S) URL.")
    target_host = target.hostname.rstrip(".").lower().encode("idna").decode("ascii")
    target_url = urlunsplit((target.scheme.lower(), target.netloc, target.path or "/", "", ""))
    source_path = Path(path)
    text = _read_source(source_path)
    suffix = source_path.suffix.lower()

    if source_path.name.lower().endswith(".xml.gz") or suffix == ".xml":
        candidates = _xml_candidates(text)
    elif suffix == ".json":
        candidates = _json_candidates(text) + _candidate_strings(text, suffix)
    else:
        candidates = _candidate_strings(text, suffix)
        # CSV values and exports can contain relative paths in columns as well as full URLs.
        if suffix == ".csv":
            reader = csv.reader(text.splitlines())
            rows = list(reader)
            if rows:
                headers = [str(value).strip().lower() for value in rows[0]]
                relevant = {
                    index for index, header in enumerate(headers)
                    if any(token in header for token in ("url", "uri", "page", "path", "request", "address", "canonical"))
                }
                for row in rows[1:]:
                    for index in relevant:
                        if index < len(row):
                            value = str(row[index]).strip()
                            if value.startswith("/") and not value.startswith("//") and not any(ch.isspace() for ch in value):
                                candidates.append(value)

    max_seeds = max(1, min(int(max_seeds), MAX_IMPORTED_SEEDS))
    accepted = []
    seen = set()
    rejected = 0
    reached_cap = False
    for candidate in candidates:
        url = _canonical_http_url(candidate, target_url, target_host)
        if not url:
            rejected += 1
            continue
        if url in seen:
            continue
        if len(accepted) >= max_seeds:
            reached_cap = True
            break
        seen.add(url)
        accepted.append(url)

    return {
        "urls": accepted,
        "input_candidates": len(candidates),
        "accepted_count": len(accepted),
        "rejected_or_out_of_scope": rejected,
        "limit": max_seeds,
        "limit_reached": reached_cap,
        "source_file": source_path.name,
        "source_type": "sitemap" if suffix == ".xml" or source_path.name.lower().endswith(".xml.gz") else (
            "csv" if suffix == ".csv" else "json" if suffix == ".json" else "url-list-or-access-log"
        ),
    }
