"""Non-invasive HTML analysis: forms, JSON-LD, and redacted secret candidates."""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup


MAX_STRUCTURED_ITEMS = 100
MAX_FINDINGS_PER_PAGE = 100
PLACEHOLDER_VALUES = {
    "", "null", "undefined", "none", "changeme", "change_me", "example",
    "your_api_key", "your-api-key", "your_token", "redacted", "xxxxxxxx",
}

# Candidate matches only: raw credential values are never retained.
_PATTERNS = (
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", re.I), "high"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"), "high"),
    ("GitLab personal token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "high"),
    ("JWT-like token", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
    ), "medium"),
    ("Private key marker", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ), "high"),
)
_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    ["']?
    (?P<name>[a-z0-9_.-]*(?:api[_-]?key|access[_-]?token|client[_-]?secret|
       secret[_-]?key|password|passwd|authorization|private[_-]?key)[a-z0-9_.-]*)
    ["']?\s*[:=]\s*["'](?P<value>[^"'\\\r\n]{6,256})["']
    """
)
_CSRF_RE = re.compile(r"(?:csrf|xsrf|authenticity|requestverification)", re.I)


def _safe_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]", "", value or "")
    return name[:100] or "unknown"


def analyze_html(url: str, html: str) -> dict:
    """Extract forms and structured metadata; report only redacted leak candidates."""
    soup = BeautifulSoup(html or "", "lxml")
    origin = urlparse(url)
    forms = []
    for form in soup.find_all("form")[:MAX_STRUCTURED_ITEMS]:
        raw_action = (form.get("action") or "").strip()
        action = urljoin(url, raw_action) if raw_action else url
        parsed_action = urlparse(action)
        same_origin = (
            parsed_action.scheme in ("http", "https")
            and parsed_action.hostname == origin.hostname
            and parsed_action.port == origin.port
        )
        fields = []
        csrf_present = False
        for field in form.find_all(["input", "select", "textarea", "button"])[:100]:
            name = str(field.get("name") or field.get("id") or "")
            field_type = str(field.get("type") or field.name).lower()
            csrf_present = csrf_present or bool(_CSRF_RE.search(name))
            fields.append({
                "name": _safe_name(name), "type": field_type[:40],
                "required": field.has_attr("required"),
                "autocomplete": str(field.get("autocomplete") or "")[:50],
            })
        forms.append({
            "page": url, "action": action,
            "method": str(form.get("method") or "get").upper()[:10],
            "same_origin_action": same_origin, "field_count": len(fields),
            "fields": fields, "csrf_field_present": csrf_present,
        })

    json_ld = []
    for script in soup.find_all("script", attrs={"type": re.compile(r"application/ld\+json", re.I)})[:MAX_STRUCTURED_ITEMS]:
        try:
            data = json.loads(script.string or script.get_text() or "")
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        objects = data if isinstance(data, list) else [data]
        for item in objects:
            if not isinstance(item, dict):
                continue
            kind = item.get("@type", "")
            if isinstance(kind, list):
                kind = ", ".join(str(k) for k in kind[:10])
            entry = {"page": url, "type": str(kind)[:160]}
            if isinstance(item.get("name"), str) and item["name"].strip():
                entry["name"] = item["name"].strip()[:200]
            json_ld.append(entry)
            if len(json_ld) >= MAX_STRUCTURED_ITEMS:
                break
        if len(json_ld) >= MAX_STRUCTURED_ITEMS:
            break

    findings, seen = [], set()
    text_sources = [("html", html or "")]
    for index, script in enumerate(soup.find_all("script", src=False)):
        text_sources.append((f"inline-script-{index + 1}", script.string or script.get_text() or ""))
    for source, content in text_sources:
        for label, pattern, severity in _PATTERNS:
            for match in pattern.finditer(content):
                marker = (label, source, match.start())
                if marker in seen:
                    continue
                seen.add(marker)
                findings.append({
                    "type": label, "severity": severity, "page": url,
                    "source": source, "match": "[REDACTED]",
                    "note": "Candidate pattern only; verify manually. Raw value intentionally omitted.",
                })
                if len(findings) >= MAX_FINDINGS_PER_PAGE:
                    break
            if len(findings) >= MAX_FINDINGS_PER_PAGE:
                break
        if len(findings) < MAX_FINDINGS_PER_PAGE:
            for match in _ASSIGNMENT_RE.finditer(content):
                key = _safe_name(match.group("name"))
                value = (match.group("value") or "").strip().lower()
                if value in PLACEHOLDER_VALUES or len(value) < 8:
                    continue
                marker = ("assignment:" + key.lower(), source, match.start())
                if marker in seen:
                    continue
                seen.add(marker)
                findings.append({
                    "type": "Possible hard-coded secret", "severity": "medium",
                    "page": url, "source": source, "key_name": key,
                    "match": "[REDACTED]",
                    "note": "Assignment-like pattern only; raw value intentionally omitted.",
                })
                if len(findings) >= MAX_FINDINGS_PER_PAGE:
                    break
        if len(findings) >= MAX_FINDINGS_PER_PAGE:
            break
    return {"forms": forms, "json_ld": json_ld, "sensitive_findings": findings}
