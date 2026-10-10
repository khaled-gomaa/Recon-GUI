"""Audit HTTP security headers against OWASP recommendations."""
from dataclasses import dataclass, field

RECOMMENDED_HEADERS = {
    "Content-Security-Policy": "Prevents XSS and data injection",
    "Strict-Transport-Security": "Forces HTTPS",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Referrer-Policy": "Controls referrer leakage",
    "Permissions-Policy": "Restricts browser features",
}


@dataclass
class HeaderAuditResult:
    url: str
    present: dict = field(default_factory=dict)
    missing: list = field(default_factory=list)


class HeaderAuditor:
    @staticmethod
    def audit(url: str, headers: dict) -> HeaderAuditResult:
        result = HeaderAuditResult(url=url)
        lower_headers = {k.lower(): v for k, v in headers.items()}
        for header, description in RECOMMENDED_HEADERS.items():
            if header.lower() in lower_headers:
                result.present[header] = lower_headers[header.lower()]
            else:
                result.missing.append(f"{header} -- {description}")
        return result
