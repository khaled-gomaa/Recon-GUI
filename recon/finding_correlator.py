"""Evidence-backed, non-invasive correlation rules for recon observations."""
from __future__ import annotations

from urllib.parse import urlsplit


def correlate_findings(report: dict) -> list[dict]:
    """Produce review leads with explicit evidence; this is not a vulnerability scanner."""
    report = report or {}
    findings = []
    seen = set()

    def add(key, title, severity, confidence, evidence, recommendation, category="recon"):
        signature = (key, title)
        if signature in seen:
            return
        seen.add(signature)
        findings.append({
            "id": f"R-{len(findings) + 1:04d}",
            "title": title,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence[:8],
            "recommendation": recommendation,
        })

    for item in report.get("sensitive_findings", []) or []:
        add(
            ("sensitive", item.get("page"), item.get("type"), item.get("source")),
            f"Potential exposed value pattern: {item.get('type', 'unknown')}",
            item.get("severity", "medium"), "low-to-medium",
            [f"Page: {item.get('page', '')}", f"Source: {item.get('source', '')}",
             "Matched value is intentionally redacted."],
            "Inspect the referenced file manually, confirm whether the value is real, and revoke it if exposed.",
            "sensitive-data",
        )

    for form in report.get("forms", []) or []:
        fields = form.get("fields", []) or []
        password_fields = [field for field in fields if str(field.get("type", "")).lower() == "password"]
        page = str(form.get("page") or "")
        is_http = urlsplit(page).scheme.lower() == "http"
        if password_fields and is_http:
            add(
                ("form-http-password", page, form.get("action")),
                "Password field appears on an HTTP page", "high", "medium",
                [f"Page: {page}", f"Form action: {form.get('action', '')}",
                 "Password-type field detected; form was not submitted."],
                "Verify the intended deployment and ensure credentials are never transported over cleartext HTTP.",
                "transport",
            )
        if not form.get("same_origin_action", True):
            add(
                ("external-form", page, form.get("action")),
                "Form submits to a different origin", "medium", "medium",
                [f"Page: {page}", f"Action: {form.get('action', '')}",
                 "Different-origin form action detected from markup."],
                "Confirm the destination is intentional and that no sensitive fields are sent to an untrusted origin.",
                "form-analysis",
            )
        if password_fields and not form.get("csrf_field_present"):
            add(
                ("password-form-no-csrf-marker", page, form.get("action")),
                "Password form has no obvious CSRF-like field", "info", "low",
                [f"Page: {page}", f"Action: {form.get('action', '')}",
                 "No field name matched common CSRF naming patterns; this does not prove CSRF protection is absent."],
                "Review the application's actual CSRF/session protections; do not infer a vulnerability from field names alone.",
                "form-analysis",
            )

    for parameter in report.get("parameters", []) or []:
        if parameter.get("classification") == "sensitive-name":
            locations = parameter.get("locations", []) or []
            add(
                ("sensitive-param", parameter.get("name")),
                f"Sensitive-looking parameter name: {parameter.get('name')}",
                "info", "low",
                [f"Sources: {', '.join(parameter.get('sources', []))}",
                 f"Occurrences: {parameter.get('occurrences', 0)}",
                 *(f"Location: {location}" for location in locations[:3])],
                "Check how the parameter is handled and avoid placing secrets in URLs. The name alone is not a vulnerability.",
                "parameter-review",
            )

    diff = report.get("history_diff", {}) or {}
    # A first scan establishes the baseline; it cannot label every route "new".
    if diff.get("previous_scan_id") is not None:
        for endpoint in diff.get("added_endpoints", []) or []:
            add(
                ("new-endpoint", endpoint), f"Endpoint newly observed since previous scan",
                "info", "high",
                [f"Endpoint: {endpoint}", "Not present in the previous completed comparison baseline."],
                "Review whether this route is expected and in scope.",
                "change-detection",
            )
        for name in diff.get("added_parameters", []) or []:
            add(
                ("new-parameter", name), f"Parameter newly observed since previous scan: {name}",
                "info", "medium",
                [f"Parameter name: {name}", "Not present in the previous completed comparison baseline."],
                "Review its associated pages and intended behavior before deciding whether more testing is warranted.",
                "change-detection",
            )

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(
        findings,
        key=lambda item: (
            severity_rank.get(str(item.get("severity", "info")).lower(), 5),
            item.get("category", ""), item.get("title", "").casefold(),
        ),
    )
