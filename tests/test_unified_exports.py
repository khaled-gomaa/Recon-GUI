from gui.report_export import render_csv_report, render_text_report


def test_exports_include_endpoint_parameter_and_correlated_finding_records():
    report = {
        "target": "https://example.com",
        "pages": [],
        "endpoint_inventory": [{
            "endpoint": "/api/users", "sources": ["javascript", "html-link"],
            "parameters": ["tenant"], "locations": ["/app.js"], "location_count": 1,
        }],
        "parameters": [{
            "name": "tenant", "classification": "review", "sources": ["query"],
            "occurrences": 2, "methods": ["GET"], "locations": ["/users"],
        }],
        "related_findings": [{
            "title": "Sensitive-looking parameter name: access_token", "severity": "info",
            "category": "parameter-review", "confidence": "low",
            "evidence": ["Source: javascript"], "recommendation": "Review manually.",
        }],
        "history_diff": {
            "previous_scan_id": 4, "comparison_status": "complete",
            "added_endpoints": ["/api/users"], "added_endpoint_count": 1,
            "added_parameters": ["tenant"], "added_parameter_count": 1,
            "added_finding_count": 1,
        },
    }
    txt = render_text_report(report)
    csv = render_csv_report(report)
    assert "ENDPOINT INVENTORY" in txt
    assert "PARAMETER INVENTORY" in txt
    assert "CORRELATED REVIEW FINDINGS" in txt
    assert "NEW ENDPOINT" in txt
    assert "NEW PARAMETER" in txt
    assert "endpoint" in csv
    assert "parameter" in csv
    assert "correlated_finding" in csv


def test_exports_include_selected_subdomain_verification_without_credentials():
    report = {
        "target": "https://example.test/",
        "pages": [],
        "subdomain_verification": {
            "candidate_count": 2,
            "verified_count": 1,
            "skipped_count": 1,
            "truncated": True,
            "results": [{
                "host": "api.example.test",
                "dns_status": "resolved",
                "ip_addresses": ["192.0.2.25"],
                "http_status": 401,
                "http_url": "https://api.example.test/",
                "http_result": "responded",
                "server": "test-server",
                "error": "",
            }],
        },
    }
    txt = render_text_report(report)
    csv = render_csv_report(report)
    assert "SELECTED SUBDOMAIN VERIFICATION" in txt
    assert "api.example.test" in txt
    assert "192.0.2.25" in txt
    assert "remain unchecked" in txt
    assert "subdomain_verification" in csv
    assert "api.example.test" in csv
