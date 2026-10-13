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
