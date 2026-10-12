from gui.report_export import render_csv_report


def test_csv_export_includes_pages_discovery_and_redacted_findings():
    report = {
        "pages": [{"url": "https://example.com/", "status": 200, "title": "Home",
                   "word_count": 12, "content_length": 100, "final_url": "https://example.com/"}],
        "wordlist_results": [{"url": "https://example.com/admin", "status": 403,
                              "size": 10, "word_count": 2, "potential_hit": True}],
        "sensitive_findings": [{"page": "https://example.com/app.js",
                                "type": "Possible hard-coded secret", "severity": "medium",
                                "match": "[REDACTED]"}],
        "passive_subdomains": ["api.example.com"],
    }
    text = render_csv_report(report)
    assert "record_type,url,status,title,severity,details" in text
    assert "https://example.com/" in text
    assert "https://example.com/admin" in text
    assert "Possible hard-coded secret" in text
    assert "api.example.com" in text
    assert "[REDACTED]" in text
