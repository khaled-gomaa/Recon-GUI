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


def test_exports_show_content_truncation_and_coverage_notes():
    report = {
        "target": "https://example.test/",
        "pages": [{
            "url": "https://example.test/large",
            "status": 200,
            "title": "Large",
            "word_count": 10,
            "content_length": 128,
            "body_truncated": True,
        }],
        "filtered_pages": [],
        "content_limit_reached": True,
        "body_truncated_pages": ["https://example.test/large"],
        "truncated_js_files": ["https://example.test/app.js"],
        "truncated_wordlist_urls": [],
        "content_limit_notes": ["1 JS file truncated at the 2 MiB per-file cap."],
        "coverage_summary": {
            "pages_crawled": 20,
            "page_cap": 200,
            "max_depth": 3,
            "javascript_files_discovered": 10,
            "javascript_files_attempted": 10,
            "javascript_files_truncated": 1,
            "response_bodies_truncated": 1,
            "content_limit_reached": True,
        },
    }
    txt = render_text_report(report)
    csv = render_csv_report(report)
    assert "Partial (page/depth/wordlist/content cap)" in txt
    assert "BODY TRUNCATED" in txt
    assert "CRAWL COVERAGE / TRUNCATION LIMITS" in txt
    assert "app.js" in txt
    assert "content_limit_reached" in csv
    assert "coverage_warning" in csv
    assert "body_truncated=True" in csv


def test_exports_label_har_only_import_and_include_import_warnings():
    report = {
        "target": "https://example.test/",
        "pages": [],
        "filtered_pages": [],
        "network_observations": [{
            "url": "https://example.test/api/profile",
            "method": "POST", "status": 202,
            "source": "burp-har-import", "page": "https://example.test/settings",
            "query_parameters": ["view"], "body_parameters": ["profileId"],
            "resource_type": "xhr", "content_type": "application/json",
        }],
        "cookie_map": [{
            "url": "https://example.test/api/profile", "name": "sid",
            "domain": "example.test", "path": "/", "secure": True,
            "httponly": True, "samesite": "Lax", "source": "burp-har-response",
        }],
        "har_import_summary": {
            "files_imported": 1, "entries_seen": 12000, "entries_imported": 10000,
            "unique_requests": 1, "truncated": True,
            "warnings": ["HAR contained 12000 entries; only the first 10000 were processed."],
        },
    }
    txt = render_text_report(report)
    csv = render_csv_report(report)
    assert "HAR metadata imported (no active scan run)" in txt
    assert "HAR IMPORT SUMMARY" in txt
    assert "Entries seen/imported: 12000/10000" in txt
    assert "first 10000 were processed" in txt
    assert "har_import_summary" in csv
    assert "profileId" in csv
    assert "sid" in csv


def test_asset_reference_inventory_is_exported_without_query_values():
    report = {
        "target": "https://example.test/",
        "pages": [],
        "asset_inventory": [{
            "url": "https://example.test/assets/app.js",
            "kind": "javascript",
            "extension": ".js",
            "reference_count": 2,
            "referrers": ["https://example.test/", "https://example.test/app"],
            "query_parameter_names": ["version"],
            "in_scope": True,
            "fetched_by_page_crawler": False,
            "fetched_by_js_collector": False,
        }],
    }
    txt = render_text_report(report)
    csv = render_csv_report(report)
    assert "ASSET REFERENCES" in txt
    assert "https://example.test/assets/app.js" in txt
    assert "reference only; not fetched" in txt
    assert "asset_reference" in csv
    assert "version" in csv
    assert "secret-value" not in txt + csv
