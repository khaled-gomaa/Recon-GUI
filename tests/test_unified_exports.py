from gui.report_export import (
    render_csv_report, render_text_report, render_markdown_report, render_html_report,
)


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


def test_exports_include_asset_history_diffs():
    report = {
        "target": "https://example.test/",
        "pages": [],
        "history_diff": {
            "comparison_status": "complete",
            "added_asset_count": 1,
            "removed_asset_count": 1,
            "changed_asset_count": 1,
            "added_assets": ["https://example.test/new.js [javascript]"],
            "removed_assets": ["https://example.test/old.css [stylesheet]"],
            "changed_assets": ["https://example.test/app.js [javascript]"],
        },
    }
    txt = render_text_report(report)
    csv = render_csv_report(report)
    assert "ASSET INVENTORY CHANGES" in txt
    assert "[NEW ASSET] https://example.test/new.js [javascript]" in txt
    assert "[REMOVED ASSET] https://example.test/old.css [stylesheet]" in txt
    assert "[CHANGED ASSET] https://example.test/app.js [javascript]" in txt
    assert "asset_added" in csv
    assert "asset_removed" in csv
    assert "asset_changed" in csv


def test_markdown_and_html_exports_include_method_evidence_and_coverage_without_raw_html():
    report = {
        "target": "https://example.test",
        "started_at": "2026-10-15T12:00:00Z",
        "pages": [{
            "url": "https://example.test/home",
            "status": 200,
            "title": "<script>alert(1)</script>",
            "content_type": "text/html",
            "word_count": 42,
            "content_length": 512,
            "depth": 0,
        }],
        "coverage_summary": {
            "pages_crawled": 1,
            "page_cap": 500,
            "page_limit_reached": False,
            "depth_limit_reached": False,
        },
        "endpoint_inventory": [{
            "endpoint": "https://example.test/api/search",
            "methods": ["GET", "POST"],
            "method_evidence": [
                {"method": "GET", "evidence": ["runtime-observed"], "sources": ["manual-browser"]},
                {"method": "POST", "evidence": ["static-js-inference"], "sources": ["javascript-fetch"]},
            ],
            "sources": ["manual-browser", "javascript-fetch"],
            "parameters": ["q", "userId"],
            "locations": ["https://example.test/app.js"],
            "location_count": 1,
        }],
        "network_observations": [{
            "url": "https://example.test/api/search",
            "method": "GET",
            "status": 200,
            "resource_type": "fetch",
            "query_parameters": ["q"],
            "body_parameters": [],
            "source": "manual-browser",
            "page": "https://example.test/home",
        }],
        "cookie_map": [{
            "url": "https://example.test/home",
            "name": "sessionid",
            "domain": "example.test",
            "path": "/",
            "secure": True,
            "httponly": True,
            "samesite": "Lax",
            "source": "manual-browser",
        }],
    }
    markdown = render_markdown_report(report)
    html = render_html_report(report)

    assert "## Endpoint Inventory" in markdown
    assert "runtime-observed" in markdown
    assert "static-js-inference" in markdown
    assert "## Coverage and Limits" in markdown
    assert "sessionid" in markdown

    assert "<!doctype html>" in html.lower()
    assert "runtime-observed" in html
    assert "static-js-inference" in html
    assert "Coverage and Limits" in html
    assert "sessionid" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "cookie_value" not in html.lower()


def test_markdown_cells_escape_table_delimiters_and_untrusted_html():
    report = {
        "target": "https://example.test",
        "pages": [{
            "url": "https://example.test/",
            "status": 200,
            "title": "A | B <img src=x onerror=alert(1)>",
        }],
    }
    markdown = render_markdown_report(report)
    html = render_html_report(report)
    assert r"A \| B &lt;img src=x onerror=alert(1)&gt;" in markdown
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_exports_include_source_coverage_and_observed_vs_inferred_request_intelligence():
    report = {
        "target": "https://example.test",
        "pages": [],
        "coverage": {
            "assessment": "partial",
            "partial": True,
            "pages": {"discovered_and_attempted": 2, "page_cap_reached": True},
            "http": {"transport_errors": 1},
            "discovery": {
                "endpoints": 1, "parameters": 2, "asset_references": 3,
                "browser_request_records": 1, "observed_request_methods": 1,
                "inferred_request_methods": 1,
            },
            "sources": {
                "endpoints": {"html-link": 1, "javascript-fetch": 1},
                "assets": {"css-url": 3},
                "network_requests": {"manual-browser": 1},
            },
            "partial_reasons": ["The page limit was reached; remaining candidates may not have been crawled."],
            "notes": ["Coverage is measured; it does not guarantee all routes were found."],
            "request_accounting": {"crawled": 3, "failed": 1, "rate_limited": 0, "truncated": 0},
        },
        "request_intelligence": [
            {
                "url": "https://example.test/api/search",
                "method": "POST",
                "evidence": "observed",
                "sources": ["manual-browser"],
                "parameter_names": ["query"],
                "content_types": ["application/json"],
                "status_codes": [200],
                "initiating_pages": ["https://example.test/home"],
                "resource_types": ["fetch"],
            },
            {
                "url": "https://example.test/api/users",
                "method": "GET",
                "evidence": "inferred",
                "sources": ["javascript-fetch"],
                "parameter_names": ["userId"],
                "content_types": [],
                "status_codes": [],
                "initiating_pages": ["https://example.test/app.js"],
                "resource_types": [],
            },
        ],
    }
    txt = render_text_report(report)
    csv = render_csv_report(report)
    markdown = render_markdown_report(report)
    html = render_html_report(report)

    assert "SOURCE-AWARE DISCOVERY COVERAGE" in txt
    assert "REQUEST INTELLIGENCE (OBSERVED VS INFERRED)" in txt
    assert "[OBSERVED] [POST] https://example.test/api/search" in txt
    assert "The page limit was reached" in txt

    assert "source_coverage" in csv
    assert "request_intelligence" in csv
    assert "userId" in csv

    assert "## Source-aware Discovery Coverage" in markdown
    assert "## Request Intelligence (observed vs inferred)" in markdown
    assert "static" not in html.lower() or "request intelligence" in html.lower()
    assert "manual-browser" in html
