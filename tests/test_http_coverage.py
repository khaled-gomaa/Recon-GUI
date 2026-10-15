from recon.http_coverage import summarize_http_outcomes


def test_http_outcome_summary_counts_failures_and_strips_query_values():
    result = summarize_http_outcomes(
        pages=[
            {
                "url": "https://example.test/app?token=secret-page-value",
                "status": 0,
                "error": "TimeoutError: secret-error-value",
            },
            {"url": "https://example.test/api", "status": 503, "error": ""},
            {"url": "https://example.test/private", "status": 403, "error": ""},
        ],
        wordlist_results=[
            {
                "url": "https://example.test/admin?key=secret-query-value",
                "status": 0,
                "error": "ClientError",
            }
        ],
        asset_probe_results=[
            {"url": "https://example.test/assets/app.js?sig=private-signature", "status": 200}
        ],
    )

    assert result["http_status_counts"] == {"200": 1, "403": 1, "503": 1}
    assert result["transport_error_count"] == 2
    assert result["server_error_response_count"] == 1
    assert result["restricted_response_count"] == 1
    assert result["failed_requests"][0]["url"] == "https://example.test/app"
    serialized = repr(result)
    assert "secret-page-value" not in serialized
    assert "secret-error-value" not in serialized
    assert "secret-query-value" not in serialized
    assert "private-signature" not in serialized


def test_text_and_csv_exports_disclose_incomplete_http_coverage():
    from gui.report_export import render_csv_report, render_text_report

    report = {
        "target": "https://example.test/",
        "started_at": "2026-10-15T00:00:00+00:00",
        "pages": [],
        "filtered_pages": [],
        "transport_error_count": 1,
        "failed_requests": [{
            "url": "https://example.test/api",
            "phase": "crawl",
            "error_type": "TimeoutError",
        }],
        "server_error_response_count": 1,
        "server_error_responses": [{
            "url": "https://example.test/admin",
            "phase": "content-discovery",
            "status": 503,
        }],
        "http_status_counts": {"200": 3, "503": 1},
        "coverage_summary": {
            "http_status_counts": {"200": 3, "503": 1},
            "transport_error_count": 1,
            "server_error_response_count": 1,
        },
    }
    txt = render_text_report(report)
    csv = render_csv_report(report)

    assert "Partial (request/server errors)" in txt
    assert "TimeoutError" in txt
    assert "HTTP 503" in txt
    assert "request_failure" in csv
    assert "http_server_error" in csv
    assert '"partial"' in csv
