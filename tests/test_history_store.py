from recon.history_store import HistoryStore, project_key


def _page(url, status=200, content_hash="same", title="Example"):
    return {
        "url": url, "status": status, "title": title, "final_url": url,
        "word_count": 5, "content_length": 50, "content_hash": content_hash,
        "text_hash": content_hash, "content_type": "text/html", "depth": 0, "error": "",
    }


def test_project_key_normalizes_origin_and_default_port():
    assert project_key("HTTPS://Example.com:443/app?a=1") == "https://example.com/"
    assert project_key("http://example.com:8080/app") == "http://example.com:8080/"


def test_scan_history_persists_reports_and_compares_previous_pages(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    first = store.save_report({
        "target": "https://example.com/", "pages": [
            _page("https://example.com/keep"), _page("https://example.com/remove"),
            _page("https://example.com/change", content_hash="old"),
        ],
        "emails": ["security@example.com"],
        "endpoint_inventory": [{"endpoint": "/api/old", "sources": ["javascript"], "locations": ["/app.js"]}],
        "parameters": [{"name": "q", "sources": ["query"], "locations": ["/search"], "classification": "ordinary"}],
    })
    assert first["history_diff"]["previous_scan_id"] is None
    second = store.save_report({
        "target": "https://example.com/login", "pages": [
            _page("https://example.com/keep"), _page("https://example.com/change", content_hash="new"),
            _page("https://example.com/add"),
        ],
        "emails": ["security@example.com"],
        "endpoint_inventory": [{"endpoint": "/api/new", "sources": ["javascript"], "locations": ["/app.js"]}],
        "parameters": [{"name": "q", "sources": ["query"], "locations": ["/search"], "classification": "ordinary"},
                       {"name": "tenant", "sources": ["query"], "locations": ["/app"], "classification": "review"}],
    })
    diff = second["history_diff"]
    assert diff["previous_scan_id"] == first["scan_id"]
    assert diff["added_urls"] == ["https://example.com/add"]
    assert diff["removed_urls"] == ["https://example.com/remove"]
    assert diff["changed_urls"] == ["https://example.com/change"]
    assert diff["added_count"] == diff["removed_count"] == diff["changed_count"] == 1
    assert diff["added_endpoints"] == ["/api/new"]
    assert diff["removed_endpoints"] == ["/api/old"]
    assert diff["added_parameters"] == ["tenant"]
    assert diff["added_endpoint_count"] == 1
    assert diff["added_parameter_count"] == 1
    assert len(store.recent_scans("https://example.com/other")) == 2
    saved = store.get_scan(second["scan_id"])
    assert saved["target"] == "https://example.com/login"
    assert saved["history_diff"]["changed_count"] == 1


def test_page_limited_scan_does_not_infer_removed_pages_endpoints_or_parameters(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    store.save_report({
        "target": "https://capped.example/",
        "pages": [_page("https://capped.example/a"), _page("https://capped.example/b")],
        "endpoint_inventory": [{"endpoint": "/api/a", "sources": ["javascript"]}],
        "parameters": [{"name": "tenant", "sources": ["query"]}],
    })
    partial = store.save_report({
        "target": "https://capped.example/",
        "pages": [_page("https://capped.example/a")],
        "endpoint_inventory": [],
        "parameters": [],
        "page_limit_reached": True,
    })
    diff = partial["history_diff"]
    scan_status = next(
        row["status"] for row in store.recent_scans("https://capped.example/")
        if row["scan_id"] == partial["scan_id"]
    )
    assert scan_status == "partial"
    assert diff["comparison_status"].startswith("partial")
    assert diff["removed_urls"] == []
    assert diff["removed_endpoints"] == []
    assert diff["removed_parameters"] == []


def test_partial_scan_does_not_infer_removed_pages_endpoints_or_parameters(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    store.save_report({
        "target": "https://partial.example/",
        "pages": [_page("https://partial.example/a"), _page("https://partial.example/b")],
        "endpoint_inventory": [{"endpoint": "/api/a", "sources": ["javascript"]}],
        "parameters": [{"name": "tenant", "sources": ["query"]}],
    })
    partial = store.save_report({
        "target": "https://partial.example/",
        "pages": [_page("https://partial.example/a")],
        "endpoint_inventory": [],
        "parameters": [],
        "crawler_rate_limited_stop": True,
    })
    diff = partial["history_diff"]
    assert diff["comparison_status"].startswith("partial")
    assert diff["removed_urls"] == []
    assert diff["removed_endpoints"] == []
    assert diff["removed_parameters"] == []


def test_content_truncation_marks_scan_partial_and_prevents_false_removals(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    store.save_report({
        "target": "https://truncated.example/",
        "pages": [
            _page("https://truncated.example/a"),
            _page("https://truncated.example/b"),
        ],
        "endpoint_inventory": [{"endpoint": "/api/a", "sources": ["javascript"]}],
        "parameters": [{"name": "id", "sources": ["query"]}],
    })
    partial = store.save_report({
        "target": "https://truncated.example/",
        "pages": [_page("https://truncated.example/a")],
        "endpoint_inventory": [],
        "parameters": [],
        "content_limit_reached": True,
        "body_truncated_pages": ["https://truncated.example/a"],
    })
    diff = partial["history_diff"]
    saved_status = next(
        row["status"] for row in store.recent_scans("https://truncated.example/")
        if row["scan_id"] == partial["scan_id"]
    )
    assert saved_status == "partial"
    assert diff["comparison_status"].startswith("partial")
    assert diff["removed_urls"] == []
    assert diff["removed_endpoints"] == []
    assert diff["removed_parameters"] == []


def test_recursive_depth_cap_marks_history_partial_and_does_not_infer_removals(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    store.save_report({
        "target": "https://recursive.example/",
        "pages": [_page("https://recursive.example/a"), _page("https://recursive.example/b")],
        "endpoint_inventory": [{"endpoint": "/api/old", "sources": ["javascript"]}],
        "parameters": [{"name": "id", "sources": ["query"]}],
    })
    partial = store.save_report({
        "target": "https://recursive.example/",
        "pages": [_page("https://recursive.example/a")],
        "endpoint_inventory": [],
        "parameters": [],
        "wordlist_recursive_enabled": True,
        "wordlist_recursion_depth": 1,
        "wordlist_recursion_rounds": 1,
        "wordlist_recursion_depth_limit_reached": True,
    })
    diff = partial["history_diff"]
    status = next(
        row["status"] for row in store.recent_scans("https://recursive.example/")
        if row["scan_id"] == partial["scan_id"]
    )
    assert status == "partial"
    assert diff["comparison_status"].startswith("partial")
    assert diff["removed_urls"] == []
    assert diff["removed_endpoints"] == []
    assert diff["removed_parameters"] == []


def test_partial_asset_head_phase_does_not_infer_removed_resources(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    store.save_report({
        "target": "https://assets.example/",
        "pages": [
            _page("https://assets.example/"),
            _page("https://assets.example/app"),
        ],
        "endpoint_inventory": [{"endpoint": "/api/app", "sources": ["javascript"]}],
        "parameters": [{"name": "q", "sources": ["query"]}],
        "asset_inventory": [
            {"url": "https://assets.example/static/app.js", "kind": "javascript"},
            {"url": "https://assets.example/static/site.css", "kind": "stylesheet"},
        ],
    })
    partial = store.save_report({
        "target": "https://assets.example/",
        "pages": [_page("https://assets.example/")],
        "endpoint_inventory": [],
        "parameters": [],
        "asset_inventory": [],
        "asset_probe_summary": {
            "enabled": True, "partial": True,
            "limit_reached": True, "requests_completed": 1,
        },
    })
    saved_status = next(
        row["status"] for row in store.recent_scans("https://assets.example/")
        if row["scan_id"] == partial["scan_id"]
    )
    assert saved_status == "partial"
    assert partial["history_diff"]["comparison_status"].startswith("partial")
    assert partial["history_diff"]["removed_urls"] == []
    assert partial["history_diff"]["removed_assets"] == []
    assert partial["history_diff"]["removed_endpoints"] == []
    assert partial["history_diff"]["removed_parameters"] == []


def test_scan_history_tracks_asset_additions_removals_and_probe_changes(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    first = store.save_report({
        "target": "https://asset-history.example/",
        "pages": [_page("https://asset-history.example/")],
        "asset_inventory": [
            {
                "url": "https://asset-history.example/static/app.js",
                "kind": "javascript",
                "extension": ".js",
                "in_scope": True,
                "referrers": ["https://asset-history.example/"],
                "query_parameter_names": ["version"],
                "probe_checked": True,
                "probe_status": 200,
                "probe_result": "HEAD supported",
                "probe_content_type": "application/javascript",
                "probe_content_length": "100",
            },
            {
                "url": "https://asset-history.example/static/old.css",
                "kind": "stylesheet",
                "extension": ".css",
                "in_scope": True,
                "referrers": ["https://asset-history.example/"],
            },
        ],
    })
    second = store.save_report({
        "target": "https://asset-history.example/",
        "pages": [_page("https://asset-history.example/")],
        "asset_inventory": [
            {
                "url": "https://asset-history.example/static/app.js",
                "kind": "javascript",
                "extension": ".js",
                "in_scope": True,
                "referrers": ["https://asset-history.example/", "https://asset-history.example/app"],
                "query_parameter_names": ["version"],
                "probe_checked": True,
                "probe_status": 304,
                "probe_result": "HTTP response",
                "probe_content_type": "application/javascript",
                "probe_content_length": "100",
            },
            {
                "url": "https://asset-history.example/static/new.svg",
                "kind": "image",
                "extension": ".svg",
                "in_scope": True,
                "referrers": ["https://asset-history.example/"],
            },
        ],
    })
    diff = second["history_diff"]
    assert diff["added_assets"] == ["https://asset-history.example/static/new.svg [image]"]
    assert diff["removed_assets"] == ["https://asset-history.example/static/old.css [stylesheet]"]
    assert diff["changed_assets"] == ["https://asset-history.example/static/app.js [javascript]"]
    assert diff["added_asset_count"] == 1
    assert first["history_diff"]["added_asset_count"] == 2
    latest_summary = store.recent_scans("https://asset-history.example/")[0]
    assert latest_summary["added_asset_count"] == 1


def test_partial_css_discovery_does_not_infer_removed_history(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    store.save_report({
        "target": "https://css-gap.example/",
        "pages": [
            _page("https://css-gap.example/a"),
            _page("https://css-gap.example/b"),
        ],
        "endpoint_inventory": [{"endpoint": "/api/old", "sources": ["javascript"]}],
        "parameters": [{"name": "id", "sources": ["query"]}],
    })
    partial = store.save_report({
        "target": "https://css-gap.example/",
        "pages": [_page("https://css-gap.example/a")],
        "endpoint_inventory": [],
        "parameters": [],
        "css_discovery_summary": {
            "status": "partial",
            "css_files_discovered": 3,
            "css_files_attempted": 3,
            "css_files_fetched": 2,
            "css_file_errors": [{"url": "https://css-gap.example/site.css", "status": 403, "error": "http-error"}],
        },
    })
    status = next(
        row["status"] for row in store.recent_scans("https://css-gap.example/")
        if row["scan_id"] == partial["scan_id"]
    )
    assert status == "partial"
    assert partial["history_diff"]["comparison_status"].startswith("partial")
    assert partial["history_diff"]["removed_urls"] == []
    assert partial["history_diff"]["removed_endpoints"] == []
    assert partial["history_diff"]["removed_parameters"] == []


def test_transport_errors_make_history_partial_and_suppress_removal_diffs(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    store.save_report({
        "target": "https://network-errors.example/",
        "pages": [
            _page("https://network-errors.example/a"),
            _page("https://network-errors.example/b"),
        ],
        "endpoint_inventory": [{"endpoint": "/api/old", "sources": ["javascript"]}],
        "parameters": [{"name": "id", "sources": ["query"]}],
    })
    partial = store.save_report({
        "target": "https://network-errors.example/",
        "pages": [_page("https://network-errors.example/a")],
        "endpoint_inventory": [],
        "parameters": [],
        "transport_error_count": 1,
        "failed_requests": [{
            "url": "https://network-errors.example/b",
            "phase": "crawl",
            "error_type": "TimeoutError",
        }],
    })
    status = next(
        row["status"] for row in store.recent_scans("https://network-errors.example/")
        if row["scan_id"] == partial["scan_id"]
    )
    assert status == "partial"
    assert partial["history_diff"]["comparison_status"].startswith("partial")
    assert partial["history_diff"]["removed_urls"] == []
    assert partial["history_diff"]["removed_endpoints"] == []
    assert partial["history_diff"]["removed_parameters"] == []


def test_javascript_fetch_failures_make_scan_partial(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    store.save_report({
        "target": "https://js-errors.example/",
        "pages": [_page("https://js-errors.example/")],
        "endpoint_inventory": [{"endpoint": "/api/old", "sources": ["javascript"]}],
        "parameters": [{"name": "id", "sources": ["query"]}],
    })
    partial = store.save_report({
        "target": "https://js-errors.example/",
        "pages": [_page("https://js-errors.example/")],
        "endpoint_inventory": [],
        "parameters": [],
        "js_fetch_error_count": 1,
        "js_fetch_errors": [{
            "url": "https://js-errors.example/app.js",
            "status": 404,
            "error_type": "HTTP 404; response not analyzed",
        }],
    })
    status = next(
        row["status"] for row in store.recent_scans("https://js-errors.example/")
        if row["scan_id"] == partial["scan_id"]
    )
    assert status == "partial"
    assert partial["history_diff"]["comparison_status"].startswith("partial")
    assert partial["history_diff"]["removed_urls"] == []
    assert partial["history_diff"]["removed_endpoints"] == []


def test_shared_rate_limit_stop_marks_history_incomplete_and_suppresses_removals(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    store.save_report({
        "target": "https://shared-429.example/",
        "pages": [
            _page("https://shared-429.example/a"),
            _page("https://shared-429.example/b"),
        ],
    })
    partial = store.save_report({
        "target": "https://shared-429.example/",
        "pages": [_page("https://shared-429.example/a")],
        "rate_limit_stopped": True,
        "rate_limit_summary": {
            "stopped": True, "cooldowns_applied": 3,
            "events": [{"phase": "javascript", "url": "https://shared-429.example/app.js", "reason": "fallback"}],
        },
    })
    status = next(
        row["status"] for row in store.recent_scans("https://shared-429.example/")
        if row["scan_id"] == partial["scan_id"]
    )
    assert status == "rate-limited"
    assert partial["history_diff"]["comparison_status"].startswith("partial")
    assert partial["history_diff"]["removed_urls"] == []
