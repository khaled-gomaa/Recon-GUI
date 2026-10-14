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
