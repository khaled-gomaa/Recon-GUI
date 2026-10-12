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
    })
    assert first["history_diff"]["previous_scan_id"] is None
    second = store.save_report({
        "target": "https://example.com/login", "pages": [
            _page("https://example.com/keep"), _page("https://example.com/change", content_hash="new"),
            _page("https://example.com/add"),
        ],
        "emails": ["security@example.com"],
    })
    diff = second["history_diff"]
    assert diff["previous_scan_id"] == first["scan_id"]
    assert diff["added_urls"] == ["https://example.com/add"]
    assert diff["removed_urls"] == ["https://example.com/remove"]
    assert diff["changed_urls"] == ["https://example.com/change"]
    assert diff["added_count"] == diff["removed_count"] == diff["changed_count"] == 1
    assert len(store.recent_scans("https://example.com/other")) == 2
    saved = store.get_scan(second["scan_id"])
    assert saved["target"] == "https://example.com/login"
    assert saved["history_diff"]["changed_count"] == 1
