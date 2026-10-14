import json

import pytest

from recon.har_import import load_har_file


def _write_har(tmp_path, entries, pages=None):
    path = tmp_path / "burp-export.har"
    path.write_text(
        json.dumps({
            "log": {
                "version": "1.2",
                "creator": {"name": "test"},
                "pages": pages or [],
                "entries": entries,
            }
        }),
        encoding="utf-8",
    )
    return path


def test_har_import_captures_methods_status_and_parameter_names_without_values(tmp_path):
    entries = [
        {
            "pageref": "home",
            "request": {
                "method": "GET",
                "url": "https://user:password@example.test/search?q=secret-query&page=2#frag",
                "headers": [{"name": "Referer", "value": "https://example.test/home?token=private"}],
                "queryString": [
                    {"name": "q", "value": "secret-query"},
                    {"name": "page", "value": "2"},
                ],
                "cookies": [{"name": "sid", "value": "super-secret-cookie", "path": "/"}],
            },
            "response": {
                "status": 200,
                "headers": [{"name": "Content-Type", "value": "text/html"}],
                "content": {"mimeType": "text/html", "text": "<html>body ignored</html>"},
                "cookies": [{
                    "name": "session", "value": "secret-response-cookie",
                    "domain": "example.test", "path": "/", "httpOnly": True, "secure": True,
                }],
            },
        },
        {
            "request": {
                "method": "POST",
                "url": "https://example.test/api/profile",
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "postData": {
                    "mimeType": "application/json",
                    "text": '{"userId":"hidden-value","profile":{"displayName":"private-name"}}',
                },
            },
            "response": {
                "status": 201,
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "content": {"mimeType": "application/json", "text": '{"response":"not stored"}'},
            },
        },
        {
            "request": {"method": "GET", "url": "https://outside.test/ignored?key=outside"},
            "response": {"status": 200, "content": {"mimeType": "text/html"}},
        },
    ]
    path = _write_har(tmp_path, entries, pages=[{"id": "home", "url": "https://example.test/"}])
    result = load_har_file(str(path), "https://example.test/")

    records = result["network_observations"]
    assert len(records) == 2
    get_record = next(item for item in records if item["method"] == "GET")
    post_record = next(item for item in records if item["method"] == "POST")
    assert get_record["url"] == "https://example.test/search"
    assert get_record["query_parameters"] == ["page", "q"]
    assert get_record["status"] == 200
    assert get_record["page"] == "https://example.test/home"
    assert post_record["status"] == 201
    assert post_record["body_parameters"] == ["displayName", "profile", "userId"]
    assert result["summary"]["entries_imported"] == 2
    assert result["summary"]["skipped_out_of_scope"] == 1

    serialized = repr(result)
    for secret in (
        "password", "secret-query", "super-secret-cookie", "secret-response-cookie",
        "hidden-value", "private-name", "not stored", "outside",
    ):
        assert secret not in serialized


def test_har_import_deduplicates_requests_and_reports_entry_limit(tmp_path):
    entries = [
        {
            "request": {"method": "GET", "url": "https://example.test/api/items?id=1"},
            "response": {"status": 200, "content": {"mimeType": "application/json"}},
        },
        {
            "request": {"method": "GET", "url": "https://example.test/api/items?id=2"},
            "response": {"status": 304, "content": {"mimeType": "application/json"}},
        },
    ]
    path = _write_har(tmp_path, entries)
    result = load_har_file(str(path), "https://example.test/", max_entries=1)

    assert result["summary"]["truncated"] is True
    assert result["summary"]["entries_considered"] == 1
    assert result["summary"]["entries_imported"] == 1
    assert result["summary"]["warnings"]
    assert result["network_observations"][0]["query_parameters"] == ["id"]


def test_har_import_rejects_invalid_target_and_oversized_file(tmp_path):
    path = _write_har(tmp_path, [])
    with pytest.raises(ValueError, match="HTTP"):
        load_har_file(str(path), "javascript:alert(1)")
    with pytest.raises(ValueError, match="larger"):
        load_har_file(str(path), "https://example.test/", max_file_bytes=1)
