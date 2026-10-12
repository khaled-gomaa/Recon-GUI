import requests
import pytest

from recon.passive_sources import collect_passive


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self.payload = payload

    def json(self):
        return self.payload


def test_collect_passive_parses_ct_and_wayback_without_probing_hosts(monkeypatch):
    calls = []

    def fake_get(self, url, params=None, timeout=None):
        calls.append((url, params, timeout))
        if "crt.sh" in url:
            return FakeResponse(200, [
                {"name_value": "example.com\napi.example.com\n*.dev.example.com"},
                {"name_value": "evil-example.com"},
            ])
        return FakeResponse(200, [
            ["original"], ["https://example.com/old"], ["https://api.example.com/v1"],
            ["https://unrelated.test/no"],
        ])

    monkeypatch.setattr(requests.Session, "get", fake_get)
    result = collect_passive("https://example.com", on_log=lambda _message: None)
    assert result["passive_subdomains"] == ["api.example.com", "dev.example.com", "example.com"]
    assert result["historical_urls"] == ["https://api.example.com/v1", "https://example.com/old"]
    assert len(calls) == 2
    assert all("crt.sh" in call[0] or "web.archive.org" in call[0] for call in calls)


def test_collect_passive_rejects_non_http_target():
    with pytest.raises(ValueError):
        collect_passive("file:///etc/passwd")
