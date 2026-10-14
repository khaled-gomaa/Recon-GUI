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


def test_optional_subfinder_merges_only_root_domain_hostnames(monkeypatch):
    import subprocess
    from types import SimpleNamespace
    import recon.passive_sources as passive

    def fake_get(self, url, params=None, timeout=None):
        if "crt.sh" in url:
            return FakeResponse(200, [{"name_value": "api.example.com"}])
        return FakeResponse(200, [["original"], ["https://example.com/old"]])

    def fake_run(command, **kwargs):
        assert command[-3:] == ["-silent", "-d", "example.com"]
        return SimpleNamespace(
            stdout=b"api.example.com\nadmin.example.com\nevil-example.com\n",
            stderr=b"", returncode=0,
        )

    monkeypatch.setattr(requests.Session, "get", fake_get)
    monkeypatch.setattr(passive.shutil, "which", lambda name: "/usr/bin/subfinder")
    monkeypatch.setattr(passive.subprocess, "run", fake_run)
    result = collect_passive(
        "https://example.com", include_subfinder=True,
        on_log=lambda _message: None,
    )
    assert result["passive_subdomains"] == [
        "admin.example.com", "api.example.com",
    ]
    source = next(item for item in result["passive_sources"] if item["name"] == "Subfinder")
    assert source["status"] == "queried"
    assert source["count"] == 2
