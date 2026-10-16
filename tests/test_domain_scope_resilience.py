import pytest

import recon.domain_scope as domain_scope
import recon.subdomain_finder as subdomain_finder
from recon.analyzer import ReconAnalyzer
from recon.subdomain_finder import SubdomainFinder


def test_missing_tldextract_disables_passive_text_discovery_without_aborting_scan(monkeypatch):
    logs = []

    def missing_dependency(_hostname):
        raise RuntimeError(
            "Public-suffix scope support is unavailable. Install the required 'tldextract'."
        )

    monkeypatch.setattr(subdomain_finder, "registrable_domain", missing_dependency)
    finder = SubdomainFinder("www.example.co.uk", on_log=logs.append)

    assert finder.enabled is False
    assert finder.find("api.example.co.uk and files.example.co.uk") == set()
    assert len(logs) == 1
    assert "run_windows.bat" in logs[0]
    assert "disabled" in logs[0].lower()


def test_analyzer_survives_missing_tldextract_and_surfaces_warning(monkeypatch):
    logs = []

    def missing_dependency(_hostname):
        raise RuntimeError("tldextract missing")

    monkeypatch.setattr(subdomain_finder, "registrable_domain", missing_dependency)
    analyzer = ReconAnalyzer("https://example.com", on_log=logs.append)

    assert analyzer.subdomain_finder.enabled is False
    assert any("public-suffix support is unavailable" in line for line in logs)
    # Ordinary page analysis is still usable; only this optional extractor is disabled.
    analyzer.analyze_page("https://example.com/", "<title>home</title> api.example.com")
    assert analyzer.report.subdomains == set()


def test_domain_scope_verification_still_fails_closed_without_public_suffix_support(monkeypatch):
    def missing_snapshot():
        raise RuntimeError("tldextract snapshot unavailable")

    monkeypatch.setattr(domain_scope, "_extractor", missing_snapshot)

    with pytest.raises(RuntimeError, match="tldextract snapshot unavailable"):
        domain_scope.registrable_domain("api.example.com")


def test_missing_tldextract_snapshot_does_not_abort_full_crawl(monkeypatch):
    logs = []

    def missing_snapshot(_hostname):
        raise FileNotFoundError(
            "No such file or directory: '_internal/tldextract/.tld_set_snapshot'"
        )

    monkeypatch.setattr(subdomain_finder, "registrable_domain", missing_snapshot)
    finder = SubdomainFinder("https://www.example.com", on_log=logs.append)

    assert finder.enabled is False
    assert finder.find("api.example.com") == set()
    assert any("disabled" in line.lower() for line in logs)
    assert any(".tld_set_snapshot" in line for line in logs)
