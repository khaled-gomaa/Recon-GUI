from recon.email_extractor import EmailExtractor
from recon.subdomain_finder import SubdomainFinder
from recon.js_endpoint_extractor import JSEndpointExtractor


def test_email_extraction():
    text = "Contact admin@example.com or support@test.co.uk"
    emails = EmailExtractor.extract(text)
    assert "admin@example.com" in emails
    assert "support@test.co.uk" in emails


def test_subdomain_finder():
    finder = SubdomainFinder("example.com")
    text = "Visit api.example.com and www.example.com"
    subs = finder.find(text)
    assert "api.example.com" in subs
    assert "www.example.com" in subs


def test_js_endpoints():
    js = 'fetch("/api/users"); axios.get("/v1/items");'
    endpoints = JSEndpointExtractor.extract(js)
    assert "/api/users" in endpoints
    assert "/v1/items" in endpoints
