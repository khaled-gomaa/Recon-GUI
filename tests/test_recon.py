from recon.email_extractor import EmailExtractor
from recon.subdomain_finder import SubdomainFinder
from recon.js_endpoint_extractor import JSEndpointExtractor
from recon.analyzer import ReconAnalyzer


def test_email_extraction():
    text = "Contact admin@acme.org or support@test.co.uk"
    emails = EmailExtractor.extract(text)
    assert "admin@acme.org" in emails
    assert "support@test.co.uk" in emails


def test_email_extraction_filters_placeholder_addresses():
    # Placeholder addresses are intentionally suppressed to reduce recon noise.
    emails = EmailExtractor.extract("Contact admin@example.com")
    assert "admin@example.com" not in emails


def test_subdomain_finder():
    finder = SubdomainFinder("example.com")
    text = "Visit api.example.com, www.example.com, and api.dev.example.com"
    subs = finder.find(text)
    assert "api.example.com" in subs
    assert "www.example.com" in subs
    assert "api.dev.example.com" in subs


def test_js_endpoints():
    js = 'fetch("/api/users"); axios.get("/v1/items");'
    endpoints = JSEndpointExtractor.extract(js)
    assert "/api/users" in endpoints
    assert "/v1/items" in endpoints


def test_analyzer_uses_url_hostname_and_response_headers():
    analyzer = ReconAnalyzer("https://www.example.com/")
    html = (
        "<html><head><title>Sample</title>"
        '<base href="/assets/">'
        '<script src="app.js"></script></head>'
        "<body>api.example.com api.dev.example.com</body></html>"
    )
    analyzer.analyze_page(
        "https://www.example.com/",
        html,
        headers={"Content-Security-Policy": "default-src 'self'"},
    )
    report = analyzer.to_dict()
    assert "api.example.com" in report["subdomains"]
    assert "api.dev.example.com" in report["subdomains"]
    assert "https://www.example.com/assets/app.js" in report["js_files"]
    assert report["header_audits"][0]["present"]["Content-Security-Policy"] == "default-src 'self'"
    assert any("Strict-Transport-Security" in item for item in report["header_audits"][0]["missing"])



def test_js_route_extractor_finds_hidden_routes_but_skips_static_assets():
    routes = JSEndpointExtractor.extract_routes(
        "const a='/admin/users'; fetch('/api/v1/items'); const b='/assets/app.js';"
    )
    assert "/admin/users" in routes
    assert "/api/v1/items" in routes
    assert "/assets/app.js" not in routes
