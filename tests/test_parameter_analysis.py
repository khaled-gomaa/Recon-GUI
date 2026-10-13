from recon.analyzer import ReconAnalyzer


def test_analyzer_exposes_parameter_and_endpoint_inventories_without_query_values():
    analyzer = ReconAnalyzer("https://example.com/")
    url = "https://example.com/search?q=private-value"
    html = """
      <form action="/search?redirect=%2Faccount" method="GET">
        <input name="tenant_id" type="hidden">
        <input name="password" type="password">
      </form>
      <script>
        fetch('/api/users?access_token=top-secret-value');
        const route = '/admin/users?userId=12345';
      </script>
    """
    analyzer.analyze_page(url, html)
    report = analyzer.to_dict()

    names = {item["name"] for item in report["parameters"]}
    assert {"q", "redirect", "tenant_id", "password", "access_token", "userId"} <= names
    assert any(item["endpoint"] == "/api/users" for item in report["endpoint_inventory"])
    assert any(item["endpoint"].endswith("/admin/users") for item in report["endpoint_inventory"])
    safe_inventory = repr({
        "endpoints": report["endpoints"],
        "endpoint_inventory": report["endpoint_inventory"],
        "parameters": report["parameters"],
        "discovered_routes": report["discovered_routes"],
    })
    assert "private-value" not in safe_inventory
    assert "top-secret-value" not in safe_inventory
    assert "12345" not in safe_inventory
