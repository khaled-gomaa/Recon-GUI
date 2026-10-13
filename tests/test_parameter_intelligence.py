from recon.parameter_intelligence import build_endpoint_inventory, build_parameter_inventory


def test_parameter_inventory_groups_query_form_and_javascript_sources_without_values():
    page_urls = ["https://example.com/search?q=private-search&page=2"]
    forms = [{
        "page": "https://example.com/login", "action": "https://example.com/session?next=%2Fhome",
        "method": "POST", "fields": [
            {"name": "username", "type": "text"},
            {"name": "password", "type": "password"},
            {"name": "csrf_token", "type": "hidden"},
        ],
    }]
    observations = [{
        "endpoint": "/api/users?access_token=super-secret-value",
        "source": "javascript", "location": "https://example.com/app.js",
    }]
    routes = {"https://example.com/redirect?url=https%3A%2F%2Foutside.test"}
    parameters = build_parameter_inventory(page_urls, forms, observations, routes)
    by_name = {item["name"]: item for item in parameters}

    assert by_name["q"]["sources"] == ["query"]
    assert by_name["password"]["sources"] == ["form-field"]
    assert by_name["csrf_token"]["classification"] == "sensitive-name"
    assert "access_token" in by_name
    assert "next" in by_name
    assert by_name["url"]["classification"] == "review"
    serialized = repr(parameters)
    assert "private-search" not in serialized
    assert "super-secret-value" not in serialized
    assert "outside.test" not in serialized


def test_endpoint_inventory_merges_sources_and_strips_query_values():
    observations = [
        {"endpoint": "/api/users?id=123", "source": "javascript", "location": "https://example.com/app.js"},
        {"endpoint": "/api/users?id=456", "source": "html-or-inline-js", "location": "https://example.com/"},
    ]
    inventory = build_endpoint_inventory(observations)
    assert len(inventory) == 1
    item = inventory[0]
    assert item["endpoint"] == "/api/users"
    assert item["source_count"] == 2
    assert item["parameters"] == ["id"]
    assert "123" not in repr(inventory)
    assert "456" not in repr(inventory)
