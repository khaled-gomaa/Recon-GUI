from recon.advanced_analysis import analyze_html


def test_extracts_form_fields_json_ld_and_csrf_without_submitting_forms():
    html = """
    <form action="/session" method="post">
      <input name="username" required>
      <input name="csrf_token" type="hidden" value="public-placeholder">
      <input name="password" type="password">
    </form>
    <script type="application/ld+json">
      {"@context":"https://schema.org","@type":"Organization","name":"Example Org"}
    </script>
    """
    report = analyze_html("https://example.com/login", html)
    assert len(report["forms"]) == 1
    form = report["forms"][0]
    assert form["action"] == "https://example.com/session"
    assert form["method"] == "POST"
    assert form["csrf_field_present"] is True
    assert form["same_origin_action"] is True
    assert any(field["name"] == "username" and field["required"] for field in form["fields"])
    assert report["json_ld"][0]["type"] == "Organization"
    assert report["json_ld"][0]["name"] == "Example Org"


def test_secret_candidates_are_reported_without_raw_values():
    secret_key = "AKIAABCDEFGHIJKLMNOP"
    html = f'<script>const token = "{secret_key}"; const api_key = "sk_live_1234567890ABCDEF";</script>'
    report = analyze_html("https://example.com/app.js", html)
    assert any(item["type"] == "AWS access key ID" for item in report["sensitive_findings"])
    assert any(item["type"] == "Possible hard-coded secret" for item in report["sensitive_findings"])
    serialized = repr(report)
    assert secret_key not in serialized
    assert "sk_live_1234567890ABCDEF" not in serialized
    assert all(item["match"] == "[REDACTED]" for item in report["sensitive_findings"])
