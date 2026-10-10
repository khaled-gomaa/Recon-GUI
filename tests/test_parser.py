from crawler.parser import PageParser

SAMPLE_HTML = """
<html><head><title>Test Page</title></head>
<body>
  <a href="/about">About</a>
  <a href="https://other.com/external">External</a>
  <a href="mailto:test@example.com">Mail</a>
  <script src="/js/app.js"></script>
</body></html>
"""


def test_parse_links():
    parser = PageParser("https://example.com")
    result = parser.parse(SAMPLE_HTML, "https://example.com")
    assert "https://example.com/about" in result["links"]
    assert "https://other.com/external" in result["links"]
    assert len(result["scripts"]) == 1


def test_is_same_domain():
    assert PageParser.is_same_domain("https://example.com/a", "https://example.com")
    assert not PageParser.is_same_domain("https://other.com/a", "https://example.com")
