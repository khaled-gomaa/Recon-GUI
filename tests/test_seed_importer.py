import gzip

import pytest

from recon.seed_importer import load_seed_urls


def test_imports_and_deduplicates_same_host_txt_urls_and_paths(tmp_path):
    source = tmp_path / "urls.txt"
    source.write_text(
        "https://example.test/a\n"
        "https://example.test/a#section\n"
        "/from-log?id=3\n"
        "https://api.example.test/out-of-scope\n"
        "https://other.test/nope\n"
        "javascript:alert(1)\n",
        encoding="utf-8",
    )

    result = load_seed_urls(source, "https://example.test/")

    assert result["urls"] == [
        "https://example.test/a",
        "https://example.test/from-log?id=3",
    ]
    assert result["accepted_count"] == 2
    assert result["rejected_or_out_of_scope"] >= 3
    assert result["source_type"] == "url-list-or-access-log"


def test_imports_sitemap_xml_and_rejects_other_hosts(tmp_path):
    source = tmp_path / "sitemap.xml"
    source.write_text(
        """<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://example.test/home</loc></url>
          <url><loc>https://example.test/account</loc></url>
          <url><loc>https://evil.test/out</loc></url>
        </urlset>""",
        encoding="utf-8",
    )

    result = load_seed_urls(source, "https://example.test/")

    assert result["urls"] == [
        "https://example.test/home",
        "https://example.test/account",
    ]
    assert result["source_type"] == "sitemap"


def test_imports_compressed_sitemap_and_csv_search_console_style_export(tmp_path):
    xml_path = tmp_path / "sitemap.xml.gz"
    with gzip.open(xml_path, "wt", encoding="utf-8") as output:
        output.write(
            "<urlset><url><loc>https://example.test/one</loc></url>"
            "<url><loc>https://example.test/two</loc></url></urlset>"
        )
    xml_result = load_seed_urls(xml_path, "https://example.test/")
    assert xml_result["urls"] == [
        "https://example.test/one",
        "https://example.test/two",
    ]

    csv_path = tmp_path / "pages.csv"
    csv_path.write_text(
        "Page,Clicks\nhttps://example.test/search?q=abc,5\nhttps://evil.test/no,1\n",
        encoding="utf-8",
    )
    csv_result = load_seed_urls(csv_path, "https://example.test/")
    assert csv_result["urls"] == ["https://example.test/search?q=abc"]
    assert csv_result["source_type"] == "csv"


def test_imports_request_targets_from_common_access_logs(tmp_path):
    source = tmp_path / "access.log"
    source.write_text(
        '127.0.0.1 - - [15/Oct/2026] "GET /admin HTTP/1.1" 200 123\n'
        '127.0.0.1 - - [15/Oct/2026] "POST /api/profile?id=4 HTTP/1.1" 200 12\n',
        encoding="utf-8",
    )

    result = load_seed_urls(source, "https://example.test/")

    assert result["urls"] == [
        "https://example.test/admin",
        "https://example.test/api/profile?id=4",
    ]


def test_seed_import_cap_is_explicit(tmp_path):
    source = tmp_path / "many.txt"
    source.write_text("\n".join(f"https://example.test/p{i}" for i in range(10)), encoding="utf-8")

    result = load_seed_urls(source, "https://example.test/", max_seeds=3)

    assert len(result["urls"]) == 3
    assert result["limit_reached"] is True


def test_rejects_invalid_target_and_malformed_xml(tmp_path):
    source = tmp_path / "sitemap.xml"
    source.write_text("<broken", encoding="utf-8")

    with pytest.raises(ValueError, match="HTTP"):
        load_seed_urls(source, "file:///etc/passwd")
    with pytest.raises(ValueError, match="parse XML"):
        load_seed_urls(source, "https://example.test/")
