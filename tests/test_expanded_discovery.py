import asyncio
import subprocess

from aiohttp import web

from recon.js_endpoint_extractor import JSEndpointExtractor
from recon.subfinder import discover_subdomains
from recon.wordlist_scanner import WordlistScanner


def test_wordlist_has_no_implicit_500_entry_cap_and_deduplicates(tmp_path):
    path = tmp_path / "paths.txt"
    path.write_text("\n".join([f"item-{i}" for i in range(610)] + ["item-0"]), encoding="utf-8")
    scanner = WordlistScanner("https://example.test/", str(path), extensions=[""])
    entries = scanner._load_wordlist()
    assert len(entries) == 610
    assert scanner.words_loaded == 610
    assert scanner.candidate_limit_reached is False


def test_explicit_wordlist_cap_is_visible_and_extension_candidates_are_expanded(tmp_path):
    path = tmp_path / "paths.txt"
    path.write_text("admin\napi/config\nrobots.txt\n", encoding="utf-8")
    logs = []
    scanner = WordlistScanner(
        "https://example.test/", str(path), extensions=["", "php", ".bak", ".bak"],
        max_words=2, on_log=logs.append,
    )
    entries = scanner._load_wordlist()
    assert entries == ["admin", "api/config"]
    assert scanner.candidate_limit_reached is True
    assert any("remaining entries were not loaded" in line for line in logs)
    assert scanner._build_targets("admin") == [
        "https://example.test/admin",
        "https://example.test/admin.php",
        "https://example.test/admin.bak",
    ]
    # Explicit files are tried as-is rather than producing robots.txt.php.
    assert scanner._build_targets("robots.txt") == ["https://example.test/robots.txt"]


def test_all_wordlist_responses_include_method_and_cookie_attribute_metadata(tmp_path):
    async def scenario():
        async def handler(request):
            if "this-path-should-not-exist-recon-baseline" in request.path:
                return web.Response(status=404, text="missing")
            return web.Response(
                status=403, text="restricted", headers={"Set-Cookie": "session=secret; HttpOnly; Secure; Path=/"}
            )

        app = web.Application()
        app.router.add_get("/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            path = tmp_path / "paths.txt"
            path.write_text("admin\n", encoding="utf-8")
            scanner = WordlistScanner(
                f"http://127.0.0.1:{port}/", str(path),
                extensions=[""], concurrency=1, delay_ms=0,
            )
            await scanner.scan()
            assert len(scanner.responses) == 1
            record = scanner.responses[0]
            assert record["method"] == "GET"
            assert record["status"] == 403
            assert record["set_cookie_names"][0]["name"] == "session"
            assert record["set_cookie_names"][0]["httponly"] is True
            assert "secret" not in repr(record)
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_static_javascript_extracts_request_methods_and_body_parameter_names():
    code = """
    fetch("/api/search", {method: "POST", body: JSON.stringify({query: q, page: p})});
    axios.get("/api/items");
    const xhr = new XMLHttpRequest(); xhr.open("PATCH", "/api/items/1");
    """
    found = JSEndpointExtractor.extract_request_observations(code)
    by_url = {item["endpoint"]: item for item in found}
    assert by_url["/api/search"]["method"] == "POST"
    assert set(by_url["/api/search"]["body_parameters"]) >= {"query", "page"}
    assert by_url["/api/items"]["method"] == "GET"
    assert by_url["/api/items/1"]["method"] == "PATCH"


def test_subfinder_results_are_filtered_to_the_requested_domain(monkeypatch):
    class Completed:
        returncode = 0
        stdout = b"api.example.test\nstaging.example.test\nnot-example.test\nother.invalid\n"
        stderr = b""

    monkeypatch.setattr("recon.subfinder.shutil.which", lambda _name: "/usr/bin/subfinder")
    monkeypatch.setattr("recon.subfinder.subprocess.run", lambda *a, **kw: Completed())
    result = discover_subdomains("https://example.test/")
    assert result["subfinder_status"] == "queried"
    assert result["subfinder_subdomains"] == ["api.example.test", "staging.example.test"]
    assert "other.invalid" not in repr(result)
