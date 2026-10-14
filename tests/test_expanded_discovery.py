import asyncio
import subprocess

from aiohttp import web

from recon.analyzer import ReconAnalyzer
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


def test_html_form_inventory_includes_declared_post_method_and_field_names():
    analyzer = ReconAnalyzer("https://example.test/")
    html = """
    <form action="/api/session" method="POST">
      <input name="username">
      <input name="password" type="password">
      <input name="csrf_token" type="hidden">
    </form>
    """
    analyzer.analyze_page("https://example.test/login", html)
    report = analyzer.to_dict()
    endpoint = next(item for item in report["endpoint_inventory"] if item["endpoint"].endswith("/api/session"))
    assert "POST" in endpoint["methods"]
    assert set(endpoint["parameters"]) >= {"username", "password", "csrf_token"}
    assert "POST" in next(item for item in report["parameters"] if item["name"] == "password")["methods"]


def test_streaming_wordlist_applies_explicit_candidate_cap_and_reports_it(tmp_path):
    async def scenario():
        async def handler(request):
            if "this-path-should-not-exist-recon-baseline" in request.path:
                return web.Response(status=404, text="missing")
            return web.Response(status=200, text="found " + ("content " * 25))

        app = web.Application()
        app.router.add_get("/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            wordlist = tmp_path / "large.txt"
            wordlist.write_text("\n".join(f"item-{i}" for i in range(20)), encoding="utf-8")
            scanner = WordlistScanner(
                f"http://127.0.0.1:{port}/", str(wordlist),
                extensions=[""], concurrency=1, delay_ms=0,
                max_candidates=3,
            )
            await scanner.scan()
            assert scanner.candidate_count == 3
            assert len(scanner.responses) == 3
            assert scanner.path_limit_reached is True
            assert scanner.candidate_limit_reached is True
            assert scanner.word_limit_reached is False
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=10))


def test_subdomain_finder_uses_private_suffix_boundaries():
    from recon.subdomain_finder import SubdomainFinder

    finder = SubdomainFinder("myblog.blogspot.com")
    found = finder.find(
        "api.myblog.blogspot.com anotherblog.blogspot.com "
        "admin.anotherblog.blogspot.com"
    )
    assert found == {"api.myblog.blogspot.com"}


def test_subdomain_finder_handles_public_suffixes_without_a_fixed_list():
    from recon.subdomain_finder import SubdomainFinder

    finder = SubdomainFinder("www.example.co.uk")
    found = finder.find("api.example.co.uk api.other.co.uk")
    assert found == {"api.example.co.uk"}


def test_subfinder_uses_registrable_root_when_target_is_a_subdomain(monkeypatch):
    captured = {}

    class Completed:
        returncode = 0
        stdout = b"api.example.com\nexample.com\nnot-example.com\n"
        stderr = b""

    monkeypatch.setattr("recon.subfinder.shutil.which", lambda _name: "/usr/bin/subfinder")

    def fake_run(command, **kwargs):
        captured["command"] = command
        return Completed()

    monkeypatch.setattr("recon.subfinder.subprocess.run", fake_run)
    result = discover_subdomains("https://www.example.com/")
    assert captured["command"][-2:] == ["-d", "example.com"]
    assert result["subfinder_subdomains"] == ["api.example.com", "example.com"]


def test_subfinder_rejects_public_suffix_as_target_root():
    import pytest

    with pytest.raises(ValueError, match="registrable DNS domain"):
        discover_subdomains("https://co.uk/")


def test_recursive_content_discovery_tries_wordlist_under_detected_directory(tmp_path):
    async def scenario():
        requested = []

        async def handler(request):
            requested.append(request.path)
            if "this-path-should-not-exist-recon-baseline" in request.path:
                return web.Response(status=404, text="missing")
            if request.path == "/admin":
                return web.Response(
                    status=200,
                    text="<html><title>Admin</title>" + ("admin panel content " * 40) + "</html>",
                    content_type="text/html",
                )
            if request.path == "/admin/users":
                return web.Response(
                    status=200,
                    text="<html><title>Users</title>" + ("users section " * 40) + "</html>",
                    content_type="text/html",
                )
            return web.Response(status=404, text="missing")

        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            path = tmp_path / "paths.txt"
            path.write_text("admin\nusers\n", encoding="utf-8")

            scanner = WordlistScanner(
                f"http://127.0.0.1:{port}/", str(path),
                extensions=[""], concurrency=1, delay_ms=0,
                recursive=True, recursion_depth=1,
            )
            await asyncio.wait_for(scanner.scan(), timeout=5)

            assert "/admin" in requested
            assert "/admin/users" in requested
            assert scanner.recursion_rounds == 1
            assert scanner.recursive_dirs_found >= 1
            assert scanner.candidate_count == 4
            assert scanner.path_limit_reached is False
            # /admin/users itself looks like another HTML directory, but only one
            # recursive round was configured, so remaining depth is reported as partial.
            assert scanner.recursion_depth_limit_reached is True
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=8))


def test_recursive_content_discovery_respects_one_global_path_cap(tmp_path):
    async def scenario():
        requested = []

        async def handler(request):
            requested.append(request.path)
            if "this-path-should-not-exist-recon-baseline" in request.path:
                return web.Response(status=404, text="missing")
            if request.path == "/admin":
                return web.Response(
                    status=200,
                    text="<html>" + ("admin area " * 40) + "</html>",
                    content_type="text/html",
                )
            return web.Response(status=404, text="missing")

        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            path = tmp_path / "paths.txt"
            path.write_text("admin\nusers\nextra\n", encoding="utf-8")

            scanner = WordlistScanner(
                f"http://127.0.0.1:{port}/", str(path),
                extensions=[""], concurrency=1, delay_ms=0,
                recursive=True, recursion_depth=2, max_candidates=3,
            )
            await asyncio.wait_for(scanner.scan(), timeout=5)

            assert scanner.candidate_count == 3
            assert scanner.path_limit_reached is True
            assert len(set(requested) - {
                "/this-path-should-not-exist-recon-baseline-74c31"
            }) <= 3
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=8))


def test_recursive_directory_classifier_rejects_external_redirects_and_files():
    scanner = WordlistScanner(
        "https://example.test/", "unused.txt", extensions=[""], recursive=True
    )
    assert scanner._recursive_directory_prefix({
        "url": "https://example.test/redirect",
        "final_url": "https://example.test/redirect",
        "location": "https://outside.invalid/path/",
        "status": 302, "content_type": "", "potential_hit": True,
    }) == ""
    assert scanner._recursive_directory_prefix({
        "url": "https://example.test/app.js",
        "final_url": "https://example.test/app.js",
        "location": "", "status": 200, "content_type": "text/html",
        "potential_hit": True,
    }) == ""
