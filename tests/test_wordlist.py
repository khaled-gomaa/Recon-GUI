"""Regression tests for bounded wordlist scanning and worker resilience."""
import asyncio

from aiohttp import web

from recon.wordlist_scanner import WordlistScanner


def test_hit_callback_failure_does_not_stop_wordlist_scan(tmp_path):
    async def scenario():
        requested = []

        async def handler(request):
            requested.append(request.path)
            if "this-path-should-not-exist-recon-baseline" in request.path:
                return web.Response(status=404, text="missing")
            return web.Response(status=200, text="FOUND-" + ("x" * 120))

        app = web.Application()
        app.router.add_get("/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            wordlist = tmp_path / "paths.txt"
            wordlist.write_text("alpha\nbeta\n", encoding="utf-8")

            def broken_hit_callback(_url, _status, _size):
                raise RuntimeError("simulated GUI callback failure")

            scanner = WordlistScanner(
                f"http://127.0.0.1:{port}/",
                str(wordlist),
                extensions=[""],
                concurrency=1,
                delay_ms=0,
                on_hit=broken_hit_callback,
            )
            hits = await scanner.scan()
            assert len(hits) == 2
            assert "/alpha" in requested
            assert "/beta" in requested
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_baseline_http_429_stops_wordlist_requests(tmp_path):
    async def scenario():
        requested = []

        async def handler(request):
            requested.append(request.path)
            if "this-path-should-not-exist-recon-baseline" in request.path:
                return web.Response(status=429, text="rate limited")
            return web.Response(status=200, text="should not be requested")

        app = web.Application()
        app.router.add_get("/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            wordlist = tmp_path / "paths.txt"
            wordlist.write_text("secret\n", encoding="utf-8")
            scanner = WordlistScanner(
                f"http://127.0.0.1:{port}/",
                str(wordlist),
                extensions=[""],
                concurrency=2,
                delay_ms=0,
            )
            hits = await scanner.scan()
            assert hits == []
            assert scanner._rate_limited is True
            assert len(requested) == 1
            assert "this-path-should-not-exist-recon-baseline" in requested[0]
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))



def test_records_404_responses_for_content_discovery_results(tmp_path):
    async def scenario():
        async def handler(request):
            if "this-path-should-not-exist-recon-baseline" in request.path:
                return web.Response(status=404, text="missing")
            if request.path == "/admin":
                # Differ clearly from the missing-path baseline to avoid wildcard false positives.
                return web.Response(status=200, text="admin area " + ("visible " * 20))
            return web.Response(status=404, text="missing")

        app = web.Application()
        app.router.add_get("/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            wordlist = tmp_path / "paths.txt"
            wordlist.write_text("admin\nmissing\n", encoding="utf-8")
            scanner = WordlistScanner(
                f"http://127.0.0.1:{port}/",
                str(wordlist),
                extensions=[""],
                concurrency=1,
                delay_ms=0,
            )
            hits = await scanner.scan()
            by_path = {item["url"].rsplit("/", 1)[-1]: item for item in scanner.responses}
            assert by_path["admin"]["status"] == 200
            assert by_path["admin"]["potential_hit"] is True
            assert by_path["missing"]["status"] == 404
            assert by_path["missing"]["potential_hit"] is False
            assert len(hits) == 1
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))



def test_result_callback_failure_does_not_stop_wordlist_scan(tmp_path):
    async def scenario():
        async def handler(request):
            if "this-path-should-not-exist-recon-baseline" in request.path:
                return web.Response(status=404, text="missing")
            return web.Response(status=200, text="a result that should be recorded")

        app = web.Application()
        app.router.add_get("/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            wordlist = tmp_path / "paths.txt"
            wordlist.write_text("one\ntwo\n", encoding="utf-8")

            def broken_result_callback(_result):
                raise RuntimeError("simulated table callback failure")

            scanner = WordlistScanner(
                f"http://127.0.0.1:{port}/", str(wordlist),
                extensions=[""], concurrency=1, delay_ms=0,
                on_result=broken_result_callback,
            )
            await scanner.scan()
            assert len(scanner.responses) == 2
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))



def test_baseline_429_honors_retry_after_then_resumes(tmp_path):
    async def scenario():
        paths = []
        baseline_count = {"value": 0}

        async def handler(request):
            paths.append(request.path)
            if "this-path-should-not-exist-recon-baseline" in request.path:
                baseline_count["value"] += 1
                if baseline_count["value"] == 1:
                    return web.Response(
                        status=429, headers={"Retry-After": "0"}, text="slow down"
                    )
                return web.Response(status=404, text="missing baseline")
            return web.Response(status=200, text="a distinct resource " + ("data " * 40))

        app = web.Application()
        app.router.add_get("/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            wordlist = tmp_path / "paths.txt"
            wordlist.write_text("admin\n", encoding="utf-8")
            logs = []
            scanner = WordlistScanner(
                f"http://127.0.0.1:{port}/", str(wordlist),
                extensions=[""], concurrency=1, delay_ms=0,
                on_log=logs.append,
            )
            await scanner.scan()
            assert baseline_count["value"] == 2
            assert "/admin" in paths
            assert scanner._rate_limited is False
            assert any("resuming remaining queued checks" in line for line in logs)
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_429_without_retry_after_stops_instead_of_retrying(tmp_path):
    async def scenario():
        requested = []

        async def handler(request):
            requested.append(request.path)
            return web.Response(status=429, text="limited")

        app = web.Application()
        app.router.add_get("/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            wordlist = tmp_path / "paths.txt"
            wordlist.write_text("admin\n", encoding="utf-8")
            scanner = WordlistScanner(
                f"http://127.0.0.1:{port}/", str(wordlist),
                extensions=[""], concurrency=1, delay_ms=0,
            )
            await scanner.scan()
            assert scanner._rate_limited is True
            assert len(requested) == 1  # only baseline; never retry before guidance
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_retry_after_parser_supports_seconds_and_invalid_values():
    from recon.wordlist_scanner import WordlistScanner

    assert WordlistScanner._parse_retry_after("15") == 15
    assert WordlistScanner._parse_retry_after("bad-value") is None
    assert WordlistScanner._parse_retry_after(None) is None


def test_wordlist_has_no_hidden_500_entry_limit_and_reports_word_caps(tmp_path):
    path = tmp_path / "many.txt"
    path.write_text("\n".join(f"path{i}" for i in range(650)), encoding="utf-8")
    scanner = WordlistScanner("https://example.com", str(path), extensions=[""])
    entries = scanner._load_wordlist()
    assert len(entries) == 650

    capped = WordlistScanner(
        "https://example.com", str(path), extensions=[""], max_words=20
    )
    assert len(capped._load_wordlist()) == 20


def test_path_candidates_expand_configured_extensions_and_reject_traversal(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("admin", encoding="utf-8")
    scanner = WordlistScanner(
        "https://example.com/base", str(path),
        extensions=["", ".php", "json"],
    )
    candidates = scanner._build_targets("admin")
    assert candidates == [
        "https://example.com/admin",
        "https://example.com/admin.php",
        "https://example.com/admin.json",
    ]
    assert scanner._build_targets("../outside") == []
    assert scanner._build_targets("https://outside.test/path") == []


def test_wordlist_request_methods_are_explicit_and_safe_by_default(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("admin", encoding="utf-8")
    scanner = WordlistScanner("https://example.com", str(path), extensions=[""])
    assert scanner.methods == ["GET"]

    selected = WordlistScanner(
        "https://example.com", str(path), extensions=[""],
        methods=["GET", "HEAD", "OPTIONS", "POST", "DELETE"],
    )
    assert selected.methods == ["GET", "HEAD", "OPTIONS"]


def test_content_discovery_records_method_for_every_response(tmp_path):
    async def scenario():
        observed = []

        async def handler(request):
            if "this-path-should-not-exist-recon-baseline" in request.path:
                return web.Response(status=404, text="missing")
            observed.append(request.method)
            return web.Response(status=200, text="method-aware " + ("resource " * 30))

        app = web.Application()
        app.router.add_route("*", "/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            wordlist = tmp_path / "paths.txt"
            wordlist.write_text("admin", encoding="utf-8")
            scanner = WordlistScanner(
                f"http://127.0.0.1:{port}/", str(wordlist),
                extensions=[""], methods=["GET", "HEAD"], concurrency=1, delay_ms=0,
            )
            await scanner.scan()
            assert observed == ["GET", "HEAD"]
            assert [item["method"] for item in scanner.responses] == ["GET", "HEAD"]
            assert scanner.scan_metadata["requests_completed"] == 2
            assert scanner.scan_metadata["request_candidates"] == 2
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))
