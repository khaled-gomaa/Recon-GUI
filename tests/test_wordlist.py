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
