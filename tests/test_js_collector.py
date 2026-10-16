"""Tests for JavaScript route collection against a local test server."""
import asyncio

from aiohttp import web

from recon.js_collector import JSCollector


def test_downloaded_javascript_produces_same_host_route_candidates():
    async def scenario():
        requested = []

        async def root(request):
            return web.Response(
                text='<script src="/static/app.js"></script>',
                content_type="text/html",
            )

        async def app_js(request):
            requested.append(request.path)
            return web.Response(
                text="const page = '/admin/dashboard'; fetch('/api/current-user');",
                content_type="application/javascript",
            )

        app = web.Application()
        app.router.add_get("/", root)
        app.router.add_get("/static/app.js", app_js)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            base = f"http://127.0.0.1:{port}/"
            collector = JSCollector(base)
            collector.collect_from_html(base, '<script src="/static/app.js"></script>')
            await collector.download_and_analyze(concurrency=2)

            assert "/static/app.js" in requested
            assert f"http://127.0.0.1:{port}/admin/dashboard" in collector.route_urls
            assert f"http://127.0.0.1:{port}/api/current-user" in collector.route_urls
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=10))


def test_oversized_javascript_assets_are_reported_as_truncated():
    async def scenario():
        async def app_js(request):
            return web.Response(
                text="const route = '/safe-route'; " + ("x" * 300),
                content_type="application/javascript",
            )

        app = web.Application()
        app.router.add_get("/large.js", app_js)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            from recon import js_collector as js_module
            js_module.MAX_JS_BYTES = 128
            url = f"http://127.0.0.1:{port}/large.js"
            collector = JSCollector(f"http://127.0.0.1:{port}/")
            collector.js_urls.add(url)
            await collector.download_and_analyze(concurrency=1)
            assert url in collector.truncated_js_files
            assert url in collector.to_dict()["truncated_js_files"]
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=10))


def test_js_collector_records_non_200_responses_without_query_values():
    async def scenario():
        async def missing(_request):
            return web.Response(status=404, text="missing")

        app = web.Application()
        app.router.add_get("/missing.js", missing)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            url = f"http://127.0.0.1:{port}/missing.js?token=do-not-store"
            collector = JSCollector(f"http://127.0.0.1:{port}/")
            collector.js_urls.add(url)
            await collector.download_and_analyze(concurrency=1)
            report = collector.to_dict()
            assert report["js_fetch_error_count"] == 1
            item = report["js_fetch_errors"][0]
            assert item["status"] == 404
            assert item["error_type"] == "HTTP 404; response not analyzed"
            assert item["url"].endswith("/missing.js")
            assert "do-not-store" not in repr(report["js_fetch_errors"])
            assert url not in collector.js_contents
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=10))


def test_js_collector_records_429_and_stops_collection_safely():
    async def scenario():
        calls = []

        async def limited(request):
            calls.append(request.path)
            if len(calls) == 1:
                return web.Response(status=429, headers={"Retry-After": "0"}, text="slow down")
            return web.Response(text="const route='/resumed';", content_type="application/javascript")

        async def other_js(request):
            calls.append(request.path)
            return web.Response(text="const route='/not-analyzed';", content_type="application/javascript")

        app = web.Application()
        app.router.add_get("/limited.js", limited)
        app.router.add_get("/other.js", other_js)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            base = f"http://127.0.0.1:{port}/"
            collector = JSCollector(base)
            collector.js_urls.update({base + "limited.js", base + "other.js"})
            await collector.download_and_analyze(concurrency=1)
            report = collector.to_dict()
            assert collector.rate_limit_stopped is False
            assert any(item["status"] == 429 for item in report["js_fetch_errors"])
            assert calls.count("/limited.js") == 2
            assert base + "limited.js" in collector.js_contents
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=10))
