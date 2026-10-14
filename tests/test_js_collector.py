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
