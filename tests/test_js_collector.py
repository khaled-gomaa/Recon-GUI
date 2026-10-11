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
