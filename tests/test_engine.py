import asyncio

from aiohttp import web

from crawler.engine import CrawlEngine, _normalize_http_url


def test_crawler_visits_multiple_depths_and_blocks_off_host_redirects():
    async def scenario():
        requested = []
        port_box = {"port": 0}

        async def root(request):
            requested.append(request.path)
            port = port_box["port"]
            html = (
                '<a href="/one">one</a>'
                '<a href="/redirect-out">redirect</a>'
                f'<a href="http://localhost:{port}/off-scope">offsite</a>'
            )
            return web.Response(text=html, content_type="text/html")

        async def one(request):
            requested.append(request.path)
            return web.Response(text='<a href="/two">two</a>', content_type="text/html")

        async def two(request):
            requested.append(request.path)
            return web.Response(text="<title>Level Two</title>done", content_type="text/html")

        async def redirect_out(request):
            requested.append(request.path)
            return web.Response(
                status=302,
                headers={"Location": f"http://localhost:{port_box['port']}/off-scope"},
            )

        async def off_scope(request):
            requested.append(request.path)
            return web.Response(text="must not be fetched", content_type="text/html")

        app = web.Application()
        app.router.add_get("/", root)
        app.router.add_get("/one", one)
        app.router.add_get("/two", two)
        app.router.add_get("/redirect-out", redirect_out)
        app.router.add_get("/off-scope", off_scope)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port_box["port"] = site._server.sockets[0].getsockname()[1]
        try:
            engine = CrawlEngine(
                f"http://127.0.0.1:{port_box['port']}/",
                max_depth=2, max_pages=10, concurrency=3,
            )
            results = await engine.crawl()
            urls = {result.url for result in results}
            assert f"http://127.0.0.1:{port_box['port']}/two" in urls
            assert "/two" in requested
            assert "/off-scope" not in requested
            redirect_result = next(result for result in results if result.url.endswith("/redirect-out"))
            assert redirect_result.status == 302
            assert redirect_result.final_url.startswith("http://localhost:")
            assert len(results) == 4
        finally:
            await runner.cleanup()

    # Fail in seconds if the async crawler/queue regresses instead of hanging CI.
    asyncio.run(asyncio.wait_for(scenario(), timeout=10))


def test_crawler_respects_max_pages_with_many_discovered_links():
    async def scenario():
        requested = []

        async def root(request):
            requested.append(request.path)
            links = "".join(f'<a href="/p{i}">p{i}</a>' for i in range(25))
            return web.Response(text=links, content_type="text/html")

        async def page(request):
            requested.append(request.path)
            return web.Response(text="child", content_type="text/html")

        app = web.Application()
        app.router.add_get("/", root)
        app.router.add_get("/{name}", page)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            engine = CrawlEngine(
                f"http://127.0.0.1:{port}/",
                max_depth=2, max_pages=4, concurrency=4,
            )
            results = await engine.crawl()
            assert len(results) <= 4
            assert len(engine.visited) <= 4
            assert len(results) == 4
            assert engine.page_limit_reached is True
        finally:
            await runner.cleanup()

    # Fail in seconds if the async crawler/queue regresses instead of hanging CI.
    asyncio.run(asyncio.wait_for(scenario(), timeout=10))



def test_url_normalization_canonicalizes_host_default_port_and_fragment():
    assert _normalize_http_url("HTTPS://EXAMPLE.COM:443/path#section") == "https://example.com/path"
    assert _normalize_http_url("http://EXAMPLE.com.:80") == "http://example.com/"
    assert _normalize_http_url("https://example.com:8443/path") == "https://example.com:8443/path"
    assert _normalize_http_url("https://[2001:db8::1]:443/path") == "https://[2001:db8::1]/path"


def test_url_normalization_rejects_invalid_ports_and_non_http_schemes():
    assert _normalize_http_url("https://example.com:notaport/path") is None
    assert _normalize_http_url("javascript:alert(1)") is None


def test_callback_failure_does_not_stop_discovery():
    async def scenario():
        requested = []

        async def root(request):
            requested.append(request.path)
            return web.Response(text='<a href="/child">child</a>', content_type="text/html")

        async def child(request):
            requested.append(request.path)
            return web.Response(text="<title>child</title>ok", content_type="text/html")

        app = web.Application()
        app.router.add_get("/", root)
        app.router.add_get("/child", child)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]

            def broken_ui_callback(_result):
                raise RuntimeError("simulated GUI callback failure")

            engine = CrawlEngine(
                f"http://127.0.0.1:{port}/",
                max_depth=1, max_pages=5, concurrency=2,
                on_page_crawled=broken_ui_callback,
            )
            results = await engine.crawl()
            assert len(results) == 2
            assert "/" in requested
            assert "/child" in requested
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=10))



def test_crawler_can_crawl_additional_seed_urls_without_revisiting_pages():
    async def scenario():
        requested = []

        async def handler(request):
            requested.append(request.path)
            if request.path == "/":
                return web.Response(text="<title>root</title>", content_type="text/html")
            if request.path == "/hidden":
                return web.Response(text="<title>hidden</title>", content_type="text/html")
            return web.Response(status=404, text="missing", content_type="text/html")

        app = web.Application()
        app.router.add_get("/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            engine = CrawlEngine(
                f"http://127.0.0.1:{port}/",
                max_depth=2, max_pages=5, concurrency=2,
            )
            initial = await engine.crawl()
            assert len(initial) == 1
            combined = await engine.crawl(
                seed_urls=[f"http://127.0.0.1:{port}/hidden",
                           f"http://127.0.0.1:{port}/hidden#fragment",
                           "https://other.example/should-not-fetch"],
                seed_depth=1,
            )
            assert len(combined) == 2
            assert requested.count("/hidden") == 1
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=10))



def test_crawler_follows_hidden_forms_data_links_and_inline_js_routes():
    async def scenario():
        requested = []

        async def root(request):
            requested.append(request.path)
            html = """
            <html><body>
              <form action="/hidden/form-action"></form>
              <div data-url="/hidden/data-route"></div>
              <script>const hidden = '/hidden/from-inline-js';</script>
            </body></html>
            """
            return web.Response(text=html, content_type="text/html")

        async def hidden(request):
            requested.append(request.path)
            return web.Response(text="<title>Found</title>", content_type="text/html")

        app = web.Application()
        app.router.add_get("/", root)
        app.router.add_get("/hidden/{name}", hidden)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            engine = CrawlEngine(
                f"http://127.0.0.1:{port}/", max_depth=1,
                max_pages=10, concurrency=3,
            )
            results = await engine.crawl()
            assert len(results) == 4
            assert "/hidden/form-action" in requested
            assert "/hidden/data-route" in requested
            assert "/hidden/from-inline-js" in requested
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=10))



def test_crawler_reads_robots_and_sitemap_content_to_discover_pages():
    async def scenario():
        requested = []

        async def root(request):
            requested.append(request.path)
            html = '<a href="/robots.txt">robots</a><a href="/sitemap.xml">sitemap</a>'
            return web.Response(text=html, content_type="text/html")

        async def robots(request):
            requested.append(request.path)
            return web.Response(
                text="User-agent: *\nDisallow: /hidden/robots-route\n",
                content_type="text/plain",
            )

        async def sitemap(request):
            requested.append(request.path)
            return web.Response(
                text="<urlset><url><loc>/hidden/sitemap-route</loc></url></urlset>",
                content_type="application/xml",
            )

        async def hidden(request):
            requested.append(request.path)
            return web.Response(text="<title>hidden</title>", content_type="text/html")

        app = web.Application()
        app.router.add_get("/", root)
        app.router.add_get("/robots.txt", robots)
        app.router.add_get("/sitemap.xml", sitemap)
        app.router.add_get("/hidden/{name}", hidden)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            engine = CrawlEngine(
                f"http://127.0.0.1:{port}/", max_depth=2,
                max_pages=10, concurrency=3,
            )
            results = await engine.crawl()
            assert len(results) == 5
            assert "/hidden/robots-route" in requested
            assert "/hidden/sitemap-route" in requested
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=10))



def test_crawler_honors_retry_after_and_resumes_queued_pages():
    async def scenario():
        requested = []

        async def root(request):
            requested.append(request.path)
            return web.Response(
                text='<a href="/a-rate-limit">limited</a><a href="/z-okay">okay</a>',
                content_type="text/html",
            )

        async def limited(request):
            requested.append(request.path)
            return web.Response(
                status=429, headers={"Retry-After": "0"}, text="slow down",
                content_type="text/plain",
            )

        async def okay(request):
            requested.append(request.path)
            return web.Response(text="<title>Still working</title>", content_type="text/html")

        app = web.Application()
        app.router.add_get("/", root)
        app.router.add_get("/a-rate-limit", limited)
        app.router.add_get("/z-okay", okay)
        runner = web.AppRunner(app)
        await runner.setup()
        logs = []
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            engine = CrawlEngine(
                f"http://127.0.0.1:{port}/", max_depth=1,
                max_pages=10, concurrency=1, on_log=logs.append,
            )
            results = await engine.crawl()
            assert "/a-rate-limit" in requested
            assert "/z-okay" in requested
            assert any(result.status == 429 for result in results)
            assert engine.rate_limit_stopped is False
            assert any("resuming queued crawl requests" in line for line in logs)
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_crawler_stops_queue_when_429_has_no_retry_after():
    async def scenario():
        requested = []

        async def root(request):
            requested.append(request.path)
            return web.Response(
                text='<a href="/a-rate-limit">limited</a><a href="/z-should-not-run">later</a>',
                content_type="text/html",
            )

        async def limited(request):
            requested.append(request.path)
            return web.Response(status=429, text="slow down", content_type="text/plain")

        async def later(request):
            requested.append(request.path)
            return web.Response(text="not expected", content_type="text/html")

        app = web.Application()
        app.router.add_get("/", root)
        app.router.add_get("/a-rate-limit", limited)
        app.router.add_get("/z-should-not-run", later)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            engine = CrawlEngine(
                f"http://127.0.0.1:{port}/", max_depth=1,
                max_pages=10, concurrency=1,
            )
            await engine.crawl()
            assert engine.rate_limit_stopped is True
            assert "/a-rate-limit" in requested
            assert "/z-should-not-run" not in requested
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_crawler_marks_truncated_html_bodies_explicitly(monkeypatch):
    async def scenario():
        async def robots(request):
            return web.Response(status=404, text="missing")

        async def root(request):
            return web.Response(
                text="<html><body>" + ("x" * 512) + "</body></html>",
                content_type="text/html",
            )

        app = web.Application()
        app.router.add_get("/robots.txt", robots)
        app.router.add_get("/", root)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            monkeypatch.setattr("crawler.engine.MAX_BODY_BYTES", 128)
            engine = CrawlEngine(
                f"http://127.0.0.1:{port}/", max_depth=1, max_pages=5, concurrency=1,
            )
            results = await engine.crawl()
            root_result = next(item for item in results if item.url.endswith("/"))
            assert root_result.body_truncated is True
            assert root_result.to_dict()["body_truncated"] is True
            assert len(root_result.html.encode("utf-8")) <= 128
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=10))
