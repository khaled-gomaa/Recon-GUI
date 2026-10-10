import asyncio

from aiohttp import web

from crawler.engine import CrawlEngine


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

    asyncio.run(scenario())


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
        finally:
            await runner.cleanup()

    asyncio.run(scenario())
